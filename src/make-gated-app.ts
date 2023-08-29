/*
 * Copyright 2023 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import cookieParser from 'cookie-parser';
import { randomUUID } from 'crypto';
import express, { json, Request, Response, NextFunction, RequestHandler } from 'express';
import { applicationDefault, initializeApp } from 'firebase-admin/app';
import { Auth, getAuth } from 'firebase-admin/auth';
import { makeRedirectHtml } from './make-redirect-html';

const SET_COOKIE_PATH = '/__setcookie';
const AUTH_DETAILS_PATH = '/__authdetails';
const SIGN_OUT_PATH = '/__signout';
const SIGNIN_HELPER_STATIC_ROOT_PATH = '/__/';

const DEFAULT_SESSION_MAX_AGE = 1000 * 60 * 60 * 24 * 5;

type Unpromise<T extends Promise<any>> = T extends Promise<infer U> ? U : never;
export type AuthDetails = Unpromise<ReturnType<Auth['verifySessionCookie']>> & {
  signOutLink: (redirectUrl: string) => string;
};

export interface Options {
  /**
   * Subset of the Firebase configuration required for authentication.
   */
  firebaseConfig: {
    apiKey: string;
    authDomain: string;
    projectId: string;
  };

  /**
   * Session expiration time in milliseconds. Defaults to 5 days.
   */
  sessionMaxAge?: number;

  /**
   * Authorization function that returns true if the user is authorized to access the site.
   * Defaults to allowing any logged in user (always returns true).
   */
  authorize?: (user: { [key: string]: any }) => boolean;

  /**
   * Optional custom handler to run if access is forbidden (i.e. `authorized` returns false).
   */
  onForbidden?: RequestHandler;

  /**
   * If true, will automatically use the browser's current host instead of the provided
   * `firebaseConfig.authDomain`, if possible. This should be used with `firebaseAuthSigninHelpers`
   * to host the firebase auth helper code on the same domain. This currently no-ops when
   * running on a custom port (e.g. `localhost:3000`), since `authDomain` must always serve on
   * port 443.
   */
  selfHostedAuthHelper?: boolean;

  /**
   * Whether or not to always show the Google account picker. Defaults to false
   */
  alwaysShowAccountPicker?: boolean;
}

/**
 * Returns a new {@link express.Express} app gated on given Firebase auth claims (e.g. admin).
 *
 * Once logged in, auth details are added to all request objects under `req.auth`, which
 * takes the shape `{ name: "User Name", picture: "https://...png" email: "user@name.com" }`.
 *
 * The returned app also has a `signOutLink(redirectUrl)` method you can use to offer sign out.
 */
export default function (options: Options) {
  let { firebaseConfig, sessionMaxAge, authorize, onForbidden } = options;
  const firebaseApp = initializeApp({
    credential: applicationDefault(),
    ...firebaseConfig,
  });

  authorize = authorize || (() => true); // by default always authorize
  sessionMaxAge = sessionMaxAge || DEFAULT_SESSION_MAX_AGE;

  const auth = getAuth(firebaseApp);
  const gatedApp = express();
  const mountpath = () => gatedApp.mountpath;
  const signOutLink = (redirect = '/') => mountpath() + SIGN_OUT_PATH + '?redirect=' + encodeURIComponent(redirect);

  // Main middleware
  gatedApp.use(cookieParser() as any, async (req: Request, res: Response, next: NextFunction) => {
    if (req.path === SET_COOKIE_PATH || req.path === SIGN_OUT_PATH || req.path.startsWith(SIGNIN_HELPER_STATIC_ROOT_PATH)) {
      next();
      return;
    }

    const sessionCookie = req.cookies?.session || '';

    // Verify the session cookie. In this case an additional check is added to detect
    // if the user's Firebase session was revoked, user deleted/disabled, etc.
    try {
      let user = await auth.verifySessionCookie(sessionCookie, true /** checkRevoked */);
      req['auth'] = {
        ...user = user,
        signOutLink
      } as AuthDetails;
      if (!authorize(user)) {
        if (onForbidden) {
          onForbidden(req, res, () => { });
        } else {
          res.status(403).type('html').send(`<!doctype html><html><body>
  Access forbidden. <a href="${signOutLink('/')}">Sign out</a>
  </body></html>`);
        }
        return;
      }
      if (req.url === AUTH_DETAILS_PATH) {
        res.status(200).type('json').json(user);
        return;
      }

      next();
    } catch (error) {
      // Session cookie is unavailable or invalid. Force user to login.
      res
        .status(200)
        .cookie('csrfToken', randomUUID(), { maxAge: 60 * 1000, httpOnly: false, secure: true })
        .type('html')
        .send(makeRedirectHtml({
          setCookieUrl: mountpath() + SET_COOKIE_PATH,
          options,
        }));
    }
  });

  gatedApp.get(SIGN_OUT_PATH, (req, res) => {
    res
      .clearCookie('csrfToken')
      .clearCookie('session')
      .status(200)
      .redirect(302, new URLSearchParams(req.url).get('redirect') || '/');
  });

  // Set cookie handler (called after auth)
  gatedApp.post(SET_COOKIE_PATH, json(), async (req, res) => {
    // Get the ID token passed and the CSRF token.
    const idToken = req.body.idToken.toString();
    const csrfToken = req.body.csrfToken.toString();
    // Guard against CSRF attacks.
    if (csrfToken !== req.cookies?.csrfToken) {
      res.status(401).send('Unauthorized');
      return;
    }
    // Create the session cookie. This will also verify the ID token in the process.
    // The session cookie will have the same claims as the ID token.
    // To only allow session cookie setting on recent sign-in, auth_time in ID token
    // can be checked to ensure user was recently signed in before creating a session cookie.
    try {
      let sessionCookie = await auth.createSessionCookie(idToken, { expiresIn: sessionMaxAge });
      // Set cookie policy for session cookie.
      res
        .type('json')
        .cookie('session', sessionCookie, { maxAge: sessionMaxAge, httpOnly: true, secure: true })
        .send(JSON.stringify({ status: 'success' }));
    } catch (error) {
      console.error(error?.errorInfo);
      if (error?.errorInfo?.code === 'auth/internal-error') {
        res.status(500).send(
          (process.env.NODE_ENV === 'development')
            ? JSON.stringify(error)
            : 'Internal error');
        return;
      }
      res.status(401).send('Unauthorized');
    }
  });

  return gatedApp;
}
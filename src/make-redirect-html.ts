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
import type { Options } from './make-gated-app';

export function makeRedirectHtml({
  options: {
    firebaseConfig,
    selfHostedAuthHelper,
    alwaysShowAccountPicker
  },
  setCookieUrl
}: {
  options: Options,
  setCookieUrl: string
}) {
  return `<!doctype html>
  <script src="https://www.gstatic.com/firebasejs/8.10.1/firebase-app.js"></script>
  <script src="https://www.gstatic.com/firebasejs/8.10.1/firebase-auth.js"></script>
  <script>
    let firebaseConfig = ${JSON.stringify(firebaseConfig)};
    ${selfHostedAuthHelper
      ? `if (!window.location.port) firebaseConfig.authDomain = window.location.host;`
      : ''}
    // Initialize Firebase
    firebase.initializeApp(firebaseConfig);
    let provider = new firebase.auth.GoogleAuthProvider();
    ${alwaysShowAccountPicker
      ? `provider.setCustomParameters({ prompt: 'select_account' });` : ''}
    firebase.auth().setPersistence(firebase.auth.Auth.Persistence.NONE);
    firebase.auth().getRedirectResult().then(result => {
      if (!result.user) {
        firebase.auth().signInWithRedirect(provider);
        return;
      }
      // Get the user's ID token as it is needed to exchange for a session cookie.
      return result.user.getIdToken().then(idToken => {
        // Session login endpoint is queried and the session cookie is set.
        // CSRF protection should be taken into account.
        // ...
        const csrfToken = getCookie('csrfToken')
        return fetch(${JSON.stringify(setCookieUrl)}, {
          body: JSON.stringify({ idToken, csrfToken }),
          headers: {
            'Content-Type': 'application/json'
          },
          method: 'post',
        });
      })
      .then(result => {
        if (!result.ok) {
          document.write('Sign in error, see console output');
          result.text().then(t => console.error(result, t));
          return;
        }
        // A page redirect would suffice as the persistence is set to NONE.
        return firebase.auth().signOut().then(() => window.location.reload());
      });
    });

    function getCookie(cookieName) {
      let name = cookieName + "=";
      let ca = document.cookie.split(';');
      for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') {
          c = c.substring(1);
        }
        if (c.indexOf(name) === 0) {
          return c.substring(name.length, c.length);
        }
      }
      return '';
    }

  </script>
  `;
}

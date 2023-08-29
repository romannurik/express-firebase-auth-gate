# Firebase Auth gate for Express.js

Protect access to Express apps using [Firebase Auth](https://firebase.google.com/products/auth) (Google Sign-In only for now).

## How does it work?

This library creates an Express app with middleware that:

1. Injects a simple redirect-style Google Sign-In flow using Firebase Auth
2. Checks that the logged-in user is authorized (based on your own logic, such as checking for [custom claims](https://firebase.google.com/docs/auth/admin/custom-claims#defining_roles_via_backend_script))
3. Sets a session cookie and passes auth credentials to your handlers, via `req.auth`.
4. Exposes additional routes, such as a sign out link (`<mount path>/__signout?redirect=/`)

## Installation

Just install it with:

```sh
npm install express-firebase-auth-gate
```

## Example usage

```js
import express from 'express';
import makeAdminApp, { firebaseAuthSigninHelpers } from 'express-firebase-auth-gate';

const app = express();

// the magic
const adminApp = makeAdminApp({
  firebaseConfig: { ... },          // get this from Firebase
  authorize: user => !!user.admin,  // custom claims for the user
});

// anything under /admin is now protected
app.use('/admin', adminApp);
adminApp.use('/assets', express.static('admin-assets'));
adminApp.get('/', (req, res) => {
  const { picture, name, email } = req.auth; // access sign in details
  res.status(200).type('html').send(`<b>Logged in as ${name}!</b>`);
});

// Want to also host the Firebase auth helpers on your domain? Just
// remove `authDomain` from the `firebaseConfig` above and add this:
app.use(firebaseAuthSigninHelpers);

// start the server
app.listen(3000);
```

## Use during development and non-Google cloud environments

The library using the Firebase Admin SDK, which requires credentials when running outside Google
environments (including local development). The easiest way to do this is by getting Admin SDK
service account credentials as a `.json` file (via the Firebase console) and setting the
`GOOGLE_APPLICATION_CREDENTIALS` environment variable to its path:

```sh
GOOGLE_APPLICATION_CREDENTIALS=./path/to/service-account.json npm run dev
```

Failing to set this up will throw errors that look like this:

```json
{
  "code": "auth/internal-error",
  "message": "//cloud.google.com/docs/authentication/. If you are getting this error with curl or similar tools, you may need to specify 'X-Goog-User-Project' HTTP header..."
}
```
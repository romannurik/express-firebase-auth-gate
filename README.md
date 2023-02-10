# Firebase Auth gate for Express.js

Protect access to Express apps using [Firebase Auth](https://firebase.google.com/products/auth) (Google Sign-In only for now).

## How does it work?

This library creates an Express app with middleware that:

1. Injects a simple redirect-style Google Sign-In flow using Firebase Auth
2. Checks that the logged-in user is authorized (based on your own logic, such as checking for [custom claims](https://firebase.google.com/docs/auth/admin/custom-claims#defining_roles_via_backend_script))
3. Sets a session cookie and passes auth credentials to your handlers, via `req.auth`.
4. Exposes additional routes, such as a sign out link (`<mount path>/__signout?redirect=/`)

## Example usage

```js
import express from 'express';
import makeAdminApp from 'express-firebase-auth-gate';

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

// start the server
app.listen(3000);
```
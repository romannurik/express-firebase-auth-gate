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

// TODO: this is clunky because `microbundle` doesn't support raw file loaders
import STATIC_FILES from './signin-helpers-static.json';
import { Request, Response, NextFunction } from 'express';

export async function firebaseAuthSigninHelpers(req: Request, res: Response, next: NextFunction) {
  if (!(req.path.startsWith('/__/auth/'))) {
    next();
    return;
  }

  let filename = req.path.replace(/^\/__\/auth\//, '');
  if (!(filename in STATIC_FILES)) {
    next();
    return;
  }

  let content = STATIC_FILES[filename];
  let extension = filename.match(/\.(.+)$/)?.[1] || '';
  let mimetype = {
    'js': 'text/javascript',
    '': 'text/html'
  }[extension] || 'text/plain';

  res.status(200).type(mimetype).send(content).end();
}
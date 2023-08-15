// allows to access PageSigner's internal classes by exposing them to the
// extension's window global

import * as utils from './utils.js';
import * as indexeddb from './indexeddb.js';
import * as globals from './globals.js';
import * as Main from './Main.js';


window.PageSigner = {
  Main:Main,
  globals:globals,
  utils:utils,
  indexeddb:indexeddb};

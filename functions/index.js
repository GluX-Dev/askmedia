const functions = require("firebase-functions/v1");

let appInstance = null;

function getApp() {
  if (!appInstance) {
    appInstance = require("./src/server").app;
  }
  return appInstance;
}

exports.app = functions
  .region("us-central1")
  .https
  .onRequest((req, res) => getApp()(req, res));

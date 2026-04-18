const functions = require("firebase-functions/v1");
const { app } = require("./server");

exports.app = functions
  .region("us-central1")
  .https
  .onRequest(app);

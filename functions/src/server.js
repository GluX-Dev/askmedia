

const crypto = require("crypto");
const cors = require("cors");
const express = require("express");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const https = require("https");
const path = require("path");
const admin = require("firebase-admin");

function loadEnvFile(envFilePath) {
  if (!fs.existsSync(envFilePath)) {
    return;
  }

  const envSource = fs.readFileSync(envFilePath, "utf8");
  const envLines = envSource.split(/\r?\n/);
  for (let lineIndex = 0; lineIndex < envLines.length; lineIndex += 1) {
    const rawLine = envLines[lineIndex];
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const separatorIndex = rawLine.indexOf("=");
    if (separatorIndex <= 0) {
      continue;
    }

    const key = rawLine.slice(0, separatorIndex).trim();
    if (!key) {
      continue;
    }

    let value = rawLine.slice(separatorIndex + 1).trim();
    if (value.startsWith('"') || value.startsWith("'")) {
      const quoteChar = value[0];
      value = value.slice(1);

      while (!value.endsWith(quoteChar) && lineIndex + 1 < envLines.length) {
        lineIndex += 1;
        value += `\n${envLines[lineIndex]}`;
      }

      if (value.endsWith(quoteChar)) {
        value = value.slice(0, -1);
      }
    }

    if (process.env[key] !== undefined) {
      continue;
    }

    process.env[key] = value;
  }
}

const envCandidatePaths = [
  path.join(__dirname, ".env"),
  path.join(process.cwd(), ".env"),
];
if (path.basename(__dirname) === "src") {
  envCandidatePaths.splice(1, 0, path.join(__dirname, "..", ".env"));
}
for (const envFilePath of new Set(envCandidatePaths.map((candidate) => path.resolve(candidate)))) {
  loadEnvFile(envFilePath);
}

const DATABASE_URL = process.env.FIREBASE_DATABASE_URL || "https://ask-media-cc963-default-rtdb.europe-west1.firebasedatabase.app";
const FIREBASE_PREFLIGHT_TIMEOUT_MS = Math.min(
  Math.max(Number.parseInt(process.env.FIREBASE_PREFLIGHT_TIMEOUT_MS || "4000", 10) || 4000, 1000),
  20000
);

// ============================================================================
// FIREBASE ADMIN SDK INITIALIZATION
// Credential priority:
//   1. Individual env vars  (FIREBASE_CLIENT_EMAIL + FIREBASE_PRIVATE_KEY) Ã¢â€ Â preferred
//   2. GOOGLE_APPLICATION_CREDENTIALS path (file on disk)
//   3. serviceAccountKey.json in project root (legacy fallback)
// ============================================================================

function buildServiceAccountFromEnv() {
  const clientEmail  = (process.env.FIREBASE_CLIENT_EMAIL  || "").trim();
  const privateKeyRaw = (process.env.FIREBASE_PRIVATE_KEY   || "").trim();
  const projectId    = (process.env.FIREBASE_PROJECT_ID    || process.env.GCLOUD_PROJECT || "").trim();

  if (!clientEmail || !privateKeyRaw || !projectId) {
    return null; // env vars not set Ã¢â‚¬â€ try next strategy
  }

  // .env files often escape newlines as \n literals Ã¢â‚¬â€ restore actual newlines
  const privateKey = privateKeyRaw.replace(/\\n/g, "\n");
  if (!privateKey.includes("BEGIN PRIVATE KEY") || !privateKey.includes("END PRIVATE KEY")) {
    return null;
  }

  return {
    type: "service_account",
    project_id: projectId,
    private_key_id: (process.env.FIREBASE_PRIVATE_KEY_ID || "").trim() || undefined,
    private_key:    privateKey,
    client_email:   clientEmail,
    client_id:      (process.env.FIREBASE_CLIENT_ID      || "").trim() || undefined,
    auth_uri:       "https://accounts.google.com/o/oauth2/auth",
    token_uri:      "https://oauth2.googleapis.com/token",
  };
}

function buildServiceAccountFromJsonEnv() {
  const rawJson = (process.env.FIREBASE_SERVICE_ACCOUNT_JSON || process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON || "").trim();
  if (!rawJson) {
    return null;
  }

  try {
    const parsed = JSON.parse(rawJson);
    if (parsed?.private_key && typeof parsed.private_key === "string") {
      parsed.private_key = parsed.private_key.replace(/\\n/g, "\n");
    }
    return parsed;
  } catch (_error) {
    return null;
  }
}

function buildServiceAccountFromBase64Env() {
  const rawBase64 = (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64 || "").trim();
  if (!rawBase64) {
    return null;
  }

  try {
    const decoded = Buffer.from(rawBase64, "base64").toString("utf8");
    const parsed = JSON.parse(decoded);
    if (parsed?.private_key && typeof parsed.private_key === "string") {
      parsed.private_key = parsed.private_key.replace(/\\n/g, "\n");
    }
    return parsed;
  } catch (_error) {
    return null;
  }
}

const isFirebaseRuntime = Boolean(
  process.env.FUNCTION_TARGET ||
  process.env.FUNCTION_NAME ||
  process.env.K_SERVICE ||
  process.env.FIREBASE_CONFIG
);

function collectFirebaseCredentialCandidates() {
  const candidates = [];
  const seenCandidates = new Set();

  function addCandidate(candidate) {
    const keyId = (candidate?.privateKeyId || "").trim();
    const clientEmail = (candidate?.clientEmail || "").trim().toLowerCase();
    const fingerprint = keyId && clientEmail
      ? `${clientEmail}:${keyId}`
      : `${candidate?.source || ""}:${candidate?.detail || ""}`;

    if (seenCandidates.has(fingerprint)) {
      return;
    }
    seenCandidates.add(fingerprint);
    candidates.push(candidate);
  }

  if (isFirebaseRuntime) {
    addCandidate({
      source: "applicationDefault",
      detail: "Firebase runtime default service account",
      credential: admin.credential.applicationDefault(),
    });
  }

  const envAccount = buildServiceAccountFromEnv();
  if (envAccount) {
    addCandidate({
      source: "env",
      detail: "environment variables",
      credential: admin.credential.cert(envAccount),
      clientEmail: envAccount.client_email || "",
      privateKeyId: envAccount.private_key_id || "",
    });
  }

  const envJsonAccount = buildServiceAccountFromJsonEnv();
  if (envJsonAccount) {
    addCandidate({
      source: "envJson",
      detail: "FIREBASE_SERVICE_ACCOUNT_JSON",
      credential: admin.credential.cert(envJsonAccount),
      clientEmail: envJsonAccount.client_email || "",
      privateKeyId: envJsonAccount.private_key_id || "",
    });
  }

  const envBase64Account = buildServiceAccountFromBase64Env();
  if (envBase64Account) {
    addCandidate({
      source: "envBase64",
      detail: "FIREBASE_SERVICE_ACCOUNT_BASE64",
      credential: admin.credential.cert(envBase64Account),
      clientEmail: envBase64Account.client_email || "",
      privateKeyId: envBase64Account.private_key_id || "",
    });
  }

  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS.trim();
    if (credPath) {
      try {
        const resolvedPath = path.isAbsolute(credPath)
          ? credPath
          : path.join(__dirname, credPath);
        const credJson = JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
        addCandidate({
          source: "googleApplicationCredentials",
          detail: `GOOGLE_APPLICATION_CREDENTIALS (${resolvedPath})`,
          credential: admin.credential.cert(credJson),
          clientEmail: credJson.client_email || "",
          privateKeyId: credJson.private_key_id || "",
        });
      } catch (error) {
        console.warn(
          `Firebase: unable to load GOOGLE_APPLICATION_CREDENTIALS (${credPath}): ${error?.message || error}`
        );
      }
    }
  }

  const serviceAccountPaths = [
    path.join(__dirname, "serviceAccountKey.json"),
    path.join(process.cwd(), "serviceAccountKey.json"),
  ];
  if (path.basename(__dirname) === "src") {
    serviceAccountPaths.splice(1, 0, path.join(__dirname, "..", "serviceAccountKey.json"));
  }

  for (const serviceAccountPath of new Set(serviceAccountPaths.map((candidate) => path.resolve(candidate)))) {
    if (!fs.existsSync(serviceAccountPath)) {
      continue;
    }

    try {
      const keyJson = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));
      addCandidate({
        source: "serviceAccountKeyFile",
        detail: `serviceAccountKey.json (${serviceAccountPath})`,
        credential: admin.credential.cert(keyJson),
        clientEmail: keyJson.client_email || "",
        privateKeyId: keyJson.private_key_id || "",
      });
      break;
    } catch (error) {
      console.warn(
        `Firebase: unable to parse serviceAccountKey.json (${serviceAccountPath}): ${error?.message || error}`
      );
    }
  }

  return candidates;
}

async function verifyActiveFirebaseCredentialToken(timeoutMs = FIREBASE_PREFLIGHT_TIMEOUT_MS) {
  const activeCandidate = firebaseCredentialCandidates[firebaseActiveCredentialIndex];
  const credential = activeCandidate?.credential;
  if (!credential || typeof credential.getAccessToken !== "function") {
    return true;
  }

  let timeoutHandle = null;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutHandle = setTimeout(() => {
      reject(new Error(`Firebase token verification timed out after ${timeoutMs}ms.`));
    }, timeoutMs);
  });

  try {
    const token = await Promise.race([credential.getAccessToken(), timeoutPromise]);
    return Boolean(token);
  } finally {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
    }
  }
}

async function getActiveKeyIdsForServiceAccount(clientEmail) {
  if (!clientEmail) {
    return null;
  }

  const certificateUrl = `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(clientEmail)}`;
  return new Promise((resolve) => {
    let settled = false;
    const settle = (value) => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(value);
    };

    const request = https.get(certificateUrl, { timeout: 4000 }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
      });
      response.on("end", () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          settle(null);
          return;
        }

        try {
          const json = JSON.parse(body);
          settle(Object.keys(json || {}));
        } catch (_error) {
          settle(null);
        }
      });
      response.on("error", () => settle(null));
    });

    request.on("timeout", () => {
      request.destroy();
      settle(null);
    });
    request.on("error", () => settle(null));
  });
}

async function logFirebaseKeyDiagnosticsForActiveCredential() {
  const activeCandidate = firebaseCredentialCandidates[firebaseActiveCredentialIndex];
  const keyId = (activeCandidate?.privateKeyId || "").trim();
  const clientEmail = (activeCandidate?.clientEmail || "").trim();
  if (!keyId || !clientEmail) {
    return;
  }

  const activeKeyIds = await getActiveKeyIdsForServiceAccount(clientEmail);
  if (!Array.isArray(activeKeyIds)) {
    return;
  }

  const isActive = activeKeyIds.includes(keyId);
  console.error(`Firebase key id active: ${isActive ? "yes" : "no"} (${keyId})`);
  if (!isActive && activeKeyIds.length) {
    console.error(`Active Firebase key ids for ${clientEmail}: ${activeKeyIds.join(", ")}`);
  }
}

const firebaseCredentialCandidates = [];
let firebaseActiveCredentialIndex = -1;
let firebaseCredentialDetail = "";

function initializeFirebaseAppWithCandidate(index) {
  const candidate = firebaseCredentialCandidates[index];
  if (!candidate) {
    throw new Error(`Firebase credential candidate index ${index} is unavailable.`);
  }

  admin.initializeApp({
    credential: candidate.credential,
    databaseURL: DATABASE_URL,
  });

  firebaseActiveCredentialIndex = index;
  firebaseCredentialDetail = candidate.detail;
  console.log(`Firebase: credential loaded from ${candidate.detail}`);
  console.log("Firebase Admin SDK initialized");
}

async function trySwitchToNextFirebaseCredential() {
  for (let index = firebaseActiveCredentialIndex + 1; index < firebaseCredentialCandidates.length; index += 1) {
    const candidate = firebaseCredentialCandidates[index];
    try {
      if (admin.apps.length) {
        await admin.app().delete();
      }

      initializeFirebaseAppWithCandidate(index);
      console.warn(`Firebase: switched credential source to ${candidate.detail}`);
      return true;
    } catch (error) {
      console.warn(
        `Firebase: failed to switch to ${candidate.detail}: ${error?.message || error}`
      );
    }
  }

  return false;
}

try {
  if (!admin.apps.length) {
    firebaseCredentialCandidates.push(...collectFirebaseCredentialCandidates());
    if (!firebaseCredentialCandidates.length) {
      throw new Error(
        "No Firebase credentials found. " +
        "Set FIREBASE_CLIENT_EMAIL + FIREBASE_PRIVATE_KEY + FIREBASE_PROJECT_ID in .env, " +
        "set GOOGLE_APPLICATION_CREDENTIALS to a key-file path, add serviceAccountKey.json, " +
        "or run inside Firebase runtime."
      );
    }

    initializeFirebaseAppWithCandidate(0);
  }
} catch (err) {
  console.error("Firebase initialization failed:", err.message);
  process.exit(1);
}

let db = admin.database();
let auth = admin.auth();

function isInvalidFirebaseCredentialError(error) {
  const message = String(error?.message || "").toLowerCase();
  return message.includes("invalid_grant")
    || message.includes("invalid jwt signature")
    || message.includes("invalid-credential")
    || message.includes("app/invalid-credential");
}

async function verifyFirebaseAdminAccess(timeoutMs = FIREBASE_PREFLIGHT_TIMEOUT_MS) {
  try {
    await verifyActiveFirebaseCredentialToken(timeoutMs);

    const verification = db.ref("_meta/firebaseCredentialCheck").limitToFirst(1).once("value");
    let timeoutHandle = null;
    const timeoutPromise = new Promise((_, reject) => {
      timeoutHandle = setTimeout(() => {
        reject(new Error(`Firebase credential verification timed out after ${timeoutMs}ms.`));
      }, timeoutMs);
    });

    try {
      await Promise.race([verification, timeoutPromise]);
    } finally {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }
    }

    return true;
  } catch (error) {
    if (isInvalidFirebaseCredentialError(error)) {
      const switched = await trySwitchToNextFirebaseCredential();
      if (switched) {
        db = admin.database();
        auth = admin.auth();
        return verifyFirebaseAdminAccess(timeoutMs);
      }

      console.error(
        "Firebase credentials were rejected. " +
        "Generate a new service-account key (or use runtime default credentials), " +
        "ensure server time is synchronized, and verify the key id is still active."
      );
      if (firebaseCredentialDetail) {
        console.error(`Firebase credential source used: ${firebaseCredentialDetail}`);
      }
      await logFirebaseKeyDiagnosticsForActiveCredential();
      throw error;
    }

    if (String(error?.message || "").toLowerCase().includes("timed out")) {
      console.warn("Firebase preflight verification timed out. Continuing startup.");
      return false;
    }

    console.warn("Firebase preflight verification failed. Continuing startup.");
    console.warn(error?.message || error);
    return false;
  }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function parseCsv(rawValue) {
  return String(rawValue || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function sanitizeString(value, maxLength = 250) {
  if (value === undefined || value === null) {
    return "";
  }
  return String(value).trim().slice(0, maxLength);
}

function normalizeEmail(value) {
  return sanitizeString(value, 320).toLowerCase();
}

function isLikelyEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function normalizePhone(value) {
  let cleaned = sanitizeString(value, 25).replace(/[^\d+]/g, "");
  if (!cleaned) return "";

  // Convert Nigerian mapping specifically if user accidentally tries to paste +234
  if (cleaned.startsWith("+234")) {
    cleaned = "+233" + cleaned.substring(4);
  } else if (cleaned.startsWith("234") && cleaned.length >= 13) {
    cleaned = "+233" + cleaned.substring(3);
  }

  // Enforce true Ghanaian numbering
  if (cleaned.startsWith("0")) {
    cleaned = "+233" + cleaned.substring(1);
  } else if (cleaned.startsWith("233")) {
    cleaned = "+" + cleaned;
  } else if (!cleaned.startsWith("+")) {
    cleaned = "+233" + cleaned;
  }

  return cleaned.slice(0, 15);
}

function normalizeSlug(value) {
  return sanitizeString(value, 80)
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "");
}

function isValidSlug(slug) {
  return /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug) && slug.length >= 3 && slug.length <= 50;
}

function toPrice(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount <= 0) {
    return null;
  }
  return Math.round(amount * 100) / 100;
}

function clampInteger(value, minimum, maximum, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed)) {
    return fallback;
  }
  return Math.min(Math.max(parsed, minimum), maximum);
}

function getCurrentTimestamp() {
  return new Date().toISOString();
}

function sendJson(res, statusCode, payload) {
  res.status(statusCode).json(payload);
}

function maskEmail(email) {
  const normalized = normalizeEmail(email);
  if (!normalized.includes("@")) {
    return normalized;
  }
  const [localPart, domain] = normalized.split("@");
  return localPart ? `${localPart[0]}***@${domain}` : normalized;
}

function deriveDefaultStoreName(name, email) {
  if (sanitizeString(name, 120)) {
    return sanitizeString(name, 120);
  }
  if (normalizeEmail(email)) {
    return `${normalizeEmail(email).split("@")[0]}'s Store`;
  }
  return "My Store";
}

function looksLikeUrl(value) {
  return /^https?:\/\//i.test(String(value || "").trim());
}

function isSecureWebhookSecret(value) {
  const secret = String(value || "").trim();
  return Boolean(secret)
    && secret !== "your_strong_random_webhook_secret_here"
    && !looksLikeUrl(secret)
    && secret.length >= 16;
}

function trimUrlForConfig(value) {
  return String(value || "").trim().replace(/\/+$/g, "");
}

function isLoopbackOrigin(value) {
  return /^https?:\/\/(localhost|127(?:\.\d{1,3}){3})(:\d+)?$/i.test(trimUrlForConfig(value));
}

function resolveAppBaseUrl({ appBaseUrl, renderExternalUrl, fallback }) {
  const explicit = trimUrlForConfig(appBaseUrl);
  const renderOrigin = trimUrlForConfig(renderExternalUrl);

  // If APP_BASE_URL is still localhost on Render, prefer Render's public URL.
  if (renderOrigin && (!explicit || isLoopbackOrigin(explicit))) {
    return renderOrigin;
  }

  if (explicit) {
    return explicit;
  }

  return trimUrlForConfig(fallback);
}

const PROJECT_ID = process.env.GCLOUD_PROJECT || process.env.PROJECT_ID || "ask-media-cc963";
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "";
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || "";
const FULFILLMENT_API_BASE_URL = process.env.FULFILLMENT_API_BASE_URL || "";
const FULFILLMENT_API_KEY = process.env.FULFILLMENT_API_KEY || "";
const HUBNET_API_KEY = process.env.HUBNET_API_KEY || "";
const HUBNET_API_BASE_URL = process.env.HUBNET_API_BASE_URL || "https://console.hubnet.app/live/api/context/business/transaction";
const HUBNET_WEBHOOK_SECRET = process.env.HUBNET_WEBHOOK_SECRET || "";
const HUBNET_REFERRER = process.env.HUBNET_REFERRER || "";
const RENDER_EXTERNAL_URL = trimUrlForConfig(process.env.RENDER_EXTERNAL_URL || "");
const APP_BASE_URL = resolveAppBaseUrl({
  appBaseUrl: process.env.APP_BASE_URL,
  renderExternalUrl: RENDER_EXTERNAL_URL,
  fallback: `https://${PROJECT_ID}.web.app`,
});
const DELIVERY_WEBHOOK_PATH = "/api/public/fulfillment/webhook";
const LEGACY_DELIVERY_WEBHOOK_PATH = "/api/public/hubnet/webhook";
const hasPaystackSecretKey = Boolean(PAYSTACK_SECRET_KEY) && !["sk_live_your_ghana_key_here", "sk_test_your_ghana_key_here"].includes(PAYSTACK_SECRET_KEY);
const hasPaystackPublicKey = Boolean(PAYSTACK_PUBLIC_KEY) && !["pk_live_your_ghana_key_here", "pk_test_your_ghana_key_here"].includes(PAYSTACK_PUBLIC_KEY);
const hasFulfillmentBaseUrl = Boolean(FULFILLMENT_API_BASE_URL) && FULFILLMENT_API_BASE_URL !== "https://api.fulfillment-provider.com";
const hasFulfillmentApiKey = Boolean(FULFILLMENT_API_KEY) && FULFILLMENT_API_KEY !== "your_api_key_here";
const hasHubnetApiKey = Boolean(HUBNET_API_KEY) && !["hubnet_live_your_key_here", "hubnet_test_your_key_here"].includes(HUBNET_API_KEY);
const hasHubnetWebhookSecret = isSecureWebhookSecret(HUBNET_WEBHOOK_SECRET);

const allowedOrigins = new Set([
  `https://${PROJECT_ID}.web.app`,
  `https://${PROJECT_ID}.firebaseapp.com`,
  APP_BASE_URL,
  RENDER_EXTERNAL_URL,
  "https://askmedia.onrender.com",
  ...parseCsv(process.env.ALLOWED_ORIGINS || ""),
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5000",
  "http://127.0.0.1:5000",
].filter(Boolean));

const DEBUG_LOGS = String(process.env.DEBUG_LOGS || "").trim() === "1";
function debugLog(...args) {
  if (DEBUG_LOGS) {
    console.log(...args);
  }
}

if (HUBNET_WEBHOOK_SECRET && !hasHubnetWebhookSecret) {
  console.warn("[Config] HUBNET_WEBHOOK_SECRET should be a long random string, not a URL.");
}

// Optional: Load Paystack helper if configured
let PaystackHelper;
let paystack = null;
try {
  PaystackHelper = require("./svc-integrations.js").PaystackHelper;
  if (hasPaystackSecretKey) {
    paystack = new PaystackHelper(PAYSTACK_SECRET_KEY, hasPaystackPublicKey ? PAYSTACK_PUBLIC_KEY : "");
    console.log("[Init] Paystack enabled");
  }
} catch (e) {
  console.warn("[Init] Paystack helper unavailable");
}

// Optional: Load Hubnet helper if configured
let HubnetHelper;
let hubnet = null;
try {
  HubnetHelper = require("./svc-integrations.js").HubnetHelper;
  if (hasHubnetApiKey) {
    hubnet = new HubnetHelper(HUBNET_API_KEY, HUBNET_API_BASE_URL);
    console.log("[Init] Hubnet enabled");
  }
} catch (e) {
  console.warn("[Init] Hubnet helper unavailable");
}

// Optional: Load Fulfillment helper if configured
let FulfillmentHelper;
let fulfillment = null;
try {
  FulfillmentHelper = require("./svc-integrations.js").FulfillmentHelper;
  if (hasFulfillmentBaseUrl && hasFulfillmentApiKey) {
    fulfillment = new FulfillmentHelper(FULFILLMENT_API_BASE_URL, FULFILLMENT_API_KEY);
    console.log("[Init] Fulfillment enabled");
  }
} catch (e) {
  console.warn("[Init] Fulfillment helper unavailable");
}

console.log("[Init] Audit logging enabled");

function getRequestOrigin(req) {
  const origin = sanitizeString(req.get("origin"), 200);
  if (origin && allowedOrigins.has(origin)) {
    return origin;
  }
  return APP_BASE_URL;
}

function maskPhone(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  if (!digits) {
    return sanitizeString(phone, 40);
  }

  const visible = digits.slice(-4);
  return `${"*".repeat(Math.max(digits.length - visible.length, 0))}${visible}`;
}

function maskReference(reference) {
  const value = sanitizeString(reference, 120);
  if (value.length <= 10) {
    return value;
  }
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

function redactUrlSecret(value) {
  const raw = sanitizeString(value, 500);
  if (!raw) {
    return raw;
  }

  try {
    const url = new URL(raw);
    if (url.searchParams.has("secret")) {
      url.searchParams.set("secret", "[redacted]");
    }
    return url.toString();
  } catch (_error) {
    return raw.replace(/(secret=)[^&]+/i, "$1[redacted]");
  }
}

function sanitizeLogValue(value, key = "", depth = 0) {
  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (depth >= 3) {
    if (Array.isArray(value)) {
      return `[array:${value.length}]`;
    }
    if (typeof value === "object") {
      return "[object]";
    }
  }

  if (Array.isArray(value)) {
    return value.slice(0, 10).map((item) => sanitizeLogValue(item, key, depth + 1));
  }

  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 20)
        .map(([entryKey, entryValue]) => [entryKey, sanitizeLogValue(entryValue, entryKey, depth + 1)])
    );
  }

  const field = String(key || "").toLowerCase();
  const stringValue = sanitizeString(value, 500);

  if (!stringValue) {
    return "";
  }

  if (field.includes("secret") || field.includes("token") || field.includes("authorization") || (field.includes("key") && !field.endsWith("id"))) {
    return "[redacted]";
  }

  if (field.includes("email")) {
    return maskEmail(stringValue);
  }

  if (field.includes("phone") || field === "msisdn" || field === "referrer") {
    return maskPhone(stringValue);
  }

  if (field.includes("reference")) {
    return maskReference(stringValue);
  }

  if (field.includes("webhook") || field.endsWith("url")) {
    return redactUrlSecret(stringValue);
  }

  return stringValue;
}

function emitLog(level, scope, event, metadata = {}) {
  const safeMetadata = sanitizeLogValue(metadata);
  const line = `[${scope}] ${event}`;

  if (level === "error") {
    console.error(line, safeMetadata);
  } else if (level === "warn") {
    console.warn(line, safeMetadata);
  } else {
    console.log(line, safeMetadata);
  }

  return safeMetadata;
}

const TERMINAL_AUDIT_EVENTS = new Set([
  "payment:initialize-succeeded",
  "payment:confirmed",
  "hubnet:fulfillment-requested",
  "hubnet:fulfillment-accepted",
  "hubnet:webhook-processed",
]);

function shouldEmitAuditLogToTerminal(level, scope, event) {
  if (level === "error" || level === "warn") {
    return true;
  }

  const sc = sanitizeString(scope, 80);
  if (sc === "hubnet") {
    return true;
  }

  return TERMINAL_AUDIT_EVENTS.has(`${sc}:${sanitizeString(event, 120)}`);
}

async function auditLog(scope, event, metadata = {}, level = "info") {
  const safeMetadata = sanitizeLogValue(metadata);
  const ownerId = sanitizeString(metadata?.ownerId, 120) || null;
  const storeId = sanitizeString(metadata?.storeId, 120) || null;

  if (shouldEmitAuditLogToTerminal(level, scope, event)) {
    emitLog(level, scope, event, safeMetadata);
  }

  try {
    await db.ref("auditLogs").push({
      scope: sanitizeString(scope, 80),
      event: sanitizeString(event, 120),
      level,
      ownerId,
      storeId,
      metadata: safeMetadata,
      createdAt: getCurrentTimestamp(),
    });
  } catch (error) {
    console.warn("[Audit] Failed to persist log", {
      scope: sanitizeString(scope, 80),
      event: sanitizeString(event, 120),
      error: sanitizeString(error?.message, 200) || "Unknown audit log failure.",
    });
  }
}

function shouldTraceRequest(req) {
  const pathName = sanitizeString(req.path, 250);
  return pathName.startsWith("/api/public/payments")
    || pathName === "/paystack/webhook"
    || pathName === "/api/public/payments/webhook"
    || pathName === DELIVERY_WEBHOOK_PATH
    || pathName === LEGACY_DELIVERY_WEBHOOK_PATH
    || pathName === "/hubnet/webhook";
}

function buildRequestTrace(req, extra = {}) {
  return {
    requestId: req.requestId || null,
    method: req.method,
    path: req.originalUrl || req.path,
    reference: sanitizeString(
      req.params?.reference
      || req.body?.reference
      || req.query?.reference
      || req.query?.trxref
      || req.body?.data?.reference,
      120
    ) || null,
    ...extra,
  };
}

const HUBNET_STALE_RETRY_MS = 5 * 60 * 1000;

function appendStatusHistory(history, entry) {
  const entries = Array.isArray(history) ? history : [];
  const lastEntry = entries[entries.length - 1];

  if (
    lastEntry
    && lastEntry.status === entry.status
    && lastEntry.source === entry.source
    && (entry.event ? lastEntry.event === entry.event : true)
  ) {
    return entries;
  }

  return entries.concat([entry]);
}

function getTimestampMs(value) {
  const parsed = Date.parse(String(value || ""));
  return Number.isFinite(parsed) ? parsed : 0;
}

function isStaleTimestamp(value, thresholdMs = HUBNET_STALE_RETRY_MS) {
  const timestampMs = getTimestampMs(value);
  if (!timestampMs) {
    return true;
  }
  return (Date.now() - timestampMs) >= thresholdMs;
}

function hasHubnetPackage(record) {
  return Boolean(sanitizeString(record?.packageNetwork, 20))
    && Boolean(sanitizeString(record?.packageVolume, 20));
}

function getPaymentSource(eventName) {
  return eventName === "charge.success" ? "paystack-webhook" : "manual-verify";
}

function requiresPaymentRepair(session, order) {
  if (sanitizeString(session?.paymentStatus, 40).toLowerCase() !== "paid") {
    return true;
  }

  if (!order) {
    return true;
  }

  if (sanitizeString(order.paymentStatus, 40).toLowerCase() !== "paid") {
    return true;
  }

  if (!hasHubnetPackage(session)) {
    return false;
  }

  if (sanitizeString(order.hubnetTransactionId, 120) || sanitizeString(order.hubnetPaymentId, 120)) {
    return false;
  }

  const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase();
  if (!fulfillmentStatus || ["pending", "queued"].includes(fulfillmentStatus)) {
    return true;
  }

  if (fulfillmentStatus === "processing") {
    return isStaleTimestamp(order.hubnetInitAt);
  }

  if (fulfillmentStatus === "failed") {
    return isStaleTimestamp(order.hubnetInitAt);
  }

  return false;
}

function extractHubnetResponseDetails(response, fallbackReference) {
  const preview = response && typeof response === "object"
    ? JSON.stringify(response).substring(0, 350)
    : String(response);
  debugLog(`  [Hubnet] parse response | preview: ${preview}${preview.length >= 350 ? "..." : ""}`);
  
  const data = response && typeof response.data === "object" ? response.data : {};
  const status = response?.status ?? data?.status ?? null;
  const rootSuccess = response?.success === true || data?.success === true;
  const transactionId = sanitizeString(
    response?.transaction_id
    || data?.transaction_id
    || data?.transactionId
    || data?.id,
    120
  ) || null;
  const paymentId = sanitizeString(
    response?.payment_id
    || data?.payment_id
    || data?.paymentId,
    120
  ) || null;
  const message = sanitizeString(
    response?.message
    || data?.message
    || data?.response_msg,
    200
  ) || null;
  const code = sanitizeString(
    response?.code
    || response?.response_code
    || data?.code
    || data?.response_code,
    120
  ) || null;
  const reason = sanitizeString(
    response?.reason
    || response?.error
    || data?.reason
    || data?.error,
    200
  ) || null;
  const ipAddress = sanitizeString(
    response?.ip_address
    || data?.ip_address,
    80
  ) || null;
  const responseReference = sanitizeString(
    response?.reference
    || data?.reference
    || fallbackReference,
    120
  ) || sanitizeString(fallbackReference, 120) || null;
  const msgCode = String(response?.message ?? "").trim();
  const dataMsgCode = String(data?.message ?? "").trim();
  const accepted = rootSuccess
    || hubnet.isSuccessStatus(status)
    || msgCode === "0000"
    || dataMsgCode === "0000"
    || Boolean(transactionId)
    || Boolean(paymentId)
    || /success|accepted|processing|queued|initiated/i.test(`${message || ""} ${reason || ""}`);

  debugLog(`  [Hubnet] extracted | status=${status} accepted=${accepted} tx=${transactionId || "-"} pay=${paymentId || "-"} msgCode=${message || "-"} reason=${reason || "-"}`);

  return {
    status,
    transactionId,
    paymentId,
    message,
    code,
    reason,
    ipAddress,
    responseReference,
    accepted,
  };
}

async function recalculateStoreMetrics(storeId) {
  const safeStoreId = sanitizeString(storeId, 120);
  if (!safeStoreId) {
    return null;
  }

  const snapshot = await db.ref("orders")
    .orderByChild("storeId")
    .equalTo(safeStoreId)
    .once("value");

  let totalOrders = 0;
  let totalRevenue = 0;
  let totalProfit = 0;

  snapshot.forEach((child) => {
    const order = child.val() || {};
    if (!isSuccessfulOrderRecord(order)) {
      return;
    }

    totalOrders += 1;
    totalRevenue += Number(order.amount || 0);
    totalProfit += Number(order.profitAmount || 0);
  });

  const metrics = {
    totalOrders,
    totalRevenue: Number(totalRevenue.toFixed(2)),
    totalProfit: Number(totalProfit.toFixed(2)),
    updatedAt: getCurrentTimestamp(),
  };

  await db.ref(`storefronts/${safeStoreId}/metrics`).update(metrics);
  return metrics;
}

function isSuccessfulOrderRecord(order = {}) {
  const paymentStatus = sanitizeString(order.paymentStatus, 40).toLowerCase();
  const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase();
  if (paymentStatus !== "paid") {
    return false;
  }
  if (order.countsAsOrder === false) {
    return false;
  }
  return fulfillmentStatus === "delivered" || fulfillmentStatus === "fulfilled";
}

function normalizeWithdrawalNetwork(value) {
  const raw = sanitizeString(value, 40).toLowerCase();
  if (raw === "mtn") return "mtn";
  if (["at", "airteltigo", "airtel tigo", "airtel-tigo"].includes(raw)) return "at";
  if (raw === "telecel" || raw === "vodafone") return "telecel";
  return "";
}

function toWithdrawalNetworkLabel(value) {
  if (value === "mtn") return "MTN";
  if (value === "at") return "AT";
  if (value === "telecel") return "Telecel";
  return value;
}

function getWalletTransactionCategory(transaction = {}) {
  const explicitCategory = sanitizeString(transaction.category, 40).toLowerCase();
  if (explicitCategory) {
    return explicitCategory;
  }

  const reference = sanitizeString(transaction.reference || transaction.paystackReference, 120).toUpperCase();
  if (reference.startsWith("WDEP-")) {
    return "deposit";
  }

  const type = sanitizeString(transaction.type, 20).toLowerCase();
  if (type === "debit") {
    return "adjustment";
  }

  return "profit";
}

async function recalculateOwnerWallet(ownerId) {
  const safeOwnerId = sanitizeString(ownerId, 120);
  if (!safeOwnerId) {
    return null;
  }

  const snapshot = await db.ref(`walletTransactions/${safeOwnerId}`).once("value");
  const seenOrderCredits = new Set();
  let balance = 0;
  let totalEarned = 0;
  let totalProfit = 0;
  let totalDeposits = 0;
  let totalDebits = 0;
  let totalOrders = 0;
  let lastCreditAt = null;
  let lastDebitAt = null;

  snapshot.forEach((child) => {
    const transaction = child.val() || {};
    const type = sanitizeString(transaction.type, 20).toLowerCase() || "credit";
    if (!["credit", "debit"].includes(type)) {
      return;
    }

    const amount = Number(transaction.amount || 0);
    if (!Number.isFinite(amount)) {
      return;
    }

    const category = getWalletTransactionCategory(transaction);
    const createdAt = sanitizeString(transaction.createdAt || transaction.updatedAt, 50);

    if (type === "credit") {
      balance += amount;

      if (!lastCreditAt || getTimestampMs(createdAt) > getTimestampMs(lastCreditAt)) {
        lastCreditAt = createdAt || lastCreditAt;
      }
    } else {
      balance -= amount;

      if (!lastDebitAt || getTimestampMs(createdAt) > getTimestampMs(lastDebitAt)) {
        lastDebitAt = createdAt || lastDebitAt;
      }
    }

    if (type === "credit" && category === "profit") {
      const uniqueReference = sanitizeString(
        transaction.reference || transaction.paystackReference,
        120
      ) || child.key;

      if (seenOrderCredits.has(uniqueReference)) {
        return;
      }

      seenOrderCredits.add(uniqueReference);
      totalEarned += amount;
      totalProfit += amount;
      totalOrders += 1;
      return;
    }

    if (type === "credit" && category === "deposit") {
      totalDeposits += amount;
      return;
    }

    if (type === "debit") {
      totalDebits += amount;
    }
  });

  const walletPayload = {
    balance: Number(balance.toFixed(2)),
    totalEarned: Number(totalEarned.toFixed(2)),
    totalProfit: Number(totalProfit.toFixed(2)),
    totalDeposits: Number(totalDeposits.toFixed(2)),
    totalDebits: Number(totalDebits.toFixed(2)),
    totalOrders,
    currency: "GHS",
    lastCreditAt: lastCreditAt || null,
    lastDebitAt: lastDebitAt || null,
    updatedAt: getCurrentTimestamp(),
  };

  await db.ref(`wallet/${safeOwnerId}`).update(walletPayload);
  return walletPayload;
}

function toIsoTimestamp(value) {
  const parsed = Date.parse(String(value || ""));
  if (!Number.isFinite(parsed)) {
    return getCurrentTimestamp();
  }
  return new Date(parsed).toISOString();
}

function addHoursIso(baseIso, hours) {
  const parsed = Date.parse(String(baseIso || ""));
  const baseMs = Number.isFinite(parsed) ? parsed : Date.now();
  return new Date(baseMs + (hours * 60 * 60 * 1000)).toISOString();
}

async function recoverSessionFromPaystack(reference, verificationData) {
  const metadata = verificationData?.metadata && typeof verificationData.metadata === "object"
    ? verificationData.metadata
    : {};
  const storeId = sanitizeString(metadata.storeId, 120);
  const slugFromMeta = normalizeSlug(metadata.slug);
  const email = normalizeEmail(verificationData?.customer?.email || metadata.email);
  const packageName = sanitizeString(metadata.packageName, 120);
  const packageId = sanitizeString(metadata.packageId, 120);
  const catalogPackageId = sanitizeString(metadata.catalogPackageId, 120) || null;
  const packageNetwork = sanitizeString(metadata.packageNetwork, 20).toLowerCase();
  const packageVolume = sanitizeString(metadata.packageVolume, 20);
  const beneficiaryPhone = normalizePhone(metadata.beneficiaryPhone || verificationData?.customer?.phone);
  const amount = Number(verificationData?.amount || 0) / 100;
  const baseAmount = toPrice(metadata.baseAmount) || null;
  const profitAmount = toPrice(metadata.profitAmount)
    || (baseAmount
      ? Number((amount - baseAmount).toFixed(2))
      : amount);
  const createdAt = toIsoTimestamp(verificationData?.created_at || verificationData?.transaction_date || getCurrentTimestamp());
  const paidAt = toIsoTimestamp(verificationData?.paid_at || verificationData?.paidAt || createdAt);
  const now = getCurrentTimestamp();

  if (!storeId && !slugFromMeta) {
    throw httpError(404, "Payment session not found and could not be recovered.");
  }
  if (!email) {
    throw httpError(400, "Paystack verification did not include customer email.");
  }
  if (!Number.isFinite(amount) || amount <= 0) {
    throw httpError(400, "Paystack verification returned an invalid amount.");
  }

  let storeSnapshot = null;
  if (storeId) {
    const snap = await db.ref(`storefronts/${storeId}`).once("value");
    if (snap.exists()) {
      storeSnapshot = snap;
    }
  }

  if (!storeSnapshot && slugFromMeta) {
    const query = await db.ref("storefronts")
      .orderByChild("slug")
      .equalTo(slugFromMeta)
      .limitToFirst(1)
      .once("value");
    query.forEach((child) => {
      if (!storeSnapshot) {
        storeSnapshot = child;
      }
    });
  }

  if (!storeSnapshot || !storeSnapshot.exists()) {
    throw httpError(404, "Storefront not found for this payment reference.");
  }

  const resolvedStore = storeSnapshot.val() || {};
  const resolvedStoreId = storeSnapshot.key;
  const ownerId = sanitizeString(resolvedStore.ownerId, 120);
  const slug = sanitizeString(resolvedStore.slug || slugFromMeta, 80);
  const storeName = sanitizeString(resolvedStore.name || metadata.storeName, 120);

  if (!ownerId || !resolvedStoreId || !slug) {
    throw httpError(404, "Storefront details are incomplete for this payment reference.");
  }

  const sessionPayload = {
    paystackReference: reference,
    paymentProvider: "paystack",
    paymentStatus: "initialized",
    webhookReceived: false,
    amount: Number(amount.toFixed(2)),
    baseAmount,
    profitAmount: Number((profitAmount || 0).toFixed(2)),
    email,
    maskedEmail: maskEmail(email),
    beneficiaryPhone,
    packageId: packageId || null,
    catalogPackageId,
    packageName: packageName || null,
    packageNetwork: packageNetwork || null,
    packageVolume: packageVolume || null,
    storeId: resolvedStoreId,
    storeName,
    ownerId,
    slug,
    fulfillmentProvider: hasHubnetPackage({ packageNetwork, packageVolume }) ? "hubnet" : null,
    fulfillmentStatus: "pending",
    createdAt,
    paidAt,
    expiresAt: addHoursIso(createdAt, 1),
    recoveredFromPaystackAt: now,
    updatedAt: now,
  };

  await db.ref(`paymentSessions/${reference}`).set(sessionPayload);
  await auditLog("payment", "session-recovered-from-paystack", {
    reference,
    storeId: resolvedStoreId,
    ownerId,
    slug,
    amount: sessionPayload.amount,
  }, "warn");

  return sessionPayload;
}

// ============================================================================
// DATABASE FUNCTIONS - REALTIME DATABASE
// ============================================================================

async function generateUniqueSlug(seedValue) {
  const baseSlug = normalizeSlug(seedValue) || `store-${crypto.randomUUID().slice(0, 8)}`;
  const trimmedBase = baseSlug.slice(0, 40);

  for (let attempt = 0; attempt < 20; attempt += 1) {
    const suffix = attempt === 0 ? "" : `-${attempt + 1}`;
    const candidate = `${trimmedBase}${suffix}`.slice(0, 50);

    const snapshot = await db.ref(`storefronts`).orderByChild("slug").equalTo(candidate).once("value");
    if (!snapshot.exists()) {
      return candidate;
    }
  }

  return `store-${crypto.randomUUID().slice(0, 12)}`;
}

async function getOwnerStore(uid) {
  const snapshot = await db.ref(`storefronts`).orderByChild("ownerId").equalTo(uid).once("value");

  if (!snapshot.exists()) {
    return null;
  }

  // Get first store (should be only one per owner typically)
  let storeId = null;
  let storeData = null;

  snapshot.forEach((child) => {
    if (!storeId) {
      storeId = child.key;
      storeData = child.val();
    }
  });

  return storeId ? { id: storeId, ...storeData } : null;
}

function normalizePackageNetwork(value) {
  let network = sanitizeString(value, 20).toLowerCase();

  if (network === "airtel-tigo" || network === "airtel tigo" || network === "airteltigo") {
    network = "at";
  }

  if (network === "vodafone" || network === "big-time" || network === "bigtime") {
    network = "telecel";
  }

  return network;
}

function normalizeTrackedOrderNetwork(value) {
  const network = normalizePackageNetwork(value);
  if (network === "mtn") return "mtn";
  if (network === "at") return "at";
  if (network === "telecel") return "telecel";
  return "";
}

function isMtnOrAtNetwork(value) {
  const network = normalizeTrackedOrderNetwork(value);
  return network === "mtn" || network === "at";
}

function getOrderNetworkCode(order = {}) {
  return normalizeTrackedOrderNetwork(
    order.packageNetwork
    || order.network
    || order.provider
    || order?.data?.network
  );
}

function isMtnOrAtOrder(order = {}) {
  return isMtnOrAtNetwork(getOrderNetworkCode(order));
}

function sanitizePackageVolume(value, label = "Package") {
  const rawVolume = sanitizeString(value, 20);

  if (!rawVolume) {
    return "";
  }

  if (!/^\d+$/.test(rawVolume)) {
    throw httpError(400, `${label} volume must be a whole number (e.g. 1000).`);
  }

  return rawVolume;
}

function normalizeCatalogPackage(record, packageId = "") {
  if (!record || typeof record !== "object") {
    return null;
  }

  const id = sanitizeString(packageId || record.id, 120);
  const name = sanitizeString(record.name, 120);
  const description = sanitizeString(record.description, 400);
  const basePrice = toPrice(record.basePrice);
  const network = normalizePackageNetwork(record.network) || null;
  const volume = sanitizeString(record.volume, 20) || null;
  const active = record.active !== false;
  const createdAt = sanitizeString(record.createdAt, 50) || null;
  const updatedAt = sanitizeString(record.updatedAt, 50) || null;
  const sortOrder = Number.parseInt(record.sortOrder, 10);

  if (!id || !name || !basePrice) {
    return null;
  }

  if ((network && !volume) || (!network && volume)) {
    return null;
  }

  if (volume && !/^\d+$/.test(volume)) {
    return null;
  }

  return {
    id,
    name,
    description,
    basePrice,
    network,
    volume,
    active,
    createdAt,
    updatedAt,
    sortOrder: Number.isInteger(sortOrder) ? sortOrder : 0,
  };
}

async function listCatalogPackages({ includeInactive = true } = {}) {
  const snapshot = await db.ref("catalogPackages").once("value");
  const packages = [];

  snapshot.forEach((child) => {
    const normalized = normalizeCatalogPackage(child.val(), child.key);
    if (!normalized) {
      return;
    }

    if (!includeInactive && !normalized.active) {
      return;
    }

    packages.push(normalized);
  });

  packages.sort((a, b) => {
    if (a.sortOrder !== b.sortOrder) {
      return a.sortOrder - b.sortOrder;
    }

    const networkCompare = String(a.network || "").localeCompare(String(b.network || ""));
    if (networkCompare !== 0) {
      return networkCompare;
    }

    const volumeA = Number.parseInt(a.volume || "0", 10) || 0;
    const volumeB = Number.parseInt(b.volume || "0", 10) || 0;
    if (volumeA !== volumeB) {
      return volumeA - volumeB;
    }

    return a.name.localeCompare(b.name);
  });

  return packages;
}

async function getCatalogPackageMap(options = {}) {
  const packages = await listCatalogPackages(options);
  return new Map(packages.map((pkg) => [pkg.id, pkg]));
}

function isLegacyStorePackage(record) {
  return !sanitizeString(record?.catalogPackageId, 120);
}

async function resolveStorePackages(packages, { includeUnavailable = false } = {}) {
  if (!Array.isArray(packages) || !packages.length) {
    return [];
  }

  const catalogMap = await getCatalogPackageMap({ includeInactive: true });
  const resolved = [];

  for (const rawPkg of packages) {
    if (!rawPkg || typeof rawPkg !== "object") {
      continue;
    }

    const packageId = sanitizeString(rawPkg.id, 80)
      || sanitizeString(rawPkg.catalogPackageId, 120)
      || crypto.randomUUID();
    const sellingPrice = toPrice(rawPkg.sellingPrice);
    const catalogPackageId = sanitizeString(rawPkg.catalogPackageId, 120);

    if (catalogPackageId) {
      const catalogPackage = catalogMap.get(catalogPackageId);
      if (!catalogPackage) {
        if (includeUnavailable) {
          resolved.push({
            id: packageId,
            catalogPackageId,
            name: sanitizeString(rawPkg.name, 120) || "Unavailable package",
            description: sanitizeString(rawPkg.description, 400),
            basePrice: toPrice(rawPkg.basePrice) || null,
            sellingPrice,
            network: normalizePackageNetwork(rawPkg.network) || null,
            volume: sanitizeString(rawPkg.volume, 20) || null,
            profitPerSale: 0,
            available: false,
            pricingStatus: "catalog-missing",
          });
        }
        continue;
      }

      const basePrice = catalogPackage.basePrice;
      const isPriceReady = Boolean(sellingPrice) && sellingPrice > basePrice;
      const available = Boolean(catalogPackage.active) && isPriceReady;

      if (!available && !includeUnavailable) {
        continue;
      }

      resolved.push({
        id: packageId,
        catalogPackageId: catalogPackage.id,
        name: catalogPackage.name,
        description: catalogPackage.description,
        basePrice,
        sellingPrice: sellingPrice || null,
        network: catalogPackage.network,
        volume: catalogPackage.volume,
        profitPerSale: isPriceReady ? Number((sellingPrice - basePrice).toFixed(2)) : 0,
        available,
        pricingStatus: !catalogPackage.active
          ? "inactive"
          : (isPriceReady ? "ready" : "below-base"),
        syncedAt: sanitizeString(rawPkg.syncedAt, 50) || null,
      });
      continue;
    }

    const name = sanitizeString(rawPkg.name, 120);
    const description = sanitizeString(rawPkg.description, 400);
    const network = normalizePackageNetwork(rawPkg.network) || null;
    const volume = sanitizeString(rawPkg.volume, 20) || null;
    const basePrice = toPrice(rawPkg.basePrice);

    const legacyMatch = [...catalogMap.values()].find((candidate) => {
      if (network && volume) {
        return candidate.network === network && candidate.volume === volume;
      }

      return sanitizeString(candidate.name, 120).toLowerCase() === name.toLowerCase();
    }) || null;
    const matchedBasePrice = legacyMatch?.basePrice || basePrice || 0;
    const isPriceReady = Boolean(sellingPrice) && sellingPrice > matchedBasePrice;

    if (!name || (!sellingPrice && !legacyMatch)) {
      continue;
    }

    resolved.push({
      id: packageId,
      catalogPackageId: legacyMatch ? legacyMatch.id : null,
      name: legacyMatch?.name || name,
      description: legacyMatch?.description || description,
      basePrice: matchedBasePrice || sellingPrice,
      sellingPrice,
      network: legacyMatch?.network || network,
      volume: legacyMatch?.volume || volume,
      profitPerSale: isPriceReady ? Number((sellingPrice - matchedBasePrice).toFixed(2)) : 0,
      available: Boolean(isPriceReady && (!legacyMatch || legacyMatch.active !== false)),
      pricingStatus: legacyMatch
        ? (legacyMatch.active !== false ? (isPriceReady ? "ready" : "below-base") : "inactive")
        : (sellingPrice ? "legacy" : "unpriced"),
      active: legacyMatch ? legacyMatch.active !== false : true,
      legacy: true,
    });
  }

  return resolved;
}

async function getPublicStorePackages(store) {
  return (await resolveStorePackages(store?.packages, { includeUnavailable: false }))
    .map((pkg) => ({
      id: sanitizeString(pkg.id, 80),
      catalogPackageId: sanitizeString(pkg.catalogPackageId, 120) || null,
      name: sanitizeString(pkg.name, 120),
      description: sanitizeString(pkg.description, 400),
      basePrice: toPrice(pkg.basePrice),
      sellingPrice: toPrice(pkg.sellingPrice),
      profitPerSale: toPrice(pkg.profitPerSale) || 0,
      network: sanitizeString(pkg.network, 20).toLowerCase() || null,
      volume: sanitizeString(pkg.volume, 20) || null,
    }))
    .filter((pkg) => pkg.id && pkg.name && pkg.sellingPrice);
}

async function ensureOwnerBootstrap({ uid, email, name, phone }) {
  const userRef = db.ref(`users/${uid}`);
  const normalizedEmail = normalizeEmail(email);
  const normalizedName = sanitizeString(name, 120);
  const normalizedPhone = normalizePhone(phone);

  const userPayload = {
    email: normalizedEmail || null,
    updatedAt: getCurrentTimestamp(),
    lastLogin: getCurrentTimestamp(),
    status: "active",
  };

  if (normalizedName) {
    userPayload.name = normalizedName;
  }

  if (normalizedPhone) {
    userPayload.phone = normalizedPhone;
  }

  const currentUser = await userRef.once("value");
  if (!currentUser.exists()) {
    userPayload.createdAt = getCurrentTimestamp();
  }

  await userRef.update(userPayload);
  const store = await getOwnerStore(uid);

  const userData = await userRef.once("value");
  return {
    user: { id: uid, ...userData.val() },
    store: store || null,
  };
}

async function requireOwnerStore(uid) {
  const store = await getOwnerStore(uid);
  if (!store) {
    throw httpError(404, "No storefront found. Configure your storefront first.");
  }
  return store;
}

async function sanitizePackages(packages) {
  if (packages === undefined) {
    return undefined;
  }

  if (!Array.isArray(packages)) {
    throw httpError(400, "Packages must be an array.");
  }

  if (packages.length > 50) {
    throw httpError(400, "No more than 50 packages are allowed.");
  }

  const catalogMap = await getCatalogPackageMap({ includeInactive: true });
  const seenCatalogPackages = new Set();

  return packages.map((pkg, index) => {
    if (!pkg || typeof pkg !== "object") {
      throw httpError(400, `Package ${index + 1} is invalid.`);
    }

    const catalogPackageId = sanitizeString(pkg.catalogPackageId, 120);
    if (!catalogPackageId) {
      throw httpError(400, `Package ${index + 1} must come from the admin package catalog.`);
    }

    const catalogPackage = catalogMap.get(catalogPackageId);
    if (!catalogPackage) {
      throw httpError(400, `Package ${index + 1} references an unknown admin package.`);
    }

    if (!catalogPackage.active) {
      throw httpError(400, `Package ${index + 1} is currently disabled by the admin.`);
    }

    if (seenCatalogPackages.has(catalogPackageId)) {
      throw httpError(400, `Package ${index + 1} duplicates another selected admin package.`);
    }
    seenCatalogPackages.add(catalogPackageId);

    const sellingPrice = toPrice(pkg.sellingPrice);
    if (!sellingPrice) {
      throw httpError(400, `Package ${index + 1} must have a valid selling price.`);
    }

    if (sellingPrice <= catalogPackage.basePrice) {
      throw httpError(
        400,
        `Package ${index + 1} selling price must be higher than the admin base price of GHS ${catalogPackage.basePrice.toFixed(2)}.`
      );
    }

    return {
      id: sanitizeString(pkg.id, 80) || catalogPackage.id,
      catalogPackageId: catalogPackage.id,
      name: catalogPackage.name,
      description: catalogPackage.description,
      basePrice: catalogPackage.basePrice,
      sellingPrice,
      markupAmount: Number((sellingPrice - catalogPackage.basePrice).toFixed(2)),
      network: catalogPackage.network || null,
      volume: catalogPackage.volume || null,
      syncedAt: getCurrentTimestamp(),
    };
  });
}

function toGhanaNationalPhone(phone) {
  const normalized = normalizePhone(phone);
  if (!normalized) return "";

  if (/^0\d{9}$/.test(normalized)) {
    return normalized;
  }

  if (normalized.startsWith("+233")) {
    const rest = normalized.slice(4).replace(/\D/g, "");
    if (rest.length === 9) {
      return `0${rest}`;
    }
  }

  const digits = normalized.replace(/\D/g, "");
  if (digits.startsWith("233") && digits.length === 12) {
    return `0${digits.slice(3)}`;
  }

  return "";
}

function normalizeHubnetNetworkForApi(network) {
  const value = sanitizeString(network, 20).toLowerCase();
  if (value === "telecel") {
    // Hubnet documentation lists Telecel as "big-time".
    return "big-time";
  }
  return value;
}

function normalizeHubnetTransactionId(value) {
  const s = sanitizeString(value, 120);
  if (!s) {
    return "";
  }
  if (/^(false|null|undefined|0+)$/i.test(s.trim())) {
    return "";
  }
  return s;
}

function makeHubnetReference(paystackReference) {
  // Hubnet reference must be 6Ã¢â‚¬â€œ25 alphanumeric/hyphen chars.
  // Hash the Paystack reference to ensure uniqueness across server restarts.
  const hash = crypto
    .createHash("sha256")
    .update(String(paystackReference || ""))
    .digest("hex")
    .toUpperCase();
  // Format: "HN-" (3) + 20 hex chars = 23 chars total (safely under 25-char limit).
  return `HN-${hash.slice(0, 20)}`;
}

function buildHubnetWebhookUrl() {
  // Allow an explicit override via DELIVERY_WEBHOOK_URL/HUBNET_WEBHOOK_URL (e.g. via ngrok in local dev).
  // Falls back to APP_BASE_URL + path which works correctly in production.
  const configuredWebhookUrl = process.env.DELIVERY_WEBHOOK_URL || process.env.HUBNET_WEBHOOK_URL || "";
  const base = configuredWebhookUrl
    ? configuredWebhookUrl.trim().replace(/\/+$/g, "")
    : `${APP_BASE_URL.replace(/\/+$/g, "")}${DELIVERY_WEBHOOK_PATH}`;
  const url = (
    base.includes(DELIVERY_WEBHOOK_PATH)
    || base.includes(LEGACY_DELIVERY_WEBHOOK_PATH)
  )
    ? base
    : `${base}${DELIVERY_WEBHOOK_PATH}`;
  if (!hasHubnetWebhookSecret) {
    return url;
  }
  return `${url}${url.includes("?") ? "&" : "?"}secret=${encodeURIComponent(HUBNET_WEBHOOK_SECRET)}`;
}

function mapHubnetWebhookToFulfillmentStatus(eventName, payload) {
  const event = sanitizeString(eventName, 80).toLowerCase();

  // Hubnet sends real status in data.status (e.g. "Processing", "Delivered", "Failed")
  // and also in payload.status. We prioritize the most specific field.
  const dataStatus = sanitizeString(
    payload?.data?.status
    || payload?.status
    || "",
    120
  ).toLowerCase().trim();

  const message = sanitizeString(
    payload?.message || payload?.data?.message || payload?.data?.response_msg || "",
    200
  ).toLowerCase();

  const reason = sanitizeString(payload?.reason || payload?.data?.reason || "", 200).toLowerCase();

  // Ã¢â€â‚¬Ã¢â€â‚¬ Priority 1: Hubnet event name (most authoritative) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
  // Known Hubnet delivery events from their docs:
  if (event === "transfer.delivered" || event === "bundle.delivered" || event === "transaction.delivered") {
    return "delivered";
  }
  if (event === "transfer.failed" || event === "bundle.failed" || event === "transaction.failed") {
    return "failed";
  }
  if (event === "transfer.processing" || event === "bundle.processing" || event === "transaction.processing") {
    return "processing";
  }

  // Ã¢â€â‚¬Ã¢â€â‚¬ Priority 2: data.status field (Hubnet real-time status string) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
  if (dataStatus) {
    if (/^(delivered|fulfilled|successful|success|completed)$/i.test(dataStatus)) {
      return "delivered";
    }
    if (/^(failed|failure|error|declined|unsuccessful)$/i.test(dataStatus)) {
      return "failed";
    }
    if (/^(processing|pending|queued|initiated|in.?transit)$/i.test(dataStatus)) {
      return "processing";
    }
  }

  // Ã¢â€â‚¬Ã¢â€â‚¬ Priority 3: Fall back to combined text analysis Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
  const combined = `${event} ${dataStatus} ${message} ${reason}`;
  if (/(delivered|fulfilled|transfer successful|bundle.*success)/.test(combined)) {
    return "delivered";
  }
  if (/(failed|failure|error|unsuccessful|declined)/.test(combined)) {
    return "failed";
  }
  if (/(processing|pending|queued|initiated)/.test(combined)) {
    return "processing";
  }

  // Default: treat as in-progress Ã¢â‚¬â€ Hubnet will send another webhook when done.
  return "processing";
}

function isDeliveredFulfillmentStatus(status) {
  const value = sanitizeString(status, 40).toLowerCase();
  return value === "delivered" || value === "fulfilled";
}

function deriveOrderStatusFromStates({ fulfillmentStatus, paymentStatus }) {
  const fulfillment = sanitizeString(fulfillmentStatus, 40).toLowerCase();
  const payment = sanitizeString(paymentStatus, 40).toLowerCase() || "pending";

  if (isDeliveredFulfillmentStatus(fulfillment)) {
    return "delivered";
  }
  if (fulfillment === "processing") {
    return "processing";
  }
  if (payment === "paid") {
    return "paid";
  }
  return payment;
}

function extractHubnetLiveOrderPayload(payload) {
  if (!payload || typeof payload !== "object") {
    return null;
  }

  const first = payload?.data && typeof payload.data === "object"
    ? payload.data
    : payload;

  if (first?.data && typeof first.data === "object") {
    return first.data;
  }

  return first;
}

function buildV1OrderResponseFromHubnet(reference, payload) {
  const details = extractHubnetLiveOrderPayload(payload);
  if (!details || typeof details !== "object") {
    return null;
  }

  const networkCode = normalizeTrackedOrderNetwork(
    details.network
    || details.packageNetwork
    || details.provider
    || payload?.network
    || payload?.data?.network
  );

  // Per requirement: /v1/orders only returns MTN/AT orders.
  if (!isMtnOrAtNetwork(networkCode)) {
    return null;
  }

  const enrichedPayload = {
    ...payload,
    message: payload?.message || details?.message || details?.response_msg || "",
    reason: payload?.reason || details?.reason || "",
    data: {
      ...(payload?.data && typeof payload.data === "object" ? payload.data : {}),
      status: details?.status || payload?.data?.status || payload?.status || "",
      message: details?.message || details?.response_msg || payload?.message || "",
      reason: details?.reason || payload?.reason || "",
    },
  };

  const fulfillmentStatus = mapHubnetWebhookToFulfillmentStatus(
    sanitizeString(payload?.event, 80),
    enrichedPayload
  );
  const paymentStatus = "paid";
  const status = deriveOrderStatusFromStates({ fulfillmentStatus, paymentStatus });

  const rawAmount = details.amount ?? details.price ?? details.cost ?? details.total ?? 0;
  const amount = Number(rawAmount);
  const phone = sanitizeString(details.msisdn || details.phone || details.mobile || "", 40);
  const volume = sanitizeString(details.volume || details.packageVolume || details.bundle || "", 20) || null;
  const packageName = sanitizeString(
    details.packageName
    || details.bundleName
    || details.bundle
    || details.product
    || "",
    120
  ) || "";
  const createdAt = sanitizeString(
    details.date_time
    || details.createdAt
    || details.updatedAt
    || payload?.date_time
    || payload?.createdAt,
    80
  ) || null;

  return {
    id: reference,
    reference: sanitizeString(
      details.reference
      || details.orderReference
      || details.transaction_id
      || details.transactionId
      || reference,
      120
    ) || reference,
    status,
    paymentStatus,
    fulfillmentStatus,
    amount: Number.isFinite(amount) ? amount : 0,
    currency: "GHS",
    storeName: "",
    packageName,
    network: networkCode.toUpperCase(),
    volume,
    phone: phone ? maskPhone(phone) : "",
    email: "",
    createdAt,
    updatedAt: getCurrentTimestamp(),
    source: "hubnet-live",
  };
}

async function fetchHubnetLiveOrderByReference(reference) {
  if (!hubnet) {
    return null;
  }

  const safeReference = sanitizeString(reference, 120);
  if (!safeReference) {
    return null;
  }

  const encodedReference = encodeURIComponent(safeReference);
  const endpoints = [
    `/orders/${encodedReference}`,
    `/order-status/${encodedReference}`,
    `/transaction-status/${encodedReference}`,
  ];

  for (const endpoint of endpoints) {
    try {
      const payload = await hubnet.request(endpoint, {
        method: "GET",
        timeoutMs: 12000,
      });
      const normalized = buildV1OrderResponseFromHubnet(safeReference, payload);
      if (normalized) {
        return normalized;
      }
    } catch (error) {
      const statusCode = Number(error?.statusCode || 0);
      if ([400, 404, 405].includes(statusCode)) {
        continue;
      }
      throw error;
    }
  }

  return null;
}

async function attemptHubnetFulfillment(orderId) {
  debugLog(`\nÃ¢â€ â€™Ã¢â€ â€™Ã¢â€ â€™ [HUBNET INTERNAL] attemptHubnetFulfillment() called for order: ${orderId}`);
  
  if (!hubnet) {
    console.error(`[Hubnet] Skipping fulfillment: helper not configured.`);
    return { attempted: false, reason: "hubnet_not_configured" };
  }
  debugLog(`  Ã¢Å“â€œ Hubnet helper loaded`);

  const orderRef = db.ref(`orders/${orderId}`);
  const sessionRef = db.ref(`paymentSessions/${orderId}`);

  debugLog(`  Ã¢â€ â€™ Reading order from Firebase...`);
  const orderSnapshot = await orderRef.once("value");
  if (!orderSnapshot.exists()) {
    console.error(`[Hubnet] Order not found: ${orderId}`);
    return { attempted: false, reason: "order_not_found" };
  }
  debugLog(`  Ã¢Å“â€œ Order found in database`);

  const order = orderSnapshot.val();
  const paymentStatus = sanitizeString(order.paymentStatus, 40).toLowerCase();
  const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase();
  
  debugLog(`  Ã¢â€ â€™ Order status: paymentStatus="${paymentStatus}" | fulfillmentStatus="${fulfillmentStatus}"`);

  if (paymentStatus !== "paid") {
    console.error(`[Hubnet] Payment not confirmed for ${orderId}: ${paymentStatus}`);
    return { attempted: false, reason: "payment_not_confirmed" };
  }
  debugLog(`  Ã¢Å“â€œ Payment confirmed`);

  if (!order.packageNetwork || !order.packageVolume) {
    console.error(`[Hubnet] Missing package network/volume for ${orderId}`);
    return { attempted: false, reason: "missing_package_network_volume" };
  }
  debugLog(`  Ã¢Å“â€œ Package details present: ${order.packageNetwork} / ${order.packageVolume}MB`);

  if (["delivered", "fulfilled"].includes(fulfillmentStatus)) {
    console.warn(`[Hubnet] Skipping ${orderId}; already delivered (${fulfillmentStatus}).`);
    return { attempted: false, reason: "already_delivered" };
  }

  const priorTx = normalizeHubnetTransactionId(order.hubnetTransactionId);
  if (priorTx) {
    // Already has a transaction ID Ã¢â‚¬â€ only skip if not failed.
    if (fulfillmentStatus !== "failed") {
      console.warn(`[Hubnet] Already initiated for ${orderId} (${priorTx})`);
      return { attempted: false, reason: "already_initiated" };
    }
    debugLog(`  Ã¢â€ â€™ Retrying after previous failure (TxID exists but status is "failed")`);
  }

  const now = getCurrentTimestamp();
  // Enforce Hubnet's 25-char max reference constraint.
  const hubnetReference = sanitizeString(order.hubnetReference, 25) || makeHubnetReference(orderId);

  debugLog(`  Ã¢â€ â€™ Acquiring Firebase transaction lock...`);
  const lock = await orderRef.transaction((current) => {
    // IMPORTANT: returning undefined aborts the transaction (committed=false).
    // Rare races can pass current=null even right after we read the order Ã¢â‚¬â€ seed from the snapshot.
    const base = current && typeof current === "object" ? current : null;
    if (!base) {
      console.warn("[Hubnet] Transaction received empty state; retrying with latest order snapshot.");
      return {
        ...order,
        fulfillmentProvider: "hubnet",
        fulfillmentStatus: "processing",
        status: "processing",
        hubnetReference,
        hubnetInitAt: now,
        fulfillmentError: null,
        hubnetLastFailedAt: null,
        statusHistory: appendStatusHistory(order.statusHistory, {
          status: "processing",
          source: "hubnet-init",
          at: now,
        }),
        updatedAt: now,
      };
    }

    const currentFulfillment = sanitizeString(base.fulfillmentStatus, 40).toLowerCase();
    const existingTx = normalizeHubnetTransactionId(base.hubnetTransactionId);
    const staleProcessing = currentFulfillment === "processing"
      && !existingTx
      && isStaleTimestamp(base.hubnetInitAt);

    if (existingTx && currentFulfillment !== "failed") return;
    if (["delivered", "fulfilled"].includes(currentFulfillment)) return;
    if (currentFulfillment === "processing" && base.hubnetInitAt && !staleProcessing) return;

    return {
      ...base,
      fulfillmentProvider: "hubnet",
      fulfillmentStatus: "processing",
      status: "processing",
      hubnetReference,
      hubnetInitAt: now,
      fulfillmentError: null,
      hubnetLastFailedAt: null,
      statusHistory: appendStatusHistory(base.statusHistory, {
        status: "processing",
        source: "hubnet-init",
        at: now,
      }),
      updatedAt: now,
    };
  });

  if (!lock.committed) {
    const refreshed = await orderRef.once("value");
    const o = refreshed.exists() ? refreshed.val() : {};
    let snapVal = null;
    try {
      snapVal = lock.snapshot && typeof lock.snapshot.val === "function" ? lock.snapshot.val() : null;
    } catch (_e) {
      snapVal = null;
    }
    const txId = normalizeHubnetTransactionId(o.hubnetTransactionId);
    const initAt = o.hubnetInitAt;
    const inflight = Boolean(initAt) && !isStaleTimestamp(initAt);
    const fs = sanitizeString(o.fulfillmentStatus, 40).toLowerCase();
    if (txId) {
      console.warn(`[Hubnet] Lock skipped, transaction already exists: ${txId}`);
      return { attempted: false, reason: "already_initiated" };
    }
    if (inflight && fs === "processing") {
      console.warn("[Hubnet] Lock skipped, provisioning already in progress.");
      return { attempted: false, reason: "hubnet_inflight" };
    }
    console.error(`[Hubnet] Lock not acquired for ${orderId}. fulfillment=${fs}`);
    return { attempted: false, reason: "locked" };
  }
  debugLog(`  Ã¢Å“â€œ Transaction lock acquired, order status set to "processing"`);

  debugLog(`  Ã¢â€ â€™ Normalizing Ghana phone number...`);
  const msisdn = toGhanaNationalPhone(order.beneficiaryPhone);
  if (!msisdn) {
    console.error(`[Hubnet] Invalid beneficiary phone for ${orderId}`);
    await Promise.all([
      orderRef.update({
        fulfillmentStatus: "failed",
        status: "paid",
        countsAsOrder: false,
        orderInvalidReason: "bundle_delivery_failed",
        fulfillmentError: "Invalid Ghana phone number.",
        updatedAt: getCurrentTimestamp(),
      }),
      sessionRef.update({ fulfillmentStatus: "failed", fulfillmentError: "Invalid Ghana phone number.", updatedAt: getCurrentTimestamp() }),
    ]);
    await auditLog("hubnet", "fulfillment-invalid-phone", {
      orderId,
      ownerId: order.ownerId,
      storeId: order.storeId,
      hubnetReference,
      beneficiaryPhone: order.beneficiaryPhone,
    }, "error");
    return { attempted: true, reason: "invalid_phone" };
  }
  debugLog(`  Ã¢Å“â€œ Phone normalized: ${msisdn}`);

  const webhookUrl = buildHubnetWebhookUrl();
  const referrer = /^\d{10}$/.test(String(HUBNET_REFERRER || ""))
    ? String(HUBNET_REFERRER)
    : msisdn;

  const networkCandidates = sanitizeString(order.packageNetwork, 20).toLowerCase() === "telecel"
    ? ["big-time", "telecel"]
    : [normalizeHubnetNetworkForApi(order.packageNetwork)];

  let hubnetNetwork = networkCandidates[0];

  try {
    const requestPayload = {
      phone: msisdn,
      volume: String(order.packageVolume),
      reference: hubnetReference,
      referrer,
      webhook: webhookUrl,
    };
    
    debugLog(`  Ã¢â€ â€™ Logging fulfillment request to audit trail...`);
    await auditLog("hubnet", "fulfillment-requested", {
      orderId,
      ownerId: order.ownerId,
      storeId: order.storeId,
      hubnetReference,
      network: hubnetNetwork,
      volume: order.packageVolume,
      beneficiaryPhone: msisdn,
      webhook: webhookUrl,
    });

    debugLog(`\nÃ¢â€ â€™ [HUBNET REQUEST] Creating ${hubnetNetwork.toUpperCase()} bundle`);
    debugLog(`  Ã¢â€â€Ã¢â€â‚¬ Reference: ${hubnetReference}`);
    debugLog(`  Ã¢â€â€Ã¢â€â‚¬ Phone: ${msisdn}`);
    debugLog(`  Ã¢â€â€Ã¢â€â‚¬ Volume: ${order.packageVolume}MB`);
    debugLog(`  Ã¢â€â€Ã¢â€â‚¬ Webhook URL: ${webhookUrl}`);
    debugLog(`  Ã¢â€ â€™ Sending to Hubnet API...`);

    let response;
    try {
      debugLog(`  Ã¢â€ â€™ [HUBNET API CALL] network="${hubnetNetwork}" phone="${msisdn}" volume="${order.packageVolume}"MB reference="${hubnetReference}"`);
      response = await hubnet.createTransaction({ network: hubnetNetwork, ...requestPayload });
      debugLog(`  Ã¢Å“â€œ [HUBNET API RESPONSE] Received response object`);
    } catch (error) {
      console.error(`[Hubnet] API request failed for ${orderId}: ${error?.message}`);
      debugLog(`[Hubnet] error message: ${error?.message}`);
      debugLog(`[Hubnet] error payload: ${JSON.stringify(error?.payload, null, 2)}`);
      debugLog(`[Hubnet] error statusCode: ${error?.statusCode}`);
      
      const msg = sanitizeString(error?.message, 300).toLowerCase();
      const msg2 = sanitizeString(error?.payload?.message, 200).toLowerCase();
      const invalidNetwork = msg.includes("invalid network") || msg2.includes("invalid network");

      if (networkCandidates.length > 1 && invalidNetwork) {
        debugLog(`  Ã¢â€ â€™ Network "${hubnetNetwork}" invalid, retrying with fallback: "${networkCandidates[1]}"`);
        hubnetNetwork = networkCandidates[1];
        response = await hubnet.createTransaction({ network: hubnetNetwork, ...requestPayload });
      } else {
        throw error;
      }
    }

    debugLog(`  Ã¢â€ â€™ Checking Hubnet response acceptance...`);
    const details = extractHubnetResponseDetails(response, hubnetReference);
    debugLog(`  Ã¢â€ â€™ Response details: accepted="${details.accepted}" transactionId="${details.transactionId}" status="${details.status}"`);
    
    if (!details.accepted) {
      const reason = details.message || details.reason || "Hubnet did not confirm the bundle request.";
      console.error(`[Hubnet] API response not accepted: ${reason}`);
      throw new Error(reason);
    }
    debugLog(`  Ã¢Å“â€œ Response marked as ACCEPTED by Hubnet`);

    const hubnetTransactionId = details.transactionId;
    const hubnetPaymentId = details.paymentId;
    const hubnetMessage = details.message;
    const hubnetCode = details.code;
    const hubnetReason = details.reason;
    const hubnetIpAddress = details.ipAddress;
    const fulfillmentReference = sanitizeString(
      hubnetTransactionId || hubnetPaymentId || details.responseReference || hubnetReference,
      120
    );

    debugLog(`  Ã¢â€ â€™ Updating order in Firebase with Hubnet response...`);
    await Promise.all([
      db.ref(`hubnetReferences/${hubnetReference}`).set({
        orderId,
        createdAt: now,
      }),
      orderRef.update({
        hubnetNetwork,
        hubnetTransactionId,
        hubnetPaymentId,
        hubnetMessage,
        hubnetCode,
        hubnetReason,
        hubnetIpAddress,
        hubnetResponseStatus: sanitizeString(details.status, 80) || null,
        fulfillmentReference,
        fulfillmentStatus: "processing",
        status: "processing",
        updatedAt: getCurrentTimestamp(),
      }),
      sessionRef.update({
        hubnetReference,
        hubnetNetwork,
        hubnetTransactionId,
        hubnetPaymentId,
        fulfillmentReference,
        fulfillmentStatus: "processing",
        updatedAt: getCurrentTimestamp(),
      }),
    ]);
    debugLog(`  Ã¢Å“â€œ Firebase updated with Hubnet response`);
    
    debugLog(`  Ã¢â€ â€™ Logging success to audit trail...`);
    await auditLog("hubnet", "fulfillment-accepted", {
      orderId,
      ownerId: order.ownerId,
      storeId: order.storeId,
      hubnetReference,
      hubnetTransactionId,
      hubnetPaymentId,
      network: hubnetNetwork,
      code: hubnetCode,
      message: hubnetMessage,
    });
    debugLog(`  Ã¢Å“â€œ Audit log recorded`);

    debugLog("Ã¢Å“â€œ [HUBNET SUCCESS] Bundle provision accepted");
    debugLog(`  Ã¢â€â€Ã¢â€â‚¬ Transaction ID: ${hubnetTransactionId}`);
    debugLog(`  Ã¢â€â€Ã¢â€â‚¬ Payment ID: ${hubnetPaymentId || "N/A"}`);
    debugLog(`  Ã¢â€â€Ã¢â€â‚¬ Network: ${hubnetNetwork.toUpperCase()}`);
    debugLog(`  Ã¢â€â€Ã¢â€â‚¬ Status Code: ${hubnetCode || "OK"}`);
    debugLog(`  Ã¢â€â€Ã¢â€â‚¬ Message: ${hubnetMessage || "Bundle provisioning initiated"}`);
    debugLog(`  Ã¢â€â€Ã¢â€â‚¬ Waiting for webhook confirmation...`);

    return { attempted: true, hubnetReference, hubnetTransactionId };
  } catch (error) {
    const message = sanitizeString(error?.message || error?.payload?.message, 500) || "Hubnet transaction failed.";
    const now2 = getCurrentTimestamp();
    
    debugLog("[Hubnet] verbose error banner omitted.");
    console.error(`[Hubnet] Provision failed for ${orderId}: ${message}`);
    debugLog("[Hubnet] verbose error frame omitted.");
    debugLog(`[Hubnet] error=${message}`);
    debugLog(`[Hubnet] orderId=${orderId}`);
    debugLog(`[Hubnet] reference=${hubnetReference}`);
    debugLog(`[Hubnet] network=${hubnetNetwork}`);
    debugLog(`[Hubnet] phone=${msisdn}`);
    debugLog(`[Hubnet] volume=${order.packageVolume}MB`);
    debugLog("[Hubnet] full error details follow in debug mode.");
    debugLog(`[Hubnet] statusCode=${error?.statusCode || "N/A"}`);
    debugLog(`[Hubnet] payload=${JSON.stringify(error?.payload, null, 2)}`);
    debugLog(`[Hubnet] stack=${error?.stack}`);
    console.error("[Hubnet] Order marked as failed; payment remains paid.");
    debugLog(`[Hubnet] manual retry: POST /api/owner/orders/${orderId}/retry-fulfillment`);
    debugLog(`[Hubnet] firebase paths: /orders/${orderId}, /paymentSessions/${orderId}`);
    
    // Mark as 'failed' but keep status as 'paid' so the payment is not lost.
    // The order can be retried by calling attemptHubnetFulfillment again.
    debugLog(`  Ã¢â€ â€™ Updating order status to "failed" in Firebase...`);
    await Promise.all([
      orderRef.update({
        fulfillmentStatus: "failed",
        // Keep overall status as 'paid' Ã¢â‚¬â€ the customer paid successfully.
        // Only fulfillment failed, not the payment.
        status: "paid",
        countsAsOrder: false,
        orderInvalidReason: "bundle_delivery_failed",
        fulfillmentError: message,
        hubnetLastFailedAt: now2,
        statusHistory: appendStatusHistory(
          (await orderRef.once("value")).val()?.statusHistory || [],
          { status: "failed", source: "hubnet-error", at: now2, error: message }
        ),
        updatedAt: now2,
      }),
      sessionRef.update({
        fulfillmentStatus: "failed",
        fulfillmentError: message,
        updatedAt: now2,
      }),
    ]);
    debugLog(`  Ã¢Å“â€œ Order and session updated to failed status`);
    
    debugLog(`  Ã¢â€ â€™ Logging failure to audit trail...`);
    await auditLog("hubnet", "fulfillment-failed", {
      orderId,
      ownerId: order.ownerId,
      storeId: order.storeId,
      hubnetReference,
      network: hubnetNetwork,
      error: message,
    }, "error");
    debugLog(`  Ã¢Å“â€œ Audit log recorded`);

    return { attempted: true, reason: "hubnet_failed", error: message };
  }
}

async function legacyProcessSuccessfulPayment(reference, verifiedData, eventName) {
  const sessionRef = db.ref(`paymentSessions/${reference}`);
  const orderRef = db.ref(`orders/${reference}`);

  // Read session to verify it exists and check amount
  const sessionSnapshot = await sessionRef.once("value");
  if (!sessionSnapshot.exists()) {
    throw httpError(404, "Payment session not found.");
  }

  const session = sessionSnapshot.val();
  const shouldAttemptHubnet = Boolean(hubnet) && Boolean(session.packageNetwork) && Boolean(session.packageVolume);
  // Hubnet: stay "queued" until attemptHubnetFulfillment acquires the lock (avoids colliding with
  // "processing" + hubnetInitAt guards). Non-Hubnet fulfillment API still uses "processing".
  const initialFulfillmentStatus = shouldAttemptHubnet
    ? "queued"
    : (fulfillment ? "processing" : "queued");
  const initialFulfillmentProvider = shouldAttemptHubnet ? "hubnet" : (fulfillment ? "fulfillment-api" : (session.fulfillmentProvider || null));
  const hubnetReference = shouldAttemptHubnet
    ? (sanitizeString(session.hubnetReference, 40) || makeHubnetReference(reference))
    : (sanitizeString(session.hubnetReference, 40) || null);

  const customerName = sanitizeString(
    `${sanitizeString(verifiedData?.customer?.first_name, 80)} ${sanitizeString(verifiedData?.customer?.last_name, 80)}`.trim(),
    120
  );

  // Amount tamper-check
  const expectedAmountKobo = Math.round((Number(session.amount) || 0) * 100);
  const actualAmountKobo = Number(verifiedData.amount || 0);

  if (expectedAmountKobo !== actualAmountKobo) {
    await sessionRef.update({
      paymentStatus: "failed",
      failureReason: "amount_mismatch",
      webhookReceived: true,
      updatedAt: getCurrentTimestamp(),
    });
    await auditLog("payment", "amount-mismatch", {
      reference,
      eventName,
      expectedAmountKobo,
      actualAmountKobo,
      storeSlug: session.slug,
    }, "error");
    throw httpError(400, "Amount mismatch detected.");
  }

  // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ IDEMPOTENCY Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
  // Use an RTDB transaction to atomically mark the session as paid.
  // If another webhook/request already set paymentStatus="paid", the transaction
  // function returns undefined (abort) and committed=false Ã¢â‚¬â€ we stop here.
  const txResult = await sessionRef.transaction((current) => {
    if (!current || current.paymentStatus === "paid") {
      return; // undefined = abort: already paid or node gone
    }
    return {
      ...current,
      paymentStatus: "paid",
      webhookReceived: true,
      fulfillmentStatus: initialFulfillmentStatus,
      fulfillmentProvider: initialFulfillmentProvider,
      hubnetReference: shouldAttemptHubnet
        ? (sanitizeString(current.hubnetReference, 40) || hubnetReference)
        : (current.hubnetReference || null),
      updatedAt: getCurrentTimestamp(),
      paidAt: getCurrentTimestamp(),
      verifiedAmountKobo: actualAmountKobo,
      webhookEvent: eventName,
    };
  });

  // Transaction aborted Ã¢Å¸Â¹ session was already paid; skip to avoid double-credit.
  if (!txResult.committed) {
    await auditLog("payment", "already-processed", {
      reference,
      eventName,
      storeSlug: session.slug,
    }, "warn");
    return;
  }

  // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ CREATE ORDER (idempotent guard) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
  const orderSnapshot = await orderRef.once("value");
  if (!orderSnapshot.exists()) {
    const now = getCurrentTimestamp();

    await orderRef.set({
      storeId: session.storeId,
      ownerId: session.ownerId,
      slug: session.slug,
      storeName: session.storeName || "",
      email: session.email,
      maskedEmail: session.maskedEmail || maskEmail(session.email),
      beneficiaryPhone: session.beneficiaryPhone,
      packageId: session.packageId,
      catalogPackageId: catalogPackageId || null,
      packageName: session.packageName,
      package: session.packageName,
      packageNetwork: session.packageNetwork || null,
      packageVolume: session.packageVolume || null,
      amount: sellingAmount,
      baseAmount: baseAmount || null,
      profitAmount: Number((profitAmount || 0).toFixed(2)),
      currency: "GHS",
      paystackReference: reference,
      hubnetReference,
      paymentStatus: "paid",
      fulfillmentProvider: initialFulfillmentProvider,
      fulfillmentStatus: initialFulfillmentStatus,
      status: "paid",
      customerInfo: {
        name: customerName || null,
        email: session.email,
        phone: session.beneficiaryPhone,
      },
      statusHistory: [{
        status: "paid",
        source: eventName === "charge.success" ? "paystack-webhook" : "manual-verify",
        at: now,
      }],
      createdAt: now,
      updatedAt: now,
    });

    // Atomically increment store metrics (no lost updates)
    await db.ref(`storefronts/${session.storeId}/metrics`).transaction((metrics) => {
      const m = metrics || { totalOrders: 0, totalRevenue: 0 };
      return {
        totalOrders: (m.totalOrders || 0) + 1,
        totalRevenue: parseFloat(((m.totalRevenue || 0) + sellingAmount).toFixed(2)),
        totalProfit: parseFloat(((m.totalProfit || 0) + Number((profitAmount || 0).toFixed(2))).toFixed(2)),
      };
    });

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ WALLET CREDIT (atomic) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    await db.ref(`wallet/${session.ownerId}`).transaction((wallet) => {
      const w = wallet || { balance: 0, totalEarned: 0, totalOrders: 0 };
      return {
        balance: parseFloat(((w.balance || 0) + Number(session.amount || 0)).toFixed(2)),
        totalEarned: parseFloat(((w.totalEarned || 0) + Number(session.amount || 0)).toFixed(2)),
        totalOrders: (w.totalOrders || 0) + 1,
        currency: "GHS",
        lastCreditAt: now,
        updatedAt: now,
      };
    });

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ WALLET LEDGER ENTRY (audit trail) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    const walletTxRef = db.ref(`walletTransactions/${session.ownerId}`).push();
    await walletTxRef.set({
      type: "credit",
      amount: Number(session.amount || 0),
      currency: "GHS",
      reference,
      paystackReference: reference,
      storeId: session.storeId,
      packageId: session.packageId,
      packageName: session.packageName,
      customerEmail: session.maskedEmail || maskEmail(session.email),
      source: eventName === "charge.success" ? "paystack-webhook" : "manual-verify",
      createdAt: now,
    });

    console.log(`[Wallet] Owner ${session.ownerId} credited GHS ${session.amount} for ref ${reference}`);
  }

  // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ FULFILLMENT Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
  await auditLog("payment", "confirmed", {
    reference,
    eventName,
    storeSlug: session.slug,
    ownerId: session.ownerId,
    amount: sellingAmount,
    baseAmount,
    profitAmount,
    fulfillmentProvider: initialFulfillmentProvider,
  });

  if (hubnet && !shouldAttemptHubnet) {
    await auditLog("hubnet", "bundle-fields-missing-on-session", {
      reference,
      ownerId: session.ownerId,
      storeId: session.storeId,
      packageNetwork: session.packageNetwork || null,
      packageVolume: session.packageVolume || null,
    }, "warn");
  }

  if (shouldAttemptHubnet) {
    await attemptHubnetFulfillment(reference);
    return;
  }

  if (!fulfillment) {
    return;
  }

  const orderSnapshot2 = await orderRef.once("value");
  if (!orderSnapshot2.exists() || orderSnapshot2.val().fulfillmentReference) {
    return;
  }

  try {
    const fulfillmentResponse = await fulfillment.createOrder({
      packageId: orderSnapshot2.val().packageId,
      email: orderSnapshot2.val().email,
      beneficiaryPhone: orderSnapshot2.val().beneficiaryPhone,
      externalReference: reference,
      metadata: {
        paystackReference: reference,
        storeId: orderSnapshot2.val().storeId,
      },
    });

    const fulfillmentReference = sanitizeString(
      fulfillmentResponse?.reference || fulfillmentResponse?.id || reference,
      120
    );
    const fulfillmentStatus = sanitizeString(
      fulfillmentResponse?.status || "queued",
      40
    ).toLowerCase();

    await Promise.all([
      orderRef.update({ fulfillmentReference, fulfillmentStatus, updatedAt: getCurrentTimestamp() }),
      sessionRef.update({ fulfillmentReference, fulfillmentStatus, updatedAt: getCurrentTimestamp() }),
    ]);
  } catch (error) {
    await Promise.all([
      orderRef.update({ fulfillmentStatus: "failed", fulfillmentError: sanitizeString(error.message, 500), updatedAt: getCurrentTimestamp() }),
      sessionRef.update({ fulfillmentStatus: "failed", fulfillmentError: sanitizeString(error.message, 500), updatedAt: getCurrentTimestamp() }),
    ]);
  }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Wallet Deposit Credit Handler Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// Called when Paystack confirms a WDEP- reference (wallet top-up payment).
// Fully idempotent: checks deposit status before crediting.
async function processWalletDeposit(reference, verifiedData, eventName) {
  const amountKobo = Math.round(Number(verifiedData?.amount || 0));
  const amountGhs = amountKobo / 100;

  if (!Number.isFinite(amountGhs) || amountGhs <= 0) {
    console.warn(`[WalletDeposit] Zero or invalid amount for ref ${reference}`);
    return;
  }

  let ownerId = sanitizeString(verifiedData?.metadata?.ownerId, 128);
  let depositRecord = null;

  if (ownerId) {
    const directSnapshot = await db.ref(`walletDeposits/${ownerId}/${reference}`).once("value");
    if (directSnapshot.exists()) {
      depositRecord = directSnapshot.val() || null;
    }
  }

  if (!depositRecord) {
    const allDepositsSnapshot = await db.ref("walletDeposits").once("value");
    if (allDepositsSnapshot.exists()) {
      allDepositsSnapshot.forEach((ownerNode) => {
        const ownerDeposits = ownerNode.val() || {};
        if (Object.prototype.hasOwnProperty.call(ownerDeposits, reference)) {
          const candidate = ownerDeposits[reference] || null;
          if (candidate) {
            ownerId = sanitizeString(candidate.ownerId || ownerNode.key, 128);
            depositRecord = candidate;
          }
        }
      });
    }
  }

  if (!depositRecord || !ownerId) {
    console.warn(`[WalletDeposit] No deposit record found for ref ${reference}`);
    return;
  }

  const depositRef = db.ref(`walletDeposits/${ownerId}/${reference}`);
  const now = getCurrentTimestamp();
  const expectedAmount = Number(depositRecord.amount || 0);
  const paystackOwnerId = sanitizeString(verifiedData?.metadata?.ownerId, 128);
  const paystackCurrency = sanitizeString(verifiedData?.currency, 12).toUpperCase() || "GHS";

  if (paystackOwnerId && paystackOwnerId !== ownerId) {
    await depositRef.update({
      status: "failed",
      failureReason: "owner-mismatch",
      paystackStatus: sanitizeString(verifiedData?.status, 40).toLowerCase() || "success",
      updatedAt: now,
    });
    console.warn(`[WalletDeposit] Owner mismatch for ${reference}: paystack=${paystackOwnerId}, record=${ownerId}`);
    return;
  }

  if (paystackCurrency !== "GHS") {
    await depositRef.update({
      status: "failed",
      failureReason: "currency-mismatch",
      paystackStatus: sanitizeString(verifiedData?.status, 40).toLowerCase() || "success",
      updatedAt: now,
    });
    console.warn(`[WalletDeposit] Currency mismatch for ${reference}: ${paystackCurrency}`);
    return;
  }

  if (Number.isFinite(expectedAmount) && expectedAmount > 0 && Math.abs(expectedAmount - amountGhs) > 0.01) {
    await depositRef.update({
      status: "failed",
      failureReason: "amount-mismatch",
      expectedAmount,
      paidAmount: amountGhs,
      paystackStatus: sanitizeString(verifiedData?.status, 40).toLowerCase() || "success",
      updatedAt: now,
    });
    console.warn(`[WalletDeposit] Amount mismatch for ${reference}: expected=${expectedAmount}, paid=${amountGhs}`);
    return;
  }

  if (depositRecord.status === "credited") {
    const existingTxRef = db.ref(`walletTransactions/${ownerId}/${reference}`);
    const existingTxSnapshot = await existingTxRef.once("value");
    if (!existingTxSnapshot.exists()) {
      await existingTxRef.set({
        type: "credit",
        category: "deposit",
        amount: amountGhs,
        currency: "GHS",
        reference,
        paystackReference: reference,
        description: "Wallet top-up via Paystack",
        source: eventName === "charge.success" ? "paystack-webhook" : "manual-verify",
        createdAt: now,
        updatedAt: now,
      });
      await recalculateOwnerWallet(ownerId);
    }
    console.log(`[WalletDeposit] Already credited for ref ${reference}, skipping.`);
    return;
  }

  const txResult = await depositRef.transaction((dep) => {
    if (!dep) return dep;
    if (dep.status === "credited") return;
    return {
      ...dep,
      status: "credited",
      creditedAt: now,
      paystackStatus: sanitizeString(verifiedData?.status, 40).toLowerCase() || "success",
      paidAmount: amountGhs,
      updatedAt: now,
    };
  });

  if (!txResult.committed) {
    console.log(`[WalletDeposit] Transaction aborted for ref ${reference} - likely already credited.`);
    return;
  }

  const txRef = db.ref(`walletTransactions/${ownerId}/${reference}`);
  await txRef.set({
    type: "credit",
    category: "deposit",
    amount: amountGhs,
    currency: "GHS",
    reference,
    paystackReference: reference,
    description: "Wallet top-up via Paystack",
    source: eventName === "charge.success" ? "paystack-webhook" : "manual-verify",
    createdAt: now,
    updatedAt: now,
  });

  await recalculateOwnerWallet(ownerId);

  console.log(`[WalletDeposit] Owner ${ownerId} credited GHS ${amountGhs} for deposit ref ${reference}`);
}


async function processSuccessfulPayment(reference, verifiedData, eventName) {
  // Ã¢â€â‚¬Ã¢â€â‚¬ WALLET DEPOSIT FAST PATH Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
  // References beginning with WDEP- belong to the wallet top-up flow,
  // not to storefront orders. Handle them separately and return early.
  if (String(reference || '').startsWith('WDEP-')) {
    await processWalletDeposit(reference, verifiedData, eventName);
    return;
  }

  const sessionRef = db.ref(`paymentSessions/${reference}`);
  const orderRef = db.ref(`orders/${reference}`);


  // Ã¢â€â‚¬Ã¢â€â‚¬ IDEMPOTENCY FAST PATH Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
  // If the order already exists and is fully paid + fulfilled, skip entirely.
  // This prevents any possible double-processing on duplicate webhook deliveries.
  const [quickSession, quickOrder] = await Promise.all([
    sessionRef.once("value"),
    orderRef.once("value"),
  ]);
  if (quickSession.exists() && quickOrder.exists()) {
    const qs = quickSession.val() || {};
    const qo = quickOrder.val() || {};
    const alreadyPaid = sanitizeString(qs.paymentStatus, 40).toLowerCase() === "paid"
      && sanitizeString(qo.paymentStatus, 40).toLowerCase() === "paid";
    const fulfillmentDone = ["delivered", "fulfilled"].includes(
      sanitizeString(qo.fulfillmentStatus, 40).toLowerCase()
    );
    // If already paid AND either fulfilled or no hubnet package needed Ã¢â‚¬â€ skip.
    if (alreadyPaid && (fulfillmentDone || !hasHubnetPackage(qs))) {
      await auditLog("payment", "already-processed-fast-path", {
        reference,
        eventName,
        storeSlug: qs.slug,
      }, "warn");
      return;
    }
  }

  let sessionSnapshot = await sessionRef.once("value");

  // Auto-recover the session from Paystack if it's missing (e.g. server restart,
  // missed webhook arriving before the initialize response was flushed, etc.).
  if (!sessionSnapshot.exists() && verifiedData) {
    try {
      await recoverSessionFromPaystack(reference, verifiedData);
      sessionSnapshot = await sessionRef.once("value");
    } catch (recoveryError) {
      await auditLog("payment", "session-recovery-failed", {
        reference,
        eventName,
        error: sanitizeString(recoveryError?.message, 200),
      }, "error");
    }
  }

  if (!sessionSnapshot.exists()) {
    throw httpError(404, "Payment session not found.");
  }

  const session = sessionSnapshot.val();
  const now = getCurrentTimestamp();
  const source = getPaymentSource(eventName);
  const sellingAmount = toPrice(session.amount) || 0;
  const baseAmount = toPrice(session.baseAmount)
    || toPrice(verifiedData?.metadata?.baseAmount)
    || null;
  const profitAmount = toPrice(session.profitAmount)
    || (baseAmount
      ? Number((sellingAmount - baseAmount).toFixed(2))
      : sellingAmount);
  const catalogPackageId = sanitizeString(
    session.catalogPackageId || verifiedData?.metadata?.catalogPackageId,
    120
  ) || null;
  const shouldAttemptHubnet = Boolean(hubnet) && hasHubnetPackage(session);
  const initialFulfillmentStatus = shouldAttemptHubnet
    ? "queued"
    : (fulfillment ? "processing" : "queued");
  const initialFulfillmentProvider = shouldAttemptHubnet
    ? "hubnet"
    : (fulfillment ? "fulfillment-api" : (session.fulfillmentProvider || null));
  const hubnetReference = shouldAttemptHubnet
    ? (sanitizeString(session.hubnetReference, 40) || makeHubnetReference(reference))
    : (sanitizeString(session.hubnetReference, 40) || null);

  const customerName = sanitizeString(
    `${sanitizeString(verifiedData?.customer?.first_name, 80)} ${sanitizeString(verifiedData?.customer?.last_name, 80)}`.trim(),
    120
  );

  const expectedAmountKobo = Math.round((Number(session.amount) || 0) * 100);
  const actualAmountKobo = Number(verifiedData.amount || 0);

  if (expectedAmountKobo !== actualAmountKobo) {
    await sessionRef.update({
      paymentStatus: "failed",
      failureReason: "amount_mismatch",
      webhookReceived: true,
      updatedAt: getCurrentTimestamp(),
    });
    await auditLog("payment", "amount-mismatch", {
      reference,
      eventName,
      expectedAmountKobo,
      actualAmountKobo,
      storeSlug: session.slug,
    }, "error");
    throw httpError(400, "Amount mismatch detected.");
  }

  const sessionFulfillmentStatus = sanitizeString(session.fulfillmentStatus, 40).toLowerCase();
  const nextSessionFulfillmentStatus = ["processing", "failed", "fulfilled", "delivered", "queued"].includes(sessionFulfillmentStatus)
    ? session.fulfillmentStatus
    : initialFulfillmentStatus;

  await sessionRef.update({
    paymentStatus: "paid",
    webhookReceived: true,
    fulfillmentStatus: nextSessionFulfillmentStatus,
    fulfillmentProvider: session.fulfillmentProvider || initialFulfillmentProvider,
    hubnetReference: shouldAttemptHubnet
      ? (sanitizeString(session.hubnetReference, 40) || hubnetReference)
      : (session.hubnetReference || null),
    updatedAt: now,
    paidAt: session.paidAt || now,
    verifiedAmountKobo: actualAmountKobo,
    webhookEvent: eventName,
    lastVerifiedAt: now,
  });

  console.log(`[Payment] Confirmed ref=${reference} amountGHS=${(actualAmountKobo / 100).toFixed(2)} provider=${initialFulfillmentProvider}`);

  await orderRef.transaction((current) => {
    const existingHistory = Array.isArray(current?.statusHistory) ? current.statusHistory : [];
    const hasPaidHistory = existingHistory.some((entry) => sanitizeString(entry?.status, 40).toLowerCase() === "paid");
    const currentFulfillmentStatus = sanitizeString(current?.fulfillmentStatus, 40).toLowerCase();
    const nextFulfillmentStatus = ["processing", "failed", "delivered", "fulfilled", "queued"].includes(currentFulfillmentStatus)
      ? current.fulfillmentStatus
      : initialFulfillmentStatus;

    let nextStatus = "paid";
    if (currentFulfillmentStatus === "processing") {
      nextStatus = "processing";
    } else if (currentFulfillmentStatus === "queued" && shouldAttemptHubnet) {
      nextStatus = "processing";
    } else if (["delivered", "fulfilled"].includes(currentFulfillmentStatus)) {
      nextStatus = "fulfilled";
    } else if (currentFulfillmentStatus === "failed") {
      nextStatus = "failed";
    }

    return {
      ...(current || {}),
      storeId: session.storeId,
      ownerId: session.ownerId,
      slug: session.slug,
      storeName: session.storeName || current?.storeName || "",
      email: session.email,
      maskedEmail: session.maskedEmail || current?.maskedEmail || maskEmail(session.email),
      beneficiaryPhone: session.beneficiaryPhone,
      packageId: session.packageId,
      catalogPackageId: catalogPackageId || current?.catalogPackageId || null,
      packageName: session.packageName,
      package: session.packageName,
      packageNetwork: session.packageNetwork || current?.packageNetwork || null,
      packageVolume: session.packageVolume || current?.packageVolume || null,
      amount: sellingAmount,
      baseAmount: baseAmount || current?.baseAmount || null,
      profitAmount: Number((profitAmount || 0).toFixed(2)),
      currency: "GHS",
      paystackReference: reference,
      hubnetReference: shouldAttemptHubnet
        ? (sanitizeString(current?.hubnetReference, 40) || hubnetReference)
        : (current?.hubnetReference || hubnetReference),
      paymentStatus: "paid",
      fulfillmentProvider: current?.fulfillmentProvider || initialFulfillmentProvider,
      fulfillmentStatus: nextFulfillmentStatus,
      status: nextStatus,
      countsAsOrder: ["delivered", "fulfilled"].includes(nextFulfillmentStatus),
      customerInfo: {
        ...(current?.customerInfo || {}),
        name: customerName || current?.customerInfo?.name || null,
        email: session.email,
        phone: session.beneficiaryPhone,
      },
      statusHistory: hasPaidHistory
        ? existingHistory
        : appendStatusHistory(existingHistory, {
          status: "paid",
          source,
          at: now,
        }),
      createdAt: current?.createdAt || now,
      updatedAt: now,
    };
  });

  const walletTxRef = db.ref(`walletTransactions/${session.ownerId}/${reference}`);
  const walletTxSnapshot = await walletTxRef.once("value");
  const existingWalletTx = walletTxSnapshot.exists() ? walletTxSnapshot.val() : null;

  await walletTxRef.set({
    ...(existingWalletTx || {}),
    type: "credit",
    category: "profit",
    amount: Number((profitAmount || 0).toFixed(2)),
    currency: "GHS",
    reference,
    paystackReference: reference,
    storeId: session.storeId,
    packageId: session.packageId,
    catalogPackageId: catalogPackageId || null,
    packageName: session.packageName,
    saleAmount: Number(sellingAmount.toFixed(2)),
    baseAmount: baseAmount || null,
    profitAmount: Number((profitAmount || 0).toFixed(2)),
    customerEmail: session.maskedEmail || maskEmail(session.email),
    source,
    createdAt: existingWalletTx?.createdAt || now,
    updatedAt: now,
  });

  await Promise.all([
    recalculateStoreMetrics(session.storeId),
    recalculateOwnerWallet(session.ownerId),
    orderRef.update({
      accountingSyncedAt: now,
      updatedAt: now,
    }),
    sessionRef.update({
      accountingSyncedAt: now,
      updatedAt: now,
    }),
  ]);

  await auditLog("payment", "confirmed", {
    reference,
    eventName,
    storeSlug: session.slug,
    ownerId: session.ownerId,
    amount: session.amount,
    fulfillmentProvider: initialFulfillmentProvider,
  });

  if (hubnet && !shouldAttemptHubnet) {
    await auditLog("hubnet", "bundle-fields-missing-on-session", {
      reference,
      ownerId: session.ownerId,
      storeId: session.storeId,
      packageNetwork: session.packageNetwork || null,
      packageVolume: session.packageVolume || null,
    }, "warn");
  }

  if (shouldAttemptHubnet) {
    // Run Hubnet in a protected try/catch: a Hubnet API error must NEVER
    // roll back the payment confirmation. The payment is already recorded as paid.
    console.log(`[Hubnet] Starting fulfillment for ${reference}`);
    try {
      const result = await attemptHubnetFulfillment(reference);
      debugLog(`[Hubnet] attempt result: ${JSON.stringify(result)}`);
    } catch (hubnetError) {
      console.error(`[Hubnet] Unhandled fulfillment error for ${reference}: ${hubnetError?.message}`);
      debugLog(`[Hubnet] stack: ${hubnetError?.stack}`);
      debugLog(`[Hubnet] payload: ${JSON.stringify(hubnetError, null, 2)}`);
      
      await auditLog("hubnet", "fulfillment-unhandled-error", {
        reference,
        ownerId: session.ownerId,
        storeId: session.storeId,
        error: sanitizeString(hubnetError?.message, 300),
      }, "error");
    }
    return;
  }

  if (!fulfillment) {
    return;
  }

  const orderSnapshot = await orderRef.once("value");
  if (!orderSnapshot.exists() || orderSnapshot.val().fulfillmentReference) {
    return;
  }

  try {
    const currentOrder = orderSnapshot.val();
    const fulfillmentResponse = await fulfillment.createOrder({
      packageId: currentOrder.packageId,
      email: currentOrder.email,
      beneficiaryPhone: currentOrder.beneficiaryPhone,
      externalReference: reference,
      metadata: {
        paystackReference: reference,
        storeId: currentOrder.storeId,
      },
    });

    const fulfillmentReference = sanitizeString(
      fulfillmentResponse?.reference || fulfillmentResponse?.id || reference,
      120
    );
    const fulfillmentStatus = sanitizeString(
      fulfillmentResponse?.status || "queued",
      40
    ).toLowerCase();

    await Promise.all([
      orderRef.update({ fulfillmentReference, fulfillmentStatus, updatedAt: getCurrentTimestamp() }),
      sessionRef.update({ fulfillmentReference, fulfillmentStatus, updatedAt: getCurrentTimestamp() }),
    ]);
  } catch (error) {
    await Promise.all([
      orderRef.update({ fulfillmentStatus: "failed", fulfillmentError: sanitizeString(error.message, 500), updatedAt: getCurrentTimestamp() }),
      sessionRef.update({ fulfillmentStatus: "failed", fulfillmentError: sanitizeString(error.message, 500), updatedAt: getCurrentTimestamp() }),
    ]);
  }
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

async function verifyAuth(req, res, next) {
  const authHeader = sanitizeString(req.headers.authorization, 2048);
  if (!authHeader.startsWith("Bearer ")) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }

  try {
    const token = authHeader.substring(7);
    const decodedToken = await auth.verifyIdToken(token);
    req.user = {
      uid: decodedToken.uid,
      email: normalizeEmail(decodedToken.email),
      name: sanitizeString(decodedToken.name, 120),
    };
    next();
  } catch (error) {
    sendJson(res, 401, { error: "Invalid token" });
  }
}

async function loadUserRecord(uid) {
  const userSnapshot = await db.ref(`users/${uid}`).once("value");
  return userSnapshot.exists() ? userSnapshot.val() : null;
}

async function requireAdmin(req, res, next) {
  try {
    const userRecord = await loadUserRecord(req.user.uid);
    if (!userRecord || userRecord.isAdmin !== true) {
      sendJson(res, 403, { error: "Admin access required." });
      return;
    }

    req.adminUser = {
      id: req.user.uid,
      ...userRecord,
    };
    next();
  } catch (error) {
    sendJson(res, 500, { error: error?.message || "Unable to verify admin access." });
  }
}

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function resolvePublicDir() {
  const seen = new Set();
  const candidates = [
    path.join(__dirname, "public"),
    path.join(process.cwd(), "public"),
    path.join(__dirname, "ASK MEDIA", "public"),
    path.join(process.cwd(), "ASK MEDIA", "public"),
  ];

  for (const candidate of candidates) {
    const normalized = path.normalize(candidate);
    if (seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    if (fs.existsSync(normalized)) {
      return normalized;
    }
  }

  // One-level deep fallback for deployment layouts that wrap the app in a folder.
  try {
    const entries = fs.readdirSync(__dirname, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      const nestedPublicDir = path.join(__dirname, entry.name, "public");
      if (fs.existsSync(nestedPublicDir)) {
        return nestedPublicDir;
      }
    }
  } catch (_error) {
    // Ignore and keep default.
  }

  return path.join(__dirname, "public");
}

// ============================================================================
// EXPRESS APP SETUP
// ============================================================================

const app = express();
const PUBLIC_DIR = resolvePublicDir();
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");
// Trust the first proxy hop (required on Render / behind a load balancer for
// rate-limit IP detection and secure cookie behaviour)
app.set("trust proxy", 1);

// Ã¢â€â‚¬Ã¢â€â‚¬ Security Headers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  // Only send HSTS on HTTPS (Render provides TLS)
  if (req.secure || req.headers["x-forwarded-proto"] === "https") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

// CORS Middleware
const corsMiddleware = cors({
  origin(origin, callback) {
    // Allow no-origin requests (same-origin, Postman, mobile apps)
    if (!origin) { callback(null, true); return; }
    if (allowedOrigins.has(origin)) { callback(null, true); return; }
    callback(new Error("CORS: Origin not allowed."));
  },
  methods: ["GET", "POST", "PUT", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Paystack-Signature", "X-Hubnet-Secret"],
  credentials: false,
  maxAge: 86400,
});

app.use(corsMiddleware);
app.options("*", corsMiddleware);

// Body parsing Ã¢â‚¬â€ the verify callback captures the raw body BEFORE JSON parsing.
// This is the ONLY correct way to get the raw body for Paystack webhook signature
// verification. A separate middleware after express.json() would see an exhausted
// stream and always produce an empty buffer, breaking signature checks.
app.use(express.json({
  limit: "512kb",
  verify: (req, res, buf) => {
    req.rawBody = buf; // raw Buffer available for HMAC signature verification
    // Guard against absurdly large payloads (belt-and-suspenders beyond limit)
    if (buf && buf.length > 524288) {
      const err = new Error("Request entity too large");
      err.statusCode = 413;
      throw err;
    }
  },
}));

app.use((req, res, next) => {
  req.requestId = crypto.randomUUID().slice(0, 8);
  next();
});

// Ã¢â€â‚¬Ã¢â€â‚¬ Rate Limiting Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// Strict limit on payment initialization Ã¢â‚¬â€ prevents brute-force attempts
const paymentInitRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,                   // max 20 payment inits per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many payment requests. Please try again in a few minutes." },
  skipSuccessfulRequests: false,
});

// General public API limit
const publicApiRateLimit = rateLimit({
  windowMs: 5 * 60 * 1000,  // 5 minutes
  max: 100,                  // max 100 requests per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please slow down." },
  skipSuccessfulRequests: false,
});

// Very strict limit on webhook endpoints (Hubnet/Paystack IPs only in theory)
const webhookRateLimit = rateLimit({
  windowMs: 60 * 1000,       // 1 minute
  max: 60,                   // 60 webhook calls per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many webhook requests." },
  skipSuccessfulRequests: true,
});

// ============================================================================
// ADMIN DATA HELPERS
// ============================================================================

function sortByNewestTimestamp(rows, fallbackFields = ["createdAt", "updatedAt", "paidAt"]) {
  return [...rows].sort((a, b) => {
    const valueA = fallbackFields.map((field) => a?.[field]).find(Boolean) || 0;
    const valueB = fallbackFields.map((field) => b?.[field]).find(Boolean) || 0;
    return getTimestampMs(valueB) - getTimestampMs(valueA);
  });
}

function matchesSearchText(query, values = []) {
  const needle = sanitizeString(query, 120).toLowerCase();
  if (!needle) {
    return true;
  }

  return values
    .filter(Boolean)
    .some((value) => sanitizeString(value, 500).toLowerCase().includes(needle));
}

async function listAllUsersWithWalletsAndStores() {
  const [usersSnapshot, walletsSnapshot, storesSnapshot] = await Promise.all([
    db.ref("users").once("value"),
    db.ref("wallet").once("value"),
    db.ref("storefronts").once("value"),
  ]);

  const wallets = new Map();
  walletsSnapshot.forEach((child) => {
    wallets.set(child.key, child.val() || {});
  });

  const storesByOwner = new Map();
  storesSnapshot.forEach((child) => {
    const store = child.val() || {};
    const ownerId = sanitizeString(store.ownerId, 120);
    if (!ownerId) {
      return;
    }

    const resolved = {
      id: child.key,
      ...store,
    };

    const current = storesByOwner.get(ownerId);
    if (!current || getTimestampMs(resolved.updatedAt || resolved.createdAt) > getTimestampMs(current.updatedAt || current.createdAt)) {
      storesByOwner.set(ownerId, resolved);
    }
  });

  const users = [];
  usersSnapshot.forEach((child) => {
    const user = child.val() || {};
    const wallet = wallets.get(child.key) || {};
    const store = storesByOwner.get(child.key) || null;
    users.push({
      id: child.key,
      ...user,
      isAdmin: user.isAdmin === true,
      wallet: {
        balance: Number(wallet.balance || 0),
        totalEarned: Number(wallet.totalEarned || 0),
        totalProfit: Number(wallet.totalProfit || 0),
        totalDeposits: Number(wallet.totalDeposits || 0),
        totalDebits: Number(wallet.totalDebits || 0),
        totalOrders: Number(wallet.totalOrders || 0),
        currency: wallet.currency || "GHS",
        lastCreditAt: wallet.lastCreditAt || null,
        lastDebitAt: wallet.lastDebitAt || null,
      },
      store: store ? {
        id: store.id,
        name: store.name || "",
        slug: store.slug || "",
        published: store.published !== false,
        packageCount: Array.isArray(store.packages) ? store.packages.length : 0,
      } : null,
    });
  });

  return users;
}

async function listAllOrdersForAdmin() {
  const snapshot = await db.ref("orders").once("value");
  const orders = [];

  snapshot.forEach((child) => {
    orders.push({
      id: child.key,
      ...child.val(),
    });
  });

  return sortByNewestTimestamp(orders, ["createdAt", "updatedAt"]);
}

async function listAllWalletTransactionsForAdmin() {
  const snapshot = await db.ref("walletTransactions").once("value");
  const transactions = [];

  snapshot.forEach((ownerNode) => {
    ownerNode.forEach((child) => {
      const tx = child.val() || {};
      transactions.push({
        id: child.key,
        ownerId: ownerNode.key,
        ...tx,
      });
    });
  });

  return sortByNewestTimestamp(transactions, ["createdAt", "updatedAt", "paidAt"]);
}

async function buildAdminBootstrapPayload() {
  const [users, orders, transactions, catalogPackages] = await Promise.all([
    listAllUsersWithWalletsAndStores(),
    listAllOrdersForAdmin(),
    listAllWalletTransactionsForAdmin(),
    listCatalogPackages({ includeInactive: true }),
  ]);

  const successfulOrders = orders.filter((order) => isSuccessfulOrderRecord(order));
  const summary = {
    totalUsers: users.length,
    totalAdmins: users.filter((user) => user.isAdmin).length,
    totalStores: users.filter((user) => Boolean(user.store?.id)).length,
    totalOrders: successfulOrders.length,
    totalPaidRevenue: Number(successfulOrders.reduce((sum, order) => sum + Number(order.amount || 0), 0).toFixed(2)),
    totalProfit: Number(successfulOrders.reduce((sum, order) => sum + Number(order.profitAmount || 0), 0).toFixed(2)),
    totalWalletBalance: Number(users.reduce((sum, user) => sum + Number(user.wallet?.balance || 0), 0).toFixed(2)),
    totalWalletCredits: Number(transactions.filter((tx) => sanitizeString(tx.type, 20).toLowerCase() === "credit").reduce((sum, tx) => sum + Number(tx.amount || 0), 0).toFixed(2)),
    totalWalletDebits: Number(transactions.filter((tx) => sanitizeString(tx.type, 20).toLowerCase() === "debit").reduce((sum, tx) => sum + Number(tx.amount || 0), 0).toFixed(2)),
    activePackages: catalogPackages.filter((pkg) => pkg.active !== false).length,
  };

  return {
    summary,
    users,
    orders,
    transactions,
    catalogPackages,
  };
}

async function validateAdminPackagePayload(payload, existingPackageId = "") {
  const name = sanitizeString(payload?.name, 120);
  const description = sanitizeString(payload?.description, 400);
  const basePrice = toPrice(payload?.basePrice);
  const sortOrder = Number.parseInt(payload?.sortOrder, 10);
  const network = normalizePackageNetwork(payload?.network) || null;
  const volume = sanitizePackageVolume(payload?.volume, "Package");
  const active = payload?.active !== undefined ? Boolean(payload.active) : true;

  if (!name) {
    throw httpError(400, "Package name is required.");
  }

  if (!basePrice) {
    throw httpError(400, "Package base price must be a positive value.");
  }

  if ((network && !volume) || (!network && volume)) {
    throw httpError(400, "Package network and volume must either both be set or both be empty.");
  }

  const existingPackages = await listCatalogPackages({ includeInactive: true });
  const duplicate = existingPackages.find((pkg) => {
    if (pkg.id === existingPackageId) {
      return false;
    }

    if (network && volume) {
      return pkg.network === network && pkg.volume === volume;
    }

    return sanitizeString(pkg.name, 120).toLowerCase() === name.toLowerCase();
  });

  if (duplicate) {
    throw httpError(409, "A package with the same identity already exists.");
  }

  return {
    name,
    description,
    basePrice,
    network,
    volume,
    active,
    sortOrder: Number.isInteger(sortOrder) ? sortOrder : 0,
  };
}

// ============================================================================
// API ROUTES
// ============================================================================

// Health check
app.get("/api/health", (req, res) => {
  sendJson(res, 200, {
    status: "ok",
    paymentsConfigured: Boolean(paystack),
    bundleDeliveryConfigured: Boolean(hubnet) || Boolean(fulfillment),
    fulfillmentConfigured: Boolean(fulfillment),
  });
});

// Public: Get store details
app.get("/api/public/store/:slug", publicApiRateLimit, asyncHandler(async (req, res) => {
  const slug = normalizeSlug(req.params.slug);
  if (!isValidSlug(slug)) {
    throw httpError(400, "Invalid store slug.");
  }

  const snapshot = await db.ref("storefronts").orderByChild("slug").equalTo(slug).once("value");

  let store = null;
  let storeId = null;

  snapshot.forEach((child) => {
    store = child.val();
    storeId = child.key;
  });

  if (!store) {
    throw httpError(404, "Store not found.");
  }

  if (store.published === false) {
    throw httpError(404, "Store not found.");
  }

  sendJson(res, 200, {
    id: storeId,
    name: sanitizeString(store.name, 120),
    slug: sanitizeString(store.slug, 50),
    theme: sanitizeString(store.theme, 20) || "light",
    supportPhone: sanitizeString(store.supportPhone, 25),
    supportWhatsapp: sanitizeString(store.supportWhatsapp, 25),
    supportEmail: normalizeEmail(store.supportEmail),
    packages: await getPublicStorePackages(store),
    logo: sanitizeString(store.logo, 400) || null,
  });
}));

// Public: Track Order Status (by reference)
app.get("/api/public/orders/track/:reference", publicApiRateLimit, asyncHandler(async (req, res) => {
  const reference = sanitizeString(req.params.reference, 120);
  if (!reference) {
    throw httpError(400, "Tracking reference is required.");
  }

  async function findByChild(childKey) {
    const snap = await db.ref("orders")
      .orderByChild(childKey)
      .equalTo(reference)
      .limitToFirst(1)
      .once("value");

    let found = null;
    let foundId = null;
    snap.forEach((child) => {
      if (!foundId) {
        foundId = child.key;
        found = child.val();
      }
    });

    return found ? { id: foundId, order: found } : null;
  }

  let orderId = null;
  let order = null;

  const direct = await db.ref(`orders/${reference}`).once("value");
  if (direct.exists()) {
    orderId = reference;
    order = direct.val();
  } else {
    const byPaystack = await findByChild("paystackReference");
    if (byPaystack) {
      orderId = byPaystack.id;
      order = byPaystack.order;
    }
  }

  if (!order) {
    const byHubnet = await findByChild("hubnetReference");
    if (byHubnet) {
      orderId = byHubnet.id;
      order = byHubnet.order;
    }
  }

  if (!order) {
    const byFulfillment = await findByChild("fulfillmentReference");
    if (byFulfillment) {
      orderId = byFulfillment.id;
      order = byFulfillment.order;
    }
  }

  if (!order) {
    throw httpError(404, "Order not found.");
  }

  const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase() || "queued";
  const paymentStatus = sanitizeString(order.paymentStatus, 40).toLowerCase() || "pending";

  let status = sanitizeString(order.status, 40).toLowerCase();
  if (!status) {
    status = fulfillmentStatus === "delivered" || fulfillmentStatus === "fulfilled"
      ? "fulfilled"
      : paymentStatus === "paid"
        ? "paid"
        : paymentStatus;
  }

  sendJson(res, 200, {
    id: orderId,
    reference: order.hubnetReference || order.fulfillmentReference || order.paystackReference || orderId,
    status,
    paymentStatus,
    fulfillmentStatus,
    amount: Number(order.amount || 0),
    storeName: sanitizeString(order.storeName, 120) || "",
    packageName: sanitizeString(order.packageName || order.package, 120) || "",
    network: sanitizeString(order.packageNetwork, 20).toLowerCase() || null,
    volume: sanitizeString(order.packageVolume, 20) || null,
    email: order.maskedEmail || maskEmail(order.email || ""),
    createdAt: order.createdAt || null,
    updatedAt: order.updatedAt || null,
  });
}));

// Public: Order lookup Ã¢â‚¬â€ supports ?reference=XYZ OR ?phone=0271234567
// Per DevNox spec: https://your-api.com/v1/orders?reference=XYZ12345
//                 https://your-api.com/v1/orders?phone=0247000195
app.get("/v1/orders", publicApiRateLimit, asyncHandler(async (req, res) => {
  const reference = sanitizeString(req.query?.reference, 120);
  const phoneRaw = sanitizeString(req.query?.phone, 40);
  const phone = phoneRaw ? normalizePhone(phoneRaw) : "";

  if (!reference && !phone) {
    throw httpError(400, "Either 'reference' or 'phone' query parameter is required.");
  }

  if (reference && reference.length < 3) {
    throw httpError(400, "Reference too short.");
  }
  if (phoneRaw && !phone) {
    throw httpError(400, "Invalid phone number format.");
  }

  let orderId = null;
  let order = null;

  if (reference) {
    const direct = await db.ref(`orders/${reference}`).once("value");
    if (direct.exists()) {
      orderId = reference;
      order = direct.val();
    }

    const refSearches = ["paystackReference", "hubnetReference", "fulfillmentReference"];
    for (const field of refSearches) {
      if (order) break;
      const snap = await db.ref("orders")
        .orderByChild(field)
        .equalTo(reference)
        .limitToFirst(1)
        .once("value");
      snap.forEach((child) => {
        if (!orderId) {
          orderId = child.key;
          order = child.val();
        }
      });
    }
  }

  if (!order && phone) {
    const byPhone = await db.ref("orders")
      .orderByChild("beneficiaryPhone")
      .equalTo(phone)
      .limitToFirst(1)
      .once("value");
    byPhone.forEach((child) => {
      if (!orderId) {
        orderId = child.key;
        order = child.val();
      }
    });
  }

  // Local match exists but non-MTN/AT: behave as not found per requirement.
  if (order && !isMtnOrAtOrder(order)) {
    order = null;
    orderId = null;
  }

  // Local-first: if missing locally and reference provided, query Hubnet live.
  if (!order && reference) {
    let liveOrder = null;
    try {
      liveOrder = await fetchHubnetLiveOrderByReference(reference);
    } catch (_error) {
      throw httpError(502, "Unable to query Hubnet live order status right now.");
    }
    if (liveOrder) {
      sendJson(res, 200, liveOrder);
      return;
    }
  }

  if (!order) {
    throw httpError(404, "Order not found for MTN/AT.");
  }

  const networkCode = getOrderNetworkCode(order);
  if (!isMtnOrAtNetwork(networkCode)) {
    throw httpError(404, "Order not found for MTN/AT.");
  }

  const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase() || "queued";
  const paymentStatus = sanitizeString(order.paymentStatus, 40).toLowerCase() || "pending";
  const status = sanitizeString(order.status, 40).toLowerCase()
    || deriveOrderStatusFromStates({ fulfillmentStatus, paymentStatus });

  sendJson(res, 200, {
    id: orderId,
    reference: order.paystackReference || order.hubnetReference || order.fulfillmentReference || orderId,
    status,
    paymentStatus,
    fulfillmentStatus,
    amount: Number(order.amount || 0),
    currency: "GHS",
    storeName: sanitizeString(order.storeName, 120) || "",
    packageName: sanitizeString(order.packageName || order.package, 120) || "",
    network: networkCode.toUpperCase(),
    volume: sanitizeString(order.packageVolume || order.volume, 20) || null,
    phone: order.maskedPhone || maskPhone(order.beneficiaryPhone || ""),
    email: order.maskedEmail || maskEmail(order.email || ""),
    createdAt: order.createdAt || null,
    updatedAt: order.updatedAt || null,
  });
}));

// Public: Initialize payment
app.post("/api/public/payments/initialize", paymentInitRateLimit, asyncHandler(async (req, res) => {
  if (!paystack) {
    throw httpError(503, "Paystack is not configured yet. Add the secret keys.");
  }

  const slug = normalizeSlug(req.body.slug);
  const packageId = sanitizeString(req.body.packageId, 80);
  const email = normalizeEmail(req.body.email);
  const beneficiaryPhone = normalizePhone(req.body.beneficiaryPhone);

  if (!isValidSlug(slug) || !packageId || !email || !isLikelyEmail(email) || !beneficiaryPhone) {
    throw httpError(400, "Missing or invalid payment fields.");
  }

  const storeSnapshot = await db.ref("storefronts").orderByChild("slug").equalTo(slug).once("value");

  let store = null;
  let storeId = null;
  storeSnapshot.forEach((child) => {
    store = child.val();
    storeId = child.key;
  });

  if (!store) {
    throw httpError(404, "Store not found.");
  }

  const selectedPackage = (await getPublicStorePackages(store)).find((pkg) => pkg.id === packageId);

  if (!selectedPackage) {
    throw httpError(404, "Package not found.");
  }

  const baseAmount = toPrice(selectedPackage.basePrice);
  const sellingAmount = toPrice(selectedPackage.sellingPrice);
  const profitAmount = baseAmount && sellingAmount
    ? Number((sellingAmount - baseAmount).toFixed(2))
    : null;

  if (!baseAmount || !sellingAmount || !Number.isFinite(profitAmount) || profitAmount <= 0) {
    throw httpError(400, "This package pricing is no longer valid. Please contact the store owner to refresh the storefront.");
  }

  // If Hubnet fulfillment is enabled, packages must include fulfillment metadata.
  if (hubnet && (!selectedPackage.network || !selectedPackage.volume)) {
    throw httpError(400, "This package is missing network/volume configuration. Please contact the store owner.");
  }

  const reference = `ASKMEDIA-${Date.now()}-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const sessionRef = db.ref(`paymentSessions/${reference}`);
  const callbackUrl = new URL("/paystack/callback", getRequestOrigin(req));
  callbackUrl.searchParams.set("store", slug);

  const sessionPayload = {
    paystackReference: reference,
    storeId,
    ownerId: sanitizeString(store.ownerId, 128),
    slug,
    storeName: sanitizeString(store.name, 120),
    packageId: selectedPackage.id,
    catalogPackageId: selectedPackage.catalogPackageId || null,
    packageName: selectedPackage.name,
    packageNetwork: selectedPackage.network || null,
    packageVolume: selectedPackage.volume || null,
    email,
    maskedEmail: maskEmail(email),
    beneficiaryPhone,
    amount: sellingAmount,
    baseAmount,
    profitAmount,
    paymentStatus: "initialized",
    fulfillmentStatus: "pending",
    fulfillmentProvider: selectedPackage.network ? "hubnet" : (fulfillment ? "fulfillment-api" : null),
    webhookReceived: false,
    callbackVisited: false,
    createdAt: getCurrentTimestamp(),
    updatedAt: getCurrentTimestamp(),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  };

  await sessionRef.set(sessionPayload);
  
  console.log(`[Payment] Init ref=${reference} slug=${slug} amountGHS=${sellingAmount.toFixed(2)}`);
  
  await auditLog("payment", "initialize-requested", {
    requestId: req.requestId,
    reference,
    storeSlug: slug,
    ownerId: sessionPayload.ownerId,
    storeId,
    packageId: selectedPackage.id,
    amount: sellingAmount,
    baseAmount,
    profitAmount,
    email,
    beneficiaryPhone,
    callbackUrl: callbackUrl.toString(),
  });

  try {
    debugLog(`[Paystack] Initializing transaction for ${reference}`);
    const paystackResponse = await paystack.initializeTransaction({
      email,
      amount: sellingAmount,
      reference,
      callbackUrl: callbackUrl.toString(),
      metadata: {
        slug,
        storeId,
        packageId: selectedPackage.id,
        catalogPackageId: selectedPackage.catalogPackageId || null,
        packageName: selectedPackage.name,
        packageNetwork: selectedPackage.network || null,
        packageVolume: selectedPackage.volume || null,
        baseAmount,
        profitAmount,
        beneficiaryPhone,
      },
    });

    const authorizationUrl = paystackResponse?.data?.authorization_url;
    if (!authorizationUrl) {
      throw new Error("Paystack did not return an authorization URL.");
    }

    console.log(`[Paystack] Initialized ref=${reference}`);
    debugLog(`[Paystack] authorization_url=${authorizationUrl}`);

    await sessionRef.update({
      paymentProvider: "paystack",
      paystackAccessCode: sanitizeString(paystackResponse?.data?.access_code, 120) || null,
      updatedAt: getCurrentTimestamp(),
    });
    await auditLog("payment", "initialize-succeeded", {
      requestId: req.requestId,
      reference,
      storeSlug: slug,
      amount: sellingAmount,
      baseAmount,
      profitAmount,
      redirectUrl: authorizationUrl,
    });

    sendJson(res, 200, {
      sessionId: reference,
      paystackReference: reference,
      amount: sellingAmount,
      baseAmount,
      profitAmount,
      authorizationUrl,
      redirectUrl: authorizationUrl,
    });
  } catch (error) {
    await sessionRef.update({
      paymentStatus: "failed",
      initializationError: sanitizeString(error.message, 500),
      updatedAt: getCurrentTimestamp(),
    });
    await auditLog("payment", "initialize-failed", {
      requestId: req.requestId,
      reference,
      storeSlug: slug,
      amount: sellingAmount,
      baseAmount,
      profitAmount,
      error: error.message,
    }, "error");

    throw httpError(502, "Unable to initialize the payment provider.");
  }
}));

// Public: Payment webhook (Paystack)
app.post(["/api/public/payments/webhook", "/paystack/webhook"], webhookRateLimit, asyncHandler(async (req, res) => {
  if (!paystack) {
    throw httpError(503, "Paystack secret key is missing.");
  }

  const signature = sanitizeString(req.get("x-paystack-signature"), 300);
  if (!signature) {
    await auditLog("payment", "paystack-webhook-missing-signature", {
      requestId: req.requestId,
      path: req.originalUrl,
    }, "warn");
    throw httpError(401, "Missing Paystack signature.");
  }

  const rawBody = Buffer.isBuffer(req.rawBody)
    ? req.rawBody.toString("utf8")
    : JSON.stringify(req.body || {});

  if (!paystack.verifyWebhookSignature(rawBody, signature)) {
    await auditLog("payment", "paystack-webhook-invalid-signature", {
      requestId: req.requestId,
      path: req.originalUrl,
    }, "warn");
    throw httpError(401, "Invalid Paystack signature.");
  }

  const eventName = sanitizeString(req.body?.event, 80);
  const reference = sanitizeString(req.body?.data?.reference, 120);
  const eventId = sanitizeString(`${eventName || "event"}-${req.body?.data?.id || reference || Date.now()}`, 120);

  await db.ref(`webhookEvents/${eventId}`).set({
    event: eventName,
    paystackReference: reference || null,
    payload: req.body,
    receivedAt: getCurrentTimestamp(),
  });
  await auditLog("payment", "paystack-webhook-received", {
    requestId: req.requestId,
    eventName,
    reference,
    eventId,
  });

  if (eventName !== "charge.success" || !reference) {
    sendJson(res, 200, { received: true });
    return;
  }

  const verification = await paystack.verifyTransaction(reference);
  if (verification?.data?.status !== "success") {
    throw httpError(400, "Paystack verification did not return a successful payment.");
  }

  // Ensure the payment session exists before processing (mirrors the verify route logic).
  // Paystack webhooks can arrive before or after the browser callback depending on network.
  const webhookSessionSnapshot = await db.ref(`paymentSessions/${reference}`).once("value");
  if (!webhookSessionSnapshot.exists()) {
    try {
      await recoverSessionFromPaystack(reference, verification.data);
    } catch (recoveryError) {
      await auditLog("payment", "webhook-session-recovery-failed", {
        requestId: req.requestId,
        eventName,
        reference,
        error: sanitizeString(recoveryError?.message, 200),
      }, "warn");
      // Still proceed Ã¢â‚¬â€ processSuccessfulPayment will attempt its own recovery.
    }
  }

  await processSuccessfulPayment(reference, verification.data, eventName);
  await auditLog("payment", "paystack-webhook-processed", {
    requestId: req.requestId,
    eventName,
    reference,
  });
  sendJson(res, 200, { received: true });
}));

// Public: Hubnet fulfillment webhook (order status updates from Hubnet)
app.post([DELIVERY_WEBHOOK_PATH, LEGACY_DELIVERY_WEBHOOK_PATH, "/hubnet/webhook"], webhookRateLimit, asyncHandler(async (req, res) => {
  if (hasHubnetWebhookSecret) {
    const secret = sanitizeString(req.query?.secret, 200) || sanitizeString(req.get("x-hubnet-secret"), 200);
    if (!secret || secret !== HUBNET_WEBHOOK_SECRET) {
      await auditLog("hubnet", "webhook-invalid-secret", {
        requestId: req.requestId,
        path: req.originalUrl,
      }, "warn");
      throw httpError(401, "Invalid Hubnet webhook secret.");
    }
  }

  const eventName = sanitizeString(req.body?.event, 80);
  const hubnetReference = sanitizeString(req.body?.reference, 120) || sanitizeString(req.body?.data?.reference, 120);

  const rawBody = Buffer.isBuffer(req.rawBody)
    ? req.rawBody.toString("utf8")
    : JSON.stringify(req.body || {});

  const eventHash = crypto.createHash("sha256").update(rawBody).digest("hex").slice(0, 16);
  const eventId = sanitizeString(`hubnet-${hubnetReference || "unknown"}-${eventHash}`, 120);

  const eventTx = await db.ref(`webhookEvents/${eventId}`).transaction((current) => {
    if (current) {
      return; // already seen
    }
    return {
      event: eventName || null,
      hubnetReference: hubnetReference || null,
      payload: req.body,
      receivedAt: getCurrentTimestamp(),
    };
  });

  if (!eventTx.committed) {
    await auditLog("hubnet", "webhook-duplicate", {
      requestId: req.requestId,
      eventName,
      hubnetReference,
      eventId,
    }, "warn");
    debugLog(`[Hubnet webhook] Duplicate event: ${eventName} ref=${hubnetReference}`);
    sendJson(res, 200, { received: true, duplicate: true });
    return;
  }

  console.log(`[Hubnet webhook] Event=${eventName} ref=${hubnetReference || "-"} id=${eventId || "-"}`);

  if (!hubnetReference) {
    await auditLog("hubnet", "webhook-received", {
      requestId: req.requestId,
      eventName,
      hubnetReference: null,
      eventId,
    });
    sendJson(res, 200, { received: true });
    return;
  }

  let orderId = null;
  const mapSnapshot = await db.ref(`hubnetReferences/${hubnetReference}`).once("value");
  if (mapSnapshot.exists()) {
    orderId = sanitizeString(mapSnapshot.val()?.orderId, 120) || null;
  }

  if (!orderId) {
    const querySnapshot = await db.ref("orders")
      .orderByChild("hubnetReference")
      .equalTo(hubnetReference)
      .limitToFirst(1)
      .once("value");

    querySnapshot.forEach((child) => {
      if (!orderId) orderId = child.key;
    });
  }

  let ownerId = null;
  let storeId = null;
  let orderNetwork = "";
  if (orderId) {
    const orderSnap = await db.ref(`orders/${orderId}`).once("value");
    if (orderSnap.exists()) {
      const ov = orderSnap.val() || {};
      ownerId = sanitizeString(ov.ownerId, 120) || null;
      storeId = sanitizeString(ov.storeId, 120) || null;
      orderNetwork = getOrderNetworkCode(ov);
    }
  }

  if (!orderNetwork) {
    orderNetwork = normalizeTrackedOrderNetwork(
      req.body?.data?.network
      || req.body?.network
    );
  }

  await auditLog("hubnet", "webhook-received", {
    requestId: req.requestId,
    eventName,
    hubnetReference,
    eventId,
    orderId,
    ownerId,
    storeId,
  });

  if (!orderId) {
    await auditLog("hubnet", "webhook-unmatched", {
      requestId: req.requestId,
      eventName,
      hubnetReference,
    }, "warn");
    sendJson(res, 200, { received: true, matched: false });
    return;
  }

  if (!isMtnOrAtNetwork(orderNetwork)) {
    await auditLog("hubnet", "webhook-ignored-network", {
      requestId: req.requestId,
      eventName,
      hubnetReference,
      orderId,
      ownerId,
      storeId,
      orderNetwork: orderNetwork || null,
    }, "warn");
    sendJson(res, 200, {
      received: true,
      matched: true,
      ignored: true,
      reason: "network_not_supported",
    });
    return;
  }

  const incomingFulfillmentStatus = mapHubnetWebhookToFulfillmentStatus(eventName, req.body);

  const now = getCurrentTimestamp();
  const orderRef = db.ref(`orders/${orderId}`);
  const sessionRef = db.ref(`paymentSessions/${orderId}`);

  let appliedFulfillmentStatus = incomingFulfillmentStatus;
  let appliedOverallStatus = incomingFulfillmentStatus === "delivered"
    ? "fulfilled"
    : incomingFulfillmentStatus === "failed"
      ? "paid"
      : "processing";
  let frozenAtDelivered = false;

  await orderRef.transaction((current) => {
    if (!current) return;

    const currentFulfillmentStatus = sanitizeString(current.fulfillmentStatus, 40).toLowerCase();
    const currentIsDelivered = isDeliveredFulfillmentStatus(currentFulfillmentStatus);
    const shouldFreeze = currentIsDelivered && incomingFulfillmentStatus !== "delivered";

    const nextFulfillmentStatus = shouldFreeze
      ? (currentFulfillmentStatus || "delivered")
      : incomingFulfillmentStatus;
    const nextOverallStatus = isDeliveredFulfillmentStatus(nextFulfillmentStatus)
      ? "fulfilled"
      : nextFulfillmentStatus === "failed"
        ? "paid"
        : "processing";

    appliedFulfillmentStatus = nextFulfillmentStatus;
    appliedOverallStatus = nextOverallStatus;
    frozenAtDelivered = shouldFreeze;

    return {
      ...current,
      fulfillmentProvider: "hubnet",
      fulfillmentStatus: nextFulfillmentStatus,
      status: nextOverallStatus,
      countsAsOrder: isDeliveredFulfillmentStatus(nextFulfillmentStatus),
      orderInvalidReason: nextFulfillmentStatus === "failed" ? "bundle_delivery_failed" : null,
      hubnetLastEvent: eventName || null,
      hubnetLastWebhookAt: now,
      statusHistory: shouldFreeze
        ? (Array.isArray(current.statusHistory) ? current.statusHistory : [])
        : appendStatusHistory(current.statusHistory, {
            status: nextFulfillmentStatus,
            source: "hubnet-webhook",
            at: now,
            event: eventName || null,
          }),
      updatedAt: now,
    };
  });

  try {
    await sessionRef.update({
      fulfillmentProvider: "hubnet",
      fulfillmentStatus: appliedFulfillmentStatus,
      status: appliedOverallStatus,
      updatedAt: now,
    });
  } catch (_err) {
    // Session may be missing (expired/cleaned). Order is source-of-truth.
  }

  await auditLog("hubnet", "webhook-processed", {
    requestId: req.requestId,
    eventName,
    hubnetReference,
    orderId,
    ownerId,
    storeId,
    fulfillmentStatus: appliedFulfillmentStatus,
    frozenAtDelivered,
  });

  sendJson(res, 200, {
    received: true,
    matched: true,
    frozenAtDelivered,
  });
}));

// Public: Get payment status
app.get("/api/public/payments/:reference", publicApiRateLimit, asyncHandler(async (req, res) => {
  const reference = sanitizeString(req.params.reference, 120);
  if (!reference) {
    throw httpError(400, "Payment reference is required.");
  }

  const [sessionSnapshot, orderSnapshot] = await Promise.all([
    db.ref(`paymentSessions/${reference}`).once("value"),
    db.ref(`orders/${reference}`).once("value"),
  ]);

  if (!sessionSnapshot.exists()) {
    throw httpError(404, "Payment session not found.");
  }

  await db.ref(`paymentSessions/${reference}`).update({
    callbackVisited: true,
    updatedAt: getCurrentTimestamp(),
  });

  const session = sessionSnapshot.val();
  const order = orderSnapshot.exists() ? orderSnapshot.val() : null;

  sendJson(res, 200, {
    reference,
    storeSlug: session.slug,
    email: session.maskedEmail || maskEmail(session.email),
    package: session.packageName,
    amount: session.amount,
    paymentStatus: order?.paymentStatus || session.paymentStatus,
    fulfillmentReference: order?.fulfillmentReference || session.fulfillmentReference || null,
    fulfillmentStatus: order?.fulfillmentStatus || session.fulfillmentStatus || null,
  });
}));

// Public: Manually verify payment with Paystack (recovery endpoint for missed webhooks)
// Call this from the callback page if paymentStatus is still "pending" after returning from Paystack.
app.post("/api/public/payments/verify/:reference", publicApiRateLimit, asyncHandler(async (req, res) => {
  if (!paystack) {
    throw httpError(503, "Paystack is not configured.");
  }

  const reference = sanitizeString(req.params.reference, 120);
  if (!reference) {
    throw httpError(400, "Payment reference is required.");
  }

  let verification;
  try {
    verification = await paystack.verifyTransaction(reference);
  } catch (_error) {
    throw httpError(502, "Unable to reach Paystack for verification.");
  }

  const paystackStatus = verification?.data?.status;
  if (paystackStatus !== "success") {
    const sessionSnapshot = await db.ref(`paymentSessions/${reference}`).once("value");
    const session = sessionSnapshot.exists() ? sessionSnapshot.val() : null;
    if (session) {
      await db.ref(`paymentSessions/${reference}`).update({
        paymentStatus: paystackStatus === "failed" ? "failed" : session.paymentStatus,
        lastVerifiedAt: getCurrentTimestamp(),
        updatedAt: getCurrentTimestamp(),
      });
    }

    sendJson(res, 200, {
      reference,
      storeSlug: session?.slug || null,
      paymentStatus: session?.paymentStatus || "pending",
      paystackStatus: paystackStatus || "unknown",
      verified: false,
      message: "Payment has not been completed on Paystack yet.",
    });
    return;
  }

  let sessionSnapshot = await db.ref(`paymentSessions/${reference}`).once("value");
  if (!sessionSnapshot.exists()) {
    try {
      await recoverSessionFromPaystack(reference, verification.data);
    } catch (recoveryError) {
      // Log the real reason but surface a clear 404 to the client.
      await auditLog("payment", "verify-session-recovery-failed", {
        requestId: req.requestId,
        reference,
        error: sanitizeString(recoveryError?.message, 200),
      }, "error");
      throw httpError(404, recoveryError?.message || "Payment session not found and could not be recovered.");
    }
    sessionSnapshot = await db.ref(`paymentSessions/${reference}`).once("value");
  }

  if (!sessionSnapshot.exists()) {
    throw httpError(404, "Payment session not found.");
  }

  const session = sessionSnapshot.val();
  const existingOrderSnapshot = await db.ref(`orders/${reference}`).once("value");
  const existingOrder = existingOrderSnapshot.exists() ? existingOrderSnapshot.val() : null;
  if (session.paymentStatus === "paid" && !requiresPaymentRepair(session, existingOrder)) {
    sendJson(res, 200, {
      reference,
      storeSlug: session.slug,
      paymentStatus: "paid",
      fulfillmentStatus: existingOrder?.fulfillmentStatus || session.fulfillmentStatus || "queued",
      alreadyProcessed: true,
    });
    return;
  }

  await processSuccessfulPayment(reference, verification.data, "manual-verify");

  const [freshSessionSnapshot, freshOrderSnapshot] = await Promise.all([
    db.ref(`paymentSessions/${reference}`).once("value"),
    db.ref(`orders/${reference}`).once("value"),
  ]);

  const freshSession = freshSessionSnapshot.exists() ? freshSessionSnapshot.val() : session;
  const freshOrder = freshOrderSnapshot.exists() ? freshOrderSnapshot.val() : null;

  sendJson(res, 200, {
    reference,
    storeSlug: freshSession.slug,
    paymentStatus: freshSession.paymentStatus || "paid",
    fulfillmentStatus: freshOrder?.fulfillmentStatus || freshSession.fulfillmentStatus || "queued",
    verified: true,
    repaired: requiresPaymentRepair(session, existingOrder),
    message: "Payment verified and order synchronized successfully.",
  });
}));

// Owner: Get user profile
app.get("/api/owner/me", verifyAuth, asyncHandler(async (req, res) => {
  const bootstrap = await ensureOwnerBootstrap(req.user);
  sendJson(res, 200, bootstrap.user);
}));

// Generic user endpoint (alias for /api/owner/me)
app.get("/api/user/me", verifyAuth, asyncHandler(async (req, res) => {
  const bootstrap = await ensureOwnerBootstrap(req.user);
  sendJson(res, 200, bootstrap.user);
}));

// Owner: Update user profile
app.put("/api/owner/me", verifyAuth, asyncHandler(async (req, res) => {
  const name = sanitizeString(req.body.name, 120);
  const phone = normalizePhone(req.body.phone);
  const email = normalizeEmail(req.body.email) || req.user.email;

  if (email && !isLikelyEmail(email)) {
    throw httpError(400, "Email address is invalid.");
  }

  if (!name && !phone && !email) {
    throw httpError(400, "At least one profile field is required.");
  }

  await ensureOwnerBootstrap({
    uid: req.user.uid,
    email,
    name,
    phone,
  });

  await db.ref(`users/${req.user.uid}`).update({
    email,
    name: name || undefined,
    phone: phone || "",
    updatedAt: getCurrentTimestamp(),
    lastLogin: getCurrentTimestamp(),
  });

  const snapshot = await db.ref(`users/${req.user.uid}`).once("value");
  sendJson(res, 200, { id: req.user.uid, ...snapshot.val() });
}));

// Owner: Get store
app.get("/api/owner/store", verifyAuth, asyncHandler(async (req, res) => {
  await ensureOwnerBootstrap(req.user);
  const [store, walletSnapshot] = await Promise.all([
    getOwnerStore(req.user.uid),
    db.ref(`wallet/${req.user.uid}`).once("value"),
  ]);
  const wallet = walletSnapshot.val() || {
    balance: 0,
    totalEarned: 0,
    totalProfit: 0,
    totalDeposits: 0,
    totalDebits: 0,
    totalOrders: 0,
    currency: "GHS",
  };

  if (!store) {
    sendJson(res, 200, {
      id: null,
      ownerId: req.user.uid,
      name: "",
      slug: "",
      theme: "light",
      supportPhone: "",
      supportWhatsapp: "",
      supportEmail: "",
      packages: [],
      published: false,
      createdAt: null,
      updatedAt: null,
      wallet,
    });
    return;
  }

  const resolvedPackages = await resolveStorePackages(store.packages, { includeUnavailable: true });
  sendJson(res, 200, {
    ...store,
    packages: resolvedPackages,
    wallet,
  });
}));

// Owner: Get admin-managed package catalog
app.get("/api/owner/catalog/packages", verifyAuth, asyncHandler(async (req, res) => {
  await ensureOwnerBootstrap(req.user);
  const packages = await listCatalogPackages({ includeInactive: false });
  sendJson(res, 200, {
    packages,
    total: packages.length,
  });
}));

// Owner: Update store
app.put("/api/owner/store", verifyAuth, asyncHandler(async (req, res) => {
  await ensureOwnerBootstrap(req.user);
  const existingStore = await getOwnerStore(req.user.uid);
  const creating = !existingStore;
  const storeId = existingStore?.id || db.ref("storefronts").push().key;
  const storeRef = db.ref(`storefronts/${storeId}`);
  const updateData = {
    updatedAt: getCurrentTimestamp(),
  };

  const name = req.body.name !== undefined ? sanitizeString(req.body.name, 120) : "";
  if (req.body.name !== undefined || creating) {
    if (!name) {
      throw httpError(400, "Store name is required.");
    }
    updateData.name = name;
  }

  if (req.body.slug !== undefined || creating) {
    const slug = normalizeSlug(req.body.slug || "");
    if (!isValidSlug(slug)) {
      throw httpError(400, "Store slug must be 3-50 characters and use only letters, numbers, or hyphens.");
    }

    const existing = await db.ref("storefronts").orderByChild("slug").equalTo(slug).once("value");
    if (existing.exists()) {
      let slugTaken = false;
      existing.forEach((child) => {
        if (child.key !== storeId) {
          slugTaken = true;
        }
      });
      if (slugTaken) {
        throw httpError(400, "Slug already taken.");
      }
    }

    updateData.slug = slug;
  }

  if (req.body.theme !== undefined) {
    const theme = sanitizeString(req.body.theme, 20).toLowerCase();
    updateData.theme = ["light", "dark", "vibrant"].includes(theme) ? theme : "light";
  } else if (creating) {
    updateData.theme = "light";
  }

  if (req.body.supportPhone !== undefined) {
    updateData.supportPhone = normalizePhone(req.body.supportPhone);
  } else if (creating) {
    updateData.supportPhone = "";
  }

  if (req.body.supportWhatsapp !== undefined) {
    updateData.supportWhatsapp = normalizePhone(req.body.supportWhatsapp);
  } else if (creating) {
    updateData.supportWhatsapp = "";
  }

  if (req.body.supportEmail !== undefined) {
    const supportEmail = normalizeEmail(req.body.supportEmail);
    if (supportEmail && !isLikelyEmail(supportEmail)) {
      throw httpError(400, "Support email is invalid.");
    }
    updateData.supportEmail = supportEmail;
  } else if (creating) {
    updateData.supportEmail = normalizeEmail(req.user.email || "");
  }

  if (req.body.logo !== undefined) {
    updateData.logo = sanitizeString(req.body.logo, 400) || null;
  } else if (creating) {
    updateData.logo = null;
  }

  const packages = await sanitizePackages(req.body.packages);
  if (packages !== undefined) {
    updateData.packages = packages;
  } else if (creating) {
    updateData.packages = [];
  }

  if (req.body.published !== undefined) {
    const published = Boolean(req.body.published);
    updateData.published = published;
    updateData.publishedAt = published ? getCurrentTimestamp() : null;
  } else if (creating) {
    updateData.published = false;
    updateData.publishedAt = null;
  }

  if (creating) {
    updateData.ownerId = req.user.uid;
    updateData.createdAt = getCurrentTimestamp();
    updateData.metrics = {
      totalOrders: 0,
      totalRevenue: 0,
      totalProfit: 0,
    };
  }

  await storeRef.update(updateData);
  const snapshot = await storeRef.once("value");
  sendJson(res, 200, { id: storeId, ...snapshot.val() });
}));

// Owner: Publish/unpublish store
app.post("/api/owner/store/publish", verifyAuth, asyncHandler(async (req, res) => {
  await ensureOwnerBootstrap(req.user);
  const store = await requireOwnerStore(req.user.uid);
  const published = Boolean(req.body.published);

  await db.ref(`storefronts/${store.id}`).update({
    published,
    publishedAt: published ? getCurrentTimestamp() : null,
    updatedAt: getCurrentTimestamp(),
  });

  sendJson(res, 200, { success: true, published });
}));

// Owner: Delete storefront (manual action from configuration page)
app.delete("/api/owner/store", verifyAuth, asyncHandler(async (req, res) => {
  await ensureOwnerBootstrap(req.user);
  const store = await getOwnerStore(req.user.uid);
  if (!store) {
    sendJson(res, 200, { success: true, deleted: false });
    return;
  }

  await db.ref(`storefronts/${store.id}`).remove();
  sendJson(res, 200, { success: true, deleted: true, storeId: store.id });
}));

// Owner: Get orders
app.get("/api/owner/orders", verifyAuth, asyncHandler(async (req, res) => {
  const bootstrap = await ensureOwnerBootstrap(req.user);
  if (!bootstrap.store?.id) {
    sendJson(res, 200, { orders: [], total: 0 });
    return;
  }

  const limit = clampInteger(req.query.limit, 1, 100, 50);
  const search = sanitizeString(req.query.search, 120).toLowerCase();
  const status = sanitizeString(req.query.status, 40).toLowerCase();

  const scanLimit = Math.min(Math.max(limit * (search || status ? 8 : 4), limit), 1000);
  const snapshot = await db.ref("orders")
    .orderByChild("storeId")
    .equalTo(bootstrap.store.id)
    .limitToLast(scanLimit)
    .once("value");

  let orders = [];
  snapshot.forEach((child) => {
    orders.push({ id: child.key, ...child.val() });
  });

  // Backward-compatible shaping for older orders.
  orders = orders.map((order) => {
    const paymentStatus = sanitizeString(order.paymentStatus, 40).toLowerCase() || "pending";
    const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase() || "queued";
    const derivedStatus = sanitizeString(order.status, 40).toLowerCase()
      || ((fulfillmentStatus === "delivered" || fulfillmentStatus === "fulfilled")
        ? "fulfilled"
        : paymentStatus === "paid"
          ? ((fulfillmentStatus === "processing" || fulfillmentStatus === "queued") ? "processing" : "paid")
          : paymentStatus);

    return {
      ...order,
      status: derivedStatus,
      storeName: order.storeName || bootstrap.store.name || "",
      packageName: order.packageName || order.package || "",
      customerInfo: order.customerInfo || {
        name: null,
        email: order.email || null,
        phone: order.beneficiaryPhone || null,
      },
    };
  });

  // Sort by createdAt descending
  orders.sort((a, b) => {
    const dateA = new Date(a.createdAt).getTime();
    const dateB = new Date(b.createdAt).getTime();
    return dateB - dateA;
  });

  if (search) {
    orders = orders.filter((order) => {
      const haystack = [order.email, order.beneficiaryPhone, order.fulfillmentReference, order.paystackReference]
        .filter(Boolean).join(' ').toLowerCase();
      return haystack.includes(search);
    });
  }

  if (status) {
    orders = orders.filter((order) =>
      String(order.paymentStatus || '').toLowerCase() === status ||
      String(order.fulfillmentStatus || '').toLowerCase() === status
    );
  }

  sendJson(res, 200, { orders: orders.slice(0, limit), total: orders.length });
}));

// Owner: Fulfillment / payment pipeline (audit trail for dashboard)
app.get("/api/owner/pipeline-activity", verifyAuth, asyncHandler(async (req, res) => {
  const rawLimit = parseInt(String(req.query.limit || "100"), 10);
  const limit = Math.min(Math.max(Number.isFinite(rawLimit) ? rawLimit : 100, 1), 250);
  const scopeOnly = sanitizeString(req.query.scope, 40);
  const includeAll = String(req.query.all || "").toLowerCase() === "1" || String(req.query.all || "").toLowerCase() === "true";

  const snapshot = await db.ref("auditLogs")
    .orderByChild("ownerId")
    .equalTo(req.user.uid)
    .limitToLast(Math.min(limit * 4, 500))
    .once("value");

  const rows = [];
  snapshot.forEach((child) => {
    rows.push({ id: child.key, ...child.val() });
  });

  rows.sort((a, b) => String(b.createdAt || "").localeCompare(String(a.createdAt || "")));

  let filtered = rows;
  if (scopeOnly) {
    filtered = rows.filter((r) => sanitizeString(r.scope, 80) === scopeOnly);
  } else if (!includeAll) {
    filtered = rows.filter((r) => {
      const s = sanitizeString(r.scope, 80);
      return s === "hubnet" || s === "payment";
    });
  }

  sendJson(res, 200, { entries: filtered.slice(0, limit), total: Math.min(filtered.length, limit) });
}));

// Owner: Get single order
app.get('/api/owner/orders/:orderId', verifyAuth, asyncHandler(async (req, res) => {
  await ensureOwnerBootstrap(req.user);
  const store = await requireOwnerStore(req.user.uid);
  const orderId = sanitizeString(req.params.orderId, 120);
  const snapshot = await db.ref('orders/' + orderId).once('value');
  if (!snapshot.exists() || snapshot.val().storeId !== store.id) {
    throw httpError(404, 'Order not found.');
  }
  sendJson(res, 200, { id: orderId, ...snapshot.val() });
}));

// Owner: Retry Hubnet fulfillment for a failed/stuck order
app.post('/api/owner/orders/:orderId/retry-fulfillment', verifyAuth, asyncHandler(async (req, res) => {
  if (!hubnet) throw httpError(503, 'Bundle delivery is not configured.');
  await ensureOwnerBootstrap(req.user);
  const store = await requireOwnerStore(req.user.uid);
  const orderId = sanitizeString(req.params.orderId, 120);
  const snapshot = await db.ref('orders/' + orderId).once('value');
  if (!snapshot.exists() || snapshot.val().storeId !== store.id) throw httpError(404, 'Order not found.');
  const order = snapshot.val();
  const paymentStatus = sanitizeString(order.paymentStatus, 40).toLowerCase();
  const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase();
  if (paymentStatus !== 'paid') throw httpError(400, 'Cannot retry: payment not confirmed.');
  if (['delivered', 'fulfilled'].includes(fulfillmentStatus)) throw httpError(409, 'Bundle already delivered.');
  if (fulfillmentStatus === 'processing' && order.hubnetInitAt && !isStaleTimestamp(order.hubnetInitAt)) {
    throw httpError(409, 'Fulfillment in progress. Try again in a few minutes.');
  }
  if (!order.packageNetwork || !order.packageVolume) throw httpError(400, 'Order missing network/volume.');
  await auditLog('hubnet', 'fulfillment-manual-retry', {
    orderId,
    ownerId: order.ownerId,
    storeId: order.storeId,
    requestedBy: req.user.uid,
    currentFulfillmentStatus: fulfillmentStatus,
  });
  const result = await attemptHubnetFulfillment(orderId);
  const freshSnapshot = await db.ref('orders/' + orderId).once('value');
  const freshOrder = freshSnapshot.exists() ? freshSnapshot.val() : order;
  sendJson(res, 200, {
    orderId, retryResult: result,
    fulfillmentStatus: freshOrder.fulfillmentStatus || 'processing',
    hubnetTransactionId: freshOrder.hubnetTransactionId || null,
    message: result.attempted
      ? (result.hubnetTransactionId ? 'Bundle delivery initiated.' : 'Retry: ' + (result.reason || result.error || 'unknown'))
      : 'Skipped: ' + (result.reason || 'unknown'),
  });
}));

// Owner: Get wallet balance
app.get('/api/owner/wallet', verifyAuth, asyncHandler(async (req, res) => {
  const walletSnapshot = await db.ref('wallet/' + req.user.uid).once('value');
  const wallet = walletSnapshot.val() || { balance: 0, totalEarned: 0, totalProfit: 0, totalDeposits: 0, totalDebits: 0, totalOrders: 0, currency: 'GHS' };
  sendJson(res, 200, {
    balance: Number(wallet.balance) || 0,
    totalEarned: Number(wallet.totalEarned) || 0,
    totalProfit: Number(wallet.totalProfit) || Number(wallet.totalEarned) || 0,
    totalDeposits: Number(wallet.totalDeposits) || 0,
    totalDebits: Number(wallet.totalDebits) || 0,
    totalOrders: Number(wallet.totalOrders) || 0,
    currency: wallet.currency || 'GHS',
    lastCreditAt: wallet.lastCreditAt || null,
    lastDebitAt: wallet.lastDebitAt || null,
  });
}));

app.post("/api/owner/wallet/withdrawals", verifyAuth, asyncHandler(async (req, res) => {
  const ownerId = sanitizeString(req.user.uid, 128);
  const network = normalizeWithdrawalNetwork(req.body.network);
  const accountName = sanitizeString(req.body.accountName, 120);
  const amount = toPrice(req.body.amount);
  const mobileNumber = toGhanaNationalPhone(req.body.mobileNumber || req.body.phone);

  if (!network) {
    throw httpError(400, "Select a valid network: MTN, AT, or Telecel.");
  }
  if (!accountName) {
    throw httpError(400, "Account name is required.");
  }
  if (!mobileNumber) {
    throw httpError(400, "Enter a valid Ghana mobile money number.");
  }
  if (!amount || amount <= 0) {
    throw httpError(400, "Withdrawal amount must be greater than zero.");
  }

  const wallet = await recalculateOwnerWallet(ownerId);
  const balance = Number(wallet?.balance || 0);
  if (amount > balance) {
    throw httpError(400, "Withdrawal amount cannot exceed your wallet balance.");
  }

  const now = getCurrentTimestamp();
  const requestRef = db.ref("walletWithdrawals").push();
  const withdrawalId = requestRef.key;
  const reference = `WDR-${String(withdrawalId || "").slice(-8).toUpperCase()}`;
  const payload = {
    id: withdrawalId,
    reference,
    ownerId,
    network,
    networkLabel: toWithdrawalNetworkLabel(network),
    mobileNumber,
    maskedMobileNumber: maskPhone(mobileNumber),
    accountName,
    amount,
    currency: "GHS",
    status: "pending",
    requestedBy: ownerId,
    availableBalanceAtRequest: Number(balance.toFixed(2)),
    createdAt: now,
    updatedAt: now,
  };

  await requestRef.set(payload);
  await auditLog("wallet", "withdrawal-requested", {
    ownerId,
    withdrawalId,
    reference,
    amount,
    network,
  });

  sendJson(res, 200, {
    success: true,
    withdrawal: payload,
    message: "Withdrawal request submitted. Admin approval is required before payout.",
  });
}));

app.get("/api/owner/wallet/withdrawals", verifyAuth, asyncHandler(async (req, res) => {
  const ownerId = sanitizeString(req.user.uid, 128);
  const limit = clampInteger(req.query.limit, 1, 100, 30);
  const snapshot = await db.ref("walletWithdrawals")
    .orderByChild("ownerId")
    .equalTo(ownerId)
    .limitToLast(limit)
    .once("value");

  const withdrawals = [];
  snapshot.forEach((child) => {
    withdrawals.unshift({ id: child.key, ...child.val() });
  });

  sendJson(res, 200, { withdrawals, total: withdrawals.length });
}));

// Owner: Get wallet transaction ledger
app.get("/api/owner/wallet/transactions", verifyAuth, asyncHandler(async (req, res) => {
  const limit = clampInteger(req.query.limit, 1, 100, 50);

  const snapshot = await db.ref(`walletTransactions/${req.user.uid}`)
    .orderByChild("createdAt")
    .limitToLast(limit)
    .once("value");

  const transactions = [];
  snapshot.forEach((child) => {
    transactions.unshift({ id: child.key, ...child.val() });
  });

  sendJson(res, 200, { transactions, total: transactions.length });
}));

// Owner: Initialize a wallet deposit via Paystack
app.post('/api/owner/wallet/deposit/initialize', verifyAuth, asyncHandler(async (req, res) => {
  if (!paystack) {
    throw httpError(503, 'Payment provider is not configured.');
  }

  const amount = toPrice(req.body.amount);
  if (!amount || amount < 1) {
    throw httpError(400, 'Amount must be at least GHS 1.00');
  }
  if (amount > 10000) {
    throw httpError(400, 'Amount cannot exceed GHS 10,000 per deposit');
  }

  const email = normalizeEmail(req.body.email || req.user.email || '');
  if (!isLikelyEmail(email)) {
    throw httpError(400, 'A valid email address is required for payment.');
  }

  const ownerId = sanitizeString(req.user.uid, 128);
  const reference = `WDEP-${ownerId.slice(0, 8).toUpperCase()}-${crypto.randomBytes(6).toString("hex").toUpperCase()}`;
  const callbackUrl = new URL("/app/balance", getRequestOrigin(req));
  callbackUrl.searchParams.set("deposit_ref", reference);
  callbackUrl.searchParams.set("deposit", "success");

  // Persist pending deposit record so webhook can credit the wallet
  const now = getCurrentTimestamp();
  await db.ref(`walletDeposits/${ownerId}/${reference}`).set({
    reference,
    ownerId,
    amount,
    email,
    status: 'initialized',
    type: 'deposit',
    currency: "GHS",
    expectedAmountKobo: Math.round(amount * 100),
    createdAt: now,
    updatedAt: now,
  });

  let paystackResult;
  try {
    paystackResult = await paystack.initializeTransaction({
      email,
      amount,
      reference,
      callbackUrl: callbackUrl.toString(),
      metadata: {
        custom_fields: [{ display_name: 'Purpose', variable_name: 'purpose', value: 'Wallet Deposit' }],
        ownerId,
        depositType: 'wallet',
        reference,
      },
    });
  } catch (err) {
    await db.ref(`walletDeposits/${ownerId}/${reference}`).update({
      status: "failed",
      failureReason: "paystack-initialize-failed",
      updatedAt: getCurrentTimestamp(),
    });
    throw httpError(502, 'Unable to initialize the payment provider.');
  }

  if (!paystackResult?.data?.authorization_url) {
    await db.ref(`walletDeposits/${ownerId}/${reference}`).update({
      status: "failed",
      failureReason: "missing-authorization-url",
      updatedAt: getCurrentTimestamp(),
    });
    throw httpError(502, 'Invalid response from payment provider.');
  }

  await db.ref(`walletDeposits/${ownerId}/${reference}`).update({
    status: "pending_payment",
    paystackAccessCode: sanitizeString(paystackResult?.data?.access_code, 120) || null,
    updatedAt: getCurrentTimestamp(),
  });

  sendJson(res, 200, {
    authorization_url: paystackResult.data.authorization_url,
    reference,
  });
}));

// Deposit endpoint alias for client compatibility
app.post('/api/wallet/deposit/initialize', verifyAuth, asyncHandler(async (req, res) => {
  // Forward to /api/owner/wallet/deposit/initialize
  // Simply call the handler directly
  if (!paystack) {
    throw httpError(503, 'Payment provider is not configured.');
  }

  const amount = toPrice(req.body.amount);
  if (!amount || amount < 1) {
    throw httpError(400, 'Amount must be at least GHS 1.00');
  }
  if (amount > 10000) {
    throw httpError(400, 'Amount cannot exceed GHS 10,000 per deposit');
  }

  const email = normalizeEmail(req.body.email || req.user.email || '');
  if (!isLikelyEmail(email)) {
    throw httpError(400, 'A valid email address is required for payment.');
  }

  const ownerId = sanitizeString(req.user.uid, 128);
  const reference = `WDEP-${ownerId.slice(0, 8).toUpperCase()}-${crypto.randomBytes(6).toString("hex").toUpperCase()}`;
  const callbackUrl = new URL("/app/balance", getRequestOrigin(req));
  callbackUrl.searchParams.set("deposit_ref", reference);
  callbackUrl.searchParams.set("deposit", "success");

  const now = getCurrentTimestamp();
  await db.ref(`walletDeposits/${ownerId}/${reference}`).set({
    reference,
    ownerId,
    amount,
    email,
    status: 'initialized',
    type: 'deposit',
    currency: "GHS",
    expectedAmountKobo: Math.round(amount * 100),
    createdAt: now,
    updatedAt: now,
  });

  let paystackResult;
  try {
    paystackResult = await paystack.initializeTransaction({
      email,
      amount,
      reference,
      callbackUrl: callbackUrl.toString(),
      metadata: {
        custom_fields: [{ display_name: 'Purpose', variable_name: 'purpose', value: 'Wallet Deposit' }],
        ownerId,
        depositType: 'wallet',
        reference,
      },
    });
  } catch (err) {
    await db.ref(`walletDeposits/${ownerId}/${reference}`).update({
      status: "failed",
      failureReason: "paystack-initialize-failed",
      updatedAt: getCurrentTimestamp(),
    });
    throw httpError(502, 'Unable to initialize the payment provider.');
  }

  if (!paystackResult?.data?.authorization_url) {
    await db.ref(`walletDeposits/${ownerId}/${reference}`).update({
      status: "failed",
      failureReason: "missing-authorization-url",
      updatedAt: getCurrentTimestamp(),
    });
    throw httpError(502, 'Invalid response from payment provider.');
  }

  await db.ref(`walletDeposits/${ownerId}/${reference}`).update({
    status: "pending_payment",
    paystackAccessCode: sanitizeString(paystackResult?.data?.access_code, 120) || null,
    updatedAt: getCurrentTimestamp(),
  });

  sendJson(res, 200, {
    authorization_url: paystackResult.data.authorization_url,
    reference,
  });
}));

// Owner: Verify a wallet deposit after Paystack redirects back to the app.
// This provides a secure, authenticated recovery path if the webhook arrives late.
app.post('/api/owner/wallet/deposits/:reference/verify', verifyAuth, asyncHandler(async (req, res) => {
  if (!paystack) {
    throw httpError(503, 'Payment provider is not configured.');
  }

  const ownerId = sanitizeString(req.user.uid, 128);
  const reference = sanitizeString(req.params.reference, 120);
  if (!reference || !reference.startsWith('WDEP-')) {
    throw httpError(400, 'Invalid deposit reference.');
  }

  const depositRef = db.ref(`walletDeposits/${ownerId}/${reference}`);
  const depositSnapshot = await depositRef.once('value');
  if (!depositSnapshot.exists()) {
    throw httpError(404, 'Deposit record not found.');
  }

  let deposit = depositSnapshot.val() || {};
  let paystackStatus = sanitizeString(deposit.paystackStatus, 40).toLowerCase() || null;

  if (deposit.status !== 'credited') {
    let verification;
    try {
      verification = await paystack.verifyTransaction(reference);
    } catch (_error) {
      throw httpError(502, 'Unable to verify the deposit with Paystack right now.');
    }

    const verificationData = verification?.data || {};
    const verificationOwnerId = sanitizeString(verificationData?.metadata?.ownerId, 128);
    const verificationCurrency = sanitizeString(verificationData?.currency, 12).toUpperCase() || "GHS";
    const paidAmountKobo = Math.round(Number(verificationData?.amount || 0));
    const expectedAmountKobo = Math.round(Number(deposit.amount || 0) * 100);

    if (verificationOwnerId && verificationOwnerId !== ownerId) {
      await depositRef.update({
        status: "failed",
        failureReason: "owner-mismatch",
        updatedAt: getCurrentTimestamp(),
      });
      throw httpError(403, "Deposit ownership verification failed.");
    }

    if (verificationCurrency !== "GHS") {
      await depositRef.update({
        status: "failed",
        failureReason: "currency-mismatch",
        updatedAt: getCurrentTimestamp(),
      });
      throw httpError(409, "Unexpected payment currency for this deposit.");
    }

    if (expectedAmountKobo > 0 && paidAmountKobo !== expectedAmountKobo) {
      await depositRef.update({
        status: "failed",
        failureReason: "amount-mismatch",
        expectedAmountKobo,
        paidAmountKobo,
        updatedAt: getCurrentTimestamp(),
      });
      throw httpError(409, "Payment amount mismatch for this deposit.");
    }

    paystackStatus = sanitizeString(verification?.data?.status, 40).toLowerCase() || null;
    await depositRef.update({
      paystackStatus,
      paidAmountKobo,
      lastVerifiedAt: getCurrentTimestamp(),
      updatedAt: getCurrentTimestamp(),
    });

    if (paystackStatus === 'success') {
      await processWalletDeposit(reference, verification.data, 'manual-verify');
    } else if (['failed', 'abandoned', 'reversed'].includes(paystackStatus)) {
      await depositRef.update({
        status: 'failed',
        failedAt: getCurrentTimestamp(),
        updatedAt: getCurrentTimestamp(),
      });
    }
  }

  const [freshDepositSnapshot, walletSnapshot] = await Promise.all([
    depositRef.once('value'),
    db.ref(`wallet/${ownerId}`).once('value'),
  ]);

  deposit = freshDepositSnapshot.val() || deposit;
  const wallet = walletSnapshot.val() || {
    balance: 0,
    totalEarned: 0,
    totalProfit: 0,
    totalDeposits: 0,
    totalDebits: 0,
    totalOrders: 0,
    currency: 'GHS',
    lastCreditAt: null,
    lastDebitAt: null,
  };

  sendJson(res, 200, {
    reference,
    status: sanitizeString(deposit.status, 40) || 'initialized',
    paystackStatus: paystackStatus || sanitizeString(deposit.paystackStatus, 40) || 'pending',
    amount: Number(deposit.amount) || 0,
    creditedAt: deposit.creditedAt || null,
    wallet: {
      balance: Number(wallet.balance) || 0,
      totalEarned: Number(wallet.totalEarned) || 0,
      totalProfit: Number(wallet.totalProfit) || Number(wallet.totalEarned) || 0,
      totalDeposits: Number(wallet.totalDeposits) || 0,
      totalDebits: Number(wallet.totalDebits) || 0,
      totalOrders: Number(wallet.totalOrders) || 0,
      currency: wallet.currency || 'GHS',
      lastCreditAt: wallet.lastCreditAt || null,
      lastDebitAt: wallet.lastDebitAt || null,
    },
  });
}));

// Paystack webhook: credit wallet on successful deposit
// NOTE: This is handled by the existing /paystack/webhook endpoint which already
// processes charge.success. We detect wallet deposits by the reference prefix 'WDEP-'
// and credit the wallet accordingly via the walletDeposits record.
// ============================================================================

// Admin: bootstrap the management console
app.get("/api/admin/bootstrap", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const payload = await buildAdminBootstrapPayload();
  sendJson(res, 200, payload);
}));

app.get("/api/admin/packages", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const includeInactive = String(req.query.includeInactive || "true").toLowerCase() !== "false";
  const packages = await listCatalogPackages({ includeInactive });
  sendJson(res, 200, { packages, total: packages.length });
}));

app.post("/api/admin/packages", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const payload = await validateAdminPackagePayload(req.body);
  const packageId = db.ref("catalogPackages").push().key;
  const now = getCurrentTimestamp();
  const record = {
    ...payload,
    id: packageId,
    createdAt: now,
    updatedAt: now,
  };

  await db.ref(`catalogPackages/${packageId}`).set(record);
  sendJson(res, 200, { id: packageId, ...record });
}));

app.put("/api/admin/packages/:packageId", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const packageId = sanitizeString(req.params.packageId, 120);
  if (!packageId) {
    throw httpError(400, "Package id is required.");
  }

  const snapshot = await db.ref(`catalogPackages/${packageId}`).once("value");
  if (!snapshot.exists()) {
    throw httpError(404, "Package not found.");
  }

  const existing = snapshot.val() || {};
  const payload = await validateAdminPackagePayload(req.body, packageId);
  const now = getCurrentTimestamp();
  const record = {
    ...existing,
    ...payload,
    id: packageId,
    updatedAt: now,
  };

  await db.ref(`catalogPackages/${packageId}`).set(record);
  sendJson(res, 200, { id: packageId, ...record });
}));

app.delete("/api/admin/packages/:packageId", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const packageId = sanitizeString(req.params.packageId, 120);
  if (!packageId) {
    throw httpError(400, "Package id is required.");
  }

  const snapshot = await db.ref(`catalogPackages/${packageId}`).once("value");
  if (!snapshot.exists()) {
    throw httpError(404, "Package not found.");
  }

  await db.ref(`catalogPackages/${packageId}`).update({
    active: false,
    updatedAt: getCurrentTimestamp(),
  });
  sendJson(res, 200, { success: true, archived: true, id: packageId });
}));

app.get("/api/admin/users", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const limit = clampInteger(req.query.limit, 1, 500, 100);
  const search = sanitizeString(req.query.search, 120);
  const users = await listAllUsersWithWalletsAndStores();

  const filtered = users.filter((user) => matchesSearchText(search, [
    user.id,
    user.name,
    user.email,
    user.phone,
    user.store?.name,
    user.store?.slug,
    user.wallet?.balance,
  ]));

  sendJson(res, 200, {
    users: sortByNewestTimestamp(filtered, ["updatedAt", "createdAt", "lastLogin"]).slice(0, limit),
    total: filtered.length,
  });
}));

app.get("/api/admin/users/:uid", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const uid = sanitizeString(req.params.uid, 128);
  if (!uid) {
    throw httpError(400, "User id is required.");
  }

  const [users, orders, transactions] = await Promise.all([
    listAllUsersWithWalletsAndStores(),
    listAllOrdersForAdmin(),
    listAllWalletTransactionsForAdmin(),
  ]);

  const user = users.find((entry) => entry.id === uid);
  if (!user) {
    throw httpError(404, "User not found.");
  }

  sendJson(res, 200, {
    user,
    orders: orders.filter((order) => sanitizeString(order.ownerId, 128) === uid).slice(0, 100),
    transactions: transactions.filter((tx) => sanitizeString(tx.ownerId, 128) === uid).slice(0, 100),
  });
}));

app.put("/api/admin/users/:uid", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const uid = sanitizeString(req.params.uid, 128);
  if (!uid) {
    throw httpError(400, "User id is required.");
  }

  const snapshot = await db.ref(`users/${uid}`).once("value");
  if (!snapshot.exists()) {
    throw httpError(404, "User not found.");
  }

  const name = req.body.name !== undefined ? sanitizeString(req.body.name, 120) : undefined;
  const email = req.body.email !== undefined ? normalizeEmail(req.body.email) : undefined;
  const phone = req.body.phone !== undefined ? normalizePhone(req.body.phone) : undefined;
  const status = req.body.status !== undefined ? sanitizeString(req.body.status, 40).toLowerCase() : undefined;
  const isAdmin = req.body.isAdmin !== undefined ? Boolean(req.body.isAdmin) : undefined;

  if (email && !isLikelyEmail(email)) {
    throw httpError(400, "Email address is invalid.");
  }

  const updateData = {
    updatedAt: getCurrentTimestamp(),
  };

  if (name !== undefined) updateData.name = name;
  if (email !== undefined) updateData.email = email;
  if (phone !== undefined) updateData.phone = phone;
  if (status !== undefined) updateData.status = ["active", "disabled", "suspended"].includes(status) ? status : "active";
  if (isAdmin !== undefined) updateData.isAdmin = isAdmin;

  await db.ref(`users/${uid}`).update(updateData);
  const fresh = await db.ref(`users/${uid}`).once("value");
  sendJson(res, 200, { id: uid, ...fresh.val() });
}));

app.post("/api/admin/users/:uid/wallet-adjustment", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const uid = sanitizeString(req.params.uid, 128);
  if (!uid) {
    throw httpError(400, "User id is required.");
  }

  const amount = toPrice(req.body.amount);
  const type = sanitizeString(req.body.type, 20).toLowerCase();
  const reason = sanitizeString(req.body.reason, 240) || "Admin wallet adjustment";

  if (!amount || amount <= 0) {
    throw httpError(400, "Adjustment amount must be greater than zero.");
  }
  if (!["credit", "debit"].includes(type)) {
    throw httpError(400, "Adjustment type must be credit or debit.");
  }

  const walletSnapshot = await db.ref(`wallet/${uid}`).once("value");
  const wallet = walletSnapshot.val() || { balance: 0 };
  if (type === "debit" && Number(wallet.balance || 0) < amount) {
    throw httpError(400, "User balance is too low for this debit.");
  }

  const now = getCurrentTimestamp();
  const txRef = db.ref(`walletTransactions/${uid}`).push();
  const transaction = {
    id: txRef.key,
    type,
    category: "adjustment",
    amount,
    currency: "GHS",
    reference: `ADMIN-${txRef.key}`,
    description: reason,
    source: "admin-panel",
    adjustedBy: req.user.uid,
    createdAt: now,
    updatedAt: now,
  };

  await txRef.set(transaction);
  const updatedWallet = await recalculateOwnerWallet(uid);

  await auditLog("admin", "wallet-adjustment", {
    ownerId: uid,
    adminId: req.user.uid,
    type,
    amount,
    reason,
  });

  sendJson(res, 200, {
    success: true,
    wallet: updatedWallet,
    transaction,
  });
}));

app.get("/api/admin/orders", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const limit = clampInteger(req.query.limit, 1, 500, 100);
  const search = sanitizeString(req.query.search, 120);
  const status = sanitizeString(req.query.status, 40).toLowerCase();
  const ownerId = sanitizeString(req.query.ownerId, 128);

  const orders = await listAllOrdersForAdmin();
  const filtered = orders.filter((order) => {
    if (ownerId && sanitizeString(order.ownerId, 128) !== ownerId) {
      return false;
    }

    if (status) {
      const paymentStatus = sanitizeString(order.paymentStatus, 40).toLowerCase();
      const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase();
      const overallStatus = sanitizeString(order.status, 40).toLowerCase();
      if (![paymentStatus, fulfillmentStatus, overallStatus].includes(status)) {
        return false;
      }
    }

    return matchesSearchText(search, [
      order.id,
      order.paystackReference,
      order.hubnetReference,
      order.fulfillmentReference,
      order.email,
      order.beneficiaryPhone,
      order.packageName,
      order.storeName,
      order.ownerId,
    ]);
  });

  sendJson(res, 200, {
    orders: filtered.slice(0, limit),
    total: filtered.length,
  });
}));

app.post("/api/admin/orders/:orderId/retry-fulfillment", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  if (!hubnet) {
    throw httpError(503, "Bundle delivery is not configured.");
  }

  const orderId = sanitizeString(req.params.orderId, 120);
  const snapshot = await db.ref(`orders/${orderId}`).once("value");
  if (!snapshot.exists()) {
    throw httpError(404, "Order not found.");
  }

  const order = snapshot.val();
  const paymentStatus = sanitizeString(order.paymentStatus, 40).toLowerCase();
  const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase();

  if (paymentStatus !== "paid") {
    throw httpError(400, "Cannot retry: payment not confirmed.");
  }
  if (["delivered", "fulfilled"].includes(fulfillmentStatus)) {
    throw httpError(409, "Bundle already delivered.");
  }
  if (fulfillmentStatus === "processing" && order.hubnetInitAt && !isStaleTimestamp(order.hubnetInitAt)) {
    throw httpError(409, "Fulfillment in progress. Try again in a few minutes.");
  }
  if (!order.packageNetwork || !order.packageVolume) {
    throw httpError(400, "Order missing network/volume.");
  }

  await auditLog("admin", "fulfillment-manual-retry", {
    orderId,
    ownerId: order.ownerId,
    storeId: order.storeId,
    requestedBy: req.user.uid,
    currentFulfillmentStatus: fulfillmentStatus,
  });

  const result = await attemptHubnetFulfillment(orderId);
  const freshSnapshot = await db.ref(`orders/${orderId}`).once("value");
  const freshOrder = freshSnapshot.exists() ? freshSnapshot.val() : order;

  sendJson(res, 200, {
    orderId,
    retryResult: result,
    fulfillmentStatus: freshOrder.fulfillmentStatus || "processing",
    hubnetTransactionId: freshOrder.hubnetTransactionId || null,
    message: result.attempted
      ? (result.hubnetTransactionId ? "Bundle delivery initiated." : `Retry: ${result.reason || result.error || "unknown"}`)
      : `Skipped: ${result.reason || "unknown"}`,
  });
}));

app.get("/api/admin/transactions", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const limit = clampInteger(req.query.limit, 1, 500, 100);
  const search = sanitizeString(req.query.search, 120);
  const type = sanitizeString(req.query.type, 40).toLowerCase();
  const ownerId = sanitizeString(req.query.ownerId, 128);

  const transactions = await listAllWalletTransactionsForAdmin();
  const filtered = transactions.filter((tx) => {
    if (ownerId && sanitizeString(tx.ownerId, 128) !== ownerId) {
      return false;
    }

    if (type) {
      const txType = sanitizeString(tx.type, 20).toLowerCase();
      const txCategory = sanitizeString(tx.category, 40).toLowerCase();
      if (![txType, txCategory].includes(type)) {
        return false;
      }
    }

    return matchesSearchText(search, [
      tx.id,
      tx.ownerId,
      tx.reference,
      tx.paystackReference,
      tx.description,
      tx.packageName,
      tx.customerEmail,
      tx.source,
    ]);
  });

  sendJson(res, 200, {
    transactions: filtered.slice(0, limit),
    total: filtered.length,
  });
}));

app.get("/api/admin/withdrawals", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const limit = clampInteger(req.query.limit, 1, 200, 100);
  const status = sanitizeString(req.query.status, 40).toLowerCase();
  const snapshot = await db.ref("walletWithdrawals").limitToLast(limit).once("value");

  let withdrawals = [];
  snapshot.forEach((child) => {
    withdrawals.unshift({ id: child.key, ...child.val() });
  });

  if (status) {
    withdrawals = withdrawals.filter((item) => sanitizeString(item.status, 40).toLowerCase() === status);
  }

  sendJson(res, 200, { withdrawals, total: withdrawals.length });
}));

app.post("/api/admin/withdrawals/:withdrawalId/approve", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const withdrawalId = sanitizeString(req.params.withdrawalId, 120);
  const payoutNote = sanitizeString(req.body.payoutNote, 240) || "Approved for manual payout";
  if (!withdrawalId) {
    throw httpError(400, "Withdrawal id is required.");
  }

  const withdrawalRef = db.ref(`walletWithdrawals/${withdrawalId}`);
  const snapshot = await withdrawalRef.once("value");
  if (!snapshot.exists()) {
    throw httpError(404, "Withdrawal request not found.");
  }

  const withdrawal = snapshot.val() || {};
  if (sanitizeString(withdrawal.status, 40).toLowerCase() !== "pending") {
    throw httpError(409, "Only pending withdrawals can be approved.");
  }

  const ownerId = sanitizeString(withdrawal.ownerId, 128);
  const amount = toPrice(withdrawal.amount);
  if (!ownerId || !amount) {
    throw httpError(400, "Withdrawal data is invalid.");
  }

  const wallet = await recalculateOwnerWallet(ownerId);
  if (Number(wallet?.balance || 0) < amount) {
    throw httpError(409, "User balance is too low for this withdrawal.");
  }

  const now = getCurrentTimestamp();
  const reference = sanitizeString(withdrawal.reference, 120) || `WDR-${withdrawalId}`;
  await db.ref(`walletTransactions/${ownerId}/${reference}`).set({
    type: "debit",
    category: "withdrawal",
    amount,
    currency: "GHS",
    reference,
    description: payoutNote,
    source: "admin-withdrawal-approval",
    withdrawalId,
    approvedBy: req.user.uid,
    createdAt: now,
    updatedAt: now,
  });

  const updatedWallet = await recalculateOwnerWallet(ownerId);
  await withdrawalRef.update({
    status: "approved",
    approvedAt: now,
    approvedBy: req.user.uid,
    payoutNote,
    updatedAt: now,
    balanceAfterApproval: Number(updatedWallet?.balance || 0),
  });

  await auditLog("admin", "withdrawal-approved", {
    withdrawalId,
    ownerId,
    amount,
    approvedBy: req.user.uid,
  });

  sendJson(res, 200, {
    success: true,
    withdrawalId,
    status: "approved",
    wallet: updatedWallet,
    message: "Withdrawal approved. Send funds manually to the owner now.",
  });
}));

app.post("/api/admin/withdrawals/:withdrawalId/reject", verifyAuth, requireAdmin, asyncHandler(async (req, res) => {
  const withdrawalId = sanitizeString(req.params.withdrawalId, 120);
  const rejectionReason = sanitizeString(req.body.reason, 240) || "Request rejected by admin";
  if (!withdrawalId) {
    throw httpError(400, "Withdrawal id is required.");
  }

  const withdrawalRef = db.ref(`walletWithdrawals/${withdrawalId}`);
  const snapshot = await withdrawalRef.once("value");
  if (!snapshot.exists()) {
    throw httpError(404, "Withdrawal request not found.");
  }
  const current = snapshot.val() || {};
  if (sanitizeString(current.status, 40).toLowerCase() !== "pending") {
    throw httpError(409, "Only pending withdrawals can be rejected.");
  }

  await withdrawalRef.update({
    status: "rejected",
    rejectedAt: getCurrentTimestamp(),
    rejectedBy: req.user.uid,
    rejectionReason,
    updatedAt: getCurrentTimestamp(),
  });

  await auditLog("admin", "withdrawal-rejected", {
    withdrawalId,
    ownerId: sanitizeString(current.ownerId, 128) || null,
    rejectedBy: req.user.uid,
    reason: rejectionReason,
  }, "warn");

  sendJson(res, 200, { success: true, withdrawalId, status: "rejected" });
}));

// Serve static files from public folder
app.use(express.static(PUBLIC_DIR));

// Silence favicon.ico 404 noise Ã¢â‚¬â€ respond with no-content
app.get('/favicon.ico', (req, res) => res.status(204).end());

// SPA routing: serve appropriate HTML for different routes
const routes = {
  "/auth/login": "auth/login.html",
  "/auth/signup": "auth/signup.html",
  "/auth/reset": "auth/reset.html",
  "/auth/action": "auth/action.html",
  "/admin": "app/admin.html",
  "/app": "app/dashboard.html",
  "/app/balance": "app/balance.html",
  "/app/profile": "app/profile.html",
  "/app/configuration": "app/configuration.html",
  "/app/orders": "app/orders.html",
  "/app/wallet": "app/balance.html",
  "/paystack/callback": "paystack/callback.html",
};

// Handle specific routes
Object.entries(routes).forEach(([route, file]) => {
  app.get(route, (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, file));
  });
});

app.get("/app/admin", (req, res) => {
  res.redirect(302, "/admin");
});

// Handle /s/:slug storefront routes
app.get("/s/:slug", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "s/index.html"));
});

// Handle root-level storefront slugs (e.g. localhost:3000/my-store)
// We exclude known subdirectories and reserved words.
app.get("/:slug", (req, res, next) => {
  const slug = normalizeSlug(req.params.slug);
  const reserved = ["admin", "api", "auth", "app", "css", "js", "img", "paystack", "s", "store"];

  if (reserved.includes(slug) || !isValidSlug(slug)) {
    return next();
  }

  res.sendFile(path.join(PUBLIC_DIR, "s/index.html"));
});

// Catch-all: serve index.html for SPA
app.get("*", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((error, req, res, next) => {
  const statusCode = error.statusCode || 500;
  const level = statusCode >= 500 ? "error" : "warn";
  emitLog(level, "HTTP", "request-error", buildRequestTrace(req, {
    statusCode,
    error: error.message,
  }));
  sendJson(res, statusCode, {
    error: statusCode === 500 ? "Internal server error" : error.message,
  });
});

// ============================================================================
// START SERVER
// ============================================================================

let server = null;

if (require.main === module) {
  verifyFirebaseAdminAccess()
    .then(() => {
      // Listen on 0.0.0.0 so Render (and other cloud hosts) can route traffic in.
      // 127.0.0.1 would silently accept connections only from localhost.
      server = app.listen(PORT, "0.0.0.0", () => {
        console.log(`[Startup] Server listening on http://localhost:${PORT}`);
        console.log(`[Startup] API base: http://localhost:${PORT}/api`);
        console.log(`[Startup] Static public dir: ${PUBLIC_DIR}`);
        console.log(`[Startup] Integrations: paystack=${paystack ? "on" : "off"}, hubnet=${hubnet ? "on" : "off"}, fulfillment=${fulfillment ? "on" : "off"}`);
        console.log("[Startup] Restart the server after code or env changes.");
      });
    })
    .catch((error) => {
      console.error("Startup aborted: Firebase admin credentials failed verification.");
      console.error(error?.message || error);
      process.exit(1);
    });
}

// Graceful shutdown
process.on("SIGTERM", () => {
  if (!server) {
    process.exit(0);
    return;
  }

  console.log("[Shutdown] Stopping server...");
  server.close(() => {
    console.log("[Shutdown] Server stopped");
    process.exit(0);
  });
});

module.exports = {
  app,
  get db() {
    return db;
  },
  get auth() {
    return auth;
  },
};



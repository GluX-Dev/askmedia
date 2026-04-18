

const crypto = require("crypto");
const cors = require("cors");
const express = require("express");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");
const admin = require("firebase-admin");

function loadEnvFile(envFilePath) {
  if (!fs.existsSync(envFilePath)) {
    return;
  }

  const envSource = fs.readFileSync(envFilePath, "utf8");
  for (const rawLine of envSource.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const separatorIndex = line.indexOf("=");
    if (separatorIndex <= 0) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim();
    if (!key || process.env[key] !== undefined) {
      continue;
    }

    let value = line.slice(separatorIndex + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    process.env[key] = value;
  }
}

loadEnvFile(path.join(__dirname, ".env"));

const DATABASE_URL = process.env.FIREBASE_DATABASE_URL || "https://ask-media-cc963-default-rtdb.europe-west1.firebasedatabase.app";

// Initialize Firebase Admin SDK with service account
try {
  const serviceAccountPath = path.join(__dirname, "serviceAccountKey.json");
  let serviceAccount;

  try {
    serviceAccount = require(serviceAccountPath);
    console.log("✓ Service account loaded from serviceAccountKey.json");
  } catch (e) {
    console.warn("⚠ serviceAccountKey.json not found, trying GOOGLE_APPLICATION_CREDENTIALS...");
    if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      serviceAccount = require(process.env.GOOGLE_APPLICATION_CREDENTIALS);
      console.log("✓ Service account loaded from GOOGLE_APPLICATION_CREDENTIALS");
    } else {
      throw new Error("No service account found");
    }
  }

  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: DATABASE_URL
    });
    console.log("✓ Firebase Admin SDK initialized");
  }
} catch (err) {
  console.error("❌ Firebase initialization failed:", err.message);
  process.exit(1);
}

const db = admin.database();
const auth = admin.auth();

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

const PROJECT_ID = process.env.GCLOUD_PROJECT || process.env.PROJECT_ID || "ask-media-cc963";
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "";
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || "";
const FULFILLMENT_API_BASE_URL = process.env.FULFILLMENT_API_BASE_URL || "";
const FULFILLMENT_API_KEY = process.env.FULFILLMENT_API_KEY || "";
const HUBNET_API_KEY = process.env.HUBNET_API_KEY || "";
const HUBNET_API_BASE_URL = process.env.HUBNET_API_BASE_URL || "https://console.hubnet.app/live/api/context/business/transaction";
const HUBNET_WEBHOOK_SECRET = process.env.HUBNET_WEBHOOK_SECRET || "";
const HUBNET_REFERRER = process.env.HUBNET_REFERRER || "";
const APP_BASE_URL = process.env.APP_BASE_URL || `https://${PROJECT_ID}.web.app`;
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
  ...parseCsv(process.env.ALLOWED_ORIGINS || ""),
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5000",
  "http://127.0.0.1:5000",
].filter(Boolean));

if (HUBNET_WEBHOOK_SECRET && !hasHubnetWebhookSecret) {
  console.warn("⚠ HUBNET_WEBHOOK_SECRET should be a long random string, not a URL. Update it to keep Hubnet webhooks secure.");
}

// Optional: Load Paystack helper if configured
let PaystackHelper;
let paystack = null;
try {
  PaystackHelper = require("./svc-integrations.js").PaystackHelper;
  if (hasPaystackSecretKey) {
    paystack = new PaystackHelper(PAYSTACK_SECRET_KEY, hasPaystackPublicKey ? PAYSTACK_PUBLIC_KEY : "");
    console.log("✓ Paystack configured");
  }
} catch (e) {
  console.warn("⚠ Paystack helper not available");
}

// Optional: Load Hubnet helper if configured
let HubnetHelper;
let hubnet = null;
try {
  HubnetHelper = require("./svc-integrations.js").HubnetHelper;
  if (hasHubnetApiKey) {
    hubnet = new HubnetHelper(HUBNET_API_KEY, HUBNET_API_BASE_URL);
    console.log("✓ Hubnet configured");
  }
} catch (e) {
  console.warn("⚠ Hubnet helper not available");
}

// Optional: Load Fulfillment helper if configured
let FulfillmentHelper;
let fulfillment = null;
try {
  FulfillmentHelper = require("./svc-integrations.js").FulfillmentHelper;
  if (hasFulfillmentBaseUrl && hasFulfillmentApiKey) {
    fulfillment = new FulfillmentHelper(FULFILLMENT_API_BASE_URL, FULFILLMENT_API_KEY);
    console.log("✓ Fulfillment configured");
  }
} catch (e) {
  console.warn("⚠ Fulfillment helper not available");
}

console.log("âœ“ Payment and Hubnet audit logging enabled");

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
    || pathName === "/api/public/hubnet/webhook"
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
  console.log(`  [Hubnet] parse response | preview: ${preview}${preview.length >= 350 ? "…" : ""}`);
  
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

  console.log(`  [Hubnet] extracted | status=${status} accepted=${accepted} tx=${transactionId || "—"} pay=${paymentId || "—"} msgCode=${message || "—"} reason=${reason || "—"}`);

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

  snapshot.forEach((child) => {
    const order = child.val() || {};
    if (sanitizeString(order.paymentStatus, 40).toLowerCase() !== "paid") {
      return;
    }

    totalOrders += 1;
    totalRevenue += Number(order.amount || 0);
  });

  const metrics = {
    totalOrders,
    totalRevenue: Number(totalRevenue.toFixed(2)),
    updatedAt: getCurrentTimestamp(),
  };

  await db.ref(`storefronts/${safeStoreId}/metrics`).update(metrics);
  return metrics;
}

async function recalculateOwnerWallet(ownerId) {
  const safeOwnerId = sanitizeString(ownerId, 120);
  if (!safeOwnerId) {
    return null;
  }

  const snapshot = await db.ref(`walletTransactions/${safeOwnerId}`).once("value");
  const seenReferences = new Set();
  let balance = 0;
  let totalEarned = 0;
  let totalOrders = 0;
  let lastCreditAt = null;

  snapshot.forEach((child) => {
    const transaction = child.val() || {};
    const type = sanitizeString(transaction.type, 20).toLowerCase() || "credit";
    if (type !== "credit") {
      return;
    }

    const uniqueReference = sanitizeString(
      transaction.reference || transaction.paystackReference,
      120
    ) || child.key;

    if (seenReferences.has(uniqueReference)) {
      return;
    }

    seenReferences.add(uniqueReference);

    const amount = Number(transaction.amount || 0);
    if (!Number.isFinite(amount)) {
      return;
    }

    balance += amount;
    totalEarned += amount;
    totalOrders += 1;

    const createdAt = sanitizeString(transaction.createdAt, 50);
    if (!lastCreditAt || getTimestampMs(createdAt) > getTimestampMs(lastCreditAt)) {
      lastCreditAt = createdAt || lastCreditAt;
    }
  });

  const walletPayload = {
    balance: Number(balance.toFixed(2)),
    totalEarned: Number(totalEarned.toFixed(2)),
    totalOrders,
    currency: "GHS",
    lastCreditAt: lastCreditAt || null,
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
  const packageNetwork = sanitizeString(metadata.packageNetwork, 20).toLowerCase();
  const packageVolume = sanitizeString(metadata.packageVolume, 20);
  const beneficiaryPhone = normalizePhone(metadata.beneficiaryPhone || verificationData?.customer?.phone);
  const amount = Number(verificationData?.amount || 0) / 100;
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
    email,
    maskedEmail: maskEmail(email),
    beneficiaryPhone,
    packageId: packageId || null,
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

function getPublicStorePackages(store) {
  return Array.isArray(store.packages)
    ? store.packages
      .map((pkg) => ({
        id: sanitizeString(pkg.id, 80),
        name: sanitizeString(pkg.name, 120),
        description: sanitizeString(pkg.description, 400),
        sellingPrice: toPrice(pkg.sellingPrice),
        network: sanitizeString(pkg.network, 20).toLowerCase() || null,
        volume: sanitizeString(pkg.volume, 20) || null,
      }))
      .filter((pkg) => pkg.id && pkg.name && pkg.sellingPrice)
    : [];
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

  let store = await getOwnerStore(uid);

  if (!store) {
    const storeRef = db.ref("storefronts").push();
    const generatedSlug = await generateUniqueSlug(normalizedName || normalizedEmail || uid);

    const storePayload = {
      ownerId: uid,
      name: deriveDefaultStoreName(normalizedName, normalizedEmail),
      slug: generatedSlug,
      theme: "light",
      supportPhone: normalizedPhone || "",
      supportWhatsapp: normalizedPhone || "",
      supportEmail: normalizedEmail || "",
      packages: [],
      published: true,
      logo: null,
      metrics: {
        totalOrders: 0,
        totalRevenue: 0,
      },
      createdAt: getCurrentTimestamp(),
      updatedAt: getCurrentTimestamp(),
    };

    await storeRef.set(storePayload);
    store = { id: storeRef.key, ...storePayload };
  }

  const userData = await userRef.once("value");
  return {
    user: { id: uid, ...userData.val() },
    store: store,
  };
}

function sanitizePackages(packages) {
  if (packages === undefined) {
    return undefined;
  }

  if (!Array.isArray(packages)) {
    throw httpError(400, "Packages must be an array.");
  }

  if (packages.length > 50) {
    throw httpError(400, "No more than 50 packages are allowed.");
  }

  return packages.map((pkg, index) => {
    if (!pkg || typeof pkg !== "object") {
      throw httpError(400, `Package ${index + 1} is invalid.`);
    }

    const name = sanitizeString(pkg.name, 120);
    const description = sanitizeString(pkg.description, 400);
    const id = sanitizeString(pkg.id, 80) || crypto.randomUUID();
    const sellingPrice = toPrice(pkg.sellingPrice);
    const rawNetwork = sanitizeString(pkg.network, 20).toLowerCase();
    const rawVolume = sanitizeString(pkg.volume, 20);

    let network = rawNetwork;
    if (network === "airtel-tigo" || network === "airtel tigo" || network === "airteltigo") {
      network = "at";
    }
    if (network === "vodafone" || network === "big-time" || network === "bigtime") {
      network = "telecel";
    }

    if (!name) {
      throw httpError(400, `Package ${index + 1} must have a name.`);
    }

    if (!sellingPrice) {
      throw httpError(400, `Package ${index + 1} must have a valid selling price.`);
    }

    if (network && !["mtn", "at", "telecel"].includes(network)) {
      throw httpError(400, `Package ${index + 1} network must be MTN, AT, or Telecel.`);
    }

    if ((network && !rawVolume) || (!network && rawVolume)) {
      throw httpError(400, `Package ${index + 1} must include both network and volume (or neither).`);
    }

    if (rawVolume && !/^\d+$/.test(rawVolume)) {
      throw httpError(400, `Package ${index + 1} volume must be a whole number (e.g. 1000).`);
    }

    const output = {
      id,
      name,
      description,
      sellingPrice,
    };

    if (network) {
      output.network = network;
      output.volume = rawVolume;
    }

    return output;
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
  // Hubnet reference must be 6–25 alphanumeric/hyphen chars.
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
  // Allow an explicit override via HUBNET_WEBHOOK_URL env var (e.g. via ngrok in local dev).
  // Falls back to APP_BASE_URL + path which works correctly in production.
  const HUBNET_WEBHOOK_URL = process.env.HUBNET_WEBHOOK_URL || "";
  const base = HUBNET_WEBHOOK_URL
    ? HUBNET_WEBHOOK_URL.trim().replace(/\/+$/g, "")
    : `${APP_BASE_URL.replace(/\/+$/g, "")}/api/public/hubnet/webhook`;
  const url = base.includes("/api/public/hubnet/webhook") ? base : `${base}/api/public/hubnet/webhook`;
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

  // ── Priority 1: Hubnet event name (most authoritative) ───────────────────────
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

  // ── Priority 2: data.status field (Hubnet real-time status string) ────────────
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

  // ── Priority 3: Fall back to combined text analysis ───────────────────────────
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

  // Default: treat as in-progress — Hubnet will send another webhook when done.
  return "processing";
}

async function attemptHubnetFulfillment(orderId) {
  console.log(`\n→→→ [HUBNET INTERNAL] attemptHubnetFulfillment() called for order: ${orderId}`);
  
  if (!hubnet) {
    console.error(`✗ [HUBNET EARLY EXIT] Hubnet not configured (HUBNET_API_KEY missing or invalid)`);
    return { attempted: false, reason: "hubnet_not_configured" };
  }
  console.log(`  ✓ Hubnet helper loaded`);

  const orderRef = db.ref(`orders/${orderId}`);
  const sessionRef = db.ref(`paymentSessions/${orderId}`);

  console.log(`  → Reading order from Firebase...`);
  const orderSnapshot = await orderRef.once("value");
  if (!orderSnapshot.exists()) {
    console.error(`✗ [HUBNET EARLY EXIT] Order not found in database: ${orderId}`);
    return { attempted: false, reason: "order_not_found" };
  }
  console.log(`  ✓ Order found in database`);

  const order = orderSnapshot.val();
  const paymentStatus = sanitizeString(order.paymentStatus, 40).toLowerCase();
  const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase();
  
  console.log(`  → Order status: paymentStatus="${paymentStatus}" | fulfillmentStatus="${fulfillmentStatus}"`);

  if (paymentStatus !== "paid") {
    console.error(`✗ [HUBNET EARLY EXIT] Payment not confirmed. Status: "${paymentStatus}" (expected "paid")`);
    return { attempted: false, reason: "payment_not_confirmed" };
  }
  console.log(`  ✓ Payment confirmed`);

  if (!order.packageNetwork || !order.packageVolume) {
    console.error(`✗ [HUBNET EARLY EXIT] Missing package details. Network: "${order.packageNetwork}" | Volume: "${order.packageVolume}"`);
    return { attempted: false, reason: "missing_package_network_volume" };
  }
  console.log(`  ✓ Package details present: ${order.packageNetwork} / ${order.packageVolume}MB`);

  if (["delivered", "fulfilled"].includes(fulfillmentStatus)) {
    console.warn(`⚠ [HUBNET EARLY EXIT] Bundle already delivered/fulfilled. Status: "${fulfillmentStatus}"`);
    return { attempted: false, reason: "already_delivered" };
  }

  const priorTx = normalizeHubnetTransactionId(order.hubnetTransactionId);
  if (priorTx) {
    // Already has a transaction ID — only skip if not failed.
    if (fulfillmentStatus !== "failed") {
      console.warn(`⚠ [HUBNET EARLY EXIT] Already initiated. TxID: "${priorTx}" | Status: "${fulfillmentStatus}"`);
      return { attempted: false, reason: "already_initiated" };
    }
    console.log(`  → Retrying after previous failure (TxID exists but status is "failed")`);
  }

  const now = getCurrentTimestamp();
  // Enforce Hubnet's 25-char max reference constraint.
  const hubnetReference = sanitizeString(order.hubnetReference, 25) || makeHubnetReference(orderId);

  console.log(`  → Acquiring Firebase transaction lock...`);
  const lock = await orderRef.transaction((current) => {
    // IMPORTANT: returning undefined aborts the transaction (committed=false).
    // Rare races can pass current=null even right after we read the order — seed from the snapshot.
    const base = current && typeof current === "object" ? current : null;
    if (!base) {
      console.warn(`  ⚠ [HUBNET LOCK] Server state was null in transaction — applying lock from last order snapshot`);
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
      console.warn(`⚠ [HUBNET] Lock skipped — bundle request already created (tx: ${txId})`);
      return { attempted: false, reason: "already_initiated" };
    }
    if (inflight && fs === "processing") {
      console.warn("⚠ [HUBNET] Lock skipped — provisioning already in progress for this order.");
      return { attempted: false, reason: "hubnet_inflight" };
    }
    console.error(`✗ [HUBNET EARLY EXIT] Transaction not committed. refreshedExists=${refreshed.exists()} fulfillment=${fs} snapshotFulfillment=${snapVal ? sanitizeString(snapVal.fulfillmentStatus, 40) : "n/a"}`);
    return { attempted: false, reason: "locked" };
  }
  console.log(`  ✓ Transaction lock acquired, order status set to "processing"`);

  console.log(`  → Normalizing Ghana phone number...`);
  const msisdn = toGhanaNationalPhone(order.beneficiaryPhone);
  if (!msisdn) {
    console.error(`✗ [HUBNET ERROR] Invalid Ghana phone number: "${order.beneficiaryPhone}"`);
    await Promise.all([
      orderRef.update({ fulfillmentStatus: "failed", status: "failed", fulfillmentError: "Invalid Ghana phone number.", updatedAt: getCurrentTimestamp() }),
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
  console.log(`  ✓ Phone normalized: ${msisdn}`);

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
    
    console.log(`  → Logging fulfillment request to audit trail...`);
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

    console.log(`\n→ [HUBNET REQUEST] Creating ${hubnetNetwork.toUpperCase()} bundle`);
    console.log(`  └─ Reference: ${hubnetReference}`);
    console.log(`  └─ Phone: ${msisdn}`);
    console.log(`  └─ Volume: ${order.packageVolume}MB`);
    console.log(`  └─ Webhook URL: ${webhookUrl}`);
    console.log(`  → Sending to Hubnet API...`);

    let response;
    try {
      console.log(`  → [HUBNET API CALL] network="${hubnetNetwork}" phone="${msisdn}" volume="${order.packageVolume}"MB reference="${hubnetReference}"`);
      response = await hubnet.createTransaction({ network: hubnetNetwork, ...requestPayload });
      console.log(`  ✓ [HUBNET API RESPONSE] Received response object`);
    } catch (error) {
      console.error(`  ✗ [HUBNET API ERROR] Error from Hubnet API:`);
      console.error(`    └─ Error message: ${error?.message}`);
      console.error(`    └─ Error payload: ${JSON.stringify(error?.payload, null, 2)}`);
      console.error(`    └─ Error statusCode: ${error?.statusCode}`);
      
      const msg = sanitizeString(error?.message, 300).toLowerCase();
      const msg2 = sanitizeString(error?.payload?.message, 200).toLowerCase();
      const invalidNetwork = msg.includes("invalid network") || msg2.includes("invalid network");

      if (networkCandidates.length > 1 && invalidNetwork) {
        console.log(`  → Network "${hubnetNetwork}" invalid, retrying with fallback: "${networkCandidates[1]}"`);
        hubnetNetwork = networkCandidates[1];
        response = await hubnet.createTransaction({ network: hubnetNetwork, ...requestPayload });
      } else {
        throw error;
      }
    }

    console.log(`  → Checking Hubnet response acceptance...`);
    const details = extractHubnetResponseDetails(response, hubnetReference);
    console.log(`  → Response details: accepted="${details.accepted}" transactionId="${details.transactionId}" status="${details.status}"`);
    
    if (!details.accepted) {
      const reason = details.message || details.reason || "Hubnet did not confirm the bundle request.";
      console.error(`  ✗ Response marked as NOT ACCEPTED: ${reason}`);
      throw new Error(reason);
    }
    console.log(`  ✓ Response marked as ACCEPTED by Hubnet`);

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

    console.log(`  → Updating order in Firebase with Hubnet response...`);
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
    console.log(`  ✓ Firebase updated with Hubnet response`);
    
    console.log(`  → Logging success to audit trail...`);
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
    console.log(`  ✓ Audit log recorded`);

    console.log("✓ [HUBNET SUCCESS] Bundle provision accepted");
    console.log(`  └─ Transaction ID: ${hubnetTransactionId}`);
    console.log(`  └─ Payment ID: ${hubnetPaymentId || "N/A"}`);
    console.log(`  └─ Network: ${hubnetNetwork.toUpperCase()}`);
    console.log(`  └─ Status Code: ${hubnetCode || "OK"}`);
    console.log(`  └─ Message: ${hubnetMessage || "Bundle provisioning initiated"}`);
    console.log(`  └─ Waiting for webhook confirmation...`);

    return { attempted: true, hubnetReference, hubnetTransactionId };
  } catch (error) {
    const message = sanitizeString(error?.message || error?.payload?.message, 500) || "Hubnet transaction failed.";
    const now2 = getCurrentTimestamp();
    
    console.error("\n╔════════════════════════════════════════════════════════════════╗");
    console.error("║ ✗ [HUBNET ERROR] Bundle provision FAILED                      ║");
    console.error("╚════════════════════════════════════════════════════════════════╝");
    console.error(`Error: ${message}`);
    console.error(`Order ID: ${orderId}`);
    console.error(`Reference: ${hubnetReference}`);
    console.error(`Network: ${hubnetNetwork}`);
    console.error(`Phone: ${msisdn}`);
    console.error(`Volume: ${order.packageVolume}MB`);
    console.error(`\nFull error object:`);
    console.error(`  Status Code: ${error?.statusCode || "N/A"}`);
    console.error(`  Payload: ${JSON.stringify(error?.payload, null, 2)}`);
    console.error(`  Stack: ${error?.stack}`);
    console.error(`\nNext action: Order marked as FAILED (payment stays PAID)`);
    console.error(`Manual retry: POST /api/owner/orders/${orderId}/retry-fulfillment`);
    console.error(`Or check Firebase: /orders/${orderId} and /paymentSessions/${orderId}`);
    
    // Mark as 'failed' but keep status as 'paid' so the payment is not lost.
    // The order can be retried by calling attemptHubnetFulfillment again.
    console.log(`  → Updating order status to "failed" in Firebase...`);
    await Promise.all([
      orderRef.update({
        fulfillmentStatus: "failed",
        // Keep overall status as 'paid' — the customer paid successfully.
        // Only fulfillment failed, not the payment.
        status: "paid",
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
    console.log(`  ✓ Order and session updated to failed status`);
    
    console.log(`  → Logging failure to audit trail...`);
    await auditLog("hubnet", "fulfillment-failed", {
      orderId,
      ownerId: order.ownerId,
      storeId: order.storeId,
      hubnetReference,
      network: hubnetNetwork,
      error: message,
    }, "error");
    console.log(`  ✓ Audit log recorded`);

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

  // ─── IDEMPOTENCY ─────────────────────────────────────────────────────────────
  // Use an RTDB transaction to atomically mark the session as paid.
  // If another webhook/request already set paymentStatus="paid", the transaction
  // function returns undefined (abort) and committed=false — we stop here.
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

  // Transaction aborted ⟹ session was already paid; skip to avoid double-credit.
  if (!txResult.committed) {
    await auditLog("payment", "already-processed", {
      reference,
      eventName,
      storeSlug: session.slug,
    }, "warn");
    return;
  }

  // ─── CREATE ORDER (idempotent guard) ─────────────────────────────────────────
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
      packageName: session.packageName,
      package: session.packageName,
      packageNetwork: session.packageNetwork || null,
      packageVolume: session.packageVolume || null,
      amount: session.amount,
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
        totalRevenue: parseFloat(((m.totalRevenue || 0) + Number(session.amount || 0)).toFixed(2)),
      };
    });

    // ─── WALLET CREDIT (atomic) ──────────────────────────────────────────────
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

    // ─── WALLET LEDGER ENTRY (audit trail) ──────────────────────────────────
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

    console.log(`[Wallet] Owner ${session.ownerId} credited ₵${session.amount} for ref ${reference}`);
  }

  // ─── FULFILLMENT ─────────────────────────────────────────────────────────────
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

async function processSuccessfulPayment(reference, verifiedData, eventName) {
  const sessionRef = db.ref(`paymentSessions/${reference}`);
  const orderRef = db.ref(`orders/${reference}`);

  // ── IDEMPOTENCY FAST PATH ─────────────────────────────────────────────────────
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
    // If already paid AND either fulfilled or no hubnet package needed — skip.
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

  console.log("\n✓ [PAYMENT CONFIRMED] Payment verified via Paystack");
  console.log(`  └─ Reference: ${reference}`);
  console.log(`  └─ Amount: ₵${(actualAmountKobo / 100).toFixed(2)}`);
  console.log(`  └─ Customer: ${session.email}`);
  console.log(`  └─ Fulfillment Provider: ${initialFulfillmentProvider}`);
  console.log(`  └─ Next Status: ${nextSessionFulfillmentStatus}`);

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
      packageName: session.packageName,
      package: session.packageName,
      packageNetwork: session.packageNetwork || current?.packageNetwork || null,
      packageVolume: session.packageVolume || current?.packageVolume || null,
      amount: Number(session.amount || 0),
      currency: "GHS",
      paystackReference: reference,
      hubnetReference: shouldAttemptHubnet
        ? (sanitizeString(current?.hubnetReference, 40) || hubnetReference)
        : (current?.hubnetReference || hubnetReference),
      paymentStatus: "paid",
      fulfillmentProvider: current?.fulfillmentProvider || initialFulfillmentProvider,
      fulfillmentStatus: nextFulfillmentStatus,
      status: nextStatus,
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
    amount: Number(session.amount || 0),
    currency: "GHS",
    reference,
    paystackReference: reference,
    storeId: session.storeId,
    packageId: session.packageId,
    packageName: session.packageName,
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
    console.log("\n→ [HUBNET] Initiating data bundle provisioning...");
    console.log(`  └─ Reference: ${reference}`);
    console.log(`  └─ Network: ${session.packageNetwork?.toUpperCase()}`);
    console.log(`  └─ Volume: ${session.packageVolume}MB`);
    console.log(`  └─ Phone: ****${String(session.beneficiaryPhone || "").slice(-4)}`);
    try {
      const result = await attemptHubnetFulfillment(reference);
      console.log(`\n[HUBNET ATTEMPT RESULT] ${JSON.stringify(result)}`);
    } catch (hubnetError) {
      console.error("\n╔════════════════════════════════════════════════════════════════╗");
      console.error("║ ✗ [HUBNET UNHANDLED ERROR] Exception thrown                   ║");
      console.error("╚════════════════════════════════════════════════════════════════╝");
      console.error(`Error message: ${hubnetError?.message}`);
      console.error(`Error stack: ${hubnetError?.stack}`);
      console.error(`Error object: ${JSON.stringify(hubnetError, null, 2)}`);
      
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

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

// ============================================================================
// EXPRESS APP SETUP
// ============================================================================

const app = express();
const PUBLIC_DIR = path.join(__dirname, "public");
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");
// Trust the first proxy hop (required on Render / behind a load balancer for
// rate-limit IP detection and secure cookie behaviour)
app.set("trust proxy", 1);

// ── Security Headers ─────────────────────────────────────────────────────────
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

// Body parsing — the verify callback captures the raw body BEFORE JSON parsing.
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

// ── Rate Limiting ─────────────────────────────────────────────────────────────
// Strict limit on payment initialization — prevents brute-force attempts
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
// API ROUTES
// ============================================================================

// Health check
app.get("/api/health", (req, res) => {
  sendJson(res, 200, {
    status: "ok",
    projectId: PROJECT_ID,
    databaseUrl: DATABASE_URL,
    paymentsConfigured: Boolean(paystack),
    hubnetConfigured: Boolean(hubnet),
    fulfillmentConfigured: Boolean(fulfillment),
    database: "firebase-realtime",
    auth: "firebase-auth",
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

  sendJson(res, 200, {
    id: storeId,
    name: sanitizeString(store.name, 120),
    slug: sanitizeString(store.slug, 50),
    theme: sanitizeString(store.theme, 20) || "light",
    supportPhone: sanitizeString(store.supportPhone, 25),
    supportWhatsapp: sanitizeString(store.supportWhatsapp, 25),
    supportEmail: normalizeEmail(store.supportEmail),
    packages: getPublicStorePackages(store),
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

// Public: Order lookup — supports ?reference=XYZ OR ?phone=0271234567
// Per DevNox spec: https://your-api.com/v1/orders?reference=XYZ12345
//                 https://your-api.com/v1/orders?phone=0247000195
app.get("/v1/orders", asyncHandler(async (req, res) => {
  const reference = sanitizeString(req.query?.reference, 120);
  const phoneRaw = sanitizeString(req.query?.phone, 40);
  const phone = phoneRaw ? normalizePhone(phoneRaw) : "";

  if (!reference && !phone) {
    throw httpError(400, "Either 'reference' or 'phone' query parameter is required.");
  }

  // Reject if neither is actually useful
  if (reference && reference.length < 3) {
    throw httpError(400, "Reference too short.");
  }
  if (phoneRaw && !phone) {
    throw httpError(400, "Invalid phone number format.");
  }

  let orderId = null;
  let order = null;

  // ── Lookup by reference ───────────────────────────────────────────────────────
  if (reference) {
    // Try direct order key first (fastest)
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
        if (!orderId) { orderId = child.key; order = child.val(); }
      });
    }
  }

  // ── Lookup by phone (if reference not found or not provided) ──────────────────
  if (!order && phone) {
    const byPhone = await db.ref("orders")
      .orderByChild("beneficiaryPhone")
      .equalTo(phone)
      .limitToFirst(1)
      .once("value");
    byPhone.forEach((child) => {
      if (!orderId) { orderId = child.key; order = child.val(); }
    });
  }

  if (!order) {
    throw httpError(404, "Order not found.");
  }

  const fulfillmentStatus = sanitizeString(order.fulfillmentStatus, 40).toLowerCase() || "queued";
  const paymentStatus = sanitizeString(order.paymentStatus, 40).toLowerCase() || "pending";

  // Derive a human-meaningful overall status:
  // - If bundle delivered → "delivered"
  // - If bundle processing → "processing"
  // - If paid but bundle pending → "paid" (bundle pending)
  // - Otherwise → fall back to payment status
  let status = sanitizeString(order.status, 40).toLowerCase();
  if (!status) {
    if (fulfillmentStatus === "delivered" || fulfillmentStatus === "fulfilled") {
      status = "delivered";
    } else if (fulfillmentStatus === "processing") {
      status = "processing";
    } else if (paymentStatus === "paid") {
      status = "paid";
    } else {
      status = paymentStatus;
    }
  }

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
    network: sanitizeString(order.packageNetwork, 20).toUpperCase() || null,
    volume: sanitizeString(order.packageVolume, 20) || null,
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

  const selectedPackage = getPublicStorePackages(store).find((pkg) => pkg.id === packageId);

  if (!selectedPackage) {
    throw httpError(404, "Package not found.");
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
    packageName: selectedPackage.name,
    packageNetwork: selectedPackage.network || null,
    packageVolume: selectedPackage.volume || null,
    email,
    maskedEmail: maskEmail(email),
    beneficiaryPhone,
    amount: selectedPackage.sellingPrice,
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
  
  console.log("\n✓ [PAYMENT INIT] Order created for customer");
  console.log(`  └─ Reference: ${reference}`);
  console.log(`  └─ Store: ${slug} (ID: ${storeId})`);
  console.log(`  └─ Package: ${selectedPackage.name}${selectedPackage.volume != null ? ` - ${selectedPackage.volume}MB` : ""}${selectedPackage.network ? ` on ${String(selectedPackage.network).toUpperCase()}` : ""}`);
  console.log(`  └─ Amount: ₵${selectedPackage.sellingPrice.toFixed(2)}`);
  console.log(`  └─ Customer: ${email} | Phone: ****${beneficiaryPhone.slice(-4)}`);
  console.log(`  └─ Fulfillment: ${sessionPayload.fulfillmentProvider || "manual"}`);
  
  await auditLog("payment", "initialize-requested", {
    requestId: req.requestId,
    reference,
    storeSlug: slug,
    ownerId: sessionPayload.ownerId,
    storeId,
    packageId: selectedPackage.id,
    amount: selectedPackage.sellingPrice,
    email,
    beneficiaryPhone,
    callbackUrl: callbackUrl.toString(),
  });

  try {
    console.log(`→ [PAYSTACK] Initializing transaction for reference: ${reference}`);
    const paystackResponse = await paystack.initializeTransaction({
      email,
      amount: selectedPackage.sellingPrice,
      reference,
      callbackUrl: callbackUrl.toString(),
      metadata: {
        slug,
        storeId,
        packageId: selectedPackage.id,
        packageName: selectedPackage.name,
        packageNetwork: selectedPackage.network || null,
        packageVolume: selectedPackage.volume || null,
        beneficiaryPhone,
      },
    });

    const authorizationUrl = paystackResponse?.data?.authorization_url;
    if (!authorizationUrl) {
      throw new Error("Paystack did not return an authorization URL.");
    }

    console.log("✓ [PAYSTACK] Transaction initialized successfully");
    console.log(`  └─ Authorization URL: ${authorizationUrl}`);
    console.log(`  └─ Access Code: ${paystackResponse?.data?.access_code}`);

    await sessionRef.update({
      paymentProvider: "paystack",
      paystackAccessCode: sanitizeString(paystackResponse?.data?.access_code, 120) || null,
      updatedAt: getCurrentTimestamp(),
    });
    await auditLog("payment", "initialize-succeeded", {
      requestId: req.requestId,
      reference,
      storeSlug: slug,
      amount: selectedPackage.sellingPrice,
      redirectUrl: authorizationUrl,
    });

    sendJson(res, 200, {
      sessionId: reference,
      paystackReference: reference,
      amount: selectedPackage.sellingPrice,
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
      amount: selectedPackage.sellingPrice,
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
      // Still proceed — processSuccessfulPayment will attempt its own recovery.
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
app.post(["/api/public/hubnet/webhook", "/hubnet/webhook"], webhookRateLimit, asyncHandler(async (req, res) => {
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
    console.log(`⚠ [HUBNET WEBHOOK] Duplicate event (already processed): ${eventName} | Ref: ${hubnetReference}`);
    sendJson(res, 200, { received: true, duplicate: true });
    return;
  }

  console.log(`\n✓ [HUBNET WEBHOOK] Event received: ${eventName}`);
  console.log(`  └─ Reference: ${hubnetReference}`);
  console.log(`  └─ Event ID: ${eventId}`);

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
  if (orderId) {
    const orderSnap = await db.ref(`orders/${orderId}`).once("value");
    if (orderSnap.exists()) {
      const ov = orderSnap.val() || {};
      ownerId = sanitizeString(ov.ownerId, 120) || null;
      storeId = sanitizeString(ov.storeId, 120) || null;
    }
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

  const newFulfillmentStatus = mapHubnetWebhookToFulfillmentStatus(eventName, req.body);
  const overallStatus = newFulfillmentStatus === "delivered"
    ? "fulfilled"
    : newFulfillmentStatus === "failed"
      ? "failed"
      : "processing";

  const now = getCurrentTimestamp();
  const orderRef = db.ref(`orders/${orderId}`);
  const sessionRef = db.ref(`paymentSessions/${orderId}`);

  await orderRef.transaction((current) => {
    if (!current) return;

    return {
      ...current,
      fulfillmentProvider: "hubnet",
      fulfillmentStatus: newFulfillmentStatus,
      status: overallStatus,
      hubnetLastEvent: eventName || null,
      hubnetLastWebhookAt: now,
      statusHistory: appendStatusHistory(current.statusHistory, {
        status: newFulfillmentStatus,
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
      fulfillmentStatus: newFulfillmentStatus,
      status: overallStatus,
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
    fulfillmentStatus: newFulfillmentStatus,
  });

  sendJson(res, 200, { received: true, matched: true });
}));

// Public: Get payment status
app.get("/api/public/payments/:reference", asyncHandler(async (req, res) => {
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
app.post("/api/public/payments/verify/:reference", asyncHandler(async (req, res) => {
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
  const bootstrap = await ensureOwnerBootstrap(req.user);
  const walletSnapshot = await db.ref(`wallet/${req.user.uid}`).once("value");
  const wallet = walletSnapshot.val() || { balance: 0, totalEarned: 0, totalOrders: 0, currency: "GHS" };

  sendJson(res, 200, {
    ...bootstrap.store,
    wallet,
  });
}));

// Owner: Update store
app.put("/api/owner/store", verifyAuth, asyncHandler(async (req, res) => {
  const bootstrap = await ensureOwnerBootstrap(req.user);
  const storeRef = db.ref(`storefronts/${bootstrap.store.id}`);
  const updateData = {
    updatedAt: getCurrentTimestamp(),
  };

  if (req.body.name !== undefined) {
    const name = sanitizeString(req.body.name, 120);
    if (!name) {
      throw httpError(400, "Store name is required.");
    }
    updateData.name = name;
  }

  if (req.body.slug !== undefined) {
    const slug = normalizeSlug(req.body.slug);
    if (!isValidSlug(slug)) {
      throw httpError(400, "Store slug must be 3-50 characters and use only letters, numbers, or hyphens.");
    }

    const existing = await db.ref("storefronts").orderByChild("slug").equalTo(slug).once("value");
    if (existing.exists()) {
      let slugTaken = false;
      existing.forEach((child) => {
        if (child.key !== bootstrap.store.id) {
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
  }

  if (req.body.supportPhone !== undefined) {
    updateData.supportPhone = normalizePhone(req.body.supportPhone);
  }

  if (req.body.supportWhatsapp !== undefined) {
    updateData.supportWhatsapp = normalizePhone(req.body.supportWhatsapp);
  }

  if (req.body.supportEmail !== undefined) {
    const supportEmail = normalizeEmail(req.body.supportEmail);
    if (supportEmail && !isLikelyEmail(supportEmail)) {
      throw httpError(400, "Support email is invalid.");
    }
    updateData.supportEmail = supportEmail;
  }

  if (req.body.logo !== undefined) {
    updateData.logo = sanitizeString(req.body.logo, 400) || null;
  }

  const packages = sanitizePackages(req.body.packages);
  if (packages !== undefined) {
    updateData.packages = packages;
  }

  await storeRef.update(updateData);
  const snapshot = await storeRef.once("value");
  sendJson(res, 200, { id: bootstrap.store.id, ...snapshot.val() });
}));

// Owner: Publish/unpublish store
app.post("/api/owner/store/publish", verifyAuth, asyncHandler(async (req, res) => {
  const bootstrap = await ensureOwnerBootstrap(req.user);
  const published = Boolean(req.body.published);

  await db.ref(`storefronts/${bootstrap.store.id}`).update({
    published,
    publishedAt: published ? getCurrentTimestamp() : null,
    updatedAt: getCurrentTimestamp(),
  });

  sendJson(res, 200, { success: true, published });
}));

// Owner: Get orders
app.get("/api/owner/orders", verifyAuth, asyncHandler(async (req, res) => {
  const bootstrap = await ensureOwnerBootstrap(req.user);
  const limit = clampInteger(req.query.limit, 1, 100, 50);
  const search = sanitizeString(req.query.search, 120).toLowerCase();
  const status = sanitizeString(req.query.status, 40).toLowerCase();

  const snapshot = await db.ref("orders").orderByChild("storeId").equalTo(bootstrap.store.id).once("value");

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

  orders = orders.slice(0, limit);

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

  sendJson(res, 200, { orders, total: orders.length });
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
  const bootstrap = await ensureOwnerBootstrap(req.user);
  const orderId = sanitizeString(req.params.orderId, 120);
  const snapshot = await db.ref('orders/' + orderId).once('value');
  if (!snapshot.exists() || snapshot.val().storeId !== bootstrap.store.id) {
    throw httpError(404, 'Order not found.');
  }
  sendJson(res, 200, { id: orderId, ...snapshot.val() });
}));

// Owner: Retry Hubnet fulfillment for a failed/stuck order
app.post('/api/owner/orders/:orderId/retry-fulfillment', verifyAuth, asyncHandler(async (req, res) => {
  if (!hubnet) throw httpError(503, 'Hubnet fulfillment is not configured.');
  const bootstrap = await ensureOwnerBootstrap(req.user);
  const orderId = sanitizeString(req.params.orderId, 120);
  const snapshot = await db.ref('orders/' + orderId).once('value');
  if (!snapshot.exists() || snapshot.val().storeId !== bootstrap.store.id) throw httpError(404, 'Order not found.');
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
  const wallet = walletSnapshot.val() || { balance: 0, totalEarned: 0, totalOrders: 0, currency: 'GHS' };
  sendJson(res, 200, { balance: Number(wallet.balance) || 0, totalEarned: Number(wallet.totalEarned) || 0, totalOrders: Number(wallet.totalOrders) || 0, currency: wallet.currency || 'GHS', lastCreditAt: wallet.lastCreditAt || null });
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

// ============================================================================
// FRONTEND - Serve static files and SPA routing
// ============================================================================

// Serve static files from public folder
app.use(express.static(PUBLIC_DIR));

// SPA routing: serve appropriate HTML for different routes
const routes = {
  "/auth/login": "auth/login.html",
  "/auth/signup": "auth/signup.html",
  "/auth/reset": "auth/reset.html",
  "/auth/action": "auth/action.html",
  "/app": "app/dashboard.html",
  "/app/profile": "app/profile.html",
  "/app/configuration": "app/configuration.html",
  "/app/orders": "app/orders.html",
  "/paystack/callback": "paystack/callback.html",
};

// Handle specific routes
Object.entries(routes).forEach(([route, file]) => {
  app.get(route, (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, file));
  });
});

// Handle /s/:slug storefront routes
app.get("/s/:slug", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "s/index.html"));
});

// Handle root-level storefront slugs (e.g. localhost:3000/my-store)
// We exclude known subdirectories and reserved words.
app.get("/:slug", (req, res, next) => {
  const { slug } = req.params;
  const reserved = ["api", "auth", "app", "css", "js", "img", "paystack", "s"];

  if (reserved.includes(slug)) {
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

// Listen on 0.0.0.0 so Render (and other cloud hosts) can route traffic in.
// 127.0.0.1 would silently accept connections only from localhost.
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`
╭─────────────────────────────────────────────────────────────╮
│   ASK MEDIA - Ghana Unified Backend & Frontend Server     │
╰─────────────────────────────────────────────────────────────╯

✓ Server running:           http://localhost:${PORT}
✓ Frontend:                 http://localhost:${PORT}
✓ API base:                 http://localhost:${PORT}/api
✓ Database:                 Firebase Realtime Database
✓ Auth:                     Firebase Auth
✓ Currency:                 GHS (Ghana Cedis - ₵)
✓ Locale:                   Ghana (en-GH)
✓ Service Account:          ${hasPaystackSecretKey ? "✓ Configured" : "⚠ Not configured"}
✓ Paystack:                 ${paystack ? "✓ Configured" : "⚠ Not configured"}
✓ Fulfillment:              ${fulfillment ? "✓ Configured" : "⚠ Not configured"}

📱 Try these URLs:
   • http://localhost:${PORT}/
   • http://localhost:${PORT}/auth/login
   • http://localhost:${PORT}/auth/signup
   • http://localhost:${PORT}/app
   • http://localhost:${PORT}/api/health

🔗 API Endpoints:
   • GET    /api/health
   • GET    /api/public/store/:slug
   • POST   /api/public/payments/initialize
   • GET    /api/public/payments/:reference
   • POST   /api/public/payments/verify/:reference  ← webhook recovery
   • GET    /api/public/orders/track/:reference
   • GET    /api/owner/me
   • PUT    /api/owner/me
   • GET    /api/owner/store
   • PUT    /api/owner/store
   • POST   /api/owner/store/publish
   • GET    /api/owner/orders
   • GET    /api/owner/pipeline-activity            ← payment + bundle audit trail
   • GET    /api/owner/orders/:orderId
   • GET    /api/owner/wallet                       ← wallet balance
   • GET    /api/owner/wallet/transactions          ← wallet ledger

🇬🇭 Ghana Configuration Active:
   • Currency: GHS | Amounts formatted as 1,234.56 ₵
   • Dates: DD MMM YYYY (e.g., 15 Apr 2026)
   • Language: English (Ghana)

⚠ Note: Restart server to reload code changes

✓ 100% Ready for Ghana! 🇬🇭

`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("\n⏹  Shutting down...");
  server.close(() => {
    console.log("✓ Server stopped");
    process.exit(0);
  });
});

module.exports = { app, db, auth };


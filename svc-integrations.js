"use strict";

const crypto = require("crypto");
const axios = require("axios");

class PaystackHelper {
  constructor(secretKey, publicKey) {
    this.secretKey = secretKey;
    this.publicKey = publicKey;
    this.baseUrl = "https://api.paystack.co";
  }

  async request(endpoint, options = {}) {
    const response = await fetch(`${this.baseUrl}${endpoint}`, options);

    let payload = null;
    try {
      payload = await response.json();
    } catch (_error) {
      payload = null;
    }

    if (!response.ok || payload?.status === false) {
      throw new Error(payload?.message || `Paystack request failed with status ${response.status}`);
    }

    return payload;
  }

  async initializeTransaction({ email, amount, reference, callbackUrl, metadata = {} }) {
    const payload = {
      email,
      amount: Math.round(Number(amount) * 100),
      currency: "GHS",
      reference,
      metadata,
    };

    if (callbackUrl) {
      payload.callback_url = callbackUrl;
    }

    return this.request("/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.secretKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  }

  async verifyTransaction(reference) {
    console.log(`→ [Paystack] Verifying transaction: ${reference}`);
    try {
      const result = await this.request(`/transaction/verify/${reference}`, {
        headers: {
          Authorization: `Bearer ${this.secretKey}`,
        },
      });
      if (result?.status && result?.data?.status === "success") {
        console.log(`✓ [Paystack] Verified | ref: ${reference} | amount: ${(result.data.amount / 100).toFixed(2)} ${result.data.currency || "GHS"}`);
      }
      return result;
    } catch (error) {
      console.error(`✗ [Paystack] Verify failed: ${error.message}`);
      throw error;
    }
  }

  verifyWebhookSignature(payload, signature) {
    const content = typeof payload === "string" ? payload : JSON.stringify(payload);
    const hash = crypto
      .createHmac("sha512", this.secretKey)
      .update(content)
      .digest("hex");

    return hash === signature;
  }

  async getTransaction(reference) {
    return this.request(`/transaction/${reference}`, {
      headers: {
        Authorization: `Bearer ${this.secretKey}`,
      },
    });
  }
}

function maskGhanaPhoneForLog(phone) {
  const d = String(phone || "").replace(/\D/g, "");
  if (d.length < 4) {
    return "***";
  }
  return `****${d.slice(-4)}`;
}

class HubnetHelper {
  constructor(apiKey, baseUrl) {
    this.apiKey = String(apiKey || "").trim();
    this.baseUrl = String(
      baseUrl || "https://console.hubnet.app/live/api/context/business/transaction"
    )
      .trim()
      .replace(/\/+$/g, "");
    /** Official docs: only "token: Bearer <key>". Optional: authorization, both */
    this.authMode = String(process.env.HUBNET_AUTH_MODE || "token").toLowerCase();
    if (!["authorization", "token", "both"].includes(this.authMode)) {
      this.authMode = "token";
    }

    const masked = this.apiKey.length > 8
      ? `${this.apiKey.slice(0, 4)}****${this.apiKey.slice(-4)}`
      : "[short]";
    console.log(`[Hubnet] client ready | auth=${this.authMode} (docs: token+Bearer) | ${this.baseUrl} | key=${masked}`);
    console.log("[Hubnet] note: Hubnet API rate limit is ~5 requests/minute (per docs).");
  }

  buildHeaders(extraHeaders) {
    const h = {
      "Content-Type": "application/json",
      ...(extraHeaders || {}),
    };
    const bearer = `Bearer ${this.apiKey}`;
    if (this.authMode === "token" || this.authMode === "both") {
      h.token = bearer;
    }
    if (this.authMode === "authorization" || this.authMode === "both") {
      h.Authorization = bearer;
    }
    return h;
  }

  isFailureStatus(status) {
    if (status === false) {
      return true;
    }

    const normalized = String(status || "").trim().toLowerCase();
    return ["fail", "failed", "error", "unsuccessful"].includes(normalized);
  }

  isSuccessStatus(status) {
    if (status === true) {
      return true;
    }

    const normalized = String(status || "").trim().toLowerCase();
    return ["ok", "success", "successful", "true", "1", "pending", "processing", "queued"].includes(normalized);
  }

  /** Hubnet docs (2025): success uses status:true, message:"0000" for OK, transaction_id present */
  isDocSuccessPayload(payload) {
    if (!payload || typeof payload !== "object") {
      return false;
    }
    if (payload.status === true) {
      return true;
    }
    const msg = String(payload.message ?? "").trim();
    if (msg === "0000") {
      return true;
    }
    const data = payload.data;
    if (data && typeof data === "object" && data.status === true) {
      return true;
    }
    if (data && String(data.message ?? "").trim() === "0000") {
      return true;
    }
    if (sanitizeStringId(payload.transaction_id) || sanitizeStringId(payload.payment_id)) {
      return true;
    }
    return false;
  }

  /**
   * Docs error codes: 1001 invalid network, 1002 invalid volume (message field may carry code).
   * If status is explicitly true, trust it over numeric message (per sample: status:true + message:"0000").
   */
  isDocErrorPayload(payload) {
    if (!payload || typeof payload !== "object") {
      return false;
    }
    if (payload.status === true) {
      return false;
    }
    if (payload.status === false) {
      return true;
    }
    const msg = String(payload.message ?? "").trim();
    if (/^(1001|1002|100[3-9]|[1-9]\d{3,})$/.test(msg)) {
      return true;
    }
    return false;
  }

  async request(endpoint, options = {}) {
    const timeoutMs = Number(options.timeoutMs || 30000);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const path = String(endpoint || "").trim();
    if (!path) {
      throw new Error("Hubnet endpoint is required.");
    }
    const url = `${this.baseUrl}${path.startsWith("/") ? "" : "/"}${path}`;
    const method = options.method || "GET";
    const t0 = Date.now();

    console.log(`[Hubnet] → ${method} ${url} (${timeoutMs}ms)`);
    if (options.body) {
      let bodyLog = options.body;
      try {
        const bodyObj = JSON.parse(options.body);
        bodyLog = JSON.stringify({
          ...bodyObj,
          phone: bodyObj.phone ? maskGhanaPhoneForLog(bodyObj.phone) : bodyObj.phone,
        });
      } catch (_e) {
        bodyLog = options.body.substring(0, 400);
      }
      console.log(`[Hubnet]   body: ${bodyLog}`);
    }

    try {
      const response = await fetch(url, {
        method,
        headers: this.buildHeaders(options.headers),
        body: options.body,
        signal: controller.signal,
      });

      const elapsed = Date.now() - t0;
      const rawText = await response.text();

      let payload = null;
      try {
        payload = rawText ? JSON.parse(rawText) : null;
      } catch (_err) {
        payload = rawText ? { raw: rawText } : null;
      }

      if (!response.ok) {
        const message =
          payload?.reason
          || payload?.message
          || payload?.data?.response_msg
          || payload?.error
          || `Hubnet HTTP ${response.status}`;
        console.error(`[Hubnet] ✗ HTTP ${response.status} (${elapsed}ms) | ${message}`);
        if (response.status === 429) {
          console.error("[Hubnet] ✗ rate limited — Hubnet allows ~5 req/min per docs");
        }
        const error = new Error(message);
        error.statusCode = response.status;
        error.payload = payload;
        throw error;
      }

      if (payload && (this.isDocErrorPayload(payload) || (this.isFailureStatus(payload.status) && !this.isDocSuccessPayload(payload)))) {
        const message =
          payload?.reason
          || payload?.code
          || payload?.message
          || payload?.data?.message
          || "Hubnet API reported failure.";
        console.error(`[Hubnet] ✗ ${message} | status=${payload.status} | msgCode=${payload.message}`);
        const error = new Error(typeof message === "string" ? message : JSON.stringify(message));
        error.statusCode = Number(payload?.response_code) || 502;
        if (!Number.isFinite(error.statusCode) || error.statusCode < 400) {
          error.statusCode = 502;
        }
        error.payload = payload;
        throw error;
      }

      if (payload && !this.isDocSuccessPayload(payload) && !sanitizeStringId(payload?.transaction_id) && !sanitizeStringId(payload?.payment_id)) {
        const msg = String(payload.message ?? "").trim();
        const rc = Number(payload.response_code || 0);
        const numericErr = msg && /^\d+$/.test(msg) && msg !== "0000";
        if (this.isFailureStatus(payload.status) || numericErr || rc >= 400) {
          const message = payload.reason || payload.code || (numericErr ? `Hubnet code ${msg}` : payload.message) || "Hubnet API reported failure.";
          console.error(`[Hubnet] ✗ ${message}`);
          const error = new Error(String(message));
          error.statusCode = rc >= 400 ? rc : 502;
          error.payload = payload;
          throw error;
        }
      }

      const summary = payload
        ? `status=${payload.status} msgCode=${payload.message} reason=${payload.reason || "—"} tx=${payload.transaction_id || "—"} pay=${payload.payment_id || "—"}`
        : "empty";
      console.log(`[Hubnet] ✓ OK (${elapsed}ms) | ${summary}`);
      return payload;
    } catch (err) {
      if (err.name === "AbortError") {
        const elapsed = Date.now() - t0;
        console.error(`[Hubnet] ✗ timeout ${elapsed}ms (limit ${timeoutMs}ms)`);
        const e = new Error(`Hubnet timed out after ${timeoutMs}ms`);
        e.statusCode = 504;
        throw e;
      }
      if (!err.statusCode) {
        console.error(`[Hubnet] ✗ network: ${err.message}`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  async checkBalance() {
    return this.request("/check_balance");
  }

  async createTransaction({ network, phone, volume, reference, referrer, webhook }) {
    const safeNetwork = String(network || "").trim().toLowerCase();
    if (!safeNetwork) {
      throw new Error("Hubnet network is required.");
    }

    const volRaw = volume != null ? String(volume).trim() : "";
    const payload = {
      phone: String(phone || "").trim(),
      volume: volRaw,
      reference: String(reference || "").trim(),
    };

    if (referrer) {
      payload.referrer = String(referrer).trim();
    }

    if (webhook) {
      payload.webhook = String(webhook).trim();
    }

    if (!payload.phone || payload.volume === "" || !payload.reference) {
      throw new Error("Missing required Hubnet transaction fields.");
    }

    console.log(
      `[Hubnet] createTransaction | network=${safeNetwork} | ref=${payload.reference.length} chars | phone=${maskGhanaPhoneForLog(payload.phone)} | volumeMB=${payload.volume}`
    );

    return this.request(`/${encodeURIComponent(safeNetwork)}-new-transaction`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }
}

function sanitizeStringId(value) {
  const s = String(value ?? "").trim();
  return s.length ? s : "";
}

class FulfillmentHelper {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
    this.client = axios.create({
      baseURL: baseUrl,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      timeout: 30000,
    });
  }

  async getCatalog() {
    const response = await this.client.get("/catalog");
    return response.data;
  }

  async createOrder(orderData) {
    console.log("→ [FallbackFulfill] create order");
    console.log(`  └─ ref: ${orderData.externalReference}`);
    const response = await this.client.post("/purchase", {
      packageId: orderData.packageId,
      email: orderData.email,
      beneficiaryPhone: orderData.beneficiaryPhone,
      externalReference: orderData.externalReference,
      metadata: orderData.metadata || {},
    });
    console.log("✓ [FallbackFulfill] created");
    return response.data;
  }

  async getOrderStatus(reference) {
    const response = await this.client.get(`/orders/${reference}`);
    return response.data;
  }

  async getBalance() {
    try {
      const response = await this.client.get("/balance");
      return response.data;
    } catch (_e) {
      return null;
    }
  }

  async healthCheck() {
    try {
      const response = await this.client.get("/health");
      return response.status === 200;
    } catch (_e) {
      return false;
    }
  }
}

module.exports = { PaystackHelper, HubnetHelper, FulfillmentHelper };

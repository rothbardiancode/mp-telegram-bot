/**
 * MP Telegram Bot + Weeztix/OpenTicket OAuth + Stats Polling + Trend + Event Night + Promo Codes
 * Render Free: instance spins down; we ACK webhook immediately + auto-poll on first command.
 *
 * ENV required:
 * BOT_TOKEN
 * OAUTH_CLIENT_ID
 * OAUTH_CLIENT_SECRET
 * OAUTH_CLIENT_REDIRECT
 * WEEZTIX_EVENT_GUID          (can be pure GUID OR "GUID?as=....")
 * MP_CAPACITY
 *
 * After connecting (seed only):
 * WEEZTIX_REFRESH_TOKEN
 *
 * Optional:
 * WEEZTIX_POLL_SECONDS (default 90)
 * ADMIN_CHAT_ID
 * WEEZTIX_API_BASE (default https://api.weeztix.com) - dashboard API base
 * WEEZTIX_AS (optional; if set, overrides any ?as=... embedded in WEEZTIX_EVENT_GUID)
 *
 * Redis (Upstash REST):
 * REDIS_URL
 * REDIS_TOKEN
 */

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// -------------------- Telegram --------------------
const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN) {
  console.error('Missing BOT_TOKEN in environment');
  process.exit(1);
}
const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

async function tgSend(chatId, text) {
  await axios.post(`${TELEGRAM_API}/sendMessage`, { chat_id: chatId, text }, { timeout: 15000 });
}

// Telegram message size limit: chunk long replies safely
async function tgSendLong(chatId, text, chunkSize = 3500) {
  if (!text || typeof text !== 'string') return;
  for (let i = 0; i < text.length; i += chunkSize) {
    await tgSend(chatId, text.slice(i, i + chunkSize));
  }
}

// -------------------- Generic retry helper --------------------
async function withRetry(fn, {
  retries = 2,
  initialDelayMs = 800,
  factor = 2,
  shouldRetry = (err) => {
    const status = err?.response?.status;
    const code = err?.code;
    if (code === 'ECONNABORTED') return true; // axios timeout
    if (!status) return true;                // network/DNS
    if (status === 429) return true;         // rate limit
    return false;
  }
} = {}) {
  let attempt = 0;
  let delay = initialDelayMs;
  while (true) {
    try {
      return await fn();
    } catch (e) {
      attempt++;
      if (attempt > retries || !shouldRetry(e)) throw e;
      await new Promise(r => setTimeout(r, delay));
      delay *= factor;
    }
  }
}

// -------------------- MP config --------------------
const MP_CAPACITY = Number(process.env.MP_CAPACITY || 0);
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID || null;

// Organizer opt-in alerts (DM)
const alertSubscribers = new Set();

// Sellout alerts (sold-based)
const selloutAlerts = { p80: false, p90: false, p95: false, p100: false };

// Door alerts (scanned-based)
const doorAlerts = { p70: false, p85: false, p95: false };

async function broadcastAlert(message) {
  const ids = Array.from(alertSubscribers);
  for (const id of ids) {
    try {
      await tgSend(id, message);
    } catch {
      alertSubscribers.delete(id);
    }
  }
}

// -------------------- Redis (Upstash REST) --------------------
const REDIS_URL = process.env.REDIS_URL || '';
const REDIS_TOKEN = process.env.REDIS_TOKEN || '';

function redisAvailable() {
  return Boolean(REDIS_URL && REDIS_TOKEN);
}

async function redisGet(key) {
  if (!redisAvailable()) return null;
  try {
    const url = `${REDIS_URL}/get/${encodeURIComponent(key)}`;
    const r = await axios.post(url, null, {
      headers: { Authorization: `Bearer ${REDIS_TOKEN}` },
      timeout: 10000
    });
    return typeof r.data?.result === 'string' ? r.data.result : null;
  } catch (e) {
    console.error('Redis GET error:', e?.response?.data || e.message || e);
    return null;
  }
}

async function redisSet(key, value) {
  if (!redisAvailable()) return;
  try {
    const url = `${REDIS_URL}/set/${encodeURIComponent(key)}`;
    await axios.post(url, value, {
      headers: {
        Authorization: `Bearer ${REDIS_TOKEN}`,
        'Content-Type': 'text/plain'
      },
      timeout: 10000
    });
  } catch (e) {
    console.error('Redis SET error:', e?.response?.data || e.message || e);
  }
}

// -------------------- Ticket mapping (fallback only — names/prices auto-discovered from API) --------------------
const TICKET_MAP = {};
const PRICE_MAP = {};

// Auto-discovered from /event/{guid}/ticket response
let weeztixTicketNameById = {};  // {guid: name}
let weeztixTicketPriceById = {}; // {guid: price_eur}

function ticketLabel(id) {
  return weeztixTicketNameById[id] || TICKET_MAP[id] || id;
}

// -------------------- OAuth connect/callback --------------------
let OAUTH_STATE = null;

app.get('/weeztix/connect', (req, res) => {
  OAUTH_STATE = crypto.randomBytes(16).toString('hex');

  const clientId = process.env.OAUTH_CLIENT_ID;
  const redirectUri = process.env.OAUTH_CLIENT_REDIRECT;

  if (!clientId || !redirectUri) {
    return res.status(500).send('Missing OAUTH_CLIENT_ID or OAUTH_CLIENT_REDIRECT in env');
  }

  const url = new URL('https://login.weeztix.com/login');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('state', OAUTH_STATE);

  return res.redirect(url.toString());
});

app.get('/weeztix/callback', async (req, res) => {
  try {
    const code = req.query.code;
    const state = req.query.state;

    if (!code) return res.status(400).send('Missing code');
    if (!state || state !== OAUTH_STATE) return res.status(400).send('Bad state');

    const clientId = process.env.OAUTH_CLIENT_ID;
    const clientSecret = process.env.OAUTH_CLIENT_SECRET;
    const redirectUri = process.env.OAUTH_CLIENT_REDIRECT;

    if (!clientId || !clientSecret || !redirectUri) {
      return res.status(500).send('Missing OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET / OAUTH_CLIENT_REDIRECT');
    }

    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
    params.append('redirect_uri', redirectUri);
    params.append('code', code);

    const r = await axios.post('https://auth.weeztix.com/tokens', params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15000
    });

    console.log('WEEZTIX TOKEN RESPONSE:', {
      has_access_token: !!r.data?.access_token,
      has_refresh_token: !!r.data?.refresh_token
    });

    if (r.data?.refresh_token && typeof r.data.refresh_token === 'string') {
      await redisSet('weeztix_refresh_token', r.data.refresh_token);
      console.log('🔑 Saved initial refresh_token to Redis');
    }

    return res.send('✅ Weeztix connected. Refresh token persisted to Redis.');
  } catch (e) {
    console.error('Callback error:', e?.response?.data || e.message || e);
    return res.status(500).send('Token exchange failed. Check logs.');
  }
});

// -------------------- Tokens --------------------
let WEEZTIX_ACCESS_TOKEN = null;
let WEEZTIX_REFRESH_TOKEN_RUNTIME = null;
let REFRESH_IN_FLIGHT = null;

(async () => {
  try {
    const fromRedis = await redisGet('weeztix_refresh_token');
    if (fromRedis) {
      WEEZTIX_REFRESH_TOKEN_RUNTIME = fromRedis;
      console.log('🔑 Loaded refresh token from Redis');
    } else if (process.env.WEEZTIX_REFRESH_TOKEN) {
      WEEZTIX_REFRESH_TOKEN_RUNTIME = process.env.WEEZTIX_REFRESH_TOKEN;
      console.log('🔑 Using refresh token from ENV (seeding Redis)');
      await redisSet('weeztix_refresh_token', WEEZTIX_REFRESH_TOKEN_RUNTIME);
    } else {
      console.warn('⚠️ No refresh token in Redis or ENV yet. Use /weeztix/connect.');
    }
  } catch (e) {
    console.error('Startup refresh token load error:', e?.message || e);
  }
})();

async function refreshAccessToken() {
  if (REFRESH_IN_FLIGHT) return REFRESH_IN_FLIGHT;

  REFRESH_IN_FLIGHT = (async () => {
    const clientId = process.env.OAUTH_CLIENT_ID;
    const clientSecret = process.env.OAUTH_CLIENT_SECRET;
    if (!clientId || !clientSecret) throw new Error('Missing OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET');

    const tokenFromRedis = await redisGet('weeztix_refresh_token');
    const refreshToken = tokenFromRedis || WEEZTIX_REFRESH_TOKEN_RUNTIME || process.env.WEEZTIX_REFRESH_TOKEN;
    if (!refreshToken) throw new Error('Missing refresh token');

    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const params = new URLSearchParams();
    params.append('grant_type', 'refresh_token');
    params.append('refresh_token', refreshToken);

    const r = await axios.post('https://auth.weeztix.com/tokens', params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basicAuth}`
      },
      timeout: 15000
    });

    const at = r.data?.access_token;
    const dotCount = (typeof at === 'string') ? (at.match(/\./g) || []).length : -1;
    console.log('🧪 access_token dots:', dotCount, 'type:', typeof at, 'preview:', (at || '').slice(0, 25));
    if (!at || typeof at !== 'string' || dotCount < 2) throw new Error('Non-JWT access_token');

    WEEZTIX_ACCESS_TOKEN = at;

    if (r.data.refresh_token && typeof r.data.refresh_token === 'string') {
      WEEZTIX_REFRESH_TOKEN_RUNTIME = r.data.refresh_token;
      await redisSet('weeztix_refresh_token', r.data.refresh_token);
      console.log('🔁 Refresh token rotated & persisted');

      if (ADMIN_CHAT_ID) {
        try { await tgSend(ADMIN_CHAT_ID, '🔁 Weeztix: refresh_token rotated and persisted to Redis.'); } catch (_) {}
      }
    }

    return WEEZTIX_ACCESS_TOKEN;
  })();

  try {
    return await REFRESH_IN_FLIGHT;
  } finally {
    REFRESH_IN_FLIGHT = null;
  }
}

async function ensureAccessToken() {
  if (!WEEZTIX_ACCESS_TOKEN) await refreshAccessToken();
}

// -------------------- Robust parsing of WEEZTIX_EVENT_GUID + ?as=... --------------------
const WEEZTIX_EVENT_GUID_RAW = (process.env.WEEZTIX_EVENT_GUID || '').trim();
const [WEEZTIX_EVENT_GUID_CLEAN, EMBEDDED_QS_PART] = WEEZTIX_EVENT_GUID_RAW.split('?');
const EMBEDDED_QS = EMBEDDED_QS_PART ? `?${EMBEDDED_QS_PART}` : '';

const WEEZTIX_AS = (process.env.WEEZTIX_AS || '').trim();
const AS_QS = WEEZTIX_AS ? `?as=${encodeURIComponent(WEEZTIX_AS)}` : '';

function qsForDashboard() {
  return AS_QS || EMBEDDED_QS || '';
}

const WEEZTIX_EVENT_GUID = WEEZTIX_EVENT_GUID_CLEAN;

// -------------------- API base --------------------
const WEEZTIX_API_BASE = process.env.WEEZTIX_API_BASE || 'https://api.weeztix.com';
const WEEZTIX_POLL_SECONDS = Number(process.env.WEEZTIX_POLL_SECONDS || 90);

// -------------------- Company scoping --------------------
let weeztixCompanyGuid = null;

async function fetchCompanyGuidIfNeeded() {
  if (weeztixCompanyGuid) return weeztixCompanyGuid;

  const cached = await redisGet('weeztix_company_guid');
  if (cached) {
    weeztixCompanyGuid = cached;
    return weeztixCompanyGuid;
  }

  await ensureAccessToken();

  try {
    const r = await axios.get('https://auth.weeztix.com/users/me', {
      headers: { Authorization: `Bearer ${WEEZTIX_ACCESS_TOKEN}` },
      timeout: 15000
    });

    const data = r.data || {};
    const candidates = [];
    const pushIfGuid = (x) => { if (typeof x === 'string' && x.length >= 30) candidates.push(x); };

    if (Array.isArray(data.companies)) {
      for (const c of data.companies) {
        pushIfGuid(c?.guid);
        pushIfGuid(c?.id);
      }
    }
    pushIfGuid(data.company_guid);
    pushIfGuid(data.companyGuid);
    pushIfGuid(data.company?.guid);

    if (candidates.length) {
      weeztixCompanyGuid = candidates[0];
      await redisSet('weeztix_company_guid', weeztixCompanyGuid);
      return weeztixCompanyGuid;
    }
    return null;
  } catch {
    return null;
  }
}

async function weeztixGet(path, { timeout = 20000, companyScoped = false } = {}) {
  await ensureAccessToken();
  const headers = { Authorization: `Bearer ${WEEZTIX_ACCESS_TOKEN}` };
  if (companyScoped) {
    const cg = await fetchCompanyGuidIfNeeded();
    if (cg) headers['Company'] = cg;
  }
  return axios.get(`${WEEZTIX_API_BASE}${path}`, { headers, timeout });
}

// -------------------- Stats polling --------------------
let weeztixLastOkAt = null;
let weeztixLastError = null;
let weeztixLastRaw = null;
let weeztixTicketStats = []; // [{id, sold, scanned}]

const statsSeries = []; // [{ts, soldTotal, scannedTotal}]
const SERIES_KEEP_MS = 48 * 60 * 60 * 1000;

function parseWeeztixStats(data) {
  const out = [];
  const aggs = data && data.aggregations ? data.aggregations : null;
  if (!aggs) return out;

  const getBuckets = (obj, path) => {
    let cur = obj;
    for (const p of path) {
      if (!cur || typeof cur !== 'object') return null;
      cur = cur[p];
    }
    return Array.isArray(cur) ? cur : null;
  };

  const soldBuckets =
    getBuckets(aggs, ['ticketCount', 'statistics', 'statistics', 'buckets']) ||
    getBuckets(aggs, ['ticketCount', 'statistics', 'buckets']) ||
    getBuckets(aggs, ['ticketCount', 'buckets']);

  if (!soldBuckets || soldBuckets.length === 0) return out;

  let scannedBuckets = null;
  for (const [k, v] of Object.entries(aggs)) {
    const key = String(k).toLowerCase();
    if (key.includes('scan') || key.includes('scanned') || key.includes('check') || key.includes('entry')) {
      scannedBuckets =
        getBuckets(v, ['statistics', 'statistics', 'buckets']) ||
        getBuckets(v, ['statistics', 'buckets']) ||
        getBuckets(v, ['buckets']);
      if (scannedBuckets && scannedBuckets.length) break;
    }
  }

  const soldById = {};
  for (const b of soldBuckets) if (b?.key) soldById[String(b.key)] = Number(b.doc_count || 0);

  const scannedById = {};
  if (scannedBuckets?.length) {
    for (const b of scannedBuckets) if (b?.key) scannedById[String(b.key)] = Number(b.doc_count || 0);
  }

  for (const [id, sold] of Object.entries(soldById)) {
    out.push({ id, sold, scanned: scannedById[id] || 0 });
  }
  return out;
}


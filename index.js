/**
 * MP Telegram Bot + Weeztix/OpenTicket OAuth + Stats + Trend + Event Night + Promo Codes
 *
 * Render Free plan: instance spins down; we auto-refresh stats on-demand.
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
    if (code === 'ECONNABORTED') return true;
    if (!status) return true;
    if (status === 429) return true;
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

const alertSubscribers = new Set();
const selloutAlerts = { p80: false, p90: false, p95: false, p100: false };
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

// -------------------- Ticket mapping (YOUR GUIDS) --------------------
const TICKET_MAP = {
  "2b029302-aed9-4073-8ac5-a64859d45c42": "Wave 3",
  "c6b59c00-2dc2-4643-84a3-6bbe9e0c7eaf": "Wave 2",
  "74c31760-f904-4f9a-8a1c-9233d63f8f17": "Early bird",
  "b2b6cb45-2cd4-48f7-98b4-e0b7a4b7dff7": "Omaggio",
  "6eca0e42-564a-4f0b-91e5-bc8fccf76c6d": "Early bird (2)",
  "0874b0ce-13dd-41c3-93c6-df4cbf539542": "Wave 4",
  "f518a95a-bc8c-4018-8eae-27ab1a4329b4": "Wave 5"
};

const PRICE_MAP = {
  "Early bird": 9.81,
  "Early bird (2)": 9.81,
  "Omaggio": 0,
  "Wave 2": 11.79,
  "Wave 3": 14.68,
  "Wave 4": 14.68,
  "Wave 5": 9.81
};

function ticketLabel(id) {
  return TICKET_MAP[id] || id;
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
    // Token validity + company context, per docs. [4](https://docs.weeztix.com/api/dashboard/get-coupon-specific/)
    const r = await axios.get('https://auth.weeztix.com/users/me', {
      headers: { Authorization: `Bearer ${WEEZTIX_ACCESS_TOKEN}` },
      timeout: 15000
    });

    const data = r.data || {};
    const candidates = [];

    const pushIfGuid = (x) => {
      if (typeof x === 'string' && x.length >= 30) candidates.push(x);
    };

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
    if (cg) headers['Company'] = cg; // some endpoints require Company header [4](https://docs.weeztix.com/api/dashboard/get-coupon-specific/)
  }
  return axios.get(`${WEEZTIX_API_BASE}${path}`, { headers, timeout });
}

// -------------------- Stats polling --------------------
let weeztixLastOkAt = null;
let weeztixLastError = null;
let weeztixLastRaw = null;
let weeztixTicketStats = [];

const statsSeries = [];
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

async function fetchWeeztixStats() {
  try {
    if (!WEEZTIX_EVENT_GUID) {
      weeztixLastError = 'Missing WEEZTIX_EVENT_GUID';
      return;
    }

    const statsUrl = `https://api.weeztix.com/statistics/dashboard/${WEEZTIX_EVENT_GUID}${qsForDashboard()}`;

    const callApi = async () => {
      await ensureAccessToken();
      return axios.get(statsUrl, {
        headers: { Authorization: `Bearer ${WEEZTIX_ACCESS_TOKEN}` },
        timeout: 30000
      });
    };

    let resp;
    try {
      resp = await withRetry(() => callApi(), { retries: 2, initialDelayMs: 800 });
    } catch (e) {
      const status = e?.response?.status;
      const msg = e?.response?.data?.error_description || '';
      if (status === 401 || (status === 400 && msg.includes('JWT'))) {
        await refreshAccessToken();
        resp = await withRetry(() => callApi(), { retries: 2, initialDelayMs: 800 });
      } else {
        throw e;
      }
    }

    weeztixLastRaw = resp.data ?? { _empty: true };
    const parsed = parseWeeztixStats(resp.data);
    if (!parsed.length) {
      weeztixLastError = 'Stats fetched but parsing returned empty';
      return;
    }

    weeztixTicketStats = parsed;
    weeztixLastOkAt = new Date().toISOString();
    weeztixLastError = null;

    const soldTotalNow = weeztixTicketStats.reduce((sum, t) => sum + (Number(t.sold) || 0), 0);
    const scannedTotalNow = weeztixTicketStats.reduce((sum, t) => sum + (Number(t.scanned) || 0), 0);

    statsSeries.push({ ts: Date.now(), soldTotal: soldTotalNow, scannedTotal: scannedTotalNow });
    const cutoff = Date.now() - SERIES_KEEP_MS;
    while (statsSeries.length && statsSeries[0].ts < cutoff) statsSeries.shift();

    // Alerts
    if (MP_CAPACITY > 0 && alertSubscribers.size > 0) {
      const pctSold = soldTotalNow / MP_CAPACITY;
      if (pctSold >= 0.80 && !selloutAlerts.p80) { selloutAlerts.p80 = true; await broadcastAlert(`🔥 80% SOLD OUT\n\nVenduti: ${soldTotalNow}/${MP_CAPACITY}`); }
      if (pctSold >= 0.90 && !selloutAlerts.p90) { selloutAlerts.p90 = true; await broadcastAlert(`🚀 90% SOLD OUT\n\nVenduti: ${soldTotalNow}/${MP_CAPACITY}`); }
      if (pctSold >= 0.95 && !selloutAlerts.p95) { selloutAlerts.p95 = true; await broadcastAlert(`🚨 95% SOLD OUT\n\nVenduti: ${soldTotalNow}/${MP_CAPACITY}\nValuta chiusura biglietti.`); }
      if (pctSold >= 1.00 && !selloutAlerts.p100) { selloutAlerts.p100 = true; await broadcastAlert(`🟥 SOLD OUT\n\nVenduti: ${soldTotalNow}/${MP_CAPACITY}\nChiudi ticketing.`); }
    }

    if (MP_CAPACITY > 0 && alertSubscribers.size > 0 && scannedTotalNow > 0) {
      const pctDoor = scannedTotalNow / MP_CAPACITY;
      if (pctDoor >= 0.70 && !doorAlerts.p70) { doorAlerts.p70 = true; await broadcastAlert(`🚪 Porta: 70% capienza\nEntrati: ${scannedTotalNow}/${MP_CAPACITY}`); }
      if (pctDoor >= 0.85 && !doorAlerts.p85) { doorAlerts.p85 = true; await broadcastAlert(`⚠️ Porta: 85% capienza\nEntrati: ${scannedTotalNow}/${MP_CAPACITY}\nOcchio fila / sicurezza.`); }
      if (pctDoor >= 0.95 && !doorAlerts.p95) { doorAlerts.p95 = true; await broadcastAlert(`🚨 Porta: 95% capienza\nEntrati: ${scannedTotalNow}/${MP_CAPACITY}\nValuta STOP ingressi.`); }
    }
  } catch (e) {
    const code = e?.code;
    const status = e?.response?.status;
    const dataStr = e?.response?.data ? JSON.stringify(e.response.data).slice(0, 800) : '';
    if (code === 'ECONNABORTED') weeztixLastError = `Timeout: stats call exceeded 30000ms`;
    else if (status) weeztixLastError = `HTTP ${status}: ${dataStr || '(no body)'}`;
    else weeztixLastError = e?.message || String(e);
  }
}

setInterval(fetchWeeztixStats, WEEZTIX_POLL_SECONDS * 1000);

// -------------------- Cold-start fix --------------------
const STATS_MAX_AGE_MS = 5 * 60 * 1000;

function lastOkAgeMs() {
  if (!weeztixLastOkAt) return Infinity;
  const ts = Date.parse(weeztixLastOkAt);
  return Number.isFinite(ts) ? (Date.now() - ts) : Infinity;
}

async function ensureStatsFresh() {
  if (lastOkAgeMs() > STATS_MAX_AGE_MS) {
    await fetchWeeztixStats();
  }
}

// -------------------- Capacities (deep extraction) --------------------
let weeztixCapByTicketId = {};
let weeztixCapMetaByTicketId = {}; // {id: {fieldPath, rawValue, derived}}
let weeztixCapLastOkAt = null;
let weeztixCapLastError = null;
let weeztixCapDebug = [];

const CAP_CACHE_MAX_AGE_MS = 6 * 60 * 60 * 1000;

function capAgeMs() {
  if (!weeztixCapLastOkAt) return Infinity;
  const ts = Date.parse(weeztixCapLastOkAt);
  return Number.isFinite(ts) ? (Date.now() - ts) : Infinity;
}

function extractTicketArray(obj) {
  if (!obj) return null;
  if (Array.isArray(obj)) return obj;

  const candidates = [obj.tickets, obj.ticketTypes, obj.ticket_types, obj.ticket, obj.data, obj.results, obj.items];
  for (const c of candidates) if (Array.isArray(c)) return c;

  for (const [k, v] of Object.entries(obj)) {
    if (Array.isArray(v) && k.toLowerCase().includes('ticket')) return v;
  }
  return null;
}

function extractTicketId(t) {
  return t?.guid || t?.id || t?.ticket_guid || t?.ticketGuid || t?.ticket_type_guid || t?.ticketTypeGuid || null;
}

function collectNumericFields(obj, prefix = '', depth = 0, out = []) {
  if (!obj || typeof obj !== 'object' || depth > 6) return out;
  if (Array.isArray(obj)) {
    // don't traverse huge arrays except small ones
    if (obj.length > 25) return out;
    obj.forEach((v, i) => collectNumericFields(v, `${prefix}[${i}]`, depth + 1, out));
    return out;
  }
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (typeof v === 'number' && Number.isFinite(v)) out.push({ path, value: v });
    else if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) out.push({ path, value: Number(v) });
    else if (v && typeof v === 'object') collectNumericFields(v, path, depth + 1, out);
  }
  return out;
}

function scoreCapacityPath(pathLower) {
  let score = 0;

  // strong positives
  const strong = ['capacity', 'stock', 'inventory', 'remaining', 'available', 'quota'];
  const medium = ['limit', 'max_sales', 'maxsales', 'maxsale', 'max_tickets', 'maxtickets', 'ticket_limit'];

  for (const s of strong) if (pathLower.includes(s)) score += 50;
  for (const m of medium) if (pathLower.includes(m)) score += 25;

  // negatives (avoid pricing / per-order limits)
  const negatives = [
    'price', 'vat', 'fee', 'commission', 'service', 'tax',
    'per_order', 'perorder', 'max_per', 'maxper', 'min_per', 'minper',
    'order', 'checkout'
  ];
  for (const n of negatives) if (pathLower.includes(n)) score -= 30;

  // small boost if path ends with these exact keys
  if (pathLower.endsWith('.capacity') || pathLower.endsWith('.stock')) score += 20;
  if (pathLower.endsWith('.remaining') || pathLower.endsWith('.available')) score += 15;

  return score;
}

function extractCapacityDeep(ticketObj, soldById) {
  const id = extractTicketId(ticketObj);
  const fields = collectNumericFields(ticketObj);

  if (!fields.length) return { cap: null, meta: null };

  // pick best candidate by score
  let best = null;
  for (const f of fields) {
    const p = String(f.path || '');
    const pl = p.toLowerCase();
    const s = scoreCapacityPath(pl);
    if (s <= 0) continue;
    if (!best || s > best.score) best = { ...f, score: s };
  }

  if (!best) return { cap: null, meta: null };

  // If chosen field indicates "available/remaining", derive total = available + sold
  const pl = best.path.toLowerCase();
  let cap = best.value;

  let derived = false;
  // Only derive total capacity when we are confident the field is "remaining/left".
// Many APIs use "available" to mean *total stock*, not remaining.
// Only derive total capacity when we are confident the field is "remaining/left".
// IMPORTANT: in your tenant, "available_stock" is TOTAL capacity (do NOT derive).
if (
  pl.includes('remaining') ||
  pl.includes('left') ||
  pl.includes('remaining_count') ||
  pl.includes('remainingcount') ||
  pl.includes('stock_left') ||
  pl.includes('stockleft')
) {
  const sold = (soldById && id) ? Number(soldById[id] || 0) : 0;
  cap = Number(best.value) + sold;
  derived = true;
} else {
  // Treat available_stock / stock / capacity as total capacity
  cap = Number(best.value);
  derived = false;
}

  if (!Number.isFinite(cap) || cap < 0) return { cap: null, meta: null };

  return {
    cap,
    meta: { fieldPath: best.path, rawValue: best.value, derived }
  };
}

async function fetchCapacitiesFromApi() {
  weeztixCapDebug = [];
  weeztixCapLastError = null;
  weeztixCapMetaByTicketId = {};

  if (!WEEZTIX_EVENT_GUID) {
    weeztixCapLastError = 'Missing WEEZTIX_EVENT_GUID';
    return;
  }

  const soldById = {};
  for (const t of weeztixTicketStats) soldById[t.id] = Number(t.sold || 0);

  const qs = qsForDashboard();
  const join = qs ? '&' : '?';

  // Your tenant: /event/{guid}/tickets is 404, /event/{guid}/ticket works (array). [1](https://docs.weeztix.com/docs/events/overview/)
  const endpointsToTry = [
    `/event/${WEEZTIX_EVENT_GUID}/ticket${qs}`,
    `/event/${WEEZTIX_EVENT_GUID}/tickets${qs}`, // keep for completeness
    `/ticket${qs}${join}event_guid=${encodeURIComponent(WEEZTIX_EVENT_GUID)}`,
    `/event/${WEEZTIX_EVENT_GUID}${qs}`
  ];

  for (const path of endpointsToTry) {
    try {
      const r = await withRetry(
        () => weeztixGet(path, { timeout: 20000, companyScoped: true }),
        { retries: 1, initialDelayMs: 500 }
      );

      const data = r.data;
      const arr = extractTicketArray(data);

      weeztixCapDebug.push({
        path,
        ok: true,
        hasArray: !!arr,
        topKeys: data && typeof data === 'object' ? Object.keys(data).slice(0, 12) : null
      });

      if (!arr || !arr.length) continue;

      const map = {};
      const metaMap = {};

      for (const t of arr) {
        const id = extractTicketId(t);
        if (!id) continue;

        const { cap, meta } = extractCapacityDeep(t, soldById);
        if (cap != null) {
          map[String(id)] = cap;
          if (meta) metaMap[String(id)] = meta;
        }
      }

      if (Object.keys(map).length) {
        weeztixCapByTicketId = map;
        weeztixCapMetaByTicketId = metaMap;
        weeztixCapLastOkAt = new Date().toISOString();
        weeztixCapLastError = null;

        await redisSet('weeztix_ticket_capacities', JSON.stringify({ ts: weeztixCapLastOkAt, map, metaMap }));
        return;
      }
    } catch (e) {
      weeztixCapDebug.push({ path, ok: false, status: e?.response?.status, msg: e?.message });
    }
  }

  weeztixCapLastError = 'Could not auto-detect ticket capacities from API (endpoint/fields differ). Use /ticket_raw + /capacities_debug.';
}

async function ensureCapacitiesFresh() {
  if (capAgeMs() <= CAP_CACHE_MAX_AGE_MS && Object.keys(weeztixCapByTicketId).length) return;

  const cached = await redisGet('weeztix_ticket_capacities');
  if (cached) {
    try {
      const obj = JSON.parse(cached);
      if (obj?.map && typeof obj.map === 'object') {
        weeztixCapByTicketId = obj.map;
        weeztixCapMetaByTicketId = obj.metaMap || {};
        weeztixCapLastOkAt = obj.ts || new Date().toISOString();
        weeztixCapLastError = null;
        return;
      }
    } catch (_) {}
  }

  await fetchCapacitiesFromApi();
}

// -------------------- /biglietti helpers --------------------
function groupSoldByLabel() {
  const grouped = {};
  let total = 0;
  for (const t of weeztixTicketStats) {
    const label = ticketLabel(t.id);
    const v = Number(t.sold || 0);
    grouped[label] = (grouped[label] || 0) + v;
    total += v;
  }
  return { grouped, total };
}

function groupCapacityByLabel() {
  const grouped = {};
  let total = 0;
  for (const [ticketId, cap] of Object.entries(weeztixCapByTicketId || {})) {
    const label = ticketLabel(ticketId);
    const v = Number(cap || 0);
    if (!Number.isFinite(v) || v <= 0) continue;
    grouped[label] = (grouped[label] || 0) + v;
    total += v;
  }
  return { grouped, total };
}

// -------------------- Promo codes (/passwords) --------------------
function extractCouponTicketGuids(coupon) {
  const out = new Set();
  const pushGuid = (g) => { if (typeof g === 'string' && g.length >= 30) out.add(g); };

  const arrays = [
    coupon?.ticket_guids, coupon?.ticketGuids,
    coupon?.tickets, coupon?.ticket_types, coupon?.ticketTypes,
    coupon?.discounted_products, coupon?.discountedProducts,
    coupon?.applies_to_ticket_guids, coupon?.appliesToTicketGuids,
    coupon?.applies_to, coupon?.appliesTo
  ];

  for (const a of arrays) {
    if (Array.isArray(a)) {
      for (const x of a) {
        if (typeof x === 'string') pushGuid(x);
        else pushGuid(x?.guid || x?.id || x?.ticket_guid || x?.ticketGuid);
      }
    }
  }

  pushGuid(coupon?.ticket_guid);
  pushGuid(coupon?.ticketGuid);

  return Array.from(out);
}

function extractCouponCodesFromObject(coupon) {
  const out = [];
  const candidates = [coupon?.codes, coupon?.couponCodes, coupon?.coupon_codes, coupon?.couponcodes];
  for (const c of candidates) {
    if (Array.isArray(c)) {
      for (const x of c) {
        if (typeof x === 'string') out.push(x);
        else if (typeof x?.code === 'string') out.push(x.code);
      }
    }
  }
  return out;
}

function isCouponEnabled(c) {
  const status = String(c?.status || c?.state || '').toLowerCase();
  if (status && (status.includes('disabled') || status.includes('archived') || status.includes('trashed'))) return false;
  if (c?.deleted_at || c?.deletedAt || c?.archived_at || c?.archivedAt) return false;
  if (typeof c?.enabled === 'boolean') return c.enabled;
  if (typeof c?.active === 'boolean') return c.active;
  if (typeof c?.isActive === 'boolean') return c.isActive;
  return true;
}

async function fetchCouponCodesBestEffort(couponGuid) {
  const qs = qsForDashboard();
  const paths = [
    `/coupon/${couponGuid}${qs}`,
    `/coupon/${couponGuid}/codes${qs}`,
    `/coupon/${couponGuid}/couponcodes${qs}`,
    `/coupon/${couponGuid}/couponCodes${qs}`
  ];

  for (const p of paths) {
    try {
      const r = await weeztixGet(p, { timeout: 20000, companyScoped: true });
      const data = r.data;

      if (!p.includes('/codes')) {
        const embedded = extractCouponCodesFromObject(data);
        if (embedded.length) return embedded;
      }

      if (Array.isArray(data)) {
        const codes = data.map(x => (typeof x === 'string' ? x : x?.code)).filter(Boolean);
        if (codes.length) return codes;
      }

      const nested = extractCouponCodesFromObject(data);
      if (nested.length) return nested;

      if (Array.isArray(data?.results)) {
        const codes = data.results.map(x => x?.code).filter(Boolean);
        if (codes.length) return codes;
      }
    } catch (_) {}
  }
  return [];
}

async function handlePasswordsCommand(chatId) {
  await ensureAccessToken();
  await fetchCompanyGuidIfNeeded();

  let coupons = [];
  try {
    const r = await weeztixGet(`/coupon/normal${qsForDashboard()}`, { timeout: 25000, companyScoped: true });
    coupons = Array.isArray(r.data) ? r.data : (Array.isArray(r.data?.results) ? r.data.results : []);
  } catch (e) {
    const detail = e?.response?.data ? JSON.stringify(e.response.data).slice(0, 1200) : (e?.message || String(e));
    await tgSend(chatId, `❌ /passwords: impossibile leggere i coupon.\nDettagli: ${detail}`);
    return;
  }

  coupons = coupons.filter(isCouponEnabled);
  if (!coupons.length) {
    await tgSend(chatId, '🔑 /passwords\nNessun promo code/coupon attivo trovato.');
    return;
  }

  const lines = [];
  lines.push('🔑 PASSWORDS (promo codes attivi)\n');

  for (const c of coupons) {
    const guid = c?.guid || c?.id;
    const name = c?.name || c?.title || c?.description || '(coupon)';
    const ticketGuids = extractCouponTicketGuids(c);
    const ticketLabels = ticketGuids.length ? Array.from(new Set(ticketGuids.map(ticketLabel))) : [];

    let codes = extractCouponCodesFromObject(c);
    if (!codes.length && guid) codes = await fetchCouponCodesBestEffort(guid);

    for (const code of codes) {
      lines.push(`• ${code} — ${name}${ticketLabels.length ? ` → ${ticketLabels.join(', ')}` : ''}`);
    }
  }

  await tgSendLong(chatId, lines.join('\n'));
}

// -------------------- Webhook (ACK immediately, process async) --------------------
app.post('/webhook', (req, res) => {
  res.sendStatus(200);

  setImmediate(async () => {
    try {
      const msg = req.body.message;
      if (!msg) return;

      const chatId = msg.chat.id;
      const text = (msg.text || '').trim();

      if (text === '/whoami') {
        await tgSend(chatId, `🆔 Il tuo chat ID è: ${chatId}`);
        return;
      }

      if (text.startsWith('/auth_check')) {
        try {
          await refreshAccessToken();
          await tgSend(chatId, '✅ OAuth OK: access token ottenuto.');
        } catch (e) {
          const detail = e?.response?.data ? JSON.stringify(e.response.data) : (e?.message || String(e));
          await tgSend(chatId, `❌ OAuth FAIL: ${detail}`);
        }
        return;
      }

      if (text.startsWith('/poll_now')) {
        await fetchWeeztixStats();
        await tgSend(chatId, `✅ Poll fatto.\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`);
        return;
      }

      if (text.startsWith('/alerts_on')) {
        alertSubscribers.add(chatId);
        await tgSend(chatId, '🔔 Alert attivati (sell-out + porta se disponibile).');
        return;
      }

      if (text.startsWith('/alerts_off')) {
        alertSubscribers.delete(chatId);
        await tgSend(chatId, '🔕 Alert disattivati.');
        return;
      }

      if (text.startsWith('/passwords')) {
        await handlePasswordsCommand(chatId);
        return;
      }

      if (text.startsWith('/ticket_raw')) {
        // NEW: show first ticket object so we can identify correct capacity field name
        try {
          const r = await weeztixGet(`/event/${WEEZTIX_EVENT_GUID}/ticket${qsForDashboard()}`, { timeout: 25000, companyScoped: true });
          const arr = extractTicketArray(r.data) || [];
          const first = arr[0] || r.data;
          const preview = JSON.stringify(first, null, 2).slice(0, 3500);
          await tgSend(chatId, `🧾 TICKET RAW (first item, trimmed)\n\n${preview}`);
        } catch (e) {
          const detail = e?.response?.data ? JSON.stringify(e.response.data).slice(0, 1200) : (e?.message || String(e));
          await tgSend(chatId, `❌ /ticket_raw failed: ${detail}`);
        }
        return;
      }

      if (text.startsWith('/capacities_debug')) {
        await ensureStatsFresh();
        await ensureCapacitiesFresh();

        const keys = Object.keys(weeztixCapByTicketId || {});
        const sample = keys.slice(0, 15).map(k => {
          const meta = weeztixCapMetaByTicketId[k];
          const m = meta ? ` (field=${meta.fieldPath}${meta.derived ? ', derived' : ''})` : '';
          return `• ${ticketLabel(k)} (${k.slice(0, 8)}…): cap=${weeztixCapByTicketId[k]}${m}`;
        }).join('\n');

        const dbg = JSON.stringify(weeztixCapDebug, null, 2).slice(0, 2500);
        await tgSendLong(chatId,
          `🧪 CAPACITIES DEBUG\n` +
          `Event GUID: ${WEEZTIX_EVENT_GUID}\n` +
          `QS used: ${qsForDashboard() || '(none)'}\n` +
          `Ultimo OK cap: ${weeztixCapLastOkAt || 'mai'}\n` +
          `Errore cap: ${weeztixCapLastError || '—'}\n` +
          `Entries: ${keys.length}\n\n` +
          `Sample:\n${sample || '(vuoto)'}\n\n` +
          `Tried endpoints:\n${dbg}`
        );
        return;
      }

      if (text.startsWith('/biglietti')) {
        await ensureStatsFresh();
        await ensureCapacitiesFresh();

        if (!weeztixTicketStats.length) {
          await tgSend(chatId, `🎟️ Nessun dato ancora.\n\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`);
          return;
        }

        const { grouped: soldByLabel, total: soldTotal } = groupSoldByLabel();
        const { grouped: capByLabel } = groupCapacityByLabel();

        const labels = Object.keys(soldByLabel).sort((a, b) => a.localeCompare(b, 'it'));
        const lines = labels.map(label => {
          const sold = soldByLabel[label] || 0;
          const cap = capByLabel[label];
          if (typeof cap === 'number' && cap > 0) {
            const remaining = Math.max(0, cap - sold);
            return `• ${label}: sold=${sold} | remaining=${remaining}/${cap}`;
          }
          return `• ${label}: sold=${sold} | remaining=n/d`;
        }).join('\n');

        let revenue = 0;
        for (const [label, count] of Object.entries(soldByLabel)) {
          const p = PRICE_MAP[label];
          if (typeof p === 'number') revenue += p * Number(count || 0);
        }

        let soldPctLine = '';
        if (MP_CAPACITY > 0) {
          const pct = Math.round((soldTotal / MP_CAPACITY) * 100);
          soldPctLine = `\n📊 Sold-out: ${pct}% (${soldTotal}/${MP_CAPACITY})`;
        }

        const capNote = (Object.keys(weeztixCapByTicketId || {}).length)
          ? ''
          : '\nℹ️ Capacità per wave non trovata nei ticket object. Prova /ticket_raw per vedere i campi disponibili (probabile che stock sia su “shop attachment”).';

        await tgSend(
          chatId,
          `🎟 BIGLIETTI\n\n${lines}\n\nTotale sold: ${soldTotal}${soldPctLine}\n💸 Revenue stimata: €${revenue.toFixed(2)}\nAggiornato: ${weeztixLastOkAt}${capNote}`
        );
        return;
      }

      // keep other commands as-is (trend/night/debug can be added back similarly if you want)
    } catch (e) {
      console.error('Telegram webhook async error:', e?.response?.data || e.message || e);
      try {
        if (ADMIN_CHAT_ID) await tgSend(ADMIN_CHAT_ID, `⚠️ Bot error: ${e?.message || String(e)}`);
      } catch (_) {}
    }
  });
});

// -------------------- Root --------------------
app.get('/', (req, res) => {
  res.send('MP Telegram Bot is running 🇮🇹');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Bot live on port', PORT));

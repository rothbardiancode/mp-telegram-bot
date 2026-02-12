/**
 * MP Telegram Bot + Weeztix OAuth + Stats Polling + Trend + Event Night
 * STABLE VERSION: polling ON, refresh ONLY on Weeztix API 401.
 *
 * Render ENV required:
 * BOT_TOKEN
 * OAUTH_CLIENT_ID
 * OAUTH_CLIENT_SECRET
 * OAUTH_CLIENT_REDIRECT   (https://mp-telegram-bot-den5.onrender.com/weeztix/callback)
 * WEEZTIX_EVENT_GUID
 * MP_CAPACITY             (e.g. 400)
 *
 * After connecting (first OAuth exchange):
 * WEEZTIX_REFRESH_TOKEN   (used only as seed; thereafter Redis is source of truth)
 *
 * Optional:
 * WEEZTIX_POLL_SECONDS (default 60)
 * ADMIN_CHAT_ID (optional; if set, bot pings you when refresh token rotates)
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
  try {
    await axios.post(`${TELEGRAM_API}/sendMessage`, { chat_id: chatId, text }, { timeout: 15000 });
  } catch (e) {
    console.error('Telegram send error:', e?.response?.data || e.message || e);
    throw e;
  }
}

// -------------------- MP config --------------------
const MP_CAPACITY = Number(process.env.MP_CAPACITY || 0);
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID || null;

// Organizer opt-in alerts (DM)
const alertSubscribers = new Set();

// Sellout alerts (sold-based)
const selloutAlerts = { p80: false, p90: false, p95: false, p100: false };

// Door alerts (scanned-based, only if scanned exists)
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

// Simple Upstash REST helpers.
// Docs: https://docs.upstash.com/redis/features/restapi
async function redisGet(key) {
  if (!redisAvailable()) return null;
  try {
    const url = `${REDIS_URL}/get/${encodeURIComponent(key)}`;
    const r = await axios.post(url, null, {
      headers: { Authorization: `Bearer ${REDIS_TOKEN}` },
      timeout: 10000
    });
    // r.data = { result: string|null }
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
    // Upstash accepts raw body as value for /set/{key}
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

// -------------------- Weeztix OAuth: connect/callback --------------------
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
      return res.status(500).send('Missing OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET / OAUTH_CLIENT_REDIRECT in env');
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

    // If we receive a refresh_token here, seed Redis immediately.
    if (r.data?.refresh_token && typeof r.data.refresh_token === 'string') {
      try {
        await redisSet('weeztix_refresh_token', r.data.refresh_token);
        console.log('🔑 Saved initial refresh_token to Redis');
      } catch (_) {}
    }

    return res.send('✅ Weeztix connected. If needed, check logs. Bot will persist refresh rotations to Redis automatically.');
  } catch (e) {
    console.error('Callback error:', e?.response?.data || e.message || e);
    return res.status(500).send('Token exchange failed. Check logs.');
  }
});

// -------------------- Weeztix tokens (stable mode) --------------------
// Access token cached in memory (no proactive refresh)
let WEEZTIX_ACCESS_TOKEN = null;

// Refresh token runtime (supports rotation) — Redis is the source of truth
let WEEZTIX_REFRESH_TOKEN_RUNTIME = null;

// On startup, load from Redis; if missing, seed from ENV then persist.
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
      console.warn('⚠️ No refresh token in Redis or ENV yet. Use /weeztix/connect to obtain one.');
    }
  } catch (e) {
    console.error('Startup refresh token load error:', e?.message || e);
  }
})();

// Refresh lock (per-process)
let REFRESH_IN_FLIGHT = null;

async function refreshAccessToken() {
  if (REFRESH_IN_FLIGHT) return REFRESH_IN_FLIGHT;

  REFRESH_IN_FLIGHT = (async () => {
    const clientId = process.env.OAUTH_CLIENT_ID;
    const clientSecret = process.env.OAUTH_CLIENT_SECRET;

    if (!clientId || !clientSecret) throw new Error('Missing OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET');

    // Always re-read the latest refresh token from Redis before refreshing
    const tokenFromRedis = await redisGet('weeztix_refresh_token');
    const refreshToken = tokenFromRedis || WEEZTIX_REFRESH_TOKEN_RUNTIME || process.env.WEEZTIX_REFRESH_TOKEN;
    if (!refreshToken) throw new Error('Missing WEEZTIX_REFRESH_TOKEN (Redis/ENV)');

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

    // Ensure access token looks like a JWT (two dots)
    const dotCount = (typeof at === 'string') ? (at.match(/\./g) || []).length : -1;
    console.log('🧪 access_token dots:', dotCount, 'type:', typeof at, 'preview:', (at || '').slice(0, 25));
    if (!at || typeof at !== 'string' || dotCount < 2) {
      throw new Error('Refresh returned non-JWT access_token (expected 2 dots)');
    }

    WEEZTIX_ACCESS_TOKEN = at;

    // If refresh token rotated, persist to Redis and update runtime
    if (r.data.refresh_token && typeof r.data.refresh_token === 'string') {
      WEEZTIX_REFRESH_TOKEN_RUNTIME = r.data.refresh_token;
      await redisSet('weeztix_refresh_token', r.data.refresh_token);
      console.log('🔁 Weeztix rotated refresh_token and saved to Redis');

      if (ADMIN_CHAT_ID) {
        try { await tgSend(ADMIN_CHAT_ID, '🔁 Weeztix: refresh_token rotated and persisted to Redis.'); }
        catch (_) {}
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

// -------------------- Weeztix stats polling --------------------
const WEEZTIX_EVENT_GUID = process.env.WEEZTIX_EVENT_GUID;
const WEEZTIX_POLL_SECONDS = Number(process.env.WEEZTIX_POLL_SECONDS || 60);

let weeztixLastOkAt = null;
let weeztixLastError = null;
let weeztixLastRaw = null;

let weeztixTicketStats = []; // [{ id, sold, scanned }]

// ---- Time series for trend/night ----
const statsSeries = []; // [{ ts, soldTotal, scannedTotal }]
const SERIES_KEEP_MS = 48 * 60 * 60 * 1000; // 48h

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
  for (const b of soldBuckets) {
    if (b && b.key) soldById[String(b.key)] = Number(b.doc_count || 0);
  }

  const scannedById = {};
  if (scannedBuckets && scannedBuckets.length) {
    for (const b of scannedBuckets) {
      if (b && b.key) scannedById[String(b.key)] = Number(b.doc_count || 0);
    }
  }

  for (const [id, sold] of Object.entries(soldById)) {
    out.push({ id, sold, scanned: scannedById[id] || 0 });
  }

  return out;
}

function groupTotals(field) {
  const grouped = {};
  let total = 0;
  for (const t of weeztixTicketStats) {
    const label = ticketLabel(t.id);
    const val = Number(t[field] || 0);
    grouped[label] = (grouped[label] || 0) + val;
    total += val;
  }
  return { grouped, total };
}

async function fetchWeeztixStats() {
  try {
    if (!WEEZTIX_EVENT_GUID) {
      weeztixLastError = 'Missing env var: WEEZTIX_EVENT_GUID';
      return;
    }

    const url = `https://api.weeztix.com/statistics/dashboard/${WEEZTIX_EVENT_GUID}`;

    const callApi = async () => {
      return axios.get(url, {
        headers: { Authorization: `Bearer ${WEEZTIX_ACCESS_TOKEN}` },
        timeout: 20000
      });
    };

    let resp;

    try {
      if (!WEEZTIX_ACCESS_TOKEN) {
        console.log('🔄 No access token → refreshing...');
        await refreshAccessToken();
      }
      resp = await callApi();
    } catch (e) {
      const status = e?.response?.status;
      const msg = e?.response?.data?.error_description || '';

      // Refresh on:
      // - 401 unauthorized
      // - 400 malformed JWT
      if (
        status === 401 ||
        (status === 400 && msg.includes('JWT'))
      ) {
        console.log('🔄 Access token invalid → refreshing...');
        await refreshAccessToken();
        resp = await callApi(); // retry once
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

    // time series store + cleanup
    statsSeries.push({ ts: Date.now(), soldTotal: soldTotalNow, scannedTotal: scannedTotalNow });
    const cutoff = Date.now() - SERIES_KEEP_MS;
    while (statsSeries.length && statsSeries[0].ts < cutoff) statsSeries.shift();

    // Sellout alerts (sold-based)
    if (MP_CAPACITY > 0 && alertSubscribers.size > 0) {
      const pct = soldTotalNow / MP_CAPACITY;
      if (pct >= 0.80 && !selloutAlerts.p80) { selloutAlerts.p80 = true; await broadcastAlert(`🔥 80% SOLD OUT\n\nVenduti: ${soldTotalNow}/${MP_CAPACITY}`); }
      if (pct >= 0.90 && !selloutAlerts.p90) { selloutAlerts.p90 = true; await broadcastAlert(`🚀 90% SOLD OUT\n\nVenduti: ${soldTotalNow}/${MP_CAPACITY}`); }
      if (pct >= 0.95 && !selloutAlerts.p95) { selloutAlerts.p95 = true; await broadcastAlert(`🚨 95% SOLD OUT\n\nVenduti: ${soldTotalNow}/${MP_CAPACITY}\nValuta chiusura biglietti.`); }
      if (pct >= 1.00 && !selloutAlerts.p100) { selloutAlerts.p100 = true; await broadcastAlert(`🟥 SOLD OUT\n\nVenduti: ${soldTotalNow}/${MP_CAPACITY}\nChiudi ticketing.`); }
    }

    // Door alerts (scanned-based) only if scanned exists
    if (MP_CAPACITY > 0 && alertSubscribers.size > 0 && scannedTotalNow > 0) {
      const pct = scannedTotalNow / MP_CAPACITY;
      if (pct >= 0.70 && !doorAlerts.p70) { doorAlerts.p70 = true; await broadcastAlert(`🚪 Porta: 70% capienza\nEntrati: ${scannedTotalNow}/${MP_CAPACITY}`); }
      if (pct >= 0.85 && !doorAlerts.p85) { doorAlerts.p85 = true; await broadcastAlert(`⚠️ Porta: 85% capienza\nEntrati: ${scannedTotalNow}/${MP_CAPACITY}\nOcchio fila / sicurezza.`); }
      if (pct >= 0.95 && !doorAlerts.p95) { doorAlerts.p95 = true; await broadcastAlert(`🚨 Porta: 95% capienza\nEntrati: ${scannedTotalNow}/${MP_CAPACITY}\nValuta STOP ingressi.`); }
    }
  } catch (e) {
    if (e?.response?.data) {
      weeztixLastError = `HTTP ${e.response.status}: ${JSON.stringify(e.response.data).slice(0, 800)}`;
    } else {
      weeztixLastError = e?.message || String(e);
    }
  }
}

// Start polling
setInterval(fetchWeeztixStats, WEEZTIX_POLL_SECONDS * 1000);

// -------------------- Telegram webhook --------------------
app.post('/webhook', async (req, res) => {
  try {
    const msg = req.body.message;
    if (!msg) return res.sendStatus(200);

    const chatId = msg.chat.id;
    const text = (msg.text || '').trim();

    // handy: get your chat id (for ADMIN_CHAT_ID)
    if (text === '/whoami') {
      await tgSend(chatId, `🆔 Il tuo chat ID è: ${chatId}`);
      return res.sendStatus(200);
    }

    if (text.startsWith('/auth_check')) {
      try {
        // Force a token refresh to validate credentials
        await refreshAccessToken();
        await tgSend(chatId, '✅ OAuth OK: access token ottenuto.');
      } catch (e) {
        const detail = e?.response?.data ? JSON.stringify(e.response.data) : (e?.message || String(e));
        await tgSend(chatId, `❌ OAuth FAIL: ${detail}`);
      }
      return res.sendStatus(200);
    }

    if (text.startsWith('/poll_now')) {
      await fetchWeeztixStats();
      await tgSend(chatId, `✅ Poll fatto.\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`);
      return res.sendStatus(200);
    }

    if (text.startsWith('/alerts_on')) {
      alertSubscribers.add(chatId);
      await tgSend(chatId, '🔔 Alert attivati (sell-out + porta se disponibile).');
      return res.sendStatus(200);
    }

    if (text.startsWith('/alerts_off')) {
      alertSubscribers.delete(chatId);
      await tgSend(chatId, '🔕 Alert disattivati.');
      return res.sendStatus(200);
    }

    if (text.startsWith('/debugweeztix')) {
      const sample = weeztixTicketStats.slice(0, 12)
        .map(t => `• ${ticketLabel(t.id)} (${t.id.slice(0, 8)}…) | sold=${t.sold} | scanned=${t.scanned}`)
        .join('\n');

      await tgSend(
        chatId,
        `🛠 DEBUG WEEZTIX\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}\nTicket rows: ${weeztixTicketStats.length}\nSubs alerts: ${alertSubscribers.size}\nMP_CAPACITY: ${MP_CAPACITY || '—'}`
        + `\n\nSample:\n${sample || '(vuoto)'}`
      );
      return res.sendStatus(200);
    }

    if (text.startsWith('/debugweeztix_raw')) {
      const preview = weeztixLastRaw ? JSON.stringify(weeztixLastRaw, null, 2).slice(0, 3500) : '(vuoto)';
      await tgSend(chatId, `🧾 WEEZTIX RAW (trimmed)\n\n${preview}`);
      return res.sendStatus(200);
    }

    if (text.startsWith('/biglietti')) {
      if (!weeztixTicketStats.length) {
        await tgSend(chatId, `🎟️ Nessun dato ancora.\n\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`);
        return res.sendStatus(200);
      }

      const { grouped, total } = groupTotals('sold');
      const lines = Object.entries(grouped).map(([k, v]) => `• ${k}: ${v}`).join('\n');

      let revenue = 0;
      for (const [label, count] of Object.entries(grouped)) {
        const p = PRICE_MAP[label];
        if (typeof p === 'number') revenue += p * Number(count || 0);
      }

      let soldPctLine = '';
      if (MP_CAPACITY > 0) {
        const pct = Math.round((total / MP_CAPACITY) * 100);
        soldPctLine = `\n📊 Sold-out: ${pct}% (${total}/${MP_CAPACITY})`;
      }

      await tgSend(
        chatId,
        `🎟 BIGLIETTI\n\n${lines}\n\nTotale: ${total}${soldPctLine}\n💸 Revenue stimata: €${revenue.toFixed(2)}\nAggiornato: ${weeztixLastOkAt}`
      );
      return res.sendStatus(200);
    }

    if (text.startsWith('/trend')) {
      if (statsSeries.length < 2) {
        await tgSend(chatId, '📈 Trend: serve qualche minuto di dati. Fai /poll_now e riprova tra 2–3 minuti.');
        return res.sendStatus(200);
      }

      const now = Date.now();
      const soldNow = statsSeries[statsSeries.length - 1].soldTotal;

      const findClosest = (msAgo) => {
        const target = now - msAgo;
        for (const p of statsSeries) if (p.ts >= target) return p;
        return statsSeries[0];
      };

      const p1h = findClosest(60 * 60 * 1000);
      const p24h = findClosest(24 * 60 * 60 * 1000);

      const delta1h = soldNow - p1h.soldTotal;
      const delta24h = soldNow - p24h.soldTotal;

      const hoursCovered24 = Math.max(1, (now - p24h.ts) / (60 * 60 * 1000));
      const avgPerHour24 = delta24h / hoursCovered24;

      let etaLine = '⏳ ETA sold-out: n/d';
      if (MP_CAPACITY > 0) {
        const remaining = Math.max(0, MP_CAPACITY - soldNow);
        const pace = delta1h > 0 ? delta1h : (avgPerHour24 > 0 ? avgPerHour24 : 0);

        if (remaining === 0) etaLine = '🟥 SOLD OUT';
        else if (pace > 0) {
          const etaTs = now + (remaining / pace) * 60 * 60 * 1000;
          etaLine = `⏳ ETA sold-out: ~${new Date(etaTs).toLocaleString('it-BE', { timeZone: 'Europe/Brussels' })} (pace ~${pace.toFixed(1)}/h)`;
        } else etaLine = '⏳ ETA sold-out: n/d (pace ~0)';
      }

      await tgSend(
        chatId,
        `📈 TREND VENDITE\n` +
        `Ultima ora: +${delta1h}\n` +
        `Media (ultime ${hoursCovered24.toFixed(1)}h): ${avgPerHour24.toFixed(1)}/h\n` +
        `${etaLine}\n` +
        `Venduti ora: ${soldNow}${MP_CAPACITY ? `/${MP_CAPACITY}` : ''}`
      );
      return res.sendStatus(200);
    }

    if (text.startsWith('/night')) {
      if (statsSeries.length < 2) {
        await tgSend(chatId, '🌙 Event Night: serve qualche punto dati. Fai /poll_now e riprova tra 2–3 minuti.');
        return res.sendStatus(200);
      }

      const now = Date.now();
      const last = statsSeries[statsSeries.length - 1];

      const target15 = now - 15 * 60 * 1000;
      let p15 = null;
      for (const p of statsSeries) { if (p.ts >= target15) { p15 = p; break; } }
      p15 = p15 || statsSeries[0];

      const scannedNow = last.scannedTotal || 0;
      const soldNow = last.soldTotal || 0;

      const delta15 = scannedNow - (p15.scannedTotal || 0);
      const perHour = delta15 * 4;

      const useProxy = scannedNow === 0;
      const used = useProxy ? soldNow : scannedNow;

      let capLine = 'Capienza: n/d';
      if (MP_CAPACITY > 0) capLine = `Capienza: ${Math.round((used / MP_CAPACITY) * 100)}% (${used}/${MP_CAPACITY})`;

      const paceLine = useProxy ? '⚡ Ritmo ingressi: n/d (scanned non disponibile)' : `⚡ Ritmo ingressi (ult 15m): ${delta15} (+${perHour}/h)`;
      const proxyNote = useProxy ? '\nℹ️ Nota: non vedo “scanned” da Weeztix → uso i venduti come proxy (non ideale per la porta).' : '';

      await tgSend(
        chatId,
        `🌙 EVENT NIGHT\n🚪 Entrati: ${useProxy ? 'n/d' : scannedNow}\n🎟 Venduti: ${soldNow}\n${paceLine}\n📊 ${capLine}${proxyNote}`
      );
      return res.sendStatus(200);
    }

    return res.sendStatus(200);
  } catch (e) {
    console.error('Telegram webhook error:', e?.response?.data || e.message || e);
    return res.sendStatus(200);
  }
});

app.get('/', (req, res) => {
  res.send('MP Telegram Bot is running 🇮🇹');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Bot live on port', PORT));

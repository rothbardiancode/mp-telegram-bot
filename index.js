/**
 * MP Telegram Bot + Weeztix OAuth + Polling
 *
 * Required ENV:
 * - BOT_TOKEN
 * - OAUTH_CLIENT_ID
 * - OAUTH_CLIENT_SECRET
 * - OAUTH_CLIENT_REDIRECT  (e.g. https://mp-telegram-bot-den5.onrender.com/weeztix/callback)
 * - WEEZTIX_EVENT_GUID
 * - MP_CAPACITY (e.g. 400)
 *
 * After first connect:
 * - WEEZTIX_REFRESH_TOKEN
 *
 * Optional:
 * - WEEZTIX_POLL_SECONDS (default 60)
 */

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// -------------------- Telegram --------------------
const BOT_TOKEN = process.env.BOT_TOKEN;
const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

async function tgSend(chatId, text) {
  await axios.post(`${TELEGRAM_API}/sendMessage`, {
    chat_id: chatId,
    text
  });
}

// -------------------- MP config --------------------
const MP_CAPACITY = Number(process.env.MP_CAPACITY || 0);

// Alerts opt-in (DM)
const alertSubscribers = new Set();
const capacityAlerts = { cap80Sent: false, cap95Sent: false };

async function broadcastAlert(message) {
  const ids = Array.from(alertSubscribers);
  for (const id of ids) {
    try {
      await tgSend(id, message);
    } catch (e) {
      alertSubscribers.delete(id);
    }
  }
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

    // Exchange authorization code for tokens
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

    // Contains refresh_token (copy it into Render ENV as WEEZTIX_REFRESH_TOKEN)
    console.log('WEEZTIX TOKEN RESPONSE:', r.data);

    return res.send('✅ Weeztix connected. Check Render logs for refresh_token and set WEEZTIX_REFRESH_TOKEN in env.');
  } catch (e) {
    console.error('Callback error:', e?.response?.data || e.message || e);
    return res.status(500).send('Token exchange failed. Check Render logs.');
  }
});

// -------------------- Weeztix OAuth: refresh access token --------------------
let WEEZTIX_ACCESS_TOKEN = null;
let WEEZTIX_ACCESS_EXPIRES_AT = 0;

async function refreshAccessToken() {
  const now = Date.now();

  if (WEEZTIX_ACCESS_TOKEN && now < WEEZTIX_ACCESS_EXPIRES_AT - 60000) {
    return WEEZTIX_ACCESS_TOKEN;
  }

  const clientId = process.env.OAUTH_CLIENT_ID;
  const clientSecret = process.env.OAUTH_CLIENT_SECRET;
  const refreshToken = process.env.WEEZTIX_REFRESH_TOKEN;

  if (!clientId || !clientSecret) throw new Error('Missing OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET');
  if (!refreshToken) throw new Error('Missing WEEZTIX_REFRESH_TOKEN');

  // Use x-www-form-urlencoded; send BOTH Basic Auth and client_id/client_secret in body (most compatible)
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  const params = new URLSearchParams();
  params.append('grant_type', 'refresh_token');
  params.append('refresh_token', refreshToken);
  params.append('client_id', clientId);
  params.append('client_secret', clientSecret);

  const r = await axios.post('https://auth.weeztix.com/tokens', params, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${basicAuth}`
    },
    timeout: 15000
  });

  WEEZTIX_ACCESS_TOKEN = r.data.access_token;
  WEEZTIX_ACCESS_EXPIRES_AT = now + (Number(r.data.expires_in || 0) * 1000);

  return WEEZTIX_ACCESS_TOKEN;
}

// -------------------- Weeztix stats polling --------------------
const WEEZTIX_EVENT_GUID = process.env.WEEZTIX_EVENT_GUID;
const WEEZTIX_POLL_SECONDS = Number(process.env.WEEZTIX_POLL_SECONDS || 60);

let weeztixLastOkAt = null;
let weeztixLastError = null;
let weeztixTicketStats = []; // [{name, sold, scanned}]
let weeztixLastRaw = null;

function parseWeeztixStats(data) {
  const out = [];

  const aggs = data && data.aggregations ? data.aggregations : null;
  if (!aggs) return out;

  const getBuckets = (obj, pathArr) => {
    let cur = obj;
    for (const p of pathArr) {
      if (!cur || typeof cur !== 'object') return null;
      cur = cur[p];
    }
    return Array.isArray(cur) ? cur : null;
  };

  // SOLD buckets (this matches your payload)
  const soldBuckets =
    getBuckets(aggs, ['ticketCount', 'statistics', 'statistics', 'buckets']) ||
    getBuckets(aggs, ['ticketCount', 'statistics', 'buckets']) ||
    getBuckets(aggs, ['ticketCount', 'buckets']);

  // Try to find SCANNED buckets (may or may not exist in payload)
  let scannedBuckets = null;
  for (const [k, v] of Object.entries(aggs)) {
    const key = String(k).toLowerCase();
    if (key.includes('scan') || key.includes('scanned') || key.includes('check') || key.includes('entry')) {
      scannedBuckets =
        getBuckets(v, ['statistics', 'statistics', 'buckets']) ||
        getBuckets(v, ['statistics', 'buckets']) ||
        getBuckets(v, ['buckets']);
      if (scannedBuckets) break;
    }
  }

  const soldById = {};
  if (soldBuckets) {
    for (const b of soldBuckets) {
      if (b && b.key) soldById[String(b.key)] = Number(b.doc_count || 0);
    }
  }

  const scannedById = {};
  if (scannedBuckets) {
    for (const b of scannedBuckets) {
      if (b && b.key) scannedById[String(b.key)] = Number(b.doc_count || 0);
    }
  }

  const ids = Object.keys(soldById);
  if (!ids.length) return out;

  for (const id of ids) {
    out.push({
      name: id,
      sold: soldById[id] || 0,
      scanned: scannedById[id] || 0
    });
  }

  return out;
};

  const aggs = data && data.aggregations ? data.aggregations : null;
  if (!aggs) return out;

  // 1) SOLD: aggregations.ticketCount.statistics.statistics.buckets
  const soldBuckets =
    getBuckets(aggs, ['ticketCount', 'statistics', 'statistics', 'buckets']) ||
    getBuckets(aggs, ['ticketCount', 'statistics', 'buckets']) ||
    getBuckets(aggs, ['ticketCount', 'buckets']);

  // 2) SCANNED: cerchiamo un aggregation che contenga "scan"/"scanned"/"check" con buckets
  let scannedBuckets = null;
  for (const [k, v] of Object.entries(aggs)) {
    const key = String(k).toLowerCase();
    if (key.includes('scan') || key.includes('scanned') || key.includes('check') || key.includes('entry')) {
      scannedBuckets =
        getBuckets(v, ['statistics', 'statistics', 'buckets']) ||
        getBuckets(v, ['statistics', 'buckets']) ||
        getBuckets(v, ['buckets']);
      if (scannedBuckets) break;
    }
  }

  // Normalizziamo in map guid -> count
  const soldById = {};
  if (soldBuckets) {
    for (const b of soldBuckets) {
      if (b && b.key) soldById[String(b.key)] = Number(b.doc_count || 0);
    }
  }

  const scannedById = {};
  if (scannedBuckets) {
    for (const b of scannedBuckets) {
      if (b && b.key) scannedById[String(b.key)] = Number(b.doc_count || 0);
    }
  }

  // Se non abbiamo nemmeno soldBuckets, non possiamo fare nulla
  const ids = Object.keys(soldById);
  if (!ids.length) return out;

  // Nomi: per ora usiamo il GUID (poi lo mappiamo a Wave 1/2/Final)
  for (const id of ids) {
    out.push({
      name: id,                 // per ora GUID
      sold: soldById[id] || 0,
      scanned: scannedById[id] || 0
    });
  }

  return out;
}

  // Try common array shapes
  const arrays = [
    data?.ticket_types,
    data?.tickets,
    data?.ticketTypes,
    data?.data?.ticket_types,
    data?.data?.tickets
  ].filter(Array.isArray);

  for (const arr of arrays) {
    for (const t of arr) {
      push(
        t?.name || t?.title || t?.key,
        t?.sold_count ?? t?.sold ?? t?.count_sold ?? t?.total_sold ?? t?.soldCount,
        t?.scanned_count ?? t?.scanned ?? t?.count_scanned ?? t?.total_scanned ?? t?.scannedCount
      );
    }
    if (out.length) return out;
  }

  // Try aggregation buckets
  const buckets =
    data?.aggregations?.ticket_types?.buckets ||
    data?.aggregations?.tickets?.buckets ||
    data?.aggs?.ticket_types?.buckets ||
    data?.aggs?.tickets?.buckets ||
    data?.data?.aggregations?.ticket_types?.buckets ||
    data?.data?.aggregations?.tickets?.buckets;

  if (Array.isArray(buckets)) {
    for (const b of buckets) {
      const sold = b?.sold_count?.value ?? b?.sold?.value ?? b?.sold_count ?? b?.sold ?? b?.doc_count;
      const scanned = b?.scanned_count?.value ?? b?.scanned?.value ?? b?.scanned_count ?? b?.scanned ?? 0;
      push(b?.key, sold, scanned);
    }
    if (out.length) return out;
  }

  // Try object map
  if (data?.ticket_types && typeof data.ticket_types === 'object' && !Array.isArray(data.ticket_types)) {
    for (const [name, v] of Object.entries(data.ticket_types)) {
      push(
        name,
        v?.sold_count ?? v?.sold ?? v?.count_sold ?? v?.total_sold,
        v?.scanned_count ?? v?.scanned ?? v?.count_scanned ?? v?.total_scanned
      );
    }
    if (out.length) return out;
  }

  return [];

function waveLabel(name) {
  const n = String(name || '').toLowerCase();
  if (n.includes('wave 1') || n.includes('first') || n.includes('early')) return 'Wave 1';
  if (n.includes('wave 2') || n.includes('second')) return 'Wave 2';
  if (n.includes('wave 3') || n.includes('third')) return 'Wave 3';
  if (n.includes('final') || n.includes('last')) return 'Final';
  return 'Altra';
}

function groupByWave(stats, field) {
  const grouped = {};
  let total = 0;
  for (const s of stats) {
    const label = waveLabel(s.name);
    const val = Number(s[field] || 0);
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

    const token = await refreshAccessToken();

    const url = `https://api.weeztix.com/statistics/dashboard/${WEEZTIX_EVENT_GUID}`;
    const resp = await axios.get(url, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 15000
    });

    weeztixLastRaw = resp.data ?? { _empty: true };

    const parsed = parseWeeztixStats(resp.data);
    if (!parsed.length) {
      weeztixLastError = 'Stats fetched but parsing returned empty';
      return;
    }

    weeztixTicketStats = parsed;
    weeztixLastOkAt = new Date().toISOString();
    weeztixLastError = null;

    // Capacity alerts
    if (MP_CAPACITY > 0 && alertSubscribers.size > 0) {
      const scannedTotal = weeztixTicketStats.reduce((sum, t) => sum + (Number(t.scanned) || 0), 0);
      const ratio = scannedTotal / MP_CAPACITY;

      if (ratio >= 0.80 && !capacityAlerts.cap80Sent) {
        capacityAlerts.cap80Sent = true;
        await broadcastAlert(`⚠️ CAPACITÀ 80%\n\nEntrati: ${scannedTotal} / ${MP_CAPACITY}`);
      }
      if (ratio >= 0.95 && !capacityAlerts.cap95Sent) {
        capacityAlerts.cap95Sent = true;
        await broadcastAlert(`🚨 CAPACITÀ 95%\n\nEntrati: ${scannedTotal} / ${MP_CAPACITY}\nValutare STOP ingressi.`);
      }
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
fetchWeeztixStats();

// -------------------- Telegram webhook --------------------
app.post('/webhook', async (req, res) => {
  try {
    const msg = req.body.message;
    if (!msg) return res.sendStatus(200);

    const chatId = msg.chat.id;
    const text = (msg.text || '').trim();

    // AUTH TEST
    if (text.startsWith('/auth_check')) {
      try {
        await refreshAccessToken();
        await tgSend(chatId, '✅ OAuth OK: access token ottenuto.');
      } catch (e) {
        const detail = e?.response?.data ? JSON.stringify(e.response.data) : (e?.message || String(e));
        await tgSend(chatId, `❌ OAuth FAIL: ${detail}`);
      }
      return res.sendStatus(200);
    }

    // Force poll now
    if (text.startsWith('/poll_now')) {
      await fetchWeeztixStats();
      await tgSend(chatId, `✅ Poll fatto.\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`);
      return res.sendStatus(200);
    }

    // Debug raw
    if (text.startsWith('/debugweeztix_raw')) {
      const preview = weeztixLastRaw ? JSON.stringify(weeztixLastRaw, null, 2).slice(0, 3500) : '(vuoto)';
      await tgSend(chatId, `🧾 WEEZTIX RAW (trimmed)\n\n${preview}`);
      return res.sendStatus(200);
    }

    // Debug summary
    if (text.startsWith('/debugweeztix')) {
      const sample = weeztixTicketStats.slice(0, 12)
        .map(s => `• ${s.name} | sold=${s.sold} | scanned=${s.scanned}`)
        .join('\n');

      await tgSend(
        chatId,
        `🛠 DEBUG WEEZTIX\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}\nSubs alerts: ${alertSubscribers.size}\nMP_CAPACITY: ${MP_CAPACITY || '—'}\n\nSample:\n${sample || '(vuoto)'}`
      );
      return res.sendStatus(200);
    }

    // Commands: tickets sold
    if (text.startsWith('/biglietti')) {
      if (!weeztixTicketStats.length) {
        await tgSend(chatId, `🎟️ Nessun dato ancora.\n\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`);
        return res.sendStatus(200);
      }
      const { grouped, total } = groupByWave(weeztixTicketStats, 'sold');
      const lines = Object.entries(grouped).map(([k, v]) => `• ${k}: ${v}`).join('\n');
      await tgSend(chatId, `🎟 BIGLIETTI VENDUTI\n\n${lines}\n\nTotale: ${total}\nAggiornato: ${weeztixLastOkAt}`);
      return res.sendStatus(200);
    }

    // Commands: scanned entries
    if (text.startsWith('/entrate')) {
      if (!weeztixTicketStats.length) {
        await tgSend(chatId, `🚪 Nessun dato ancora.\n\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`);
        return res.sendStatus(200);
      }
      const { grouped, total } = groupByWave(weeztixTicketStats, 'scanned');
      const lines = Object.entries(grouped).map(([k, v]) => `• ${k}: ${v}`).join('\n');

      let capLine = '';
      if (MP_CAPACITY > 0) {
        const pct = Math.round((total / MP_CAPACITY) * 100);
        capLine = `\nCapienza: ${pct}% (${total}/${MP_CAPACITY})`;
      }

      await tgSend(chatId, `🚪 ENTRATE (SCANNER)\n\n${lines}\n\nTotale entrati: ${total}${capLine}\nAggiornato: ${weeztixLastOkAt}`);
      return res.sendStatus(200);
    }

    // Alerts opt-in
    if (text.startsWith('/alerts_on')) {
      alertSubscribers.add(chatId);
      await tgSend(chatId, '🔔 Alert attivati. Ti avviso a 80% e 95% capienza.');
      return res.sendStatus(200);
    }

    if (text.startsWith('/alerts_off')) {
      alertSubscribers.delete(chatId);
      await tgSend(chatId, '🔕 Alert disattivati.');
      return res.sendStatus(200);
    }

    if (text.startsWith('/testalerts')) {
      alertSubscribers.add(chatId);
      await tgSend(chatId, '🧪 Test alerts: ok. Ti invio due messaggi di prova.');
      await broadcastAlert('⚠️ [TEST] CAPACITÀ 80%\n\nEntrati: 320 / 400');
      await broadcastAlert('🚨 [TEST] CAPACITÀ 95%\n\nEntrati: 380 / 400\nValutare STOP ingressi.');
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
app.listen(PORT, () => console.log('Bot live'));

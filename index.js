/**
 * MP Telegram Bot + Weeztix OAuth + Stats Polling
 *
 * Render ENV required:
 * BOT_TOKEN
 * OAUTH_CLIENT_ID
 * OAUTH_CLIENT_SECRET
 * OAUTH_CLIENT_REDIRECT   (https://mp-telegram-bot-den5.onrender.com/weeztix/callback)
 * WEEZTIX_EVENT_GUID
 * MP_CAPACITY             (e.g. 400)
 *
 * After connecting:
 * WEEZTIX_REFRESH_TOKEN
 *
 * Optional:
 * WEEZTIX_POLL_SECONDS (default 60)
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

    // Exchange authorization_code for tokens
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

    console.log('WEEZTIX TOKEN RESPONSE:', r.data); // copy refresh_token to env

    return res.send('✅ Weeztix connected. Check Render logs and set WEEZTIX_REFRESH_TOKEN in env.');
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

  if (WEEZTIX_ACCESS_TOKEN && now < WEEZTIX_ACCESS_EXPIRES_AT - 60_000) {
    return WEEZTIX_ACCESS_TOKEN;
  }

  const clientId = process.env.OAUTH_CLIENT_ID;
  const clientSecret = process.env.OAUTH_CLIENT_SECRET;
  const refreshToken = process.env.WEEZTIX_REFRESH_TOKEN;

  if (!clientId || !clientSecret) throw new Error('Missing OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET');
  if (!refreshToken) throw new Error('Missing WEEZTIX_REFRESH_TOKEN');

  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  const params = new URLSearchParams();
  params.append('grant_type', 'refresh_token');
  params.append('refresh_token', refreshToken);

  // Many providers accept Basic Auth; Weeztix worked for you with auth_check.
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
let weeztixLastRaw = null;

// normalized stats: [{ id, sold, scanned }]
let weeztixTicketStats = [];

/**
 * Parser tailored to your payload:
 * aggregations.ticketCount.statistics.statistics.buckets => [{key: <ticketTypeGuid>, doc_count: <sold>}]
 *
 * For scanned, we try to discover an aggregation key containing scan/check/entry.
 * If not found, scanned will be 0.
 */
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

  // SOLD buckets (confirmed by your raw)
  const soldBuckets =
    getBuckets(aggs, ['ticketCount', 'statistics', 'statistics', 'buckets']) ||
    getBuckets(aggs, ['ticketCount', 'statistics', 'buckets']) ||
    getBuckets(aggs, ['ticketCount', 'buckets']);

  if (!soldBuckets || soldBuckets.length === 0) return out;

  // SCANNED buckets: try best-effort discovery
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
    out.push({
      id,
      sold,
      scanned: scannedById[id] || 0
    });
  }

  return out;
}

/**
 * Simple mapping of ticket-type GUID to wave names.
 * For now returns the GUID itself. We'll hardcode mapping once you paste /biglietti output.
 */
function ticketLabel(id) {
  // TODO: after first successful /biglietti, we map these IDs to "Wave 1/Wave 2/Final"
  return id;
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

    const token = await refreshAccessToken();

    const url = `https://api.weeztix.com/statistics/dashboard/${WEEZTIX_EVENT_GUID}`;
    const resp = await axios.get(url, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 20000
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

    // Capacity alerts based on scanned total
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

    // Health debug
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

    if (text.startsWith('/poll_now')) {
      await fetchWeeztixStats();
      await tgSend(chatId, `✅ Poll fatto.\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`);
      return res.sendStatus(200);
    }

    if (text.startsWith('/debugweeztix_raw')) {
      const preview = weeztixLastRaw ? JSON.stringify(weeztixLastRaw, null, 2).slice(0, 3500) : '(vuoto)';
      await tgSend(chatId, `🧾 WEEZTIX RAW (trimmed)\n\n${preview}`);
      return res.sendStatus(200);
    }

    if (text.startsWith('/debugweeztix')) {
      const sample = weeztixTicketStats.slice(0, 12)
        .map(t => `• ${t.id} | sold=${t.sold} | scanned=${t.scanned}`)
        .join('\n');

      await tgSend(
        chatId,
        `🛠 DEBUG WEEZTIX\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}\nTicket rows: ${weeztixTicketStats.length}\nSubs alerts: ${alertSubscribers.size}\nMP_CAPACITY: ${MP_CAPACITY || '—'}\n\nSample:\n${sample || '(vuoto)'}`
      );
      return res.sendStatus(200);
    }

    // Commands
    if (text.startsWith('/biglietti')) {
      if (!weeztixTicketStats.length) {
        await tgSend(chatId, `🎟️ Nessun dato ancora.\n\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`);
        return res.sendStatus(200);
      }
      const { grouped, total } = groupTotals('sold');
      const lines = Object.entries(grouped).map(([k, v]) => `• ${k}: ${v}`).join('\n');
      await tgSend(chatId, `🎟 BIGLIETTI (da ticketCount)\n\n${lines}\n\nTotale: ${total}\nAggiornato: ${weeztixLastOkAt}`);
      return res.sendStatus(200);
    }

    if (text.startsWith('/entrate')) {
      if (!weeztixTicketStats.length) {
        await tgSend(chatId, `🚪 Nessun dato ancora.\n\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`);
        return res.sendStatus(200);
      }
      const { grouped, total } = groupTotals('scanned');
      const lines = Object.entries(grouped).map(([k, v]) => `• ${k}: ${v}`).join('\n');

      let capLine = '';
      if (MP_CAPACITY > 0) {
        const pct = Math.round((total / MP_CAPACITY) * 100);
        capLine = `\nCapienza: ${pct}% (${total}/${MP_CAPACITY})`;
      }

      // Important note if scans are missing
      const note = total === 0
        ? `\n\nℹ️ Nota: se vedi tutto 0, nel payload Weeztix non c’è (ancora) un’aggregazione “scan”.`
        : '';

      await tgSend(chatId, `🚪 ENTRATE (best effort)\n\n${lines}\n\nTotale entrati: ${total}${capLine}${note}\nAggiornato: ${weeztixLastOkAt}`);
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

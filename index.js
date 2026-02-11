/**
 * MP Telegram Bot (Render) + Weeztix OAuth + Polling + Alerts
 *
 * Required ENV on Render:
 * - BOT_TOKEN
 * - OAUTH_CLIENT_ID
 * - OAUTH_CLIENT_SECRET
 * - WEEZTIX_REFRESH_TOKEN
 * - WEEZTIX_EVENT_GUID
 * - MP_CAPACITY (e.g. 400)
 *
 * Optional:
 * - WEEZTIX_POLL_SECONDS (default 60)
 */

const express = require('express')
const axios = require('axios')
const crypto = require('crypto')

const app = express()
app.use(express.json())

// -------------------- Telegram --------------------
const BOT_TOKEN = process.env.BOT_TOKEN
const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`

async function tgSend(chatId, text, extra = {}) {
  return axios.post(`${TELEGRAM_API}/sendMessage`, {
    chat_id: chatId,
    text,
    ...extra
  })
}

// -------------------- MP settings --------------------
const MP_CAPACITY = Number(process.env.MP_CAPACITY || 0)

// alert opt-in (no group needed)
const alertSubscribers = new Set() // chat_id who opted in
const capacityAlerts = { cap80Sent: false, cap95Sent: false }

async function broadcastAlert(message) {
  const ids = Array.from(alertSubscribers)
  for (const id of ids) {
    try {
      await tgSend(id, message)
    } catch (e) {
      // user blocked the bot or chat invalid -> remove
      alertSubscribers.delete(id)
    }
  }
}

// -------------------- Weeztix OAuth (refresh flow) --------------------
let WEEZTIX_ACCESS_TOKEN = null
let WEEZTIX_ACCESS_EXPIRES_AT = 0

async function refreshAccessToken() {
  const now = Date.now()

  // reuse token if still valid (1 min safety margin)
  if (WEEZTIX_ACCESS_TOKEN && now < WEEZTIX_ACCESS_EXPIRES_AT - 60_000) {
    return WEEZTIX_ACCESS_TOKEN
  }

  if (!process.env.WEEZTIX_REFRESH_TOKEN) {
    throw new Error('Missing env var: WEEZTIX_REFRESH_TOKEN')
  }
  if (!process.env.OAUTH_CLIENT_ID || !process.env.OAUTH_CLIENT_SECRET) {
    throw new Error('Missing env var: OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET')
  }

  const r = await axios.post('https://auth.weeztix.com/tokens', {
    grant_type: 'refresh_token',
    refresh_token: process.env.WEEZTIX_REFRESH_TOKEN,
    client_id: process.env.OAUTH_CLIENT_ID,
    client_secret: process.env.OAUTH_CLIENT_SECRET
  })

  WEEZTIX_ACCESS_TOKEN = r.data.access_token
  WEEZTIX_ACCESS_EXPIRES_AT = now + (Number(r.data.expires_in || 0) * 1000)

  return WEEZTIX_ACCESS_TOKEN
}

// -------------------- Weeztix stats cache --------------------
const WEEZTIX_EVENT_GUID = process.env.WEEZTIX_EVENT_GUID
const WEEZTIX_POLL_SECONDS = Number(process.env.WEEZTIX_POLL_SECONDS || 60)

let weeztixLastOkAt = null
let weeztixLastError = null

// normalized ticket stats (per ticket type)
// [{ name, sold, scanned }]
let weeztixTicketStats = []

function parseWeeztixStats(data) {
  const out = []

  const push = (name, sold, scanned) => {
    if (!name) return
    out.push({
      name: String(name),
      sold: Number(sold ?? 0),
      scanned: Number(scanned ?? 0)
    })
  }

  // 1) direct arrays (different possible keys)
  const directArrays = [
    data?.ticket_types,
    data?.tickets,
    data?.ticketTypes,
    data?.tickettypes
  ].filter(Array.isArray)

  for (const arr of directArrays) {
    for (const t of arr) {
      push(
        t?.name || t?.title || t?.key,
        t?.sold_count ?? t?.sold ?? t?.count_sold ?? t?.total_sold,
        t?.scanned_count ?? t?.scanned ?? t?.count_scanned ?? t?.total_scanned
      )
    }
    if (out.length) return out
  }

  // 2) elastic-style buckets
  const buckets =
    data?.aggregations?.ticket_types?.buckets ||
    data?.aggregations?.tickets?.buckets ||
    data?.aggs?.ticket_types?.buckets ||
    data?.aggs?.tickets?.buckets

  if (Array.isArray(buckets)) {
    for (const b of buckets) {
      const sold =
        b?.sold_count?.value ?? b?.sold?.value ?? b?.sold_count ?? b?.sold ?? b?.doc_count
      const scanned =
        b?.scanned_count?.value ?? b?.scanned?.value ?? b?.scanned_count ?? b?.scanned ?? 0
      push(b?.key, sold, scanned)
    }
    if (out.length) return out
  }

  // 3) last resort: shallow bucket search
  for (const [k, v] of Object.entries(data || {})) {
    if (v && typeof v === 'object') {
      const maybeBuckets = v?.buckets
      if (Array.isArray(maybeBuckets)) {
        for (const b of maybeBuckets) {
          push(
            b?.key || b?.name,
            b?.sold_count?.value ?? b?.sold ?? b?.doc_count,
            b?.scanned_count?.value ?? b?.scanned ?? 0
          )
        }
        if (out.length) return out
      }
    }
  }

  return []
}

function waveLabel(name = '') {
  const n = name.toLowerCase()
  // customize these to your exact ticket names
  if (n.includes('wave 1') || n.includes('first wave') || n.includes('early')) return 'Wave 1'
  if (n.includes('wave 2') || n.includes('second wave')) return 'Wave 2'
  if (n.includes('wave 3') || n.includes('third wave')) return 'Wave 3'
  if (n.includes('final') || n.includes('last')) return 'Final'
  return 'Altra'
}

function groupByWave(stats, field) {
  const grouped = {}
  let total = 0
  for (const s of stats) {
    const label = waveLabel(s.name)
    const val = Number(s[field] || 0)
    grouped[label] = (grouped[label] || 0) + val
    total += val
  }
  return { grouped, total }
}

async function fetchWeeztixStats() {
  try {
    if (!WEEZTIX_EVENT_GUID) {
      weeztixLastError = 'Missing env var: WEEZTIX_EVENT_GUID'
      return
    }

    const token = await refreshAccessToken()

    // Dashboard statistics endpoint (event scoped)
    const url = `https://api.weeztix.com/statistics/dashboard/${WEEZTIX_EVENT_GUID}`

    const resp = await axios.get(url, {
      timeout: 15000,
      headers: {
        Authorization: `Bearer ${token}`
      }
    })

    const parsed = parseWeeztixStats(resp.data)

    if (!parsed.length) {
      weeztixLastError = 'Stats fetched but parsing returned empty (use /debugweeztix)'
      return
    }

    weeztixTicketStats = parsed
    weeztixLastOkAt = new Date().toISOString()
    weeztixLastError = null

    // ---- Capacity alerts (80% / 95%) ----
    if (MP_CAPACITY > 0 && alertSubscribers.size > 0) {
      const scannedTotal = weeztixTicketStats.reduce((sum, t) => sum + (Number(t.scanned) || 0), 0)
      const ratio = scannedTotal / MP_CAPACITY

      if (ratio >= 0.80 && !capacityAlerts.cap80Sent) {
        capacityAlerts.cap80Sent = true
        await broadcastAlert(`⚠️ CAPACITÀ 80%\n\nEntrati: ${scannedTotal} / ${MP_CAPACITY}\nOcchio agli ingressi 👀`)
      }

      if (ratio >= 0.95 && !capacityAlerts.cap95Sent) {
        capacityAlerts.cap95Sent = true
        await broadcastAlert(`🚨 CAPACITÀ 95%\n\nEntrati: ${scannedTotal} / ${MP_CAPACITY}\nValutare STOP ingressi.`)
      }
    }
  } catch (e) {
    // normalize error
    if (e?.response?.data) {
      weeztixLastError = `HTTP ${e.response.status}: ${JSON.stringify(e.response.data).slice(0, 600)}`
    } else {
      weeztixLastError = e?.message || String(e)
    }
  }
}

// start polling
setInterval(fetchWeeztixStats, WEEZTIX_POLL_SECONDS * 1000)
// run once at boot
fetchWeeztixStats()

// -------------------- Optional: OAuth connect/callback (only if you want re-connect) --------------------
// If you don't need this anymore, you can delete these routes safely.
// They are handy if you ever need to generate a new refresh token.
let OAUTH_STATE = null

app.get('/weeztix/connect', (req, res) => {
  OAUTH_STATE = crypto.randomBytes(16).toString('hex')
  const url = new URL('https://login.weeztix.com/login')
  url.searchParams.set('client_id', process.env.OAUTH_CLIENT_ID)
  url.searchParams.set('redirect_uri', process.env.OAUTH_CLIENT_REDIRECT || 'https://example.com')
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('state', OAUTH_STATE)
  res.redirect(url.toString())
})

app.get('/weeztix/callback', async (req, res) => {
  try {
    if (!req.query.code) return res.status(400).send('Missing code')
    if (!req.query.state || req.query.state !== OAUTH_STATE) return res.status(400).send('Bad state')

    const r = await axios.post('https://auth.weeztix.com/tokens', {
      grant_type: 'authorization_code',
      client_id: process.env.OAUTH_CLIENT_ID,
      client_secret: process.env.OAUTH_CLIENT_SECRET,
      redirect_uri: process.env.OAUTH_CLIENT_REDIRECT,
      code: req.query.code
    })

    // ⚠️ This will include refresh_token. Do NOT paste it publicly.
    console.log('WEEZTIX TOKEN RESPONSE:', r.data)

    res.send('✅ Weeztix connected. Check Render logs and set WEEZTIX_REFRESH_TOKEN in env vars.')
  } catch (e) {
    console.error(e?.response?.data || e.message)
    res.status(500).send('Token exchange failed (check logs).')
  }
})

// -------------------- Documents (upload/docs) --------------------
const userState = {}
const documents = {}

// TTL cleanup for documents (24h)
setInterval(() => {
  const now = Date.now()
  for (const id of Object.keys(documents)) {
    if (documents[id].expiresAt <= now) delete documents[id]
  }
}, 60_000)

// -------------------- Telegram webhook --------------------
app.post('/webhook', async (req, res) => {
  try {
    const message = req.body.message
    if (!message) return res.sendStatus(200)

    const chatId = message.chat.id
    const text = (message.text || '').trim()

    // --- Weeztix commands ---
    if (text.startsWith('/debugweeztix')) {
      const sample = weeztixTicketStats
        .slice(0, 12)
        .map(s => `• ${s.name} | sold=${s.sold} | scanned=${s.scanned}`)
        .join('\n')

      await tgSend(
        chatId,
        `🛠 DEBUG WEEZTIX\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}\n\nSample:\n${sample || '(vuoto)'}`
      )
      return res.sendStatus(200)
    }

    if (text.startsWith('/biglietti')) {
      if (!weeztixTicketStats.length) {
        await tgSend(chatId, `🎟️ Nessun dato ancora.\n\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`)
        return res.sendStatus(200)
      }
      const { grouped, total } = groupByWave(weeztixTicketStats, 'sold')
      const lines = Object.entries(grouped).map(([k, v]) => `• ${k}: ${v}`).join('\n')
      await tgSend(chatId, `🎟 BIGLIETTI VENDUTI\n\n${lines}\n\nTotale: ${total}\nAggiornato: ${weeztixLastOkAt}`)
      return res.sendStatus(200)
    }

    if (text.startsWith('/entrate')) {
      if (!weeztixTicketStats.length) {
        await tgSend(chatId, `🚪 Nessun dato ancora.\n\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}`)
        return res.sendStatus(200)
      }
      const { grouped, total } = groupByWave(weeztixTicketStats, 'scanned')
      const lines = Object.entries(grouped).map(([k, v]) => `• ${k}: ${v}`).join('\n')

      let capLine = ''
      if (MP_CAPACITY > 0) {
        const pct = Math.round((total / MP_CAPACITY) * 100)
        capLine = `\nCapienza: ${pct}% (${total}/${MP_CAPACITY})`
      }

      await tgSend(chatId, `🚪 ENTRATE (SCANNER)\n\n${lines}\n\nTotale entrati: ${total}${capLine}\nAggiornato: ${weeztixLastOkAt}`)
      return res.sendStatus(200)
    }

    // --- Alerts opt-in ---
    if (text.startsWith('/alerts_on')) {
      alertSubscribers.add(chatId)
      await tgSend(chatId, '🔔 Alert attivati. Ti avviso a 80% e 95% capienza.')
      return res.sendStatus(200)
    }

    if (text.startsWith('/alerts_off')) {
      alertSubscribers.delete(chatId)
      await tgSend(chatId, '🔕 Alert disattivati.')
      return res.sendStatus(200)
    }

    if (text.startsWith('/testalerts')) {
      alertSubscribers.add(chatId)
      await tgSend(chatId, '🧪 Test alerts: ok. Ti invio due messaggi di prova.')
      await broadcastAlert('⚠️ [TEST] CAPACITÀ 80%\n\nEntrati: 320 / 400')
      await broadcastAlert('🚨 [TEST] CAPACITÀ 95%\n\nEntrati: 380 / 400\nValutare STOP ingressi.')
      return res.sendStatus(200)
    }

    // --- Existing upload/docs ---
    if (text.startsWith('/upload')) {
      userState[chatId] = 'WAITING_DOCUMENT'
      await tgSend(chatId, '📎 Mandami il documento (PDF o Word)')
      return res.sendStatus(200)
    }

    if (text.startsWith('/docs')) {
      const now = Date.now()
      const active = Object.values(documents)
      if (!active.length) {
        await tgSend(chatId, '📭 Nessun documento attivo.')
      } else {
        const lines = active.map((d, i) => {
          const mins = Math.max(0, Math.round((d.expiresAt - now) / 60000))
          return `${i + 1}. ${d.name} — ⏳ ${mins} min`
        })
        await tgSend(chatId, `📚 Documenti attivi\n\n${lines.join('\n')}`)
      }
      return res.sendStatus(200)
    }

    if (message.document && userState[chatId] === 'WAITING_DOCUMENT') {
      documents[message.document.file_id] = {
        name: message.document.file_name,
        expiresAt: Date.now() + 24 * 60 * 60 * 1000
      }
      delete userState[chatId]
      await tgSend(chatId, `✅ Documento ricevuto: ${message.document.file_name}`)
      return res.sendStatus(200)
    }

    return res.sendStatus(200)
  } catch (e) {
    console.error('Telegram webhook error:', e?.response?.data || e.message || e)
    return res.sendStatus(200)
  }
})

app.get('/', (req, res) => res.send('MP Telegram Bot is running 🇮🇹'))

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log('Bot live'))

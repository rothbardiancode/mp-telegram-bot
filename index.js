/**
 * MP Telegram Bot + Weeztix OAuth + Polling + Capacity Alerts
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
 * - OAUTH_CLIENT_REDIRECT (only needed if you want /weeztix/connect)
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

// Alerts opt-in (no group needed)
const alertSubscribers = new Set()
const capacityAlerts = { cap80Sent: false, cap95Sent: false }

async function broadcastAlert(message) {
  const ids = Array.from(alertSubscribers)
  for (const id of ids) {
    try {
      await tgSend(id, message)
    } catch (e) {
      alertSubscribers.delete(id)
    }
  }
}

// -------------------- Weeztix OAuth (refresh token flow) --------------------
let WEEZTIX_ACCESS_TOKEN = null
let WEEZTIX_ACCESS_EXPIRES_AT = 0

async function refreshAccessToken() {
  const now = Date.now()

  if (WEEZTIX_ACCESS_TOKEN && now < WEEZTIX_ACCESS_EXPIRES_AT - 60000) {
    return WEEZTIX_ACCESS_TOKEN
  }

  const params = new URLSearchParams()
  params.append('grant_type', 'refresh_token')
  params.append('refresh_token', process.env.WEEZTIX_REFRESH_TOKEN)
  params.append('client_id', process.env.OAUTH_CLIENT_ID)
  params.append('client_secret', process.env.OAUTH_CLIENT_SECRET)

  const r = await axios.post(
    'https://auth.weeztix.com/tokens',
    params,
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }
  )

  WEEZTIX_ACCESS_TOKEN = r.data.access_token
  WEEZTIX_ACCESS_EXPIRES_AT = now + (Number(r.data.expires_in || 0) * 1000)

  return WEEZTIX_ACCESS_TOKEN
}

// -------------------- Weeztix polling + cache --------------------
const WEEZTIX_EVENT_GUID = process.env.WEEZTIX_EVENT_GUID
const WEEZTIX_POLL_SECONDS = Number(process.env.WEEZTIX_POLL_SECONDS || 60)

let weeztixLastOkAt = null
let weeztixLastError = null
let weeztixTicketStats = [] // normalized: [{name, sold, scanned}]
let weeztixLastRaw = null   // for /debugweeztix_raw

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

  // A) direct arrays (most common)
  const arrays = [
    data?.ticket_types,
    data?.tickets,
    data?.ticketTypes,
    data?.tickettypes,
    data?.data?.ticket_types,
    data?.data?.tickets
  ].filter(Array.isArray)

  for (const arr of arrays) {
    for (const t of arr) {
      push(
        t?.name || t?.title || t?.key,
        t?.sold_count ?? t?.sold ?? t?.count_sold ?? t?.total_sold ?? t?.soldCount,
        t?.scanned_count ?? t?.scanned ?? t?.count_scanned ?? t?.total_scanned ?? t?.scannedCount
      )
    }
    if (out.length) return out
  }

  // B) aggregation buckets
  const buckets =
    data?.aggregations?.ticket_types?.buckets ||
    data?.aggregations?.tickets?.buckets ||
    data?.aggs?.ticket_types?.buckets ||
    data?.aggs?.tickets?.buckets ||
    data?.data?.aggregations?.ticket_types?.buckets ||
    data?.data?.aggregations?.tickets?.buckets

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

  // C) if there is a "ticket_types" object map
  if (data?.ticket_types && typeof data.ticket_types === 'object' && !Array.isArray(data.ticket_types)) {
    for (const [name, v] of Object.entries(data.ticket_types)) {
      push(
        name,
        v?.sold_count ?? v?.sold ?? v?.count_sold ?? v?.total_sold,
        v?.scanned_count ?? v?.scanned ?? v?.count_scanned ?? v?.total_scanned
      )
    }
    if (out.length) return out
  }

  // nothing matched
  return []
}

function waveLabel(name = '') {
  const n = name.toLowerCase()

  // TODO: customize when we see your real ticket names
  if (n.includes('wave 1') || n.includes('first') || n.includes('early')) return 'Wave 1'
  if (n.includes('wave 2') || n.includes('second')) return 'Wave 2'
  if (n.includes('wave 3') || n.includes('third')) return 'Wave 3'
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

    const url = `https://api.weeztix.com/statistics/dashboard/${WEEZTIX_EVENT_GUID}`

    const resp = await axios.get(url, {
      timeout: 15000,
      headers: { Authorization: `Bearer ${token}` }
    })

    weeztixLastRaw = resp.data

    const parsed = parseWeeztixStats(resp.data)
    if (!parsed.length) {
      weeztixLastError = 'Stats fetched but parsing returned empty'
      return
    }

    weeztixTicketStats = parsed
    weeztixLastOkAt = new Date().toISOString()
    weeztixLastError = null

    // Capacity alerts
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
    if (e?.response?.data) {
      weeztixLastError = `HTTP ${e.response.status}: ${JSON.stringify(e.response.data).slice(0, 600)}`
    } else {
      weeztixLastError = e?.message || String(e)
    }
  }
}

// start polling
setInterval(fetchWeeztixStats, WEEZTIX_POLL_SECONDS * 1000)
fetchWeeztixStats()

// -------------------- Optional: OAuth connect/callback (regenerate refresh token) --------------------
let OAUTH_STATE = null

app.get('/weeztix/connect', (req, res) => {
  OAUTH_STATE = crypto.randomBytes(16).toString('hex')
  const redirectUri = process.env.OAUTH_CLIENT_REDIRECT
  if (!redirectUri) return res.status(500).send('Missing env var: OAUTH_CLIENT_REDIRECT')

  const url = new URL('https://login.weeztix.com/login')
  url.searchParams.set('client_id', process.env.OAUTH_CLIENT_ID)
  url.searchParams.set('redirect_uri', redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('state', OAUTH_STATE)
  res.redirect(url.toString())
})

app.get('/weeztix/callback', async (req, res) => {
  try {
    const redirectUri = process.env.OAUTH_CLIENT_REDIRECT
    if (!redirectUri) return res.status(500).send('Missing env var: OAUTH_CLIENT_REDIRECT')

    if (!req.query.code) return res.status(400).send('Missing code')
    if (!req.query.state || req.query.state !== OAUTH_STATE) return res.status(400).send('Bad state')

    const r = await axios.post('https://auth.weeztix.com/tokens', {
      grant_type: 'authorization_code',
      client_id: process.env.OAUTH_CLIENT_ID,
      client_secret: process.env.OAUTH_CLIENT_SECRET,
      redirect_uri: redirectUri,
      code: req.query.code
    })

    console.log('WEEZTIX TOKEN RESPONSE:', r.data) // contains refresh_token

    res.send('✅ Weeztix connected. Check Render logs and set WEEZTIX_REFRESH_TOKEN in env vars.')
  } catch (e) {
    console.error(e?.response?.data || e.message)
    res.status(500).send('Token exchange failed (check logs).')
  }
})

// -------------------- Documents (upload/docs) --------------------
const userState = {}
const documents = {}

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

    // DEBUG
    if (text.startsWith('/debugweeztix_raw')) {
      const preview = weeztixLastRaw ? JSON.stringify(weeztixLastRaw, null, 2).slice(0, 3500) : '(vuoto)'
      await tgSend(chatId, `🧾 WEEZTIX RAW (trimmed)\n\n${preview}`)
      return res.sendStatus(200)
    }

    if (text.startsWith('/debugweeztix')) {
      const sample = weeztixTicketStats
        .slice(0, 12)
        .map(s => `• ${s.name} | sold=${s.sold} | scanned=${s.scanned}`)
        .join('\n')

      await tgSend(
        chatId,
        `🛠 DEBUG WEEZTIX\nUltimo OK: ${weeztixLastOkAt || 'mai'}\nErrore: ${weeztixLastError || '—'}\nSubs alerts: ${alertSubscribers.size}\nMP_CAPACITY: ${MP_CAPACITY || '—'}\n\nSample:\n${sample || '(vuoto)'}`
      )
      return res.sendStatus(200)
    }

    // Weeztix commands
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

    // Alerts opt-in
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

    // Documents
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

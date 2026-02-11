const express = require('express')
const axios = require('axios')

const app = express()
app.use(express.json())
const crypto = require('crypto');

let OAUTH_STATE = null;

app.get('/weeztix/connect', (req, res) => {
  OAUTH_STATE = crypto.randomBytes(16).toString('hex');
  const url = new URL('https://login.weeztix.com/login');
  url.searchParams.set('client_id', process.env.OAUTH_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.OAUTH_CLIENT_REDIRECT);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('state', OAUTH_STATE);
  res.redirect(url.toString());
});

// Weeztix redirects here with ?code=...&state=...
app.get('/weeztix/callback', async (req, res) => {
  try {
    if (!req.query.code) return res.status(400).send('Missing code');
    if (!req.query.state || req.query.state !== OAUTH_STATE) return res.status(400).send('Bad state');

    const r = await axios.post('https://auth.weeztix.com/tokens', {
      grant_type: 'authorization_code',
      client_id: process.env.OAUTH_CLIENT_ID,
      client_secret: process.env.OAUTH_CLIENT_SECRET,
      redirect_uri: process.env.OAUTH_CLIENT_REDIRECT,
      code: req.query.code
    });

    // IMPORTANT: COPIA IL refresh_token e mettilo su Render come env var
    console.log('WEEZTIX TOKEN RESPONSE:', r.data);

    res.send('✅ Weeztix connected. Now set WEEZTIX_REFRESH_TOKEN on Render (check logs).');
  } catch (e) {
    console.error(e?.response?.data || e.message);
    res.status(500).send('Token exchange failed (check logs).');
  }
});

const TOKEN = process.env.BOT_TOKEN
const TELEGRAM_API = `https://api.telegram.org/bot${TOKEN}`

const userState = {}
const documents = {}

// TTL cleanup (ogni minuto)
setInterval(() => {
  const now = Date.now()
  for (const id of Object.keys(documents)) {
    if (documents[id].expiresAt <= now) {
      delete documents[id]
    }
  }
}, 60000)

app.post('/webhook', async (req, res) => {
  const message = req.body.message
  if (!message) return res.sendStatus(200)

  const chatId = message.chat.id
  const text = message.text

  // /upload
  if (text === '/upload') {
    userState[chatId] = 'WAITING_DOCUMENT'
    await axios.post(`${TELEGRAM_API}/sendMessage`, {
      chat_id: chatId,
      text: '📎 Mandami il documento (PDF o Word)'
    })
  }

  // /docs
  if (text === '/docs') {
    const now = Date.now()
    const active = Object.values(documents)

    if (active.length === 0) {
      await axios.post(`${TELEGRAM_API}/sendMessage`, {
        chat_id: chatId,
        text: '📭 Nessun documento attivo.'
      })
    } else {
      const lines = active.map((d, i) => {
        const mins = Math.max(0, Math.round((d.expiresAt - now) / 60000))
        return `${i + 1}. ${d.name} — ⏳ ${mins} min`
      })

      await axios.post(`${TELEGRAM_API}/sendMessage`, {
        chat_id: chatId,
        text: `📚 Documenti attivi\n\n${lines.join('\n')}`
      })
    }
  }

  // ricezione documento
  if (message.document && userState[chatId] === 'WAITING_DOCUMENT') {
    documents[message.document.file_id] = {
      name: message.document.file_name,
      expiresAt: Date.now() + 24 * 60 * 60 * 1000
    }

    delete userState[chatId]

    await axios.post(`${TELEGRAM_API}/sendMessage`, {
      chat_id: chatId,
      text: `✅ Documento ricevuto: ${message.document.file_name}`
    })
  }

  res.sendStatus(200)
})

app.get('/', (req, res) => {
  res.send('MP Telegram Bot is running 🇮🇹')
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log('Bot live')
})

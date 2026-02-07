const express = require('express')
const axios = require('axios')

const app = express()
app.use(express.json())

const TOKEN = process.env.BOT_TOKEN
const TELEGRAM_API = `https://api.telegram.org/bot${TOKEN}`

// Stato utenti (chi ha lanciato /upload)
const userState = {}

// Documenti caricati (in memoria)
const documents = // TTL cleanup: ogni minuto elimina documenti scaduti
setInterval(async () => {
  const now = Date.now()
  for (const fileId of Object.keys(documents)) {
    if (documents[fileId].expiresAt <= now) {
      const expiredName = documents[fileId].name
      delete documents[fileId]
      console.log(`🗑 Scaduto e rimosso: ${expiredName} (${fileId})`)
    }
  }
}, 60 * 1000)

app.post('/webhook', // Comando /docs: lista documenti attivi
if (text === '/docs') {
  const now = Date.now()
  const active = Object.values(documents)
    .filter(d => d.expiresAt > now)
    .sort((a, b) => a.expiresAt - b.expiresAt)

  if (active.length === 0) {
    await axios.post(`${TELEGRAM_API}/sendMessage`, {
      chat_id: chatId,
      text: '📭 Nessun documento attivo al momento.'
    })
  } else {
    const lines = active.map((d, idx) => {
      const minsLeft = Math.max(0, Math.round((d.expiresAt - now) / 60000))
      const hours = Math.floor(minsLeft / 60)
      const mins = minsLeft % 60
      const left = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`
      return `${idx + 1}. ${d.name} — ⏳ scade tra ${left}`
    })

    await axios.post(`${TELEGRAM_API}/sendMessage`, {
      chat_id: chatId,
      text: `📚 Documenti attivi (24h)\n\n${lines.join('\n')}`
    })
  }
}async (req, res) => {
  const message = req.body.message
  if (!message) return res.sendStatus(200)

  const chatId = message.chat.id
  const text = message.text

  // Comando /upload
  if (text === '/upload') {
    userState[chatId] = 'WAITING_DOCUMENT'
    await axios.post(`${TELEGRAM_API}/sendMessage`, {
      chat_id: chatId,
      text: '📎 Mandami il documento (PDF o Word)'
    })
  }

  // Ricezione documento
  if (message.document && userState[chatId] === 'WAITING_DOCUMENT') {
    documents[message.document.file_id] = {
      name: message.document.file_name,
      expiresAt: Date.now() + 24 * 60 * 60 * 1000
    }

    delete userState[chatId]

    await axios.post(`${TELEGRAM_API}/sendMessage`, {
      chat_id: chatId,
      text: `✅ Documento ricevuto: ${message.document.file_name}\n⏳ Sarà disponibile per 24h`
    })
  }

  res.sendStatus(200)
})

app.get('/', (req, res) => {
  res.send('MP Telegram Bot is running 🇮🇹')
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Bot live on port ${PORT}`)
})

const express = require('express')
const axios = require('axios')

const app = express()
app.use(express.json())

const TOKEN = process.env.BOT_TOKEN
const TELEGRAM_API = `https://api.telegram.org/bot${TOKEN}`

const userState = {}
const documents = {}

// TTL cleanup
setInterval(() => {
  const now = Date.now()
  for (const id of Object.keys(documents)) {
    if (documents[id].expiresAt <= now) {
      console.log(`🗑 Rimosso: ${documents[id].name}`)
      delete documents[id]
    }
  }
}, 60000)

app.post('/webhook', async (req, res) => {
  const message = req.body.message
  if (!message) return res.sendStatus(200)

  const chatId = message.chat.id
  const text = message.text

  if (text === '/upload') {
    userState[chatId] = 'WAITING_DOCUMENT'
    await axios.post(`${TELEGRAM_API}/sendMessage`, {
      chat_id: chatId,
      text: '📎 Mandami il documento (PDF o Word)'
    })
  }

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
        const mins = Math.round((d.expiresAt - now) / 60000)
        return `${i + 1}. ${d.name} — ⏳ ${mins} min`
      })

      await axios.post(`${TELEGRAM_API}/sendMessage`, {
        chat_id: chatId,
        text: `📚 Documenti attivi\n\n${lines.join('\n')}`
      })
    }
  }

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
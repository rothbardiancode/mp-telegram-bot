const express = require('express')
const axios = require('axios')

const app = express()
app.use(express.json())

const TOKEN = process.env.BOT_TOKEN
const TELEGRAM_API = `https://api.telegram.org/bot${TOKEN}`

// Stato utenti (chi ha lanciato /upload)
const userState = {}

// Documenti caricati (in memoria)
const documents = {}

app.post('/webhook', async (req, res) => {
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

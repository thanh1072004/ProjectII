const WebSocket = require('ws');
const crypto = require('crypto');
const mongoose = require('mongoose');
const Message = require('./models/message');
const dotenv = require('dotenv').config();

const wss = new WebSocket.Server({ port: 4000 });
const uri = process.env.MONGO_URL;

// Dùng key cố định để đảm bảo giải mã được cả lịch sử
const SECRET_KEY = Buffer.from(process.env.CHAT_SECRET_KEY, 'base64');

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return iv.toString('base64') + ':' + encrypted;
}

function decrypt(data) {
  const [ivBase64, encrypted] = data.split(':');
  const iv = Buffer.from(ivBase64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', SECRET_KEY, iv);
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

wss.on('connection', async function connection(ws) {
  try {
    // Gửi lại lịch sử tin nhắn cho client mới
    const recentMessages = await Message.find().sort({ timestamp: 1 }).limit(50); // có thể bỏ limit nếu muốn
    recentMessages.forEach(msg => {
      const plain = `${msg.sender}:${msg.content}`;
      const encrypted = encrypt(plain);
      ws.send(encrypted);
    });
  } catch (err) {
    console.error('Error loading messages from DB:', err);
  }

  ws.on('message', async function incoming(message) {
    try {
      // Giải mã tin nhắn nhận được
      const decrypted = decrypt(message.toString()); // e.g., "Alice:Hello"
      const [sender, ...rest] = decrypted.split(':');
      const content = rest.join(':').trim();

      // Lưu vào MongoDB
      await Message.create({ sender, content });

      // Gửi lại cho tất cả client (giữ nguyên bản đã mã hóa)
      wss.clients.forEach(function each(client) {
        if (client.readyState === WebSocket.OPEN) {
          client.send(message);
        }
      });
    } catch (err) {
      console.error('Error handling message:', err);
    }
  });
});

mongoose.connect(uri)
  .then(() => console.log('Connected to Database'))
  .catch((err) => console.error('Database connection error:', err));

console.log('WebSocket chat server running on ws://localhost:4000');

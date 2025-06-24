const WebSocket = require('ws');
const crypto = require('crypto');

const wss = new WebSocket.Server({ port: 4000 });

// For demo: a shared secret key (in real E2EE, each client would have their own)
const SECRET_KEY = crypto.randomBytes(32); // 256-bit key

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

wss.on('connection', function connection(ws) {
  ws.on('message', function incoming(message) {
    // Broadcast encrypted message to all clients
    wss.clients.forEach(function each(client) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message); // Already encrypted by client
      }
    });
  });
});

console.log('WebSocket chat server running on ws://localhost:4000');
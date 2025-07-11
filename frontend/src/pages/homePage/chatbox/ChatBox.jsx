import React, { useEffect, useRef, useState, useContext } from 'react';
import { UserContext } from '../../../context/UserContext';
import './ChatBox.css';

const SECRET_KEY = 'qvosW4lgMyzNUp8XLSbiNZpyvWkJyqS6Ix2CCAkqosQ=';
const key = Uint8Array.from(atob(SECRET_KEY), c => c.charCodeAt(0));

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let b of bytes) binary += String.fromCharCode(b);
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function encrypt(text) {
  const iv = window.crypto.getRandomValues(new Uint8Array(16));
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw', key, 'AES-CBC', false, ['encrypt']
  );
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-CBC', iv }, cryptoKey, new TextEncoder().encode(text)
  );
  return arrayBufferToBase64(iv) + ':' + arrayBufferToBase64(encrypted);
}

async function decrypt(data) {
  const [ivBase64, encryptedBase64] = data.split(':');
  const iv = base64ToArrayBuffer(ivBase64);
  const encrypted = base64ToArrayBuffer(encryptedBase64);
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw', key, 'AES-CBC', false, ['decrypt']
  );
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: new Uint8Array(iv) }, cryptoKey, encrypted
  );
  return new TextDecoder().decode(decrypted);
}

export default function ChatBox() {
  const { user } = useContext(UserContext);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const ws = useRef(null);

  useEffect(() => {
    ws.current = new window.WebSocket('ws://localhost:4000');
    ws.current.onmessage = async (event) => {
      let data = event.data;
      if (typeof data !== 'string') {
        data = await event.data.text();
      }

      try {
        const decrypted = await decrypt(data); 
        const [sender, ...rest] = decrypted.split(':');
        const content = rest.join(':').trim();

        setMessages(msgs => [...msgs, { sender, content }]);
      } catch (err) {
        console.error('Failed to decrypt message:', err);
      }
    };
    return () => ws.current.close();
  }, []);

  const sendMessage = async () => {
    if (
      input.trim() &&
      ws.current.readyState === 1 &&
      user &&
      user.email
    ) {
      const plain = `${user.email}:${input}`;
      const encrypted = await encrypt(plain);
      ws.current.send(encrypted);
      setInput('');
    }
  };

  return (
    <div className="chatbox-container">
      <div className="chatbox-title">Team Chat</div>
      <div className="chatbox-messages">
        {messages.map((msg, idx) => (
          <div className="chatbox-message" key={idx}>
            <span style={{ fontWeight: 600, color: '#388e3c' }}>
              {msg.sender}:
            </span>
            <span style={{ marginLeft: 8 }}>{msg.content}</span>
          </div>
        ))}
      </div>
      <div className="chatbox-input-row">
        <input
          className="chatbox-input"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && sendMessage()}
          placeholder="Type a message..."
        />
        <button className="chatbox-send-btn" onClick={sendMessage}>Send</button>
      </div>
    </div>
  );
}

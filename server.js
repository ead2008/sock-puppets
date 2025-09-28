// server.js
// Express server for guestbook logging

const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const LOG_FILE = path.join(__dirname, 'user_texts.txt');

// Admin credentials (set via environment variables)
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme';

// Trust proxy if behind reverse proxy
app.set('trust proxy', true);

app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));

// --- Basic Auth middleware for admin routes ---
function checkAdminAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Authentication required');
  }
  const base64 = auth.split(' ')[1];
  const decoded = Buffer.from(base64, 'base64').toString('utf8');
  const [user, pass] = decoded.split(':');
  if (user === ADMIN_USER && pass === ADMIN_PASS) {
    return next();
  } else {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Invalid credentials');
  }
}

// Serve user-facing guestbook page
app.use('/', express.static(path.join(__dirname, 'public')));

// Serve admin page (protected)
app.use('/admin', checkAdminAuth, express.static(path.join(__dirname, 'admin')));

// --- Add guestbook entry ---
app.post('/add-entry', (req, res) => {
  const message = typeof req.body.message === 'string' ? req.body.message.trim() : '';
  if (!message) return res.status(400).json({ error: 'Message required' });

  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const timestamp = new Date().toLocaleString();

  // Sanitize message (replace newlines to prevent log injection)
  const safeMessage = message.replace(/\r?\n/g, ' ⏎ ');
  const entry = `${timestamp} — IP: ${ip} — Message: ${safeMessage}\n`;

  fs.appendFile(LOG_FILE, entry, (err) => {
    if (err) {
      console.error('Error writing entry:', err);
      return res.status(500).json({ error: 'Failed to save entry' });
    }
    return res.json({ success: true });
  });
});

// --- Admin-only: view entries ---
app.get('/admin/entries', checkAdminAuth, (req, res) => {
  fs.readFile(LOG_FILE, 'utf8', (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') return res.send(''); // no entries yet
      return res.status(500).send('Failed to read entries');
    }
    res.type('text/plain').send(data);
  });
});

// --- Admin-only: clear entries ---
app.post('/admin/clear', checkAdminAuth, (req, res) => {
  fs.writeFile(LOG_FILE, '', (err) => {
    if (err) return res.status(500).json({ error: 'Failed to clear entries' });
    res.json({ success: true });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Admin credentials: ${ADMIN_USER} / ${ADMIN_PASS}`);
});

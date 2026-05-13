'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const express = require('express');
const basicAuth = require('express-basic-auth');
const path = require('path');
const apiRoutes = require('./routes/api');

const app = express();
const PORT = parseInt(process.env.WEB_PORT, 10) || 3000;
const HOST = process.env.WEB_HOST || '127.0.0.1';

// Basic Auth — required for all routes
const WEB_USER = process.env.WEB_USER;
const WEB_PASS = process.env.WEB_PASS;

if (!WEB_USER || !WEB_PASS) {
  console.error('[web] ERROR: WEB_USER and WEB_PASS must be set in .env');
  process.exit(1);
}

app.use(express.json());
app.use(basicAuth({
  users: { [WEB_USER]: WEB_PASS },
  challenge: true,
  realm: 'Server Watchdog',
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', apiRoutes);

// Serve index.html for any non-API route (SPA fallback)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`[web] Server Watchdog UI running at http://${HOST}:${PORT}`);
});

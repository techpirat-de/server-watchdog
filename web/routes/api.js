'use strict';

const { Router } = require('express');
const db = require('../../lib/db');
const emailNotifier = require('../../notifiers/emailNotifier');
const telegramNotifier = require('../../notifiers/telegramNotifier');

const router = Router();

router.get('/stats', async (req, res) => {
  try {
    const stats = await db.getStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/latest', async (req, res) => {
  try {
    const report = await db.getLatestReport();
    if (!report) return res.status(404).json({ error: 'No reports yet' });
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reports', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const offset = parseInt(req.query.offset, 10) || 0;
    const risk = req.query.risk || null;
    const reports = await db.getReports({ limit, offset, risk });
    res.json(reports);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reports/:id', async (req, res) => {
  try {
    const report = await db.getReportById(req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/cron-status', async (req, res) => {
  try {
    const [latest, stats] = await Promise.all([db.getLatestReport(), db.getStats()]);
    const now             = Date.now();
    const intervalMinutes = parseInt(process.env.CHECK_INTERVAL_MINUTES, 10) || 60;

    if (!latest) {
      return res.json({ status: 'no_data', message: 'Noch kein Report in der Datenbank', intervalMinutes, stats });
    }

    const lastRun    = new Date(latest.timestamp).getTime();
    const minutesAgo = Math.round((now - lastRun) / 60000);

    res.json({
      status:         minutesAgo > intervalMinutes * 4 ? 'missed'
                    : minutesAgo > intervalMinutes * 2 ? 'late' : 'ok',
      lastRun:        latest.timestamp,
      minutesAgo,
      intervalMinutes,
      overallRisk:    latest.overall_risk,
      stats,
    });
  } catch (err) {
    console.error('[api/cron-status]', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/test-ai', async (req, res) => {
  const { execFile } = require('child_process');
  const path = require('path');
  const aiPath  = path.join(__dirname, '../../ai-review.js');
  const nodeBin = process.execPath;

  if (global._aiRunning) {
    return res.status(409).json({ error: 'KI-Analyse läuft bereits — bitte warten.' });
  }
  global._aiRunning = true;

  execFile(nodeBin, [aiPath, '--force'], { timeout: 60000, cwd: path.join(__dirname, '../..') }, async (err, stdout, stderr) => {
    global._aiRunning = false;
    const output = (stdout + stderr).trim();

    if (err && err.code !== 0) {
      return res.status(500).json({ error: err.message, output: output.slice(-800) });
    }

    // After ai-review.js ran, fetch the latest report with AI result from DB
    try {
      const latest = await db.getLatestReport();
      res.json({ ok: true, output: output.slice(-800), aiReview: latest?.ai_review || null });
    } catch (_) {
      res.json({ ok: true, output: output.slice(-800), aiReview: null });
    }
  });
});

router.post('/run-now', async (req, res) => {
  const { execFile } = require('child_process');
  const path = require('path');
  const monitorPath = path.join(__dirname, '../../monitor.js');
  const nodeBin = process.execPath;

  // Prevent parallel runs
  if (global._monitorRunning) {
    return res.status(409).json({ error: 'Ein Check läuft bereits — bitte warten.' });
  }
  global._monitorRunning = true;

  execFile(nodeBin, [monitorPath], { timeout: 120000, cwd: path.join(__dirname, '../..') }, (err, stdout, stderr) => {
    global._monitorRunning = false;
    if (err && err.code !== 0) {
      return res.status(500).json({ error: err.message, stderr: stderr?.slice(-500) });
    }
    res.json({ ok: true, output: (stdout + stderr).slice(-1000) });
  });
});

router.post('/test-notify', async (req, res) => {
  const { channel } = req.body;
  if (!channel || !['email', 'telegram', 'all'].includes(channel)) {
    return res.status(400).json({ error: 'channel must be email, telegram or all' });
  }

  const testReport = {
    timestamp: new Date().toISOString(),
    hostname: process.env.SERVER_NAME || require('os').hostname(),
    overallRisk: 'medium',
    checks: [{
      name: 'testNotification',
      status: 'warning',
      risk: 'medium',
      findings: [{ type: 'test', message: 'Dies ist eine Test-Benachrichtigung vom Plesk Server Watchdog Dashboard.' }],
      metrics: {},
    }],
    aiReview: null,
    notificationsSent: [],
  };

  const config = {
    ENABLE_EMAIL_NOTIFIER: ['email', 'all'].includes(channel) ? 'true' : 'false',
    SMTP_HOST: process.env.SMTP_HOST,
    SMTP_PORT: process.env.SMTP_PORT,
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASS: process.env.SMTP_PASS,
    ALERT_EMAIL_TO: process.env.ALERT_EMAIL_TO,
    ALERT_EMAIL_FROM: process.env.ALERT_EMAIL_FROM,
    ENABLE_TELEGRAM_NOTIFIER: ['telegram', 'all'].includes(channel) ? 'true' : 'false',
    TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID: process.env.TELEGRAM_CHAT_ID,
  };

  const results = {};

  if (['email', 'all'].includes(channel)) {
    try {
      await emailNotifier.send(testReport, config);
      results.email = 'ok';
    } catch (err) {
      results.email = `error: ${err.message}`;
    }
  }

  if (['telegram', 'all'].includes(channel)) {
    try {
      await telegramNotifier.send(testReport, config);
      results.telegram = 'ok';
    } catch (err) {
      results.telegram = `error: ${err.message}`;
    }
  }

  res.json({ results });
});

module.exports = router;

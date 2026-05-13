'use strict';

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const os = require('os');

const mailQueue = require('./checks/mailQueue');
const mailLog = require('./checks/mailLog');
const suspiciousFiles = require('./checks/suspiciousFiles');
const serverLoad = require('./checks/serverLoad');
const aiReview = require('./checks/aiReview');
const emailNotifier = require('./notifiers/emailNotifier');
const telegramNotifier = require('./notifiers/telegramNotifier');

const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

const config = {
  SERVER_NAME: process.env.SERVER_NAME || os.hostname(),
  CHECK_INTERVAL_MINUTES: parseInt(process.env.CHECK_INTERVAL_MINUTES, 10) || 60,
  MAIL_QUEUE_WARNING_THRESHOLD: parseInt(process.env.MAIL_QUEUE_WARNING_THRESHOLD, 10) || 20,
  MAIL_QUEUE_CRITICAL_THRESHOLD: parseInt(process.env.MAIL_QUEUE_CRITICAL_THRESHOLD, 10) || 100,
  MAIL_LOG_PATH: process.env.MAIL_LOG_PATH || '/var/log/mail.log',
  VHOSTS_PATH: process.env.VHOSTS_PATH || '/var/www/vhosts',
  RECENT_FILE_HOURS: parseInt(process.env.RECENT_FILE_HOURS, 10) || 24,
  ENABLE_AI_REVIEW: process.env.ENABLE_AI_REVIEW || 'false',
  OPENAI_API_KEY: process.env.OPENAI_API_KEY || '',
  OPENAI_MODEL: process.env.OPENAI_MODEL || 'gpt-4o',
  ENABLE_EMAIL_NOTIFIER: process.env.ENABLE_EMAIL_NOTIFIER || 'false',
  SMTP_HOST: process.env.SMTP_HOST || '',
  SMTP_PORT: process.env.SMTP_PORT || '587',
  SMTP_USER: process.env.SMTP_USER || '',
  SMTP_PASS: process.env.SMTP_PASS || '',
  ALERT_EMAIL_TO: process.env.ALERT_EMAIL_TO || '',
  ALERT_EMAIL_FROM: process.env.ALERT_EMAIL_FROM || '',
  ENABLE_TELEGRAM_NOTIFIER: process.env.ENABLE_TELEGRAM_NOTIFIER || 'false',
  TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN || '',
  TELEGRAM_CHAT_ID: process.env.TELEGRAM_CHAT_ID || '',
  ALWAYS_SEND_REPORT: process.env.ALWAYS_SEND_REPORT || 'false',
};

function computeOverallRisk(checks) {
  let highest = 'low';
  for (const c of checks) {
    if (RISK_RANK[c.risk] > RISK_RANK[highest]) highest = c.risk;
  }
  return highest;
}

function shouldNotify(overallRisk, config) {
  if (config.ALWAYS_SEND_REPORT === 'true') return true;
  return RISK_RANK[overallRisk] >= RISK_RANK['medium'];
}

function saveReport(report) {
  const dir = path.join(__dirname, 'reports');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const now = new Date(report.timestamp);
  const pad = (n) => String(n).padStart(2, '0');
  const fname = `report-${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}-${pad(now.getHours())}-${pad(now.getMinutes())}`;

  const jsonPath = path.join(dir, `${fname}.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2), 'utf8');
  console.log(`[monitor] Report saved: ${jsonPath}`);

  return jsonPath;
}

function saveTxtReport(report) {
  const dir = path.join(__dirname, 'reports');
  const now = new Date(report.timestamp);
  const pad = (n) => String(n).padStart(2, '0');
  const fname = `report-${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}-${pad(now.getHours())}-${pad(now.getMinutes())}.txt`;

  const lines = [
    `Server Watchdog Report`,
    `======================`,
    `Hostname   : ${report.hostname}`,
    `Timestamp  : ${report.timestamp}`,
    `Risk Level : ${report.overallRisk.toUpperCase()}`,
    '',
  ];

  for (const c of report.checks) {
    lines.push(`[${c.name.toUpperCase()}] status=${c.status}  risk=${c.risk}`);
    for (const f of c.findings) {
      lines.push(`  • ${f.message || f.type || JSON.stringify(f)}`);
    }
    if (c.metrics && Object.keys(c.metrics).length) {
      lines.push(`  Metrics: ${JSON.stringify(c.metrics)}`);
    }
    lines.push('');
  }

  if (report.aiReview?.response) {
    lines.push('AI Assessment:');
    lines.push(JSON.stringify(report.aiReview.response, null, 2));
  }

  const txtPath = path.join(dir, fname);
  fs.writeFileSync(txtPath, lines.join('\n'), 'utf8');
  console.log(`[monitor] Text report saved: ${txtPath}`);
}

async function runCheck(name, fn, ...args) {
  console.log(`[monitor] Running check: ${name}`);
  try {
    return await fn(...args);
  } catch (err) {
    console.error(`[monitor] Check ${name} threw unexpectedly: ${err.message}`);
    return { name, status: 'error', risk: 'low', findings: [{ type: 'unexpected_error', message: err.message }], metrics: {} };
  }
}

async function main() {
  const startTime = Date.now();
  console.log(`\n[monitor] ===== Server Watchdog starting at ${new Date().toISOString()} =====`);
  console.log(`[monitor] Host: ${config.SERVER_NAME}`);

  const checks = await Promise.all([
    runCheck('mailQueue', mailQueue.check, config),
    runCheck('mailLog', mailLog.check, config),
    runCheck('suspiciousFiles', suspiciousFiles.check, config),
    runCheck('serverLoad', serverLoad.check),
  ]);

  const overallRisk = computeOverallRisk(checks);

  const report = {
    timestamp: new Date().toISOString(),
    hostname: config.SERVER_NAME,
    overallRisk,
    checks,
    aiReview: null,
    notificationsSent: [],
  };

  // AI review runs after initial checks (needs the report)
  const ai = await runCheck('aiReview', aiReview.check, report, config);
  report.aiReview = ai;
  if (ai.response?.risk) report.overallRisk = ai.response.risk;

  // Print console summary
  console.log('\n[monitor] ===== RESULTS =====');
  console.log(`[monitor] Overall Risk: ${report.overallRisk.toUpperCase()}`);
  for (const c of checks) {
    const icon = c.status === 'ok' ? '✓' : c.status === 'warning' ? '⚠' : '✗';
    console.log(`  ${icon} ${c.name}: ${c.status} (risk: ${c.risk}) — ${c.findings.length} finding(s)`);
    for (const f of c.findings) {
      console.log(`      → ${f.message || f.type}`);
    }
  }

  // Save reports
  saveReport(report);
  saveTxtReport(report);

  // Send notifications
  if (shouldNotify(report.overallRisk, config)) {
    console.log('[monitor] Sending notifications...');

    for (const [name, notifier] of [['email', emailNotifier], ['telegram', telegramNotifier]]) {
      try {
        await notifier.send(report, config);
        report.notificationsSent.push(name);
      } catch (err) {
        console.error(`[monitor] ${name} notifier failed: ${err.message}`);
      }
    }
  } else {
    console.log(`[monitor] Risk ${report.overallRisk} — no notifications required`);
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`\n[monitor] ===== Done in ${elapsed}s =====\n`);
  process.exit(0);
}

main().catch((err) => {
  console.error('[monitor] Fatal error:', err);
  process.exit(1);
});

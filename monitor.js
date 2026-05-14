'use strict';

require('dotenv').config({ override: true });
const os = require('os');

const mailQueue = require('./checks/mailQueue');
const mailLog = require('./checks/mailLog');
const suspiciousFiles = require('./checks/suspiciousFiles');
const serverLoad = require('./checks/serverLoad');
const db = require('./lib/db');

const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

const config = {
  SERVER_NAME:                   process.env.SERVER_NAME || os.hostname(),
  CHECK_INTERVAL_MINUTES:        parseInt(process.env.CHECK_INTERVAL_MINUTES, 10) || 60,
  MAIL_QUEUE_WARNING_THRESHOLD:  parseInt(process.env.MAIL_QUEUE_WARNING_THRESHOLD, 10) || 20,
  MAIL_QUEUE_CRITICAL_THRESHOLD: parseInt(process.env.MAIL_QUEUE_CRITICAL_THRESHOLD, 10) || 100,
  MAIL_LOG_PATH:                 process.env.MAIL_LOG_PATH || '/var/log/mail.log',
  VHOSTS_PATH:                   process.env.VHOSTS_PATH || '/var/www/vhosts',
  RECENT_FILE_HOURS:             parseInt(process.env.RECENT_FILE_HOURS, 10) || 24,
};

function computeOverallRisk(checks) {
  let highest = 'low';
  for (const c of checks) {
    if (RISK_RANK[c.risk] > RISK_RANK[highest]) highest = c.risk;
  }
  return highest;
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

  console.log('\n[monitor] ===== RESULTS =====');
  console.log(`[monitor] Overall Risk: ${report.overallRisk.toUpperCase()}`);
  for (const c of checks) {
    const icon = c.status === 'ok' ? '✓' : c.status === 'warning' ? '⚠' : '✗';
    console.log(`  ${icon} ${c.name}: ${c.status} (risk: ${c.risk}) — ${c.findings.length} finding(s)`);
    for (const f of c.findings) {
      console.log(`      → ${f.message || f.type}`);
    }
  }

  try {
    const id = await db.saveReport(report);
    console.log(`[monitor] Report saved to MySQL (id=${id})`);
  } catch (err) {
    console.error(`[monitor] Failed to save report to MySQL: ${err.message}`);
  } finally {
    await db.closePool();
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`[monitor] Done in ${elapsed}s — notifications handled by ai-review.js\n`);
  process.exit(0);
}

main().catch((err) => {
  console.error('[monitor] Fatal error:', err);
  process.exit(1);
});

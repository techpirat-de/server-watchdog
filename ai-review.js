'use strict';

require('dotenv').config({ override: true });
const aiReview = require('./checks/aiReview');
const emailNotifier = require('./notifiers/emailNotifier');
const telegramNotifier = require('./notifiers/telegramNotifier');

const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

const config = {
  SERVER_NAME:              process.env.SERVER_NAME || require('os').hostname(),
  ENABLE_AI_REVIEW:         process.env.ENABLE_AI_REVIEW || 'false',
  OPENAI_API_KEY:           process.env.OPENAI_API_KEY || '',
  OPENAI_MODEL:             process.env.OPENAI_MODEL || 'gpt-4o-mini',
  OPENAI_TIMEOUT_MS:        process.env.OPENAI_TIMEOUT_MS || '30000',
  AI_REVIEW_MIN_RISK:       process.env.AI_REVIEW_MIN_RISK || 'medium',
  AI_NOTIFY_MIN_RISK:       process.env.AI_NOTIFY_MIN_RISK || 'high',
  AI_NOTIFY_COOLDOWN_MINUTES: parseInt(process.env.AI_NOTIFY_COOLDOWN_MINUTES, 10) || 360,
  ENABLE_EMAIL_NOTIFIER:    process.env.ENABLE_EMAIL_NOTIFIER || 'false',
  SMTP_HOST:                process.env.SMTP_HOST,
  SMTP_PORT:                process.env.SMTP_PORT,
  SMTP_USER:                process.env.SMTP_USER,
  SMTP_PASS:                process.env.SMTP_PASS,
  ALERT_EMAIL_TO:           process.env.ALERT_EMAIL_TO,
  ALERT_EMAIL_FROM:         process.env.ALERT_EMAIL_FROM,
  ENABLE_TELEGRAM_NOTIFIER: process.env.ENABLE_TELEGRAM_NOTIFIER || 'false',
  TELEGRAM_BOT_TOKEN:       process.env.TELEGRAM_BOT_TOKEN,
  TELEGRAM_CHAT_ID:         process.env.TELEGRAM_CHAT_ID,
};

// ── DB: fetch last hour's reports ─────────────────────────────────────────────

async function getLastHourReports() {
  const mysql = require('mysql2/promise');
  const conn = await mysql.createConnection({
    host:     process.env.DB_HOST || '127.0.0.1',
    port:     parseInt(process.env.DB_PORT, 10) || 3306,
    user:     process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    timezone: 'Z',
  });

  const [rows] = await conn.execute(
    `SELECT id, timestamp, hostname, overall_risk, checks, ai_review
     FROM reports
     WHERE timestamp >= UTC_TIMESTAMP() - INTERVAL 1 HOUR
     ORDER BY timestamp ASC`
  );

  await conn.end();

  return rows.map((r) => ({
    ...r,
    checks:    typeof r.checks    === 'string' ? JSON.parse(r.checks)    : r.checks,
    ai_review: typeof r.ai_review === 'string' ? JSON.parse(r.ai_review) : r.ai_review,
  }));
}

async function updateAiReview(id, aiReview, notificationsSent = null) {
  const mysql = require('mysql2/promise');
  const conn = await mysql.createConnection({
    host:     process.env.DB_HOST || '127.0.0.1',
    port:     parseInt(process.env.DB_PORT, 10) || 3306,
    user:     process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    timezone: 'Z',
  });
  if (notificationsSent) {
    await conn.execute(
      'UPDATE reports SET ai_review = ?, notifications_sent = ? WHERE id = ?',
      [JSON.stringify(aiReview), JSON.stringify(notificationsSent), id]
    );
  } else {
    await conn.execute('UPDATE reports SET ai_review = ? WHERE id = ?', [JSON.stringify(aiReview), id]);
  }
  await conn.end();
}

async function getRecentNotification({ sinceMinutes }) {
  const mysql = require('mysql2/promise');
  const conn = await mysql.createConnection({
    host:     process.env.DB_HOST || '127.0.0.1',
    port:     parseInt(process.env.DB_PORT, 10) || 3306,
    user:     process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    timezone: 'Z',
  });

  const cutoff = new Date(Date.now() - sinceMinutes * 60 * 1000);
  const [rows] = await conn.execute(
    `SELECT id, timestamp, overall_risk, ai_review, notifications_sent
     FROM reports
     WHERE timestamp >= ?
       AND notifications_sent IS NOT NULL
     ORDER BY timestamp DESC
     LIMIT 50`,
    [cutoff]
  );

  await conn.end();

  for (const row of rows) {
    const notifications = typeof row.notifications_sent === 'string'
      ? JSON.parse(row.notifications_sent || '[]')
      : row.notifications_sent || [];

    const sent = notifications.some((n) => n.status === 'sent' || n.status === 'partial');
    if (!sent) continue;

    const ai = row.ai_review
      ? (typeof row.ai_review === 'string' ? JSON.parse(row.ai_review) : row.ai_review)
      : null;

    return {
      id: row.id,
      timestamp: row.timestamp,
      risk: ai?.risk || row.overall_risk,
      summary: ai?.response?.summary || null,
      notifications,
    };
  }

  return null;
}

// ── Shared AI review input ───────────────────────────────────────────────────

function buildHourlyReport(reports, worstRisk) {
  const latestReport = reports[reports.length - 1];

  return {
    timestamp: new Date().toISOString(),
    hostname: config.SERVER_NAME,
    overallRisk: worstRisk,
    reportWindow: {
      label: 'last_hour',
      reportCount: reports.length,
      firstTimestamp: reports[0]?.timestamp || null,
      latestTimestamp: latestReport?.timestamp || null,
    },
    checks: latestReport?.checks || [],
    reports: reports.map((r) => ({
      id: r.id,
      timestamp: r.timestamp,
      overallRisk: r.overall_risk,
      checks: (r.checks || []).map((c) => ({
        name: c.name,
        status: c.status,
        risk: c.risk,
        findings: (c.findings || []).map((f) => ({
          type: f.type,
          risk: f.risk,
          message: f.message || f.type,
          file: f.file,
          patterns: f.patterns,
        })).slice(0, 8),
        metrics: c.metrics || {},
      })),
    })),
  };
}

// ── Notifications ─────────────────────────────────────────────────────────────

async function sendNotifications(aiResult, latestReport) {
  const notifyReport = {
    timestamp:        new Date().toISOString(),
    hostname:         config.SERVER_NAME,
    overallRisk:      aiResult.risk,
    checks:           latestReport.checks,
    aiReview:         { response: aiResult },
    notificationsSent: [],
  };

  for (const [name, notifier] of [['email', emailNotifier], ['telegram', telegramNotifier]]) {
    try {
      const result = await notifier.send(notifyReport, config);
      notifyReport.notificationsSent.push(result || { channel: name, status: 'unknown' });
      if (result?.status === 'sent' || result?.status === 'partial') {
        const detail = result.messageId ? ` messageId=${result.messageId}` : '';
        console.log(`[ai-review] ${name} notification ${result.status}${detail}`);
      } else {
        console.log(`[ai-review] ${name} notification skipped: ${result?.reason || 'unknown reason'}`);
      }
    } catch (err) {
      notifyReport.notificationsSent.push({ channel: name, status: 'failed', error: err.message });
      console.error(`[ai-review] ${name} notification failed: ${err.message}`);
    }
  }

  return notifyReport.notificationsSent;
}

async function shouldSendNotification(aiResult, latestReport) {
  const minRisk = config.AI_NOTIFY_MIN_RISK;
  if (aiResult.notify !== true) {
    return { send: false, reason: `AI notify=false` };
  }

  if (RISK_RANK[aiResult.risk] < RISK_RANK[minRisk]) {
    return { send: false, reason: `risk ${aiResult.risk} below notification threshold ${minRisk}` };
  }

  const recent = await getRecentNotification({
    sinceMinutes: config.AI_NOTIFY_COOLDOWN_MINUTES,
  });

  if (recent) {
    return {
      send: false,
      reason: `already notified within ${config.AI_NOTIFY_COOLDOWN_MINUTES} min (report id=${recent.id})`,
    };
  }

  return { send: true, reason: 'AI requested notification and cooldown is clear' };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const force = process.argv.includes('--force');
  console.log(`\n[ai-review] ===== AI Review starting at ${new Date().toISOString()} ${force ? '[FORCE]' : ''} =====`);

  if (config.ENABLE_AI_REVIEW !== 'true') {
    console.log('[ai-review] ENABLE_AI_REVIEW is not true — exiting');
    process.exit(0);
  }
  if (!config.OPENAI_API_KEY) {
    console.error('[ai-review] OPENAI_API_KEY not set — exiting');
    process.exit(1);
  }

  const reports = await getLastHourReports();
  console.log(`[ai-review] Found ${reports.length} report(s) from the last hour`);

  if (reports.length === 0) {
    console.log('[ai-review] No reports yet — nothing to analyze');
    process.exit(0);
  }

  // Determine worst risk in the last hour
  const worstRisk = reports.reduce((worst, r) => {
    return RISK_RANK[r.overall_risk] > RISK_RANK[worst] ? r.overall_risk : worst;
  }, 'low');

  console.log(`[ai-review] Worst risk in last hour: ${worstRisk.toUpperCase()}`);

  if (!force && RISK_RANK[worstRisk] < RISK_RANK['medium']) {
    console.log('[ai-review] All reports LOW — no AI call needed, no notification sent');
    process.exit(0);
  }

  if (force && RISK_RANK[worstRisk] < RISK_RANK['medium']) {
    console.log('[ai-review] Force mode — running AI analysis despite LOW risk');
  }

  const hourlyReport = buildHourlyReport(reports, worstRisk);
  const aiConfig = {
    ...config,
    AI_REVIEW_MIN_RISK: force ? 'low' : config.AI_REVIEW_MIN_RISK,
  };

  const aiCheck = await aiReview.check(hourlyReport, aiConfig);
  if (aiCheck.status !== 'ok') {
    const reason = aiCheck.findings.map((f) => f.message || f.type).join('; ') || 'unknown reason';
    if (aiCheck.status === 'skipped') {
      console.log(`[ai-review] AI review skipped: ${reason}`);
      process.exit(0);
    }
    console.error(`[ai-review] AI review failed: ${reason}`);
    process.exit(1);
  }

  const aiResult = aiCheck.response;
  console.log(`[ai-review] AI result: risk=${aiResult.risk}, trend=${aiResult.trend}, confidence=${aiResult.confidence}, urgency=${aiResult.urgency}, notify=${aiResult.notify}`);
  console.log(`[ai-review] Summary: ${aiResult.summary}`);

  // Write AI result to the most recent report in DB
  const latestReport = reports[reports.length - 1];
  await updateAiReview(latestReport.id, { status: 'ok', risk: aiResult.risk, findings: aiCheck.findings, response: aiResult });
  console.log(`[ai-review] AI result saved to report id=${latestReport.id}`);

  const notificationDecision = await shouldSendNotification(aiResult, latestReport);
  if (notificationDecision.send) {
    const notificationsSent = await sendNotifications(aiResult, latestReport);
    await updateAiReview(latestReport.id, { status: 'ok', risk: aiResult.risk, findings: aiCheck.findings, response: aiResult }, notificationsSent);
  } else {
    const notificationsSent = [{ channel: 'all', status: 'skipped', reason: notificationDecision.reason }];
    await updateAiReview(latestReport.id, { status: 'ok', risk: aiResult.risk, findings: aiCheck.findings, response: aiResult }, notificationsSent);
    console.log(`[ai-review] notification skipped: ${notificationDecision.reason}`);
  }

  console.log('[ai-review] ===== Done =====\n');
  process.exit(0);
}

main().catch((err) => {
  console.error('[ai-review] Fatal error:', err);
  process.exit(1);
});

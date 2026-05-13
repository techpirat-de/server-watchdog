'use strict';

require('dotenv').config();
const db = require('./lib/db');
const emailNotifier = require('./notifiers/emailNotifier');
const telegramNotifier = require('./notifiers/telegramNotifier');

const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

const config = {
  SERVER_NAME:              process.env.SERVER_NAME || require('os').hostname(),
  ENABLE_AI_REVIEW:         process.env.ENABLE_AI_REVIEW || 'false',
  OPENAI_API_KEY:           process.env.OPENAI_API_KEY || '',
  OPENAI_MODEL:             process.env.OPENAI_MODEL || 'gpt-4o',
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
  const pool = require('./lib/db');
  // Re-use pool from db module — query directly
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
     WHERE timestamp >= NOW() - INTERVAL 1 HOUR
     ORDER BY timestamp ASC`
  );

  await conn.end();

  return rows.map((r) => ({
    ...r,
    checks:    typeof r.checks    === 'string' ? JSON.parse(r.checks)    : r.checks,
    ai_review: typeof r.ai_review === 'string' ? JSON.parse(r.ai_review) : r.ai_review,
  }));
}

async function updateAiReview(id, aiReview) {
  const mysql = require('mysql2/promise');
  const conn = await mysql.createConnection({
    host:     process.env.DB_HOST || '127.0.0.1',
    port:     parseInt(process.env.DB_PORT, 10) || 3306,
    user:     process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    timezone: 'Z',
  });
  await conn.execute('UPDATE reports SET ai_review = ? WHERE id = ?', [JSON.stringify(aiReview), id]);
  await conn.end();
}

// ── OpenAI call ───────────────────────────────────────────────────────────────

async function callOpenAI(reports) {
  const fetch = (await import('node-fetch')).default;

  // Build a compact summary of all reports in the last hour
  const summary = reports.map((r) => ({
    id:          r.id,
    timestamp:   r.timestamp,
    overallRisk: r.overall_risk,
    checks: r.checks.map((c) => ({
      name:     c.name,
      risk:     c.risk,
      findings: c.findings.map((f) => f.message || f.type).slice(0, 3),
    })),
  }));

  const prompt = `You are a server security analyst. Below are server monitoring reports from the last hour (one per 5-minute interval). Analyze the trend and current state, then respond with JSON only.

Reports (${reports.length} runs in the last hour):
${JSON.stringify(summary, null, 2)}

Respond ONLY with this JSON schema — no markdown, no extra text:
{
  "risk": "low|medium|high|critical",
  "summary": "One sentence summary of the overall situation in the last hour",
  "likely_cause": "Most probable cause if issues exist, or 'No issues detected'",
  "trend": "stable|improving|worsening",
  "recommended_actions": ["Action 1", "Action 2"],
  "notify": true,
  "urgency": "normal|urgent"
}`;

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: config.OPENAI_MODEL,
      temperature: 0.2,
      max_tokens: 600,
      messages: [
        { role: 'system', content: 'You are a server security analyst. Respond ONLY with valid JSON.' },
        { role: 'user', content: prompt },
      ],
    }),
    timeout: 30000,
  });

  if (!response.ok) throw new Error(`OpenAI API ${response.status}: ${response.statusText}`);

  const data = await response.json();
  const raw = data.choices?.[0]?.message?.content?.trim();
  if (!raw) throw new Error('Empty response from OpenAI');

  // Strip markdown code fences if present
  const clean = raw.replace(/^```json?\n?/, '').replace(/\n?```$/, '').trim();
  return JSON.parse(clean);
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
      await notifier.send(notifyReport, config);
      console.log(`[ai-review] ${name} notification sent`);
    } catch (err) {
      console.error(`[ai-review] ${name} notification failed: ${err.message}`);
    }
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n[ai-review] ===== AI Review starting at ${new Date().toISOString()} =====`);

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

  if (RISK_RANK[worstRisk] < RISK_RANK['medium']) {
    console.log('[ai-review] All reports LOW — no AI call needed, no notification sent');
    process.exit(0);
  }

  // Call AI with all reports from last hour
  let aiResult;
  try {
    aiResult = await callOpenAI(reports);
    console.log(`[ai-review] AI result: risk=${aiResult.risk}, trend=${aiResult.trend}, urgency=${aiResult.urgency}, notify=${aiResult.notify}`);
    console.log(`[ai-review] Summary: ${aiResult.summary}`);
  } catch (err) {
    console.error(`[ai-review] OpenAI call failed: ${err.message}`);
    process.exit(1);
  }

  // Write AI result to the most recent report in DB
  const latestReport = reports[reports.length - 1];
  await updateAiReview(latestReport.id, { status: 'ok', risk: aiResult.risk, response: aiResult });
  console.log(`[ai-review] AI result saved to report id=${latestReport.id}`);

  // Send notification only if AI says so or risk is high+
  const shouldNotify = aiResult.notify === true || RISK_RANK[aiResult.risk] >= RISK_RANK['high'];
  if (shouldNotify) {
    await sendNotifications(aiResult, latestReport);
  } else {
    console.log(`[ai-review] Risk ${aiResult.risk} / notify=${aiResult.notify} — no notification needed`);
  }

  console.log('[ai-review] ===== Done =====\n');
  process.exit(0);
}

main().catch((err) => {
  console.error('[ai-review] Fatal error:', err);
  process.exit(1);
});

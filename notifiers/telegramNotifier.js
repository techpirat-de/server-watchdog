'use strict';

const RISK_EMOJI = { low: 'ℹ️', medium: '⚠️', high: '🔴', critical: '🚨' };
const RISK_LABELS = { low: 'Niedrig', medium: 'Mittel', high: 'Hoch', critical: 'Kritisch' };
const TREND_LABELS = { improving: 'verbessert sich', stable: 'stabil', worsening: 'verschlechtert sich', unknown: 'unklar' };

function buildMessage(report) {
  const emoji = RISK_EMOJI[report.overallRisk] || '⚠️';
  const ai = report.aiReview?.response || null;
  const actions = Array.isArray(ai?.recommended_actions) ? ai.recommended_actions.filter(Boolean).slice(0, 3) : [];
  const lines = [
    `${emoji} Plesk Server Watchdog - ${RISK_LABELS[report.overallRisk] || report.overallRisk}`,
    `Host: ${report.hostname}`,
    `Zeit: ${report.timestamp}`,
    '',
  ];

  if (ai?.summary) {
    lines.push(`Kurzfazit: ${ai.summary}`);
  }
  if (ai?.likely_cause) {
    lines.push(`Ursache: ${ai.likely_cause}`);
  }
  if (ai?.trend) {
    lines.push(`Trend: ${TREND_LABELS[ai.trend] || ai.trend}`);
  }
  if (actions.length) {
    lines.push('', 'Nächste Schritte:');
    actions.forEach((action, idx) => lines.push(`${idx + 1}. ${action}`));
  }

  const findingLines = [];
  for (const check of report.checks) {
    if (check.findings.length === 0) continue;
    for (const f of check.findings.slice(0, 3)) {
      findingLines.push(`- ${check.name}: ${f.message || f.type}`);
    }
  }

  if (findingLines.length) {
    lines.push('', 'Auffällige Checks:', ...findingLines.slice(0, 6));
  }

  return lines.join('\n');
}

async function send(report, config) {
  if (!config.ENABLE_TELEGRAM_NOTIFIER || config.ENABLE_TELEGRAM_NOTIFIER === 'false') {
    return { channel: 'telegram', status: 'skipped', reason: 'disabled' };
  }
  if (!config.TELEGRAM_BOT_TOKEN || !config.TELEGRAM_CHAT_ID) {
    return { channel: 'telegram', status: 'skipped', reason: 'missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID' };
  }

  const fetch = (await import('node-fetch')).default;
  const url = `https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendMessage`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: config.TELEGRAM_CHAT_ID,
      text: buildMessage(report),
    }),
    timeout: 10000,
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Telegram API error ${res.status}: ${body}`);
  }

  const body = await res.json().catch(() => ({}));
  return {
    channel: 'telegram',
    status: 'sent',
    messageId: body.result?.message_id || null,
    chatId: body.result?.chat?.id || config.TELEGRAM_CHAT_ID,
  };
}

module.exports = { send };

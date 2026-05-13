'use strict';

const RISK_EMOJI = { low: 'ℹ️', medium: '⚠️', high: '🔴', critical: '🚨' };

function buildMessage(report) {
  const emoji = RISK_EMOJI[report.overallRisk] || '⚠️';
  const lines = [
    `${emoji} *Server Watchdog* — ${report.overallRisk.toUpperCase()}`,
    `Host: \`${report.hostname}\``,
    `Time: ${report.timestamp}`,
    '',
  ];

  for (const check of report.checks) {
    if (check.findings.length === 0) continue;
    lines.push(`*${check.name}* [${check.risk}]`);
    for (const f of check.findings.slice(0, 3)) {
      lines.push(`• ${f.message || f.type}`);
    }
  }

  if (report.aiReview?.response?.summary) {
    lines.push('', `_AI: ${report.aiReview.response.summary}_`);
  }

  return lines.join('\n');
}

async function send(report, config) {
  if (!config.ENABLE_TELEGRAM_NOTIFIER || config.ENABLE_TELEGRAM_NOTIFIER === 'false') return;
  if (!config.TELEGRAM_BOT_TOKEN || !config.TELEGRAM_CHAT_ID) {
    console.error('[telegramNotifier] Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID');
    return;
  }

  const fetch = (await import('node-fetch')).default;
  const url = `https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendMessage`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: config.TELEGRAM_CHAT_ID,
      text: buildMessage(report),
      parse_mode: 'Markdown',
    }),
    timeout: 10000,
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Telegram API error ${res.status}: ${body}`);
  }

  console.log(`[telegramNotifier] Alert sent to chat ${config.TELEGRAM_CHAT_ID}`);
}

module.exports = { send };

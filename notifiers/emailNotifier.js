'use strict';

const nodemailer = require('nodemailer');

function buildSubject(report) {
  return `[Server Watchdog] ${report.overallRisk.toUpperCase()} Risk auf ${report.hostname}`;
}

function buildTextBody(report) {
  const lines = [
    `Server Watchdog Report`,
    `======================`,
    `Hostname  : ${report.hostname}`,
    `Timestamp : ${report.timestamp}`,
    `Risk Level: ${report.overallRisk.toUpperCase()}`,
    ``,
    `Check Results:`,
  ];

  for (const check of report.checks) {
    lines.push(`  [${check.name}] status=${check.status} risk=${check.risk}`);
    for (const f of check.findings) {
      lines.push(`    - ${f.message || JSON.stringify(f)}`);
    }
  }

  if (report.aiReview?.response) {
    lines.push('', 'AI Assessment:', JSON.stringify(report.aiReview.response, null, 2));
  }

  return lines.join('\n');
}

async function send(report, config) {
  if (!config.ENABLE_EMAIL_NOTIFIER || config.ENABLE_EMAIL_NOTIFIER === 'false') {
    return { channel: 'email', status: 'skipped', reason: 'disabled' };
  }

  const required = ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASS', 'ALERT_EMAIL_TO', 'ALERT_EMAIL_FROM'];
  const missing = required.filter((key) => !config[key]);
  if (missing.length) {
    return { channel: 'email', status: 'skipped', reason: `missing ${missing.join(', ')}` };
  }

  const transporter = nodemailer.createTransport({
    host: config.SMTP_HOST,
    port: parseInt(config.SMTP_PORT, 10) || 587,
    secure: parseInt(config.SMTP_PORT, 10) === 465,
    auth: {
      user: config.SMTP_USER,
      pass: config.SMTP_PASS,
    },
  });

  const info = await transporter.sendMail({
    from: config.ALERT_EMAIL_FROM,
    to: config.ALERT_EMAIL_TO,
    subject: buildSubject(report),
    text: buildTextBody(report),
  });

  return {
    channel: 'email',
    status: info.rejected?.length ? 'partial' : 'sent',
    messageId: info.messageId,
    accepted: info.accepted || [],
    rejected: info.rejected || [],
    response: info.response,
  };
}

module.exports = { send };

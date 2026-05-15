'use strict';

const nodemailer = require('nodemailer');

const RISK_LABELS = {
  low: 'Niedrig',
  medium: 'Mittel',
  high: 'Hoch',
  critical: 'Kritisch',
};

const STATUS_LABELS = {
  ok: 'OK',
  warning: 'Warnung',
  error: 'Fehler',
  skipped: 'Übersprungen',
};

const TREND_LABELS = {
  improving: 'Verbessert sich',
  stable: 'Stabil',
  worsening: 'Verschlechtert sich',
  unknown: 'Unklar',
};

const URGENCY_LABELS = {
  normal: 'Normal',
  urgent: 'Dringend',
};

function buildSubject(report) {
  return `[Plesk Server Watchdog] ${riskLabel(report.overallRisk)}: ${report.hostname}`;
}

function buildTextBody(report) {
  const ai = report.aiReview?.response || null;
  const findings = collectFindings(report.checks);
  const actions = Array.isArray(ai?.recommended_actions) ? ai.recommended_actions.filter(Boolean) : [];

  const lines = [
    'Plesk Server Watchdog Bericht',
    '=======================',
    `Server      : ${report.hostname}`,
    `Zeitpunkt   : ${formatDate(report.timestamp)}`,
    `Risiko      : ${riskLabel(report.overallRisk)}`,
    ``,
    `Kurzfazit`,
    `---------`,
    ai?.summary || fallbackSummary(report),
  ];

  if (ai?.likely_cause) {
    lines.push('', 'Wahrscheinliche Ursache', '------------------------', ai.likely_cause);
  }

  if (ai) {
    lines.push(
      '',
      'Einordnung',
      '----------',
      `Trend       : ${TREND_LABELS[ai.trend] || ai.trend || 'Unklar'}`,
      `Dringlichkeit: ${URGENCY_LABELS[ai.urgency] || ai.urgency || 'Normal'}`,
      `Sicherheit  : ${formatConfidence(ai.confidence)}`
    );
  }

  if (actions.length) {
    lines.push('', 'Empfohlene nächste Schritte', '----------------------------');
    actions.forEach((action, idx) => lines.push(`${idx + 1}. ${action}`));
  }

  lines.push('', 'Auffällige Checks', '------------------');
  if (findings.length) {
    for (const item of findings) {
      lines.push(`- ${item.check}: ${item.message}`);
    }
  } else {
    lines.push('Keine konkreten Findings in den Einzelchecks. Die KI-Bewertung basiert auf Verlauf, Metriken oder externen Mustern im Report.');
  }

  lines.push('', 'Check-Übersicht', '---------------');
  for (const check of report.checks) {
    lines.push(`- ${check.name}: ${STATUS_LABELS[check.status] || check.status}, Risiko ${riskLabel(check.risk)}`);
  }

  lines.push('', 'Hinweis', '-------', 'Bitte prüfe auffällige Punkte manuell, bevor Dateien gelöscht, Cronjobs entfernt oder Dienste neu gestartet werden.');

  return lines.join('\n');
}

function collectFindings(checks = []) {
  const items = [];
  for (const check of checks) {
    for (const finding of check.findings || []) {
      items.push({
        check: check.name,
        message: finding.message || finding.type || JSON.stringify(finding),
      });
    }
  }
  return items;
}

function fallbackSummary(report) {
  return `Der aktuelle Server-Watchdog-Lauf wurde mit Risiko ${riskLabel(report.overallRisk)} bewertet.`;
}

function formatDate(timestamp) {
  if (!timestamp) return 'Unbekannt';
  try {
    return new Date(timestamp).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'medium' });
  } catch (_) {
    return timestamp;
  }
}

function riskLabel(risk) {
  return RISK_LABELS[risk] || String(risk || 'Unbekannt').toUpperCase();
}

function formatConfidence(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return 'Unbekannt';
  return `${Math.round(num * 100)}%`;
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

module.exports = { send, buildTextBody };

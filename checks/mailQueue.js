'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const WARNING_DOMAINS = ['outlook.com', 'hotmail.com', 'live.com', 'gmail.com', 'yahoo.com', 'yahoo.de'];
const ERROR_PATTERNS = [
  'rate limited', 'blocked', 'too many errors', 'ip reputation',
  'connection not accepted', 'banned', 'blacklisted', 'rejected',
  'service unavailable', 'policy violation',
];
const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
const SIZE_THRESHOLDS = {
  notice: 20,
  warning: 50,
  high: 150,
  critical: 500,
};

async function getRawQueue() {
  const candidates = [
    ['/usr/sbin/postqueue', ['-p']],
    ['/usr/bin/postqueue', ['-p']],
    ['/usr/sbin/mailq',    []],
    ['/usr/bin/mailq',     []],
    ['postqueue',          ['-p']],
    ['mailq',              []],
  ];
  for (const [bin, args] of candidates) {
    try {
      const { stdout } = await execFileAsync(bin, args, { timeout: 10000 });
      return stdout;
    } catch (_) {}
  }
  return null;
}

function parseQueue(raw) {
  const entries = [];
  if (!raw || raw.includes('Mail queue is empty')) return entries;

  // Postfix queue format:
  // QUEUEID  SIZE  DATE TIME  SENDER
  //                           RECIPIENT [error]
  const lines = raw.split('\n');
  let current = null;

  for (const line of lines) {
    // Queue entry header: starts with queue ID (hex chars + optional *)
    const headerMatch = line.match(/^([A-F0-9a-f]+[*!]?)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(.+)/);
    if (headerMatch) {
      if (current) entries.push(current);
      current = {
        id: headerMatch[1],
        size: parseInt(headerMatch[2], 10),
        queuedAt: parsePostfixDate(headerMatch[3]),
        sender: headerMatch[4].trim(),
        recipients: [],
        errors: [],
      };
      continue;
    }

    if (current) {
      // Recipient line starts with whitespace
      const recipientMatch = line.match(/^\s+([^\s(]+@[^\s)]+)/);
      if (recipientMatch) {
        current.recipients.push(recipientMatch[1].trim());
      }
      // Error message in parens
      const errorMatch = line.match(/\((.+)\)/);
      if (errorMatch) {
        current.errors.push(errorMatch[1]);
      }
    }
  }
  if (current) entries.push(current);
  return entries;
}

function parsePostfixDate(value) {
  const year = new Date().getFullYear();
  const parsed = new Date(`${value} ${year}`);
  if (Number.isNaN(parsed.getTime())) return null;

  // Around New Year, Postfix entries from December can otherwise land in the future.
  if (parsed.getTime() - Date.now() > 7 * 24 * 60 * 60 * 1000) {
    parsed.setFullYear(year - 1);
  }
  return parsed.toISOString();
}

function countTop(map, key, increment = 1) {
  if (!key) return;
  map[key] = (map[key] || 0) + increment;
}

function sortAndSlice(obj, n = 10) {
  return Object.fromEntries(
    Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n)
  );
}

function computeTrend(history, currentSize) {
  const sizes = [...(history || []).map((h) => Number(h.queueSize)).filter(Number.isFinite), currentSize];
  if (sizes.length < 2) {
    return { direction: 'unknown', samples: sizes, deltaLast: 0, deltaWindow: 0 };
  }

  const previous = sizes[sizes.length - 2];
  const first = sizes[0];
  const deltaLast = currentSize - previous;
  const deltaWindow = currentSize - first;

  let direction = 'stable';
  if (deltaWindow <= -10 || deltaLast <= -10) direction = 'falling';
  if (deltaWindow >= 25 || deltaLast >= 25) direction = 'rising';
  if ((currentSize >= 100 && deltaWindow >= 100) || (previous > 0 && currentSize / previous >= 2 && deltaLast >= 50)) {
    direction = 'strongly_rising';
  }

  return { direction, samples: sizes, deltaLast, deltaWindow };
}

function analyzeEntries(entries, config) {
  const findings = [];
  const queuedDates = entries.map((e) => e.queuedAt ? new Date(e.queuedAt).getTime() : null).filter(Number.isFinite);
  const now = Date.now();
  const metrics = {
    total: entries.length,
    queueSize: entries.length,
    totalSizeBytes: entries.reduce((s, e) => s + e.size, 0),
    suspiciousDomainCount: 0,
    errorCount: 0,
    uniqueSenders: new Set(),
    topSenders: {},
    topRecipientDomains: {},
    topErrors: {},
    oldestAgeMinutes: queuedDates.length ? Math.round((now - Math.min(...queuedDates)) / 60000) : null,
    newestAgeMinutes: queuedDates.length ? Math.round((now - Math.max(...queuedDates)) / 60000) : null,
  };

  for (const entry of entries) {
    metrics.uniqueSenders.add(entry.sender);
    countTop(metrics.topSenders, entry.sender);

    for (const recipient of entry.recipients) {
      const domain = recipient.split('@')[1]?.toLowerCase() || '';
      countTop(metrics.topRecipientDomains, domain);
      if (WARNING_DOMAINS.includes(domain)) {
        metrics.suspiciousDomainCount++;
      }
    }

    for (const err of entry.errors) {
      const errLower = err.toLowerCase();
      if (ERROR_PATTERNS.some((p) => errLower.includes(p))) {
        metrics.errorCount++;
        countTop(metrics.topErrors, err);
        findings.push({ type: 'queue_error', message: err, queueId: entry.id });
      }
    }
  }

  metrics.uniqueSenders = metrics.uniqueSenders.size;
  metrics.topSenders = sortAndSlice(metrics.topSenders);
  metrics.topRecipientDomains = sortAndSlice(metrics.topRecipientDomains);
  metrics.topErrors = sortAndSlice(metrics.topErrors, 5);
  metrics.trend = computeTrend(config.MAIL_QUEUE_HISTORY || [], entries.length);

  let risk = 'low';
  let status = 'ok';

  if (entries.length >= SIZE_THRESHOLDS.critical) {
    risk = 'critical';
    status = 'error';
    findings.push({ type: 'queue_size', message: `Mail-Queue kritisch groß: ${entries.length} Nachrichten` });
  } else if (entries.length >= SIZE_THRESHOLDS.high) {
    risk = 'high';
    status = 'warning';
    findings.push({ type: 'queue_size', message: `Mail-Queue hoch: ${entries.length} Nachrichten` });
  } else if (entries.length >= SIZE_THRESHOLDS.warning) {
    risk = 'medium';
    status = 'warning';
    findings.push({ type: 'queue_size', message: `Mail-Queue erhöht: ${entries.length} Nachrichten` });
  } else if (entries.length >= SIZE_THRESHOLDS.notice) {
    findings.push({ type: 'queue_notice', message: `Mail-Queue leicht erhöht: ${entries.length} Nachrichten — beobachten, aber kein akuter Alarm` });
  }

  if (metrics.trend.direction === 'strongly_rising' && entries.length >= SIZE_THRESHOLDS.warning) {
    risk = RISK_RANK[risk] < RISK_RANK.high ? 'high' : risk;
    status = 'warning';
    findings.push({ type: 'queue_trend', message: `Mail-Queue steigt stark (${metrics.trend.deltaWindow >= 0 ? '+' : ''}${metrics.trend.deltaWindow} im Trendfenster)` });
  } else if (metrics.trend.direction === 'rising' && entries.length >= SIZE_THRESHOLDS.notice) {
    risk = RISK_RANK[risk] < RISK_RANK.medium ? 'medium' : risk;
    status = 'warning';
    findings.push({ type: 'queue_trend', message: `Mail-Queue steigt (${metrics.trend.deltaWindow >= 0 ? '+' : ''}${metrics.trend.deltaWindow} im Trendfenster)` });
  }

  if (metrics.suspiciousDomainCount > 10 && risk !== 'critical') {
    risk = risk === 'low' ? 'medium' : risk;
    status = 'warning';
    findings.push({ type: 'bulk_recipients', message: `${metrics.suspiciousDomainCount} mails to major consumer mail providers` });
  }

  if (metrics.errorCount > 5) {
    risk = RISK_RANK[risk] < RISK_RANK.medium ? 'medium' : risk;
    status = 'warning';
    findings.push({ type: 'queue_errors', message: `${metrics.errorCount} Zustellfehler mit Reputation-/Block-Mustern` });
  }

  return { status, risk, findings, metrics };
}

async function check(config) {
  const result = {
    name: 'mailQueue',
    status: 'ok',
    risk: 'low',
    findings: [],
    metrics: {},
  };

  try {
    const raw = await getRawQueue();
    if (raw === null) {
      result.status = 'error';
      result.findings.push({ type: 'exec_error', message: 'postqueue/mailq nicht ausführbar — monitor.js muss als root laufen (root-Cronjob einrichten)' });
      return result;
    }

    const entries = parseQueue(raw);
    const analysis = analyzeEntries(entries, config);

    return { ...result, ...analysis };
  } catch (err) {
    result.status = 'error';
    result.findings.push({ type: 'exec_error', message: `mailQueue check failed: ${err.message}` });
    return result;
  }
}

module.exports = { check };

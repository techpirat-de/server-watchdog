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
    const headerMatch = line.match(/^([A-F0-9a-f]+[*!]?)\s+(\d+)\s+\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+\s+(.+)/);
    if (headerMatch) {
      if (current) entries.push(current);
      current = {
        id: headerMatch[1],
        size: parseInt(headerMatch[2], 10),
        sender: headerMatch[3].trim(),
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

function analyzeEntries(entries, warningThreshold, criticalThreshold) {
  const findings = [];
  const metrics = {
    queueSize: entries.length,
    totalSizeBytes: entries.reduce((s, e) => s + e.size, 0),
    suspiciousDomainCount: 0,
    errorCount: 0,
    uniqueSenders: new Set(),
  };

  for (const entry of entries) {
    metrics.uniqueSenders.add(entry.sender);

    for (const recipient of entry.recipients) {
      const domain = recipient.split('@')[1]?.toLowerCase() || '';
      if (WARNING_DOMAINS.includes(domain)) {
        metrics.suspiciousDomainCount++;
      }
    }

    for (const err of entry.errors) {
      const errLower = err.toLowerCase();
      if (ERROR_PATTERNS.some((p) => errLower.includes(p))) {
        metrics.errorCount++;
        findings.push({ type: 'queue_error', message: err, queueId: entry.id });
      }
    }
  }

  metrics.uniqueSenders = metrics.uniqueSenders.size;

  let risk = 'low';
  let status = 'ok';

  if (entries.length >= criticalThreshold) {
    risk = 'critical';
    status = 'error';
    findings.push({ type: 'queue_size', message: `Mail queue critically large: ${entries.length} messages` });
  } else if (entries.length >= warningThreshold) {
    risk = 'high';
    status = 'warning';
    findings.push({ type: 'queue_size', message: `Mail queue elevated: ${entries.length} messages` });
  }

  if (metrics.suspiciousDomainCount > 10 && risk !== 'critical') {
    risk = risk === 'low' ? 'medium' : risk;
    status = 'warning';
    findings.push({ type: 'bulk_recipients', message: `${metrics.suspiciousDomainCount} mails to major consumer mail providers` });
  }

  if (metrics.errorCount > 5) {
    risk = risk === 'low' ? 'medium' : risk;
    status = 'warning';
    findings.push({ type: 'queue_errors', message: `${metrics.errorCount} delivery errors with reputation/block patterns` });
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
    const analysis = analyzeEntries(
      entries,
      config.MAIL_QUEUE_WARNING_THRESHOLD,
      config.MAIL_QUEUE_CRITICAL_THRESHOLD
    );

    return { ...result, ...analysis };
  } catch (err) {
    result.status = 'error';
    result.findings.push({ type: 'exec_error', message: `mailQueue check failed: ${err.message}` });
    return result;
  }
}

module.exports = { check };

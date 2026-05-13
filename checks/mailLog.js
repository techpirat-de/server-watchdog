'use strict';

const fs = require('fs');
const readline = require('readline');

const REJECT_PATTERNS = [
  'reject:', 'rejected', 'blocked', 'rate limit', 'rate-limit',
  'too many', 'banned', 'blacklist', 'policy violation', 'reputation',
];

function parseLine(line) {
  return {
    isSent: line.includes(' status=sent '),
    isBounced: line.includes(' status=bounced ') || line.includes('bounce'),
    isDeferred: line.includes(' status=deferred '),
    isRejected: REJECT_PATTERNS.some((p) => line.toLowerCase().includes(p)),
    from: (line.match(/from=<([^>]*)>/) || [])[1] || null,
    to: (line.match(/to=<([^>]*)>/) || [])[1] || null,
  };
}

function extractDomain(address) {
  if (!address) return null;
  const parts = address.split('@');
  return parts.length === 2 ? parts[1].toLowerCase() : null;
}

async function readRecentLines(logPath, sinceMinutes) {
  const cutoff = Date.now() - sinceMinutes * 60 * 1000;
  const lines = [];

  if (!fs.existsSync(logPath)) return lines;

  const stream = fs.createReadStream(logPath, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  const currentYear = new Date().getFullYear();

  for await (const line of rl) {
    // Syslog timestamp: "May 13 14:23:01"
    const tsMatch = line.match(/^(\w{3}\s+\d+\s+\d+:\d+:\d+)/);
    if (!tsMatch) continue;
    const ts = new Date(`${tsMatch[1]} ${currentYear}`).getTime();
    if (!isNaN(ts) && ts >= cutoff) {
      lines.push(line);
    }
  }

  return lines;
}

async function check(config) {
  const result = {
    name: 'mailLog',
    status: 'ok',
    risk: 'low',
    findings: [],
    metrics: {
      sent: 0,
      bounced: 0,
      deferred: 0,
      rejected: 0,
      topSenders: {},
      topRecipientDomains: {},
    },
  };

  try {
    const lines = await readRecentLines(config.MAIL_LOG_PATH, config.CHECK_INTERVAL_MINUTES);

    for (const line of lines) {
      const parsed = parseLine(line);
      if (parsed.isSent) result.metrics.sent++;
      if (parsed.isBounced) result.metrics.bounced++;
      if (parsed.isDeferred) result.metrics.deferred++;
      if (parsed.isRejected) result.metrics.rejected++;

      if (parsed.from) {
        result.metrics.topSenders[parsed.from] = (result.metrics.topSenders[parsed.from] || 0) + 1;
      }
      const domain = extractDomain(parsed.to);
      if (domain) {
        result.metrics.topRecipientDomains[domain] = (result.metrics.topRecipientDomains[domain] || 0) + 1;
      }
    }

    // Trim to top 10
    result.metrics.topSenders = sortAndSlice(result.metrics.topSenders, 10);
    result.metrics.topRecipientDomains = sortAndSlice(result.metrics.topRecipientDomains, 10);

    // Risk assessment
    const totalOut = result.metrics.sent + result.metrics.deferred;
    const bounceRatio = totalOut > 0 ? result.metrics.bounced / totalOut : 0;

    if (result.metrics.rejected > 50 || bounceRatio > 0.3) {
      result.risk = 'high';
      result.status = 'warning';
      result.findings.push({ type: 'high_reject_rate', message: `${result.metrics.rejected} rejections, bounce ratio ${(bounceRatio * 100).toFixed(1)}%` });
    } else if (result.metrics.rejected > 10 || result.metrics.bounced > 20) {
      result.risk = 'medium';
      result.status = 'warning';
      result.findings.push({ type: 'elevated_bounces', message: `${result.metrics.bounced} bounced, ${result.metrics.rejected} rejected in last ${config.CHECK_INTERVAL_MINUTES} min` });
    }

    if (result.metrics.sent > 1000) {
      result.risk = result.risk === 'low' ? 'medium' : result.risk;
      result.status = 'warning';
      result.findings.push({ type: 'high_volume', message: `${result.metrics.sent} mails sent in last ${config.CHECK_INTERVAL_MINUTES} min — unusually high` });
    }

  } catch (err) {
    result.status = 'error';
    result.findings.push({ type: 'read_error', message: `mailLog check failed: ${err.message}` });
  }

  return result;
}

function sortAndSlice(obj, n) {
  return Object.fromEntries(
    Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n)
  );
}

module.exports = { check };

'use strict';

const fs = require('fs');
const readline = require('readline');

const REJECT_PATTERNS = [
  'reject:', 'rejected', 'blocked', 'rate limit', 'rate-limit',
  'too many', 'banned', 'blacklist', 'policy violation', 'reputation',
];

function parseLine(line) {
  const lower = line.toLowerCase();
  return {
    isSent: line.includes(' status=sent '),
    isBounced: line.includes(' status=bounced ') || line.includes('bounce'),
    isDeferred: line.includes(' status=deferred '),
    isRejected: REJECT_PATTERNS.some((p) => lower.includes(p)),
    isMicrosoftIpv6PtrError: lower.includes('450 4.7.25')
      && lower.includes('ipv6')
      && lower.includes('reverse dns'),
    from: (line.match(/from=<([^>]*)>/) || [])[1] || null,
    to: (line.match(/to=<([^>]*)>/) || [])[1] || null,
  };
}

function extractDomain(address) {
  if (!address) return null;
  const parts = address.split('@');
  return parts.length === 2 ? parts[1].toLowerCase() : null;
}

function resolveLogPath(configPath) {
  const candidates = [
    configPath,
    '/var/log/mail.log',
    '/var/log/maillog',
    '/var/log/mail/mail.log',
    '/var/log/plesk/maillog',
    '/usr/local/psa/var/log/maillog',
    '/var/log/psa-mm.log',
  ];
  for (const p of candidates) {
    if (!p) continue;
    try {
      fs.accessSync(p, fs.constants.R_OK);
      return p;
    } catch (_) {}
  }
  return null;
}

async function readRecentLines(logPath, sinceMinutes) {
  const cutoff = Date.now() - sinceMinutes * 60 * 1000;
  const lines = [];

  const resolvedPath = resolveLogPath(logPath);
  if (!resolvedPath) return { lines, resolvedPath: null };

  const stream = fs.createReadStream(resolvedPath, { encoding: 'utf8' });
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

  return { lines, resolvedPath };
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
      microsoftIpv6PtrErrors: 0,
      topSenders: {},
      topRecipientDomains: {},
    },
  };

  try {
    const { lines, resolvedPath } = await readRecentLines(config.MAIL_LOG_PATH, config.CHECK_INTERVAL_MINUTES);

    if (!resolvedPath) {
      result.status = 'error';
      result.findings.push({ type: 'read_error', message: `Mail-Log nicht lesbar — geprüfte Pfade: ${config.MAIL_LOG_PATH || '(keiner)'}, /var/log/mail.log, /var/log/maillog, /var/log/plesk/maillog, /usr/local/psa/var/log/maillog. Ggf. MAIL_LOG_PATH setzen oder Berechtigungen prüfen.` });
      return result;
    }

    result.metrics.logPath = resolvedPath;

    for (const line of lines) {
      const parsed = parseLine(line);
      if (parsed.isSent) result.metrics.sent++;
      if (parsed.isBounced) result.metrics.bounced++;
      if (parsed.isDeferred) result.metrics.deferred++;
      if (parsed.isRejected) result.metrics.rejected++;
      if (parsed.isMicrosoftIpv6PtrError) result.metrics.microsoftIpv6PtrErrors++;

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

    // Require minimum volume before bounce ratio is statistically meaningful
    const significantVolume = totalOut >= 10;

    if (result.metrics.rejected > 50 || (significantVolume && bounceRatio > 0.3)) {
      result.risk = 'high';
      result.status = 'warning';
      result.findings.push({ type: 'high_reject_rate', message: `${result.metrics.rejected} rejections, bounce ratio ${(bounceRatio * 100).toFixed(1)}%` });
    } else if (result.metrics.rejected > 10 || result.metrics.bounced > 20 || (significantVolume && bounceRatio > 0.15)) {
      result.risk = 'medium';
      result.status = 'warning';
      result.findings.push({ type: 'elevated_bounces', message: `${result.metrics.bounced} bounced, ${result.metrics.rejected} rejected in last ${config.CHECK_INTERVAL_MINUTES} min` });
    }

    if (result.metrics.sent > 1000) {
      result.risk = result.risk === 'low' ? 'medium' : result.risk;
      result.status = 'warning';
      result.findings.push({ type: 'high_volume', message: `${result.metrics.sent} mails sent in last ${config.CHECK_INTERVAL_MINUTES} min — unusually high` });
    }

    if (result.metrics.microsoftIpv6PtrErrors > 0) {
      if (result.metrics.microsoftIpv6PtrErrors > 20 && result.risk === 'low') result.risk = 'medium';
      result.status = result.status === 'ok' ? 'warning' : result.status;
      result.findings.push({
        type: 'microsoft_ipv6_reverse_dns',
        risk: result.metrics.microsoftIpv6PtrErrors > 20 ? 'medium' : 'low',
        message: `${result.metrics.microsoftIpv6PtrErrors} Microsoft/Outlook-Ablehnung wegen fehlendem Reverse-DNS für IPv6. Kein Malware-Hinweis; PTR bei Provider setzen oder Postfix bevorzugt über IPv4 senden lassen.`,
      });
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

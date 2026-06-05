'use strict';

const RISK_EMOJI  = { low: 'ℹ️', medium: '⚠️', high: '🔴', critical: '🚨' };
const RISK_LABELS = { low: 'Niedrig', medium: 'Mittel', high: 'Hoch', critical: 'Kritisch' };
const TREND_LABELS = { improving: 'verbessert sich', stable: 'stabil', worsening: 'verschlechtert sich', unknown: 'unklar' };

// Finding labels from suspiciousFiles that are typically plugin boilerplate noise
const NOISE_PATTERNS = new Set([
  'Remote URL im Code', 'WordPress HTTP API', 'curl_exec()', 'Variable Funktion',
  'Sehr lange Codezeile', 'Langer Base64-ähnlicher String', 'call_user_func()',
]);

// ── Helpers ───────────────────────────────────────────────────────────────────

function isNoiseFinding(finding) {
  if (!Array.isArray(finding.patterns) || finding.patterns.length === 0) return false;
  return finding.patterns.every((p) => NOISE_PATTERNS.has(p.label));
}

function siteOf(finding) {
  return finding.site || (finding.message?.match(/^\[([^\]]+)\]/) || [])[1] || null;
}

function getCheck(checks, name) {
  return checks.find((c) => c.name === name) || null;
}

// ── Top action (single most important thing to do) ────────────────────────────

function extractTopAction(checks, ai) {
  const wp = getCheck(checks, 'wordpressCheck');
  if (wp?.metrics?.siteDetails) {
    // PHP in uploads → highest urgency
    for (const s of wp.metrics.siteDetails) {
      if (s.phpInUploads > 0) {
        return `PHP-Dateien in wp-content/uploads auf ${s.site} sofort prüfen und entfernen.`;
      }
    }
    // Risky plugin (highest-risk site first)
    const risky = wp.metrics.siteDetails
      .filter((s) => s.riskyPlugins?.length)
      .sort((a, b) => (b.score || 0) - (a.score || 0));
    if (risky.length) {
      const s = risky[0];
      return `${s.riskyPlugins[0]} auf ${s.site} entfernen oder deaktivieren.`;
    }
  }

  // Critical suspicious file
  const sf = getCheck(checks, 'suspiciousFiles');
  if (sf) {
    const crit = sf.findings.find((f) => f.risk === 'critical' && !isNoiseFinding(f));
    if (crit) return `Kritische Datei prüfen: ${crit.file || crit.message}`;
    const high = sf.findings.find((f) => f.risk === 'high' && !isNoiseFinding(f));
    if (high) return `Auffällige Datei prüfen: ${high.file || high.message}`;
  }

  // AI recommended action as fallback
  if (ai?.recommended_actions?.[0]) return ai.recommended_actions[0];

  return null;
}

// ── Secondary findings (filtered, aggregated, max 3) ─────────────────────────

function extractSecondaryFindings(checks, topAction) {
  const items = [];

  // 1. Remaining WP risky plugins / no-security-plugin (not already top action)
  const wp = getCheck(checks, 'wordpressCheck');
  if (wp?.metrics?.siteDetails) {
    const moreRisky = wp.metrics.siteDetails
      .filter((s) => s.riskyPlugins?.length)
      .slice(1); // first one is the top action
    for (const s of moreRisky) {
      items.push(`${s.riskyPlugins[0]} auf ${s.site} prüfen.`);
    }

    // xmlrpc — aggregate into one line
    const xmlrpcSites = wp.metrics.siteDetails
      .filter((s) => s.issues?.some((i) => i.type.startsWith('xmlrpc')));
    if (xmlrpcSites.length === 1) {
      items.push(`xmlrpc.php auf ${xmlrpcSites[0].site} vorhanden. Blockierung empfohlen, wenn nicht genutzt.`);
    } else if (xmlrpcSites.length > 1) {
      items.push(`xmlrpc.php auf ${xmlrpcSites.length} WordPress-Installationen vorhanden. Blockierung empfohlen.`);
    }

    // Sites with no security plugin but no other issue
    const noSec = wp.metrics.siteDetails
      .filter((s) => s.securityPlugins?.length === 0 && !s.riskyPlugins?.length && s.phpInUploads === 0);
    if (noSec.length === 1) {
      items.push(`${noSec[0].site}: kein Security-Plugin (Wordfence o.ä.) installiert.`);
    } else if (noSec.length > 1) {
      items.push(`${noSec.length} WordPress-Installationen ohne Security-Plugin.`);
    }

    // Unexpected legacy root files
    const unexpectedSites = wp.metrics.siteDetails.filter((s) => s.unexpectedFiles?.length > 0);
    if (unexpectedSites.length === 1) {
      const files = unexpectedSites[0].unexpectedFiles.slice(0, 3).join(', ');
      items.push(`Veraltete WP-Dateien auf ${unexpectedSites[0].site}: ${files} — sichern und entfernen.`);
    } else if (unexpectedSites.length > 1) {
      items.push(`Veraltete WP-Root-Dateien auf ${unexpectedSites.length} Installationen gefunden — sichern und entfernen.`);
    }

    // Checksum errors
    const checksumFailed = wp.metrics.siteDetails.filter((s) => s.checksumStatus === 'failed');
    if (checksumFailed.length > 0) {
      items.push(`Core-Checksum-Fehler auf ${checksumFailed.map((s) => s.site).join(', ')} — WP-Core neu installieren.`);
    }
  }

  // 2. Suspicious files — hash-changed trusted files first, then other real findings
  const sf = getCheck(checks, 'suspiciousFiles');
  if (sf) {
    // Hash-changed trusted files are highest priority — known file was tampered with
    const hashChanged = sf.findings.filter((f) => f.hashChanged === true);
    for (const f of hashChanged.slice(0, 2)) {
      const short = f.file ? f.file.split('/').slice(-2).join('/') : f.message;
      const desc = f.trustDescription ? ` (${f.trustDescription})` : '';
      items.push(`Bekannte Datei verändert${desc}: ${short} — SHA256 stimmt nicht mehr überein.`);
    }

    const realFindings = sf.findings.filter(
      (f) => (f.risk === 'high' || f.risk === 'critical')
        && !isNoiseFinding(f)
        && f.type !== 'core_checksum_ok'
        && f.type !== 'vendor_lib_suppressed'
        && !f.hashChanged,
    );
    const noiseFindings = sf.findings.filter((f) => isNoiseFinding(f) && !f.trustedFile);

    for (const f of realFindings.slice(0, 2)) {
      const msg = f.file ? `${f.file.split('/').slice(-3).join('/')}` : f.message;
      items.push(`Auffällige Datei: ${msg}`);
    }

    if (noiseFindings.length > 0) {
      const pluginNames = [...new Set(noiseFindings.map((f) => {
        const m = f.message?.match(/wordpress-plugins:([^)]+)\)/);
        return m ? m[1] : null;
      }).filter(Boolean))].slice(0, 2);

      if (pluginNames.length) {
        items.push(`${pluginNames.join(', ')} enthält auffällige Muster (Remote URLs o.ä.) — vermutlich normaler Plugin-Code. Manuell prüfen.`);
      }
    }

    // Trusted files with verified hash — show as info only, not an alert
    const trustedOk = sf.findings.filter((f) => f.trustedFile && f.hashVerified === true);
    if (trustedOk.length > 0) {
      const names = trustedOk.slice(0, 2).map((f) => f.file?.split('/').slice(-1)[0] || '').filter(Boolean);
      items.push(`Bekannte Anwendung${trustedOk.length > 1 ? 'en' : ''} (Hash OK): ${names.join(', ')} — keine Aktion.`);
    }

    const coreOk = sf.findings.find((f) => f.type === 'core_checksum_ok');
    if (coreOk) {
      items.push(`Core-Checksums OK: ${coreOk.message}`);
    }

    const vendorOk = sf.findings.find((f) => f.type === 'vendor_lib_suppressed');
    if (vendorOk) {
      items.push(`Vendor-Libs ignoriert: ${vendorOk.message}`);
    }
  }

  // Deduplicate and cap at 3
  return [...new Set(items)].slice(0, 3);
}

// ── Status line (what's clean) ────────────────────────────────────────────────

function buildStatusLine(checks) {
  const parts = [];

  const mq = getCheck(checks, 'mailQueue');
  if (mq) {
    if (mq.status === 'ok' && mq.risk === 'low') {
      const total = mq.metrics?.total ?? 0;
      parts.push(total === 0 ? 'Mailqueue leer' : `${total} Mail(s) in Queue`);
    }
  }

  const ml = getCheck(checks, 'mailLog');
  if (ml?.status === 'ok' && ml.risk === 'low') parts.push('Mail-Log sauber');

  const sl = getCheck(checks, 'serverLoad');
  if (sl?.risk === 'low') parts.push('Serverlast normal');

  const sf = getCheck(checks, 'suspiciousFiles');
  if (sf && sf.risk === 'low' && (sf.metrics?.critical || 0) === 0) parts.push('keine kritischen Dateien');

  return parts.join(', ');
}

// ── Main message builder ──────────────────────────────────────────────────────

function buildMessage(report) {
  const emoji = RISK_EMOJI[report.overallRisk] || '⚠️';
  const ai    = report.aiReview?.response || null;
  const lines = [];

  lines.push(`${emoji} Plesk Server Watchdog - ${RISK_LABELS[report.overallRisk] || report.overallRisk}`);
  lines.push(`Host: ${report.hostname}`);
  lines.push('');

  // Summary: prefer AI, else build from checks
  const summary = ai?.summary || buildFallbackSummary(report.checks, report.overallRisk);
  if (summary) lines.push(`Kurzfazit: ${summary}`);

  // Top action
  const topAction = extractTopAction(report.checks, ai);
  if (topAction) {
    lines.push('');
    lines.push('Wichtigste Aktion:');
    lines.push(topAction);
  }

  // Secondary findings
  const secondary = extractSecondaryFindings(report.checks, topAction);
  if (secondary.length) {
    lines.push('');
    lines.push('Weitere Hinweise:');
    secondary.forEach((f) => lines.push(`- ${f}`));
  }

  // Clean status
  const status = buildStatusLine(report.checks);
  if (status) {
    lines.push('');
    lines.push(`Status: ${status}`);
  }

  // Trend (last hour delta)
  const trend = report.trendDetails;
  if (trend?.changes?.length) {
    const arrow = trend.improved ? '↘ verbessert' : trend.worsened ? '↗ verschlechtert' : '→ stabil';
    lines.push('');
    lines.push(`Verlauf (${trend.reportCount} Läufe, ${arrow}):`);
    trend.changes.forEach((c) => lines.push(`  · ${c}`));
  } else if (trend?.stable && trend.reportCount > 1) {
    lines.push('');
    lines.push(`Verlauf: Stabil auf ${trend.lastRisk.toUpperCase()} (${trend.reportCount} Läufe)`);
  }

  return lines.join('\n');
}

function buildFallbackSummary(checks, overallRisk) {
  if (overallRisk === 'low') return 'Alle Checks unauffällig.';
  const issues = checks
    .filter((c) => c.risk !== 'low' && c.findings.length > 0)
    .map((c) => c.name);
  return issues.length ? `Auffälligkeiten in: ${issues.join(', ')}.` : null;
}

// ── Send ──────────────────────────────────────────────────────────────────────

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

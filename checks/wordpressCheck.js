'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');

const execFileAsync = promisify(execFile);
const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

const SECURITY_PLUGINS = [
  { slug: 'wordfence',                           name: 'Wordfence' },
  { slug: 'better-wp-security',                  name: 'iThemes Security' },
  { slug: 'sucuri-scanner',                      name: 'Sucuri Scanner' },
  { slug: 'all-in-one-wp-security-and-firewall', name: 'All In One WP Security' },
  { slug: 'wp-cerber',                           name: 'WP Cerber Security' },
  { slug: 'shield-security',                     name: 'Shield Security' },
  { slug: 'bulletproof-security',                name: 'BulletProof Security' },
  { slug: 'loginizer',                           name: 'Loginizer' },
  { slug: 'wps-hide-login',                      name: 'WPS Hide Login' },
];

// Higher score = higher standalone danger
const RISKY_PLUGINS = [
  { slug: 'wp-file-manager',       name: 'WP File Manager',       baseRisk: 'high',   score: 65, reason: 'RCE-Schwachstelle bekannt (CVE-2020-25213)' },
  { slug: 'file-manager-advanced', name: 'File Manager Advanced',  baseRisk: 'medium', score: 35, reason: 'Datei-Manager mit erhöhtem Angriffspotenzial' },
  { slug: 'revslider',             name: 'Revolution Slider',      baseRisk: 'medium', score: 35, reason: 'Historisch bekannte LFI/RFI-Schwachstellen' },
  { slug: 'cherry-plugin',         name: 'Cherry Plugin',          baseRisk: 'high',   score: 65, reason: 'File-Upload / Remote-File-Inclusion' },
  { slug: 'wp-symposium',          name: 'WP Symposium',           baseRisk: 'high',   score: 65, reason: 'Mehrfach kritische Schwachstellen' },
];

// ── Filesystem helpers ────────────────────────────────────────────────────────

async function findWordPressRoots(vhostsPath) {
  try {
    const { stdout } = await execFileAsync('find', [
      vhostsPath, '-name', 'wp-config.php',
      '-maxdepth', '10', '-type', 'f',
      '-not', '-path', '*/vendor/*',
      '-not', '-path', '*/node_modules/*',
    ], { timeout: 30000, maxBuffer: 5 * 1024 * 1024 });
    const paths = (stdout || '').split('\n').filter(Boolean).map((p) => path.dirname(p));
    return [...new Set(paths)];
  } catch (err) {
    if (err.stdout) return [...new Set(err.stdout.split('\n').filter(Boolean).map((p) => path.dirname(p)))];
    throw err;
  }
}

function readWpVersion(wpRoot) {
  try {
    const content = fs.readFileSync(path.join(wpRoot, 'wp-includes', 'version.php'), 'utf8');
    const m = content.match(/\$wp_version\s*=\s*['"]([^'"]+)['"]/);
    return m ? m[1] : null;
  } catch (_) { return null; }
}

function getInstalledSecurityPlugins(pluginsDir) {
  return SECURITY_PLUGINS
    .filter(({ slug }) => { try { fs.accessSync(path.join(pluginsDir, slug), fs.constants.R_OK); return true; } catch (_) { return false; } })
    .map(({ name }) => name);
}

function getInstalledRiskyPlugins(pluginsDir) {
  return RISKY_PLUGINS
    .filter(({ slug }) => { try { fs.accessSync(path.join(pluginsDir, slug), fs.constants.R_OK); return true; } catch (_) { return false; } });
}

async function countPhpInUploads(wpRoot) {
  try {
    const { stdout } = await execFileAsync('find', [
      path.join(wpRoot, 'wp-content', 'uploads'),
      '(', '-name', '*.php', '-o', '-name', '*.phtml', ')',
      '-type', 'f',
    ], { timeout: 10000, maxBuffer: 1024 * 1024 });
    return (stdout || '').split('\n').filter(Boolean).length;
  } catch (err) {
    return err.stdout ? err.stdout.split('\n').filter(Boolean).length : 0;
  }
}

function hasXmlRpcOnDisk(wpRoot) {
  try { fs.accessSync(path.join(wpRoot, 'xmlrpc.php'), fs.constants.F_OK); return true; } catch (_) { return false; }
}

function isDebugEnabled(wpRoot) {
  try {
    const c = fs.readFileSync(path.join(wpRoot, 'wp-config.php'), 'utf8');
    return /define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true\s*\)/i.test(c);
  } catch (_) { return false; }
}

function wordfenceRecentlySeen(pluginsDir) {
  try {
    const stat = fs.statSync(path.join(path.dirname(pluginsDir), 'wflogs'));
    return stat.isDirectory() && (Date.now() - stat.mtime.getTime()) / 3_600_000 < 24 * 7;
  } catch (_) { return false; }
}

// ── XML-RPC live probe ────────────────────────────────────────────────────────

async function getFetch() {
  if (typeof globalThis.fetch === 'function') return globalThis.fetch;
  return (await import('node-fetch')).default;
}

async function probeXmlRpc(domain) {
  let fetch;
  try { fetch = await getFetch(); } catch (_) { return null; }

  for (const scheme of ['https', 'http']) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(`${scheme}://${domain}/xmlrpc.php`, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
        headers: { 'User-Agent': 'Server-Watchdog/1.0 (security-check)' },
      });
      clearTimeout(timer);
      const text = await res.text().catch(() => '');
      // WordPress xmlrpc responds with this string on GET requests when active
      if (text.includes('XML-RPC server accepts POST requests only') || text.includes('xmlrpc')) {
        return true;
      }
      // 405 Method Not Allowed also indicates it's there
      if (res.status === 405) return true;
      if (res.status === 403 || res.status === 404) return false;
    } catch (_) {
      // network error / abort — try next scheme
    }
  }
  return null; // indeterminate
}

// ── Per-site analysis ─────────────────────────────────────────────────────────

function extractDomain(wpRoot, vhostsPath) {
  const rel = wpRoot.startsWith(vhostsPath + '/') ? wpRoot.slice(vhostsPath.length + 1) : wpRoot;
  return rel.split('/')[0] || null;
}

function siteLabel(wpRoot, vhostsPath) {
  const rel = wpRoot.startsWith(vhostsPath + '/') ? wpRoot.slice(vhostsPath.length + 1) : wpRoot;
  return rel.split('/').slice(0, 2).join('/') || wpRoot;
}

async function analyzeSite(wpRoot, vhostsPath, { enableXmlRpcProbe }) {
  const pluginsDir    = path.join(wpRoot, 'wp-content', 'plugins');
  const domain        = extractDomain(wpRoot, vhostsPath);
  const version       = readWpVersion(wpRoot);
  const securityPlugins = getInstalledSecurityPlugins(pluginsDir);
  const riskyPlugins  = getInstalledRiskyPlugins(pluginsDir);
  const hasWordfence  = securityPlugins.includes('Wordfence');
  const wfActive      = hasWordfence && wordfenceRecentlySeen(pluginsDir);
  const xmlRpcOnDisk  = hasXmlRpcOnDisk(wpRoot);
  const debugEnabled  = isDebugEnabled(wpRoot);
  const noSecPlugin   = securityPlugins.length === 0;

  const [phpInUploadsCount, xmlRpcExposed] = await Promise.all([
    countPhpInUploads(wpRoot),
    (xmlRpcOnDisk && enableXmlRpcProbe && domain) ? probeXmlRpc(domain) : Promise.resolve(xmlRpcOnDisk ? null : false),
  ]);

  const issues = [];
  let score = 0;

  // PHP in uploads — critical regardless of anything else
  if (phpInUploadsCount > 0) {
    issues.push({ type: 'php_in_uploads', risk: 'critical',
      message: `${phpInUploadsCount} PHP/PHTML-Datei(en) im Upload-Verzeichnis — sofort prüfen` });
    score += 100;
  }

  // Security plugin status
  if (noSecPlugin) {
    issues.push({ type: 'no_security_plugin', risk: 'low',
      message: 'Kein Security-Plugin installiert (Wordfence, Sucuri o.ä.)' });
    score += 20;
  } else if (hasWordfence && !wfActive) {
    issues.push({ type: 'wordfence_inactive', risk: 'low',
      message: 'Wordfence installiert, aber seit >7 Tagen keine Scan-Aktivität erkannt' });
    score += 10;
  }

  // Risky plugins — CRITICAL if WP File Manager without any security plugin
  for (const p of riskyPlugins) {
    let effectiveRisk = p.baseRisk;
    let effectiveScore = p.score;
    if (p.slug === 'wp-file-manager' && noSecPlugin) {
      effectiveRisk = 'critical';
      effectiveScore = 100;
    }
    issues.push({ type: 'risky_plugin', risk: effectiveRisk,
      message: `Risiko-Plugin: ${p.name} — ${p.reason}${p.slug === 'wp-file-manager' && noSecPlugin ? ' (kein Security-Plugin aktiv!)' : ''}` });
    score += effectiveScore;
  }

  // XML-RPC
  if (xmlRpcExposed === true) {
    const risk = noSecPlugin ? 'medium' : 'low';
    issues.push({ type: 'xmlrpc_exposed', risk,
      message: 'xmlrpc.php öffentlich erreichbar — per .htaccess oder Nginx blockieren' });
    score += noSecPlugin ? 20 : 10;
  } else if (xmlRpcOnDisk && xmlRpcExposed === null) {
    issues.push({ type: 'xmlrpc_disk', risk: 'low',
      message: 'xmlrpc.php vorhanden (Erreichbarkeit nicht geprüft — blockieren empfohlen)' });
    score += 5;
  }

  // WP_DEBUG
  if (debugEnabled) {
    issues.push({ type: 'debug_enabled', risk: 'low',
      message: 'WP_DEBUG=true in wp-config.php — Fehlerdetails öffentlich sichtbar' });
    score += 10;
  }

  let risk = 'low';
  if (score >= 100) risk = 'critical';
  else if (score >= 60) risk = 'high';
  else if (score >= 30) risk = 'medium';

  return {
    site:           siteLabel(wpRoot, vhostsPath),
    domain,
    version,
    risk,
    score,
    securityPlugins,
    riskyPlugins:   riskyPlugins.map((p) => p.name),
    phpInUploads:   phpInUploadsCount,
    xmlRpcExposed,
    debugEnabled,
    issues,
  };
}

// ── Path resolver ─────────────────────────────────────────────────────────────

function resolveVhostsPath(configPath) {
  const candidates = [configPath, '/var/www/vhosts', '/home/httpd/vhosts', '/var/www/html', '/srv/www/vhosts']
    .filter((v, i, arr) => v && arr.indexOf(v) === i);
  for (const p of candidates) {
    if (!p) continue;
    try { fs.accessSync(p, fs.constants.R_OK); return p; } catch (_) {}
  }
  return null;
}

// ── Main check ────────────────────────────────────────────────────────────────

async function check(config) {
  const result = {
    name: 'wordpressCheck',
    status: 'ok',
    risk: 'low',
    findings: [],
    metrics: {
      sites: 0,
      withSecurityPlugin: 0,
      withoutSecurityPlugin: 0,
      riskyPluginsTotal: 0,
      phpInUploadsTotal: 0,
      siteDetails: [],
    },
  };

  const vhostsPath = resolveVhostsPath(config.VHOSTS_PATH);
  if (!vhostsPath) {
    result.status = 'error';
    result.findings.push({ type: 'path_error', risk: 'low', message: 'Vhosts-Verzeichnis nicht lesbar — WordPress-Check übersprungen' });
    return result;
  }

  const enableXmlRpcProbe = (process.env.ENABLE_XMLRPC_PROBE || 'true') !== 'false';

  try {
    const roots = await findWordPressRoots(vhostsPath);
    result.metrics.sites = roots.length;

    if (roots.length === 0) {
      result.findings.push({ type: 'info', risk: 'low', message: 'Keine WordPress-Installation gefunden' });
      return result;
    }

    const analyses = await Promise.all(roots.map((r) => analyzeSite(r, vhostsPath, { enableXmlRpcProbe })));

    for (const a of analyses) {
      if (a.securityPlugins.length > 0) result.metrics.withSecurityPlugin++;
      else result.metrics.withoutSecurityPlugin++;
      result.metrics.riskyPluginsTotal += a.riskyPlugins.length;
      result.metrics.phpInUploadsTotal += a.phpInUploads;
      result.metrics.siteDetails.push(a);

      for (const issue of a.issues) {
        result.findings.push({
          type:    issue.type,
          risk:    issue.risk,
          message: `[${a.site}${a.version ? ` WP ${a.version}` : ''}] ${issue.message}`,
          site:    a.site,
        });
        if (RISK_RANK[issue.risk] > RISK_RANK[result.risk]) result.risk = issue.risk;
      }
    }

    if (result.risk === 'critical' || result.metrics.phpInUploadsTotal > 0) result.status = 'error';
    else if (result.risk !== 'low') result.status = 'warning';

  } catch (err) {
    result.status = 'error';
    result.findings.push({ type: 'exec_error', risk: 'low', message: `WordPress-Check fehlgeschlagen: ${err.message}` });
  }

  return result;
}

module.exports = { check };

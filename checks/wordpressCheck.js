'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');

const execFileAsync = promisify(execFile);
const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

const PHP_BINARY_CANDIDATES = [
  '/opt/plesk/php/8.3/bin/php',
  '/opt/plesk/php/8.2/bin/php',
  '/opt/plesk/php/8.1/bin/php',
  '/opt/plesk/php/7.4/bin/php',
];
const WP_CLI_CANDIDATES = ['/usr/local/bin/wp', '/usr/bin/wp'];

// Legacy WP root files removed in old versions — presence is unusual but not malicious
const UNEXPECTED_ROOT_FILES = [
  'wp-rss2.php', 'wp-feed.php', 'wp-atom.php', 'wp-register.php',
  'wp-pass.php', 'wp-rdf.php', 'wp-rss.php', 'wp-commentsrss2.php',
];

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

// ── WP-CLI helpers ────────────────────────────────────────────────────────────

function findPhpBinary() {
  for (const p of PHP_BINARY_CANDIDATES) {
    try { require('child_process').execFileSync(p, ['--version'], { stdio: 'ignore', timeout: 3000 }); return p; } catch (_) {}
  }
  try { require('child_process').execFileSync('php', ['--version'], { stdio: 'ignore', timeout: 3000 }); return 'php'; } catch (_) {}
  return null;
}

function findWpCliBinary() {
  for (const p of WP_CLI_CANDIDATES) {
    try { fs.accessSync(p, fs.constants.X_OK); return p; } catch (_) {}
  }
  try {
    const found = require('child_process').execFileSync('which', ['wp'], { encoding: 'utf8', timeout: 3000 }).trim();
    if (found) return found;
  } catch (_) {}
  return null;
}

function resolveWpCli() {
  const wpBin = findWpCliBinary();
  if (!wpBin) return null;
  return { wpBin, phpBin: findPhpBinary() };
}

async function runWpVerifyChecksums(wpRoot, wpCliInfo) {
  const { wpBin, phpBin } = wpCliInfo;
  const env = phpBin && phpBin !== 'php'
    ? { ...process.env, PATH: `${path.dirname(phpBin)}:${process.env.PATH || ''}` }
    : process.env;

  let stdout = '';
  try {
    const res = await execFileAsync(wpBin, ['core', 'verify-checksums', '--allow-root', '--format=json'], {
      cwd: wpRoot, timeout: 30000, maxBuffer: 4 * 1024 * 1024, env,
    });
    stdout = res.stdout;
  } catch (err) {
    // wp exited non-zero (checksums failed) — stdout still contains JSON
    stdout = err.stdout || '';
    // If PHP not in PATH, retry with explicit php
    if (!stdout && phpBin) {
      try {
        const res2 = await execFileAsync(phpBin, [wpBin, 'core', 'verify-checksums', '--allow-root', '--format=json'], {
          cwd: wpRoot, timeout: 30000, maxBuffer: 4 * 1024 * 1024,
        });
        stdout = res2.stdout;
      } catch (err2) { stdout = err2.stdout || ''; }
    }
  }

  const entries = (() => {
    if (!stdout.trim()) return [];
    try { return JSON.parse(stdout); } catch (_) { return []; }
  })();

  const errors        = entries.filter((e) => e.type === 'error').map((e) => e.file_name || e.file || '');
  const warnings      = entries.filter((e) => e.type === 'warning').map((e) => ({ file: e.file_name || e.file || '', message: e.message || '' }));
  const unexpectedFiles = warnings.filter((w) => /should not exist/i.test(w.message)).map((w) => w.file);

  return {
    checksumStatus: errors.length > 0 ? 'failed' : (entries.length > 0 ? 'warnings' : 'ok'),
    checksumErrors: errors,
    checksumWarnings: warnings.map((w) => `${w.file}: ${w.message}`),
    unexpectedFiles,
    phpBinaryUsed: phpBin || 'php',
    wpCliPath: wpBin,
  };
}

function findUnexpectedRootFiles(wpRoot) {
  return UNEXPECTED_ROOT_FILES.filter((f) => {
    try { fs.accessSync(path.join(wpRoot, f), fs.constants.F_OK); return true; } catch (_) { return false; }
  });
}

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

async function analyzeSite(wpRoot, vhostsPath, { enableXmlRpcProbe, wpCliInfo }) {
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

  // WP-CLI checksum verification
  let checksumResult = null;
  if (wpCliInfo) {
    try { checksumResult = await runWpVerifyChecksums(wpRoot, wpCliInfo); } catch (_) {}
  }

  // Unexpected legacy root files (from filesystem + checksum warnings)
  const fsUnexpected = findUnexpectedRootFiles(wpRoot);
  const checksumUnexpected = checksumResult?.unexpectedFiles || [];
  const allUnexpected = [...new Set([...fsUnexpected, ...checksumUnexpected])];

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

  // Unexpected legacy root files
  for (const f of allUnexpected) {
    issues.push({
      type: 'unexpected_core_adjacent_file',
      risk: 'low',
      message: `Unerwartete/veraltete WordPress-Datei: ${f} — sichern und entfernen`,
      file: f,
    });
    score += 5;
  }

  // Checksum errors (modified core files)
  if (checksumResult?.checksumErrors?.length) {
    issues.push({
      type: 'checksum_error',
      risk: 'high',
      message: `${checksumResult.checksumErrors.length} WordPress-Core-Datei(en) weichen vom offiziellen Checksum ab: ${checksumResult.checksumErrors.slice(0, 3).join(', ')}`,
    });
    score += 60;
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
    checksumStatus:    checksumResult?.checksumStatus   || 'not_checked',
    checksumErrors:    checksumResult?.checksumErrors   || [],
    checksumWarnings:  checksumResult?.checksumWarnings || [],
    unexpectedFiles:   allUnexpected,
    phpBinaryUsed:     checksumResult?.phpBinaryUsed    || null,
    wpCliPath:         checksumResult?.wpCliPath        || null,
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

    const wpCliInfo = resolveWpCli();
    const analyses = await Promise.all(roots.map((r) => analyzeSite(r, vhostsPath, { enableXmlRpcProbe, wpCliInfo })));

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

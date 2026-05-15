'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');

const execFileAsync = promisify(execFile);
const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

const SECURITY_PLUGINS = [
  { slug: 'wordfence',                          name: 'Wordfence' },
  { slug: 'better-wp-security',                 name: 'iThemes Security' },
  { slug: 'sucuri-scanner',                     name: 'Sucuri Scanner' },
  { slug: 'all-in-one-wp-security-and-firewall',name: 'All In One WP Security' },
  { slug: 'wp-cerber',                          name: 'WP Cerber Security' },
  { slug: 'shield-security',                    name: 'Shield Security' },
  { slug: 'bulletproof-security',               name: 'BulletProof Security' },
  { slug: 'loginizer',                          name: 'Loginizer' },
  { slug: 'wps-hide-login',                     name: 'WPS Hide Login' },
];

// Plugins with known severe vulnerabilities or high attack surface
const RISKY_PLUGINS = [
  { slug: 'wp-file-manager',      name: 'WP File Manager',      risk: 'high',   reason: 'RCE-Schwachstelle bekannt (CVE-2020-25213)' },
  { slug: 'file-manager-advanced',name: 'File Manager Advanced', risk: 'medium', reason: 'Datei-Manager mit erhöhtem Angriffspotenzial' },
  { slug: 'revslider',            name: 'Revolution Slider',     risk: 'medium', reason: 'Historisch bekannte LFI/RFI-Schwachstellen' },
  { slug: 'cherry-plugin',        name: 'Cherry Plugin',         risk: 'high',   reason: 'File-Upload / Remote-File-Inclusion' },
  { slug: 'wp-symposium',         name: 'WP Symposium',          risk: 'high',   reason: 'Mehrfach kritische Schwachstellen' },
  { slug: 'wp-ecommerce',         name: 'WP e-Commerce',         risk: 'medium', reason: 'SQL-Injection in älteren Versionen' },
];

// ── Filesystem helpers ────────────────────────────────────────────────────────

async function findWordPressRoots(vhostsPath) {
  try {
    const { stdout } = await execFileAsync('find', [
      vhostsPath,
      '-name', 'wp-config.php',
      '-maxdepth', '10',
      '-type', 'f',
      '-not', '-path', '*/vendor/*',
      '-not', '-path', '*/node_modules/*',
    ], { timeout: 30000, maxBuffer: 5 * 1024 * 1024 });

    const paths = (stdout || '').split('\n').filter(Boolean).map((p) => path.dirname(p));
    return [...new Set(paths)];
  } catch (err) {
    if (err.stdout) {
      const paths = err.stdout.split('\n').filter(Boolean).map((p) => path.dirname(p));
      return [...new Set(paths)];
    }
    throw err;
  }
}

function readWpVersion(wpRoot) {
  try {
    const content = fs.readFileSync(path.join(wpRoot, 'wp-includes', 'version.php'), 'utf8');
    const match = content.match(/\$wp_version\s*=\s*['"]([^'"]+)['"]/);
    return match ? match[1] : null;
  } catch (_) {
    return null;
  }
}

function getInstalledSecurityPlugins(pluginsDir) {
  return SECURITY_PLUGINS.filter(({ slug }) => {
    try { fs.accessSync(path.join(pluginsDir, slug), fs.constants.R_OK); return true; } catch (_) { return false; }
  }).map(({ name }) => name);
}

function getInstalledRiskyPlugins(pluginsDir) {
  return RISKY_PLUGINS.filter(({ slug }) => {
    try { fs.accessSync(path.join(pluginsDir, slug), fs.constants.R_OK); return true; } catch (_) { return false; }
  });
}

async function countPhpInUploads(wpRoot) {
  try {
    const uploadsPath = path.join(wpRoot, 'wp-content', 'uploads');
    const { stdout } = await execFileAsync('find', [
      uploadsPath, '-name', '*.php', '-o', '-name', '*.phtml',
    ], { timeout: 10000, maxBuffer: 1024 * 1024 });
    return (stdout || '').split('\n').filter(Boolean).length;
  } catch (err) {
    return err.stdout ? err.stdout.split('\n').filter(Boolean).length : 0;
  }
}

function hasXmlRpc(wpRoot) {
  try { fs.accessSync(path.join(wpRoot, 'xmlrpc.php'), fs.constants.F_OK); return true; } catch (_) { return false; }
}

function isDebugEnabled(wpRoot) {
  try {
    const content = fs.readFileSync(path.join(wpRoot, 'wp-config.php'), 'utf8');
    return /define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true\s*\)/i.test(content);
  } catch (_) {
    return false;
  }
}

function wordfenceRecentlySeen(pluginsDir) {
  // wflogs directory mtime indicates last scan activity
  try {
    const wflogsPath = path.join(path.dirname(pluginsDir), 'wflogs');
    const stat = fs.statSync(wflogsPath);
    const ageHours = (Date.now() - stat.mtime.getTime()) / 3_600_000;
    return ageHours < 24 * 7; // active within last 7 days
  } catch (_) {
    return false;
  }
}

function siteLabel(wpRoot, vhostsPath) {
  const rel = wpRoot.startsWith(vhostsPath + '/') ? wpRoot.slice(vhostsPath.length + 1) : wpRoot;
  return rel.split('/').slice(0, 2).join('/') || wpRoot;
}

// ── Per-site analysis ─────────────────────────────────────────────────────────

async function analyzeSite(wpRoot, vhostsPath) {
  const pluginsDir = path.join(wpRoot, 'wp-content', 'plugins');
  const [phpInUploadsCount] = await Promise.all([countPhpInUploads(wpRoot)]);

  const version         = readWpVersion(wpRoot);
  const securityPlugins = getInstalledSecurityPlugins(pluginsDir);
  const riskyPlugins    = getInstalledRiskyPlugins(pluginsDir);
  const hasWordfence    = securityPlugins.includes('Wordfence');
  const wfActive        = hasWordfence && wordfenceRecentlySeen(pluginsDir);
  const xmlRpc          = hasXmlRpc(wpRoot);
  const debugEnabled    = isDebugEnabled(wpRoot);

  const issues = [];
  let score = 0;

  // PHP files inside wp-content/uploads → critical indicator
  if (phpInUploadsCount > 0) {
    issues.push({ type: 'php_in_uploads', risk: 'critical', message: `${phpInUploadsCount} PHP/PHTML-Datei(en) im Upload-Verzeichnis` });
    score += 100;
  }

  // No security plugin at all
  if (securityPlugins.length === 0) {
    issues.push({ type: 'no_security_plugin', risk: 'low', message: 'Kein Security-Plugin installiert (Wordfence, Sucuri o.ä.)' });
    score += 20;
  } else if (hasWordfence && !wfActive) {
    issues.push({ type: 'wordfence_inactive', risk: 'low', message: 'Wordfence installiert, aber seit >7 Tagen keine Scan-Aktivität' });
    score += 10;
  }

  // Risky plugins
  for (const p of riskyPlugins) {
    issues.push({ type: 'risky_plugin', risk: p.risk, message: `Risiko-Plugin: ${p.name} — ${p.reason}` });
    score += p.risk === 'high' ? 60 : 35;
  }

  // XML-RPC present (informational — real risk depends on server config)
  if (xmlRpc) {
    issues.push({ type: 'xmlrpc_exposed', risk: 'low', message: 'xmlrpc.php vorhanden — per .htaccess oder Nginx blockieren empfohlen' });
    score += 10;
  }

  // WP_DEBUG on in production
  if (debugEnabled) {
    issues.push({ type: 'debug_enabled', risk: 'low', message: 'WP_DEBUG=true in wp-config.php — Fehlerdetails öffentlich sichtbar' });
    score += 10;
  }

  let risk = 'low';
  if (score >= 100) risk = 'critical';
  else if (score >= 60) risk = 'high';
  else if (score >= 30) risk = 'medium';

  return {
    site:           siteLabel(wpRoot, vhostsPath),
    version,
    risk,
    securityPlugins,
    riskyPlugins:   riskyPlugins.map((p) => p.name),
    phpInUploads:   phpInUploadsCount,
    issues,
  };
}

// ── Path resolver (same pattern as suspiciousFiles) ───────────────────────────

function resolveVhostsPath(configPath) {
  const candidates = [
    configPath,
    '/var/www/vhosts',
    '/home/httpd/vhosts',
    '/var/www/html',
    '/srv/www/vhosts',
  ].filter((v, i, arr) => v && arr.indexOf(v) === i);
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
      sites:                 0,
      withSecurityPlugin:    0,
      withoutSecurityPlugin: 0,
      riskyPluginsTotal:     0,
      phpInUploadsTotal:     0,
    },
  };

  const vhostsPath = resolveVhostsPath(config.VHOSTS_PATH);
  if (!vhostsPath) {
    result.status = 'error';
    result.findings.push({ type: 'path_error', risk: 'low', message: 'Vhosts-Verzeichnis nicht lesbar — WordPress-Check übersprungen' });
    return result;
  }

  try {
    const roots = await findWordPressRoots(vhostsPath);
    result.metrics.sites = roots.length;

    if (roots.length === 0) {
      result.findings.push({ type: 'info', risk: 'low', message: 'Keine WordPress-Installation gefunden' });
      return result;
    }

    const analyses = await Promise.all(roots.map((r) => analyzeSite(r, vhostsPath)));

    for (const a of analyses) {
      if (a.securityPlugins.length > 0) result.metrics.withSecurityPlugin++;
      else result.metrics.withoutSecurityPlugin++;
      result.metrics.riskyPluginsTotal += a.riskyPlugins.length;
      result.metrics.phpInUploadsTotal += a.phpInUploads;

      for (const issue of a.issues) {
        result.findings.push({
          type:    issue.type,
          risk:    issue.risk,
          message: `[${a.site}${a.version ? ` WP ${a.version}` : ''}] ${issue.message}`,
        });
        if (RISK_RANK[issue.risk] > RISK_RANK[result.risk]) result.risk = issue.risk;
      }
    }

    if (result.risk === 'critical' || result.metrics.phpInUploadsTotal > 0) {
      result.status = 'error';
    } else if (result.risk !== 'low') {
      result.status = 'warning';
    }

  } catch (err) {
    result.status = 'error';
    result.findings.push({ type: 'exec_error', risk: 'low', message: `WordPress-Check fehlgeschlagen: ${err.message}` });
  }

  return result;
}

module.exports = { check };

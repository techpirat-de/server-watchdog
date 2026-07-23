'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const execFileAsync = promisify(execFile);

const INCIDENT_ROOT = process.env.INCIDENT_OUTPUT_DIR || '/root/watchdog-incidents';
const MAX_COPY_FILES = parseInt(process.env.INCIDENT_MAX_COPY_FILES, 10) || 250;
const MAX_FILE_READ_BYTES = 512 * 1024;
const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

const INCIDENT_TRIGGER_TYPES = new Set([
  'checksum_error',
  'php_in_uploads',
  'suspicious_file',
  'mass_infection_hash',
  'mass_infection_size',
  'mass_modification_burst',
  'http_status',
  'url_unreachable',
]);

const INCIDENT_TRIGGER_LABELS = [
  /checksum/i,
  /core.*ver[aä]ndert/i,
  /php-datei in upload/i,
  /eval\(base64_decode/i,
  /gzinflate/i,
  /base64/i,
  /zuf[aä]llig wirkender php-dateiname/i,
  /generischer dateiname/i,
  /verstecktem pfad/i,
  /include\/require/i,
  /compress\.zlib/i,
  /openssl_decrypt/i,
  /verschleiert|obfuskation/i,
  /wordfence/i,
];

const WEBSHELL_PATTERNS = [
  { label: 'eval()', pattern: /eval\s*\(/i },
  { label: 'assert()', pattern: /assert\s*\(/i },
  { label: 'preg_replace /e', pattern: /preg_replace\s*\([^;]+\/e['"]/i },
  { label: 'base64_decode()', pattern: /base64_decode\s*\(/i },
  { label: 'gzinflate()', pattern: /gzinflate\s*\(/i },
  { label: 'gzuncompress()', pattern: /gzuncompress\s*\(/i },
  { label: 'str_rot13()', pattern: /str_rot13\s*\(/i },
  { label: 'openssl_decrypt()', pattern: /openssl_decrypt\s*\(/i },
  { label: 'decryptChunks()', pattern: /decryptChunks\s*\(/i },
  { label: 'Security check failed', pattern: /Security check failed/i },
  { label: 'compress.zlib://', pattern: /compress\.zlib:\/\//i },
  { label: 'php://input', pattern: /php:\/\/input/i },
  { label: 'php://filter', pattern: /php:\/\/filter/i },
  { label: 'create_function()', pattern: /create_function\s*\(/i },
  { label: 'system()', pattern: /\bsystem\s*\(/i },
  { label: 'exec()', pattern: /\bexec\s*\(/i },
  { label: 'shell_exec()', pattern: /shell_exec\s*\(/i },
  { label: 'passthru()', pattern: /passthru\s*\(/i },
  { label: 'popen()', pattern: /popen\s*\(/i },
  { label: 'proc_open()', pattern: /proc_open\s*\(/i },
  { label: 'move_uploaded_file()', pattern: /move_uploaded_file\s*\(/i },
  { label: 'file_put_contents()', pattern: /file_put_contents\s*\(/i },
  { label: 'Stealth Shell', pattern: /\b(?:FilesMan|WSO|c99shell|r57shell|b374k|IndoXploit|alfanew)\b/i },
  { label: 'WAF Bypass', pattern: /\b(?:disable_functions|open_basedir|safe_mode|ini_set)\b/i },
];
const WP_CLI_CANDIDATES = ['/usr/local/bin/wp', '/usr/bin/wp'];
const PHP_BINARY_CANDIDATES = [
  '/opt/plesk/php/8.3/bin/php',
  '/opt/plesk/php/8.2/bin/php',
  '/opt/plesk/php/8.1/bin/php',
  '/opt/plesk/php/7.4/bin/php',
];
const WP_CRITICAL_FILES = ['wp-config.php', 'wp-settings.php', 'wp-load.php', 'xmlrpc.php', 'index.php', '.htaccess'];

function riskAtLeast(risk, minRisk) {
  return RISK_RANK[risk || 'low'] >= RISK_RANK[minRisk || 'low'];
}

function nowStamp(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}_${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

function safeFileName(value) {
  return String(value || 'unknown').replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 180);
}

function normalizePath(filePath) {
  return String(filePath || '').replace(/\\/g, '/');
}

function relativeCopyPath(filePath) {
  const normalized = normalizePath(filePath).replace(/^\/+/, '');
  return normalized || safeFileName(filePath);
}

async function mkdirp(dir) {
  await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
}

async function fileExists(filePath) {
  try {
    await fs.promises.access(filePath, fs.constants.R_OK);
    return true;
  } catch (_) {
    return false;
  }
}

async function statFile(filePath) {
  try {
    const stat = await fs.promises.stat(filePath);
    return {
      exists: true,
      sizeBytes: stat.size,
      mode: `0${(stat.mode & 0o7777).toString(8)}`,
      uid: stat.uid,
      gid: stat.gid,
      modifiedAt: stat.mtime.toISOString(),
      changedAt: stat.ctime.toISOString(),
    };
  } catch (err) {
    return { exists: false, error: err.message };
  }
}

async function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function readSample(filePath) {
  const handle = await fs.promises.open(filePath, 'r');
  try {
    const buffer = Buffer.alloc(MAX_FILE_READ_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.slice(0, bytesRead).toString('utf8');
  } finally {
    await handle.close();
  }
}

function detectIncidentTriggers(report) {
  const triggers = [];
  for (const check of report.checks || []) {
    if (check.name === 'wordpressCheck') {
      for (const site of check.metrics?.siteDetails || []) {
        if (site.checksumStatus === 'failed' || (site.checksumErrors || []).length > 0) {
          triggers.push({ check: check.name, type: 'wordpress_core_checksum', risk: 'high', message: `${site.site}: WordPress-Core-Checksum fehlgeschlagen` });
        }
        if (site.phpInUploads > 0) {
          triggers.push({ check: check.name, type: 'php_in_uploads', risk: 'critical', message: `${site.site}: ${site.phpInUploads} PHP-Datei(en) in Uploads` });
        }
      }
    }

    if (check.name === 'suspiciousFiles') {
      const metrics = check.metrics || {};
      if ((metrics.critical || 0) > 0 || (metrics.high || 0) > 0) {
        triggers.push({ check: check.name, type: 'suspicious_files_high_risk', risk: check.risk, message: `${metrics.critical || 0} critical / ${metrics.high || 0} high verdächtige Dateien` });
      }
    }

    for (const finding of check.findings || []) {
      const message = finding.message || finding.type || '';
      const labels = (finding.reasons || finding.patterns || []).map((r) => r.label || '').join(' ');
      const text = `${message} ${labels}`;
      const triggerType = INCIDENT_TRIGGER_TYPES.has(finding.type);
      const triggerLabel = INCIDENT_TRIGGER_LABELS.some((pattern) => pattern.test(text));
      if (riskAtLeast(finding.risk || check.risk, 'high') && (triggerType || triggerLabel)) {
        triggers.push({
          check: check.name,
          type: finding.type || 'finding',
          risk: finding.risk || check.risk,
          message,
          file: finding.file || null,
          site: finding.site || null,
        });
      }
    }
  }
  return triggers;
}

function collectSuspiciousFiles(report) {
  const files = new Map();
  for (const check of report.checks || []) {
    for (const finding of check.findings || []) {
      const paths = [];
      if (finding.file) paths.push(finding.file);
      if (Array.isArray(finding.files)) paths.push(...finding.files);
      for (const filePath of paths) {
        if (!filePath || typeof filePath !== 'string') continue;
        const existing = files.get(filePath) || {
          file: filePath,
          sources: [],
          reasons: [],
          risk: 'low',
          score: finding.score || null,
        };
        existing.sources.push(check.name);
        existing.reasons.push(finding.message || finding.type || 'Verdächtiger Befund');
        if (riskAtLeast(finding.risk || check.risk, existing.risk)) existing.risk = finding.risk || check.risk || 'low';
        if (finding.sha256) existing.sha256 = finding.sha256;
        if (finding.sizeBytes) existing.sizeBytes = finding.sizeBytes;
        if (finding.modifiedAt) existing.modifiedAt = finding.modifiedAt;
        files.set(filePath, existing);
      }
    }
  }
  return [...files.values()];
}

function extractDomains(filePath, config) {
  const vhostsPath = normalizePath(config.VHOSTS_PATH || '/var/www/vhosts').replace(/\/$/, '');
  const normalized = normalizePath(filePath);
  if (!normalized.startsWith(`${vhostsPath}/`)) return [];
  const parts = normalized.slice(vhostsPath.length + 1).split('/');
  return parts[0] ? [parts[0]] : [];
}

function extractIocsFromContent(content) {
  const base64Blocks = [...new Set((content.match(/[A-Za-z0-9+/]{80,}={0,2}/g) || []).slice(0, 20))];
  const aesKeys = [...new Set((content.match(/(?:key|secret|pass(?:word)?)\s*=\s*['"][A-Za-z0-9+/=_-]{16,64}['"]/gi) || []).slice(0, 20))];
  const classes = [...new Set([...content.matchAll(/\bclass\s+([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]).slice(0, 20))];
  const variables = [...new Set([...content.matchAll(/\$([A-Za-z_][A-Za-z0-9_]{2,})/g)].map((m) => m[1]).slice(0, 50))];
  const patterns = WEBSHELL_PATTERNS.filter((rule) => rule.pattern.test(content)).map((rule) => rule.label);
  const normalizedCodeHash = crypto.createHash('sha256')
    .update(content.replace(/\s+/g, '').replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, ''))
    .digest('hex');
  return { base64Blocks, aesKeys, classes, variables, patterns, normalizedCodeHash };
}

async function enrichFileRecord(record, config) {
  const metadata = await statFile(record.file);
  const enriched = {
    ...record,
    sources: [...new Set(record.sources)],
    domains: extractDomains(record.file, config),
    metadata,
    copiedTo: null,
    iocs: { base64Blocks: [], aesKeys: [], classes: [], variables: [], patterns: [], normalizedCodeHash: null },
  };
  if (!metadata.exists) return enriched;

  try {
    enriched.sha256 = record.sha256 || await hashFile(record.file);
  } catch (err) {
    enriched.hashError = err.message;
  }

  try {
    const content = await readSample(record.file);
    enriched.iocs = extractIocsFromContent(content);
  } catch (err) {
    enriched.readError = err.message;
  }

  return enriched;
}

async function copySuspiciousFiles(files, incidentDir) {
  const copied = [];
  const evidenceDir = path.join(incidentDir, 'files');
  await mkdirp(evidenceDir);

  for (const file of files.slice(0, MAX_COPY_FILES)) {
    if (!file.metadata?.exists) continue;
    const target = path.join(evidenceDir, relativeCopyPath(file.file));
    try {
      await mkdirp(path.dirname(target));
      await fs.promises.copyFile(file.file, target);
      await fs.promises.chmod(target, 0o400);
      file.copiedTo = target;
      copied.push({ source: file.file, target });
    } catch (err) {
      file.copyError = err.message;
    }
  }
  return copied;
}

function groupBy(items, keyFn) {
  const groups = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (!key) continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return [...groups.entries()]
    .map(([key, values]) => ({ key, count: values.length, items: values }))
    .sort((a, b) => b.count - a.count || String(a.key).localeCompare(String(b.key)));
}

function buildTimeline(files) {
  const sortable = files
    .filter((f) => f.metadata?.modifiedAt || f.modifiedAt)
    .map((f) => ({ ...f, time: new Date(f.metadata?.modifiedAt || f.modifiedAt) }))
    .filter((f) => Number.isFinite(f.time.getTime()))
    .sort((a, b) => a.time - b.time);

  const fmt = (date, mode) => {
    const iso = date.toISOString();
    if (mode === 'minute') return iso.slice(0, 16).replace('T', ' ');
    if (mode === 'hour') return iso.slice(0, 13).replace('T', ' ');
    return iso.slice(0, 10);
  };

  const minuteGroups = groupBy(sortable, (f) => fmt(f.time, 'minute'));
  const hourGroups = groupBy(sortable, (f) => fmt(f.time, 'hour'));
  const dayGroups = groupBy(sortable, (f) => fmt(f.time, 'day'));
  const attackWaves = minuteGroups.filter((g) => g.count >= 10)
    .map((g) => ({ time: g.key, count: g.count, examples: g.items.slice(0, 10).map((f) => f.file) }));

  return {
    firstActivity: sortable[0]?.time.toISOString() || null,
    lastActivity: sortable[sortable.length - 1]?.time.toISOString() || null,
    byMinute: minuteGroups.map((g) => ({ time: g.key, count: g.count, files: g.items.slice(0, 20).map((f) => f.file) })),
    byHour: hourGroups.map((g) => ({ time: g.key, count: g.count })),
    byDay: dayGroups.map((g) => ({ date: g.key, count: g.count })),
    attackWaves,
    firstAffectedWebsite: sortable.find((f) => f.domains?.length)?.domains?.[0] || null,
  };
}

function buildIocGroups(files) {
  const sha256 = groupBy(files.filter((f) => f.sha256), (f) => f.sha256);
  const size = groupBy(files.filter((f) => f.metadata?.sizeBytes), (f) => String(f.metadata.sizeBytes));
  const normalizedCode = groupBy(files.filter((f) => f.iocs?.normalizedCodeHash), (f) => f.iocs.normalizedCodeHash);

  const patternGroups = new Map();
  const classGroups = new Map();
  const variableGroups = new Map();
  const aesKeyGroups = new Map();
  const base64Groups = new Map();

  for (const file of files) {
    for (const pattern of file.iocs?.patterns || []) addGrouped(patternGroups, pattern, file);
    for (const cls of file.iocs?.classes || []) addGrouped(classGroups, cls, file);
    for (const variable of file.iocs?.variables || []) addGrouped(variableGroups, variable, file);
    for (const key of file.iocs?.aesKeys || []) addGrouped(aesKeyGroups, key, file);
    for (const block of file.iocs?.base64Blocks || []) addGrouped(base64Groups, crypto.createHash('sha256').update(block).digest('hex'), file);
  }

  return {
    identicalSha256: simplifyGroups(sha256, 2),
    identicalSize: simplifyGroups(size, 10),
    identicalCode: simplifyGroups(normalizedCode, 2),
    sameWebshellPatterns: simplifyMapGroups(patternGroups, 2),
    sameClasses: simplifyMapGroups(classGroups, 2),
    sameVariables: simplifyMapGroups(variableGroups, 5),
    sameAesKeys: simplifyMapGroups(aesKeyGroups, 2),
    sameBase64Blocks: simplifyMapGroups(base64Groups, 2),
  };
}

function addGrouped(map, key, file) {
  if (!key) return;
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(file);
}

function simplifyGroups(groups, minCount) {
  return groups
    .filter((g) => g.count >= minCount)
    .slice(0, 25)
    .map((g) => ({ key: g.key, count: g.count, files: g.items.slice(0, 20).map((f) => f.file) }));
}

function simplifyMapGroups(map, minCount) {
  return [...map.entries()]
    .map(([key, items]) => ({ key, count: new Set(items.map((f) => f.file)).size, items }))
    .filter((g) => g.count >= minCount)
    .sort((a, b) => b.count - a.count || String(a.key).localeCompare(String(b.key)))
    .slice(0, 25)
    .map((g) => ({ key: g.key, count: g.count, files: [...new Set(g.items.map((f) => f.file))].slice(0, 20) }));
}

async function runCommand(name, args, options = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(name, args, {
      timeout: options.timeout || 10000,
      maxBuffer: options.maxBuffer || 1024 * 1024,
      cwd: options.cwd,
      env: options.env || process.env,
    });
    return { command: [name, ...args].join(' '), ok: true, stdout: stdout.trim(), stderr: stderr.trim() };
  } catch (err) {
    return {
      command: [name, ...args].join(' '),
      ok: false,
      stdout: (err.stdout || '').trim(),
      stderr: (err.stderr || '').trim(),
      error: err.message,
    };
  }
}

async function readTextIfExists(filePath, maxBytes = 128 * 1024) {
  try {
    const stat = await fs.promises.stat(filePath);
    if (!stat.isFile()) return null;
    const handle = await fs.promises.open(filePath, 'r');
    try {
      const buffer = Buffer.alloc(Math.min(stat.size, maxBytes));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      return buffer.slice(0, bytesRead).toString('utf8');
    } finally {
      await handle.close();
    }
  } catch (_) {
    return null;
  }
}

async function collectPersistence() {
  const files = [
    '/etc/crontab',
    '/etc/rc.local',
    '/root/.bashrc',
    '/root/.profile',
    '/root/.ssh/authorized_keys',
  ];
  const directories = ['/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/init.d'];
  const fileReads = {};
  for (const filePath of files) {
    const content = await readTextIfExists(filePath);
    if (content !== null) fileReads[filePath] = content;
  }

  const dirListings = {};
  for (const dir of directories) {
    try {
      dirListings[dir] = await fs.promises.readdir(dir);
    } catch (err) {
      dirListings[dir] = { error: err.message };
    }
  }

  const commands = [
    await runCommand('crontab', ['-l']),
    await runCommand('systemctl', ['list-unit-files', '--type=service', '--no-pager']),
    await runCommand('find', ['/etc', '/root', '-name', '.*', '-type', 'f', '-maxdepth', '4']),
    await runCommand('awk', ['-F:', '{print $1 ":" $7}', '/etc/passwd']),
  ];

  const suspicious = [];
  const combined = JSON.stringify({ fileReads, dirListings, commands }).toLowerCase();
  for (const marker of ['curl ', 'wget ', '/tmp/', '/dev/shm', 'base64', 'php ', 'nc ', 'bash -i', 'authorized_keys']) {
    if (combined.includes(marker)) suspicious.push(marker.trim());
  }

  return {
    cronChanged: suspicious.some((s) => ['curl', 'wget', '/tmp/', '/dev/shm', 'php'].includes(s)),
    sshChanged: combined.includes('authorized_keys') && fileReads['/root/.ssh/authorized_keys'],
    suspiciousMarkers: suspicious,
    files: fileReads,
    directories: dirListings,
    commands,
  };
}

async function collectLogClues(config, timeline) {
  const candidates = [
    '/var/log/apache2/access.log',
    '/var/log/nginx/access.log',
    '/var/log/plesk/panel.log',
    '/var/log/auth.log',
    '/var/log/secure',
    '/var/log/messages',
    config.MAIL_LOG_PATH,
  ].filter(Boolean);
  const existing = [];
  for (const filePath of [...new Set(candidates)]) {
    if (await fileExists(filePath)) existing.push(filePath);
  }

  const terms = [
    'POST ',
    'admin-ajax.php',
    'xmlrpc.php',
    '/wp-json/',
    'plugin-upload',
    'upload.php',
    'wp-login.php',
    ' 404 ',
    ' 500 ',
  ];
  const results = [];
  for (const filePath of existing) {
    const grep = await runCommand('grep', ['-Eai', terms.map(escapeGrepTerm).join('|'), filePath], { timeout: 15000, maxBuffer: 512 * 1024 });
    const lines = (grep.stdout || '').split('\n').filter(Boolean).slice(-200);
    results.push({ file: filePath, matchedLines: lines.length, lines });
  }

  return {
    searchedFiles: existing,
    firstActivity: timeline.firstActivity,
    likelyEntryHints: results.filter((r) => r.matchedLines > 0),
  };
}

function escapeGrepTerm(term) {
  return term.replace(/[|\\{}()[\]^$+*?.]/g, '\\$&');
}

function buildCampaigns(files, iocGroups) {
  const campaigns = [];
  let idx = 1;
  for (const group of iocGroups.identicalSha256.filter((g) => g.count >= 3)) {
    const groupFiles = files.filter((f) => f.sha256 === group.key);
    const domains = [...new Set(groupFiles.flatMap((f) => f.domains || []))];
    const times = groupFiles
      .map((f) => new Date(f.metadata?.modifiedAt || f.modifiedAt).getTime())
      .filter(Number.isFinite)
      .sort((a, b) => a - b);
    campaigns.push({
      name: `Malware Campaign #${idx++}`,
      files: group.count,
      identicalSha256: true,
      sha256: group.key,
      sizeBytes: groupFiles[0]?.metadata?.sizeBytes || groupFiles[0]?.sizeBytes || null,
      firstSeen: times[0] ? new Date(times[0]).toISOString() : null,
      lastSeen: times[times.length - 1] ? new Date(times[times.length - 1]).toISOString() : null,
      affectedDomains: domains,
      assessment: domains.length >= 2 || group.count >= 10
        ? 'Sehr wahrscheinlich automatisierter Massenangriff'
        : 'Mehrfachfund mit identischem Schadcode',
    });
  }
  return campaigns;
}

function buildQuarantineRecommendations(files, incidentDir) {
  return files
    .filter((file) => riskAtLeast(file.risk, 'high') && file.metadata?.exists)
    .map((file) => {
      const quarantinePath = path.join('/root/watchdog-quarantine', relativeCopyPath(file.file));
      return {
        file: file.file,
        reason: file.reasons.join('; '),
        risk: file.risk,
        sha256: file.sha256 || null,
        owner: file.metadata ? `${file.metadata.uid}:${file.metadata.gid}` : null,
        modifiedAt: file.metadata?.modifiedAt || null,
        recommendedAction: 'Manuell prüfen, Backup/Evidence sichern, danach chmod 000 oder Quarantäne nur nach Bestätigung.',
        quarantinePath,
        commands: [
          `install -d '${path.dirname(quarantinePath).replace(/'/g, "'\\''")}'`,
          `cp -a -- '${file.file.replace(/'/g, "'\\''")}' '${quarantinePath.replace(/'/g, "'\\''")}.bak'`,
          `chmod 000 -- '${file.file.replace(/'/g, "'\\''")}'`,
          `mv -- '${file.file.replace(/'/g, "'\\''")}' '${quarantinePath.replace(/'/g, "'\\''")}'`,
        ],
        evidenceCopy: file.copiedTo ? path.relative(incidentDir, file.copiedTo) : null,
      };
    });
}

function buildWordPressSummary(report) {
  const wp = (report.checks || []).find((check) => check.name === 'wordpressCheck');
  const sites = wp?.metrics?.siteDetails || [];
  return sites.map((site) => ({
    site: site.site,
    domain: site.domain,
    version: site.version,
    risk: site.risk,
    checksumStatus: site.checksumStatus,
    checksumErrors: site.checksumErrors || [],
    plugins: site.riskyPlugins || [],
    securityPlugins: site.securityPlugins || [],
    phpInUploads: site.phpInUploads,
    muPlugins: 'nicht separat geprüft',
    dropIns: 'nicht separat geprüft',
    wpConfig: site.debugEnabled ? 'WP_DEBUG=true' : 'unauffällig laut Standardcheck',
    xmlRpcExposed: site.xmlRpcExposed,
    filePermissions: 'Metadaten verdächtiger Dateien im Datei-Report enthalten',
    adminUsers: 'nicht geprüft (WP-CLI/DB-Auswertung noch nicht aktiviert)',
    restApi: 'nicht geprüft',
  }));
}

function findExecutable(candidates, fallback) {
  for (const candidate of candidates) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch (_) {}
  }
  if (fallback) {
    try {
      const result = require('child_process').execFileSync('which', [fallback], { encoding: 'utf8', timeout: 3000 }).trim();
      if (result) return result;
    } catch (_) {}
  }
  return null;
}

function resolveWpCliForensics() {
  const wpBin = findExecutable(WP_CLI_CANDIDATES, 'wp');
  if (!wpBin) return null;
  const phpBin = findExecutable(PHP_BINARY_CANDIDATES, 'php') || 'php';
  return { wpBin, phpBin };
}

async function runWpCliJson(wpCliInfo, wpRoot, args) {
  if (!wpCliInfo) return { status: 'not_checked', reason: 'wp-cli nicht gefunden' };
  const { wpBin, phpBin } = wpCliInfo;
  const fullArgs = [...args, '--allow-root', '--format=json'];
  const env = phpBin && phpBin !== 'php'
    ? { ...process.env, PATH: `${path.dirname(phpBin)}:${process.env.PATH || ''}` }
    : process.env;
  let result = await runCommand(wpBin, fullArgs, { timeout: 20000, maxBuffer: 2 * 1024 * 1024, cwd: wpRoot, env });
  if (!result.ok && phpBin) {
    result = await runCommand(phpBin, [wpBin, ...fullArgs], { timeout: 20000, maxBuffer: 2 * 1024 * 1024, cwd: wpRoot });
  }
  if (!result.ok) return { status: 'error', error: result.error || result.stderr || 'wp-cli fehlgeschlagen' };
  try {
    return { status: 'ok', data: result.stdout ? JSON.parse(result.stdout) : [] };
  } catch (err) {
    return { status: 'error', error: `wp-cli JSON nicht parsebar: ${err.message}`, raw: result.stdout.slice(0, 500) };
  }
}

async function findWordPressRootsForensics(vhostsPath) {
  if (!vhostsPath || !(await fileExists(vhostsPath))) return [];
  const result = await runCommand('find', [
    vhostsPath,
    '-maxdepth', '10',
    '-name', 'wp-config.php',
    '-type', 'f',
    '-not', '-path', '*/vendor/*',
    '-not', '-path', '*/node_modules/*',
  ], { timeout: 30000, maxBuffer: 2 * 1024 * 1024 });
  return (result.stdout || '').split('\n').filter(Boolean).map((file) => path.dirname(file));
}

async function listDirNames(dir) {
  try {
    const entries = await fs.promises.readdir(dir, { withFileTypes: true });
    return entries.filter((entry) => entry.isDirectory() || entry.isFile()).map((entry) => entry.name).sort();
  } catch (err) {
    return { error: err.message };
  }
}

async function collectCriticalFileStats(wpRoot) {
  const result = {};
  for (const name of WP_CRITICAL_FILES) {
    const filePath = path.join(wpRoot, name);
    result[name] = await statFile(filePath);
    if (result[name].exists) {
      try {
        result[name].sha256 = await hashFile(filePath);
      } catch (err) {
        result[name].hashError = err.message;
      }
    }
  }
  return result;
}

function wpSiteLabel(wpRoot, vhostsPath) {
  const normalizedRoot = normalizePath(wpRoot);
  const normalizedVhosts = normalizePath(vhostsPath || '').replace(/\/$/, '');
  if (normalizedVhosts && normalizedRoot.startsWith(`${normalizedVhosts}/`)) {
    return normalizedRoot.slice(normalizedVhosts.length + 1).split('/').slice(0, 2).join('/');
  }
  return wpRoot;
}

async function collectWordPressForensics(config, existingSummary) {
  const vhostsPath = config.VHOSTS_PATH || '/var/www/vhosts';
  const roots = await findWordPressRootsForensics(vhostsPath);
  const wpCliInfo = resolveWpCliForensics();
  const bySite = new Map((existingSummary || []).map((site) => [site.site, site]));
  const sites = [];

  for (const wpRoot of roots) {
    const label = wpSiteLabel(wpRoot, vhostsPath);
    const contentDir = path.join(wpRoot, 'wp-content');
    const admins = await runWpCliJson(wpCliInfo, wpRoot, ['user', 'list', '--role=administrator', '--fields=ID,user_login,user_email,user_registered']);
    const coreChecksums = await runWpCliJson(wpCliInfo, wpRoot, ['core', 'verify-checksums']);

    sites.push({
      ...(bySite.get(label) || {}),
      site: label,
      root: wpRoot,
      coreChecksums,
      plugins: await listDirNames(path.join(contentDir, 'plugins')),
      themes: await listDirNames(path.join(contentDir, 'themes')),
      uploadsTopLevel: await listDirNames(path.join(contentDir, 'uploads')),
      muPlugins: await listDirNames(path.join(contentDir, 'mu-plugins')),
      dropIns: (await Promise.all(['advanced-cache.php', 'db.php', 'object-cache.php', 'sunrise.php', 'fatal-error-handler.php']
        .map(async (name) => ((await fileExists(path.join(contentDir, name))) ? name : null)))).filter(Boolean),
      criticalFiles: await collectCriticalFileStats(wpRoot),
      adminUsers: admins,
      xmlRpc: await statFile(path.join(wpRoot, 'xmlrpc.php')),
      restApi: 'nicht live geprüft; Access-Log-Hinweise in logClues',
      filePermissions: 'criticalFiles enthält Modus/Besitzer der wichtigsten Dateien',
    });
  }

  return {
    wpCli: wpCliInfo ? { wpBin: wpCliInfo.wpBin, phpBin: wpCliInfo.phpBin } : null,
    sites,
  };
}

function buildSummary({ files, report, timeline, persistence, campaigns, triggers }) {
  const wp = (report.checks || []).find((check) => check.name === 'wordpressCheck');
  const wpSites = wp?.metrics?.siteDetails || [];
  const changedCoreFiles = wpSites.reduce((sum, site) => sum + (site.checksumErrors || []).length, 0);
  const affectedWebsites = new Set(files.flatMap((f) => f.domains || []));
  for (const site of wpSites) {
    if (riskAtLeast(site.risk, 'high')) affectedWebsites.add(site.domain || site.site);
  }
  const webshells = files.filter((f) => (f.iocs?.patterns || []).length > 0).length;
  const possibleEntry = inferEntryPoint(report, campaigns);

  return {
    suspiciousFiles: files.length,
    webshells,
    changedCoreFiles,
    affectedWebsites: affectedWebsites.size,
    firstActivity: timeline.firstActivity,
    lastActivity: timeline.lastActivity,
    possibleEntry,
    persistenceFound: persistence.suspiciousMarkers.length > 0,
    cronChanged: persistence.cronChanged,
    sshChanged: Boolean(persistence.sshChanged),
    systemServices: persistence.commands.find((cmd) => cmd.command.startsWith('systemctl'))?.ok ? 'geprüft, Details in persistence.json' : 'nicht prüfbar',
    status: files.length > 0 || triggers.length > 0 ? 'Bereinigung empfohlen' : 'Kein Incident bestätigt',
    recommendedNextSteps: [
      'Server nicht voreilig bereinigen: zuerst Evidence-Ordner sichern.',
      'Betroffene Dateien aus incident.json und quarantine-recommendations.json manuell prüfen.',
      'WordPress-Core betroffener Sites aus offiziellen Quellen neu installieren.',
      'Plugins/Themes aktualisieren oder kompromittierte Komponenten entfernen.',
      'Alle Webspace-, WordPress-, FTP-, SSH- und Datenbank-Passwörter rotieren.',
      'Access-Logs um die erste Aktivität prüfen und Eintrittspunkt schließen.',
    ],
  };
}

function inferEntryPoint(report, campaigns) {
  const wp = (report.checks || []).find((check) => check.name === 'wordpressCheck');
  const risky = [];
  for (const site of wp?.metrics?.siteDetails || []) {
    for (const plugin of site.riskyPlugins || []) risky.push(`${site.site}: ${plugin}`);
  }
  if (risky.some((item) => /file manager/i.test(item))) return 'Plugin File Manager';
  if (campaigns.length > 0) return 'Automatisierter Massenangriff auf mehrere Websites';
  return 'Unbekannt, Logs prüfen';
}

function renderTextReport(data) {
  const s = data.summary;
  const lines = [
    '==========================',
    'Incident Summary',
    '==========================',
    `Verdächtige Dateien: ${s.suspiciousFiles}`,
    `Webshells: ${s.webshells}`,
    `Veränderte Core-Dateien: ${s.changedCoreFiles}`,
    `Betroffene Websites: ${s.affectedWebsites}`,
    `Erste Aktivität: ${s.firstActivity || 'unbekannt'}`,
    `Letzte Aktivität: ${s.lastActivity || 'unbekannt'}`,
    `Möglicher Einstieg: ${s.possibleEntry}`,
    `Persistenz gefunden: ${s.persistenceFound ? 'Ja' : 'Nein'}`,
    `Cron verändert: ${s.cronChanged ? 'Ja' : 'Nein'}`,
    `SSH verändert: ${s.sshChanged ? 'Ja' : 'Nein'}`,
    `Systemdienste: ${s.systemServices}`,
    `Status: ${s.status}`,
    '',
    'Trigger:',
    ...data.triggers.map((t) => `- [${t.risk || 'low'}] ${t.check}: ${t.message}`),
    '',
    'Angriffswellen:',
    ...data.timeline.byMinute.filter((g) => g.count >= 2).slice(0, 20).map((g) => `- ${g.time}: ${g.count} Datei(en)`),
    '',
    'Kampagnen:',
    ...(data.campaigns.length ? data.campaigns.map((c) => `- ${c.name}: ${c.files} Dateien, ${c.affectedDomains.length} Domain(s), SHA256 ${c.sha256}`) : ['- Keine eindeutige Kampagne erkannt']),
    '',
    'Empfohlene nächste Schritte:',
    ...s.recommendedNextSteps.map((step) => `- ${step}`),
  ];
  return lines.join('\n') + '\n';
}

function renderHtmlReport(data) {
  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const rows = data.files.slice(0, 200).map((f) => `
    <tr>
      <td>${esc(f.risk)}</td>
      <td><code>${esc(f.file)}</code></td>
      <td>${esc(f.sha256 || '')}</td>
      <td>${esc(f.metadata?.sizeBytes || '')}</td>
      <td>${esc(f.metadata?.modifiedAt || '')}</td>
      <td>${esc((f.iocs?.patterns || []).join(', '))}</td>
    </tr>`).join('');
  const campaigns = data.campaigns.map((c) => `<li><strong>${esc(c.name)}</strong>: ${c.files} Dateien, ${c.affectedDomains.length} Domains, ${esc(c.assessment)}</li>`).join('');
  return `<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><title>Watchdog Incident Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:32px;color:#151923;background:#f6f7fb}
section{background:#fff;border:1px solid #d9deea;border-radius:8px;padding:18px;margin:18px 0}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{border-bottom:1px solid #e5e8f0;padding:8px;text-align:left;vertical-align:top}
code{word-break:break-all}.risk{font-weight:700}
</style></head><body>
<h1>Watchdog Incident Report</h1>
<section><h2>Summary</h2><pre>${esc(renderTextReport(data))}</pre></section>
<section><h2>Kampagnen</h2><ul>${campaigns || '<li>Keine eindeutige Kampagne erkannt</li>'}</ul></section>
<section><h2>Verdächtige Dateien</h2><table><thead><tr><th>Risiko</th><th>Datei</th><th>SHA256</th><th>Größe</th><th>mtime</th><th>Muster</th></tr></thead><tbody>${rows}</tbody></table></section>
</body></html>`;
}

async function writeJson(filePath, value) {
  await fs.promises.writeFile(filePath, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

async function writeText(filePath, value) {
  await fs.promises.writeFile(filePath, value, 'utf8');
}

async function run(report, config = {}) {
  const enabled = (process.env.ENABLE_INCIDENT_MODE || 'true') !== 'false';
  if (!enabled) return null;

  const triggers = detectIncidentTriggers(report);
  if (triggers.length === 0) return null;

  const incidentDir = path.join(INCIDENT_ROOT, nowStamp());
  await mkdirp(incidentDir);

  const rawFiles = collectSuspiciousFiles(report);
  const files = [];
  for (const record of rawFiles) {
    files.push(await enrichFileRecord(record, config));
  }
  await copySuspiciousFiles(files, incidentDir);

  const timeline = buildTimeline(files);
  const iocGroups = buildIocGroups(files);
  const persistence = await collectPersistence();
  const logClues = await collectLogClues(config, timeline);
  const wordpress = await collectWordPressForensics(config, buildWordPressSummary(report));
  const campaigns = buildCampaigns(files, iocGroups);
  const quarantineRecommendations = buildQuarantineRecommendations(files, incidentDir);

  const data = {
    createdAt: new Date().toISOString(),
    incidentDir,
    readOnly: true,
    triggers,
    summary: null,
    files,
    timeline,
    iocGroups,
    persistence,
    wordpress,
    logClues,
    campaigns,
    quarantineRecommendations,
    originalReport: report,
  };
  data.summary = buildSummary({ files, report, timeline, persistence, campaigns, triggers });

  await writeJson(path.join(incidentDir, 'incident.json'), data);
  await writeJson(path.join(incidentDir, 'scan-report.json'), report);
  await writeJson(path.join(incidentDir, 'ioc-list.json'), iocGroups);
  await writeJson(path.join(incidentDir, 'file-list.json'), files);
  await writeJson(path.join(incidentDir, 'timeline.json'), timeline);
  await writeJson(path.join(incidentDir, 'persistence.json'), persistence);
  await writeJson(path.join(incidentDir, 'quarantine-recommendations.json'), quarantineRecommendations);
  await writeText(path.join(incidentDir, 'incident-summary.txt'), renderTextReport(data));
  await writeText(path.join(incidentDir, 'incident-report.html'), renderHtmlReport(data));
  await writeText(path.join(incidentDir, 'terminal-output.txt'), renderTerminalOutput(report, triggers));
  await writeText(path.join(incidentDir, 'README.txt'), [
    'Plesk Server Watchdog Incident Evidence',
    '',
    'Dieser Ordner wurde read-only erzeugt. Der Watchdog hat keine Originaldateien gelöscht, verschoben oder verändert.',
    'Verdächtige Dateien wurden nur als Evidence-Kopie unter files/ gespeichert.',
    'Quarantäne-Befehle sind Empfehlungen in quarantine-recommendations.json und müssen manuell geprüft werden.',
    '',
  ].join('\n'));

  return {
    incidentDir,
    triggerCount: triggers.length,
    suspiciousFiles: files.length,
    campaigns: campaigns.length,
    summary: data.summary,
  };
}

function renderTerminalOutput(report, triggers) {
  const lines = [
    `[incident] Incident Mode aktiviert: ${new Date().toISOString()}`,
    `[incident] Host: ${report.hostname}`,
    `[incident] Overall Risk: ${String(report.overallRisk || 'low').toUpperCase()}`,
    `[incident] Trigger: ${triggers.length}`,
    '',
  ];
  for (const check of report.checks || []) {
    lines.push(`[monitor] ${check.name}: ${check.status} (${check.risk}) - ${(check.findings || []).length} finding(s)`);
    for (const finding of (check.findings || []).slice(0, 50)) {
      lines.push(`  -> ${finding.message || finding.type}`);
    }
  }
  return lines.join('\n') + '\n';
}

module.exports = { run, detectIncidentTriggers, collectSuspiciousFiles };

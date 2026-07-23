'use strict';

const { execFile, execFileSync } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const execFileAsync = promisify(execFile);
const { load: loadTrustedFiles, checkTrust } = require('../lib/trustedFiles');

const PHP_BINARY_CANDIDATES = [
  '/opt/plesk/php/8.3/bin/php',
  '/opt/plesk/php/8.2/bin/php',
  '/opt/plesk/php/8.1/bin/php',
  '/opt/plesk/php/7.4/bin/php',
];
const WP_CLI_CANDIDATES = ['/usr/local/bin/wp', '/usr/bin/wp'];

const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

// Security plugins legitimately use base64, eval, WAF patterns, crypto, php://input —
// only flag if POST/GET command execution or crypto miners appear (those are never expected)
// Security plugins: cap almost everything to LOW (WAF, crypto, eval etc. are expected here)
const TRUSTED_SECURITY_PLUGINS = new Set([
  'wordfence', 'better-wp-security', 'sucuri-scanner',
  'shield-security', 'bulletproof-security', 'wp-cerber', 'all-in-one-wp-security-and-firewall',
]);
const SECURITY_PLUGIN_ALLOWED_HIGH_CONFIDENCE = new Set([
  'POST/GET-basierte Command Execution',
  'Upload-Datei wird per include/require geladen',
  'compress.zlib Stream Wrapper',
  'Crypto-Miner Hinweis',
]);

// Popular large plugins: base64, call_user_func, Remote URLs etc. are normal —
// cap accumulated boilerplate scores to MEDIUM unless a real red flag is present
const TRUSTED_POPULAR_PLUGINS = new Set([
  'woocommerce', 'elementor', 'elementor-pro', 'updraftplus',
  'yoast-seo', 'wordpress-seo', 'contact-form-7', 'wpforms-lite',
  'advanced-custom-fields', 'acf', 'jetpack', 'gutenberg',
  'the-events-calendar', 'bbpress', 'buddypress', 'mailchimp-for-woocommerce',
  'creame-whatsapp-me', 'joinchat',
]);

// HIGH_CONFIDENCE rules that still fire even in vendor libs of trusted plugins
const VENDOR_SAFE_HIGH_CONFIDENCE = new Set([
  'POST/GET-basierte Command Execution',
  'eval(base64_decode(...))',
  'assert($_POST/$_GET)',
  'Crypto-Miner Hinweis',
]);

// Patterns that are always real red flags regardless of plugin
const REAL_RED_FLAG_LABELS = new Set([
  'POST/GET-basierte Command Execution',
  'Upload-Datei wird per include/require geladen',
  'compress.zlib Stream Wrapper',
  'Crypto-Miner Hinweis',
  'eval(base64_decode(...))',
  'assert($_POST/$_GET)',
  'PHP-Datei in Upload/Media-Verzeichnis',
  'PHP-Datei in System-Temp-Verzeichnis',
  'Kombination: eval() + base64',
  'Kombination: Command Execution + Obfuskation',
  'Kombination: gzinflate() + Obfuskation',
]);
const RISK_SCORE = { medium: 30, high: 60, critical: 100 };

// Explicit upload/temp path fragments — must match real WordPress write locations, not class/namespace names
const UPLOAD_PATH_FRAGMENTS = [
  '/wp-content/uploads/',
  '/wp-content/cache/',
  '/wp-content/upgrade/',
  '/wp-content/tmp/',
];
const TEMP_PATH_FRAGMENTS = [
  '/tmp/',
  '/var/tmp/',
  '/dev/shm/',
];
const DEFAULT_EXCLUDES = [
  '/wp-content/wflogs/',
  '/wp-content/uploads/cache/',
];
const LOW_PRIORITY_CACHE_PARTS = [
  'wflogs',
  'uploads/cache',
  'wp-content/cache',
  'wp-content/uploads/cache',
];
const CRITICAL_FILE_BASENAMES = new Set([
  'wp-config.php',
  'wp-settings.php',
  'wp-load.php',
  'xmlrpc.php',
  '.htaccess',
]);
const SUSPICIOUS_WEBROOT_NAMES = new Set([
  'about', 'atom', 'chosen', 'class', 'content', 'default', 'inputs',
  'license', 'moon', 'network', 'options', 'radio', 'simple', 'style',
  'system', 'update',
]);

const HIGH_CONFIDENCE_RULES = [
  { label: 'POST/GET-basierte Command Execution', score: 100, risk: 'critical', pattern: /\b(?:system|shell_exec|exec|passthru|proc_open|popen)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)\s*\[/i },
  { label: 'eval(base64_decode(...))', score: 95, risk: 'critical', pattern: /eval\s*\(\s*base64_decode\s*\(/i },
  { label: 'gzinflate(base64_decode(...))', score: 90, risk: 'high', pattern: /gzinflate\s*\(\s*base64_decode\s*\(/i },
  { label: 'assert($_POST/$_GET)', score: 90, risk: 'high', pattern: /assert\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)\s*\[/i },
  { label: 'PHP-Datei wird geschrieben', score: 80, risk: 'high', pattern: /file_put_contents\s*\([^;]+\.php/i },
  { label: 'php://input Zugriff', score: 70, risk: 'high', pattern: /php:\/\/input/i },
  { label: 'preg_replace /e Modifier', score: 85, risk: 'high', pattern: /preg_replace\s*\([^;]+\/e['"]/i },
  { label: 'create_function()', score: 70, risk: 'high', pattern: /create_function\s*\(/i },
  { label: 'Remote Download mit Ausführungshinweis', score: 70, risk: 'high', pattern: /(?:curl_exec|file_get_contents|fopen)\s*\([^;]+https?:\/\/[\s\S]{0,300}\b(?:eval|include|require|file_put_contents|shell_exec|system|exec)\s*\(/i },
  { label: 'Upload-Datei wird per include/require geladen', score: 95, risk: 'critical', pattern: /\b(?:include|include_once|require|require_once)\s*\(?\s*[^;]*(?:wp-content\/uploads|\/uploads\/)[^;]*\.php/i },
  { label: 'compress.zlib Stream Wrapper', score: 90, risk: 'high', pattern: /compress\.zlib:\/\//i },
  { label: 'Versteckte iframe/script Injection', score: 70, risk: 'high', pattern: /<iframe[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)|<script[^>]+src\s*=\s*["']https?:\/\/[^"']+/i },
  { label: 'Crypto-Miner Hinweis', score: 100, risk: 'critical', pattern: /\b(?:xmrig|monero|cryptonight|stratum\+tcp|xmr-stak)\b/i },
];

const CONTEXTUAL_RULES = [
  { label: 'eval()', score: 40, risk: 'medium', pattern: /eval\s*\(/i },
  { label: 'base64_decode()', score: 35, risk: 'medium', pattern: /base64_decode\s*\(/i },
  { label: 'gzinflate()', score: 35, risk: 'medium', pattern: /gzinflate\s*\(/i },
  { label: 'assert()', score: 35, risk: 'medium', pattern: /assert\s*\(/i },
  { label: 'shell_exec()', score: 50, risk: 'medium', pattern: /shell_exec\s*\(/i, command: true },
  { label: 'system()', score: 50, risk: 'medium', pattern: /system\s*\(/i, command: true },
  { label: 'exec()', score: 45, risk: 'medium', pattern: /\bexec\s*\(/i, command: true },
  { label: 'passthru()', score: 50, risk: 'medium', pattern: /passthru\s*\(/i, command: true },
  { label: 'proc_open()', score: 50, risk: 'medium', pattern: /proc_open\s*\(/i, command: true },
  { label: 'curl_exec()', score: 5, risk: 'low', pattern: /curl_exec\s*\(/i },
  { label: 'WordPress HTTP API', score: 5, risk: 'low', pattern: /\bwp_remote_(?:get|post|request|head)\s*\(/i },
  { label: 'Remote URL im Code', score: 5, risk: 'low', pattern: /https?:\/\/[^\s'"]+/i },
  { label: 'Variable Funktion', score: 10, risk: 'low', pattern: /\$[A-Za-z_][A-Za-z0-9_]*\s*\(/ },
  { label: 'call_user_func()', score: 10, risk: 'low', pattern: /call_user_func(?:_array)?\s*\(/i },
];

function buildExcludeList() {
  const raw = process.env.SUSPICIOUS_FILES_EXCLUDE || '';
  return [
    ...DEFAULT_EXCLUDES,
    ...raw.split(',').map((s) => s.trim()).filter(Boolean),
  ];
}

function parseCsvEnv(name) {
  return (process.env[name] || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function getTrustedPluginSlugs() {
  return new Set([
    ...TRUSTED_POPULAR_PLUGINS,
    ...parseCsvEnv('SUSPICIOUS_FILES_TRUSTED_PLUGINS').map((s) => s.toLowerCase()),
  ]);
}

function getTrustedFileFragments() {
  return parseCsvEnv('SUSPICIOUS_FILES_TRUSTED_FILES').map(normalizePath);
}

function isExcluded(filePath, excludeList) {
  const normalized = normalizePath(filePath);
  return excludeList.some((pattern) => normalized.includes(normalizePath(pattern)));
}

function isConfiguredTrustedFile(filePath) {
  const normalized = normalizePath(filePath);
  return getTrustedFileFragments().some((fragment) => normalized.includes(fragment));
}

async function findRecentScanFiles(vhostsPath, hours) {
  try {
    const { stdout } = await execFileAsync('find', [
      vhostsPath,
      '(',
      '-name', '*.php',
      '-o', '-name', '*.phtml',
      '-o', '-name', '.htaccess',
      ')',
      '-mmin', `-${hours * 60}`,
      '-type', 'f',
      '-not', '-path', '*/.*/*',
    ], { timeout: 30000, maxBuffer: 10 * 1024 * 1024 });

    return stdout.split('\n').filter(Boolean);
  } catch (err) {
    // find exits with non-zero if some dirs are unreadable — that's fine
    if (err.stdout) return err.stdout.split('\n').filter(Boolean);
    throw err;
  }
}

function getPathParts(filePath) {
  const parts = normalizePath(filePath).split('/');
  return parts.filter(Boolean);
}

function normalizePath(filePath) {
  return String(filePath || '').replace(/\\/g, '/').toLowerCase();
}

function isLowPriorityCachePath(filePath) {
  const normalized = normalizePath(filePath);
  return LOW_PRIORITY_CACHE_PARTS.some((part) => normalized.includes(`/${part}/`));
}

function classifyPath(filePath) {
  const parts = getPathParts(filePath);
  const wpContentIndex = parts.indexOf('wp-content');
  const context = {
    area: 'unknown',
    component: null,
    componentType: null,
    isWordPressCore: false,
    isUploadLike: false,
    isTempLike: false,
    isLowPriorityCache: isLowPriorityCachePath(filePath),
    isKnownWordPressCode: false,
    isSystemTemp: filePath.startsWith('/tmp/') || filePath.startsWith('/var/tmp/') || filePath.startsWith('/dev/shm/'),
    criticalFile: null,
  };

  const baseName = path.basename(filePath).toLowerCase();
  if (CRITICAL_FILE_BASENAMES.has(baseName) || baseName === 'index.php') {
    context.criticalFile = baseName;
  }

  if (parts.includes('wp-admin') || parts.includes('wp-includes') || /^wp-[^/]+\.php$/i.test(path.basename(filePath))) {
    context.area = 'wordpress-core';
    context.isWordPressCore = true;
  }

  if (wpContentIndex >= 0) {
    const type = parts[wpContentIndex + 1];
    const slug = parts[wpContentIndex + 2] || null;
    if (type === 'plugins' || type === 'themes' || type === 'mu-plugins') {
      context.area = `wordpress-${type}`;
      context.componentType = type;
      context.component = slug;
      context.isKnownWordPressCode = true;
      // vendor/ = third-party library bundled in the plugin, not the plugin's own code
      if (type === 'plugins' && parts[wpContentIndex + 3] === 'vendor') {
        context.isVendorLibrary = true;
      }
    } else if (type === 'languages') {
      context.area = 'wordpress-languages';
      context.componentType = 'languages';
      context.component = slug;
      context.isWordPressLanguages = true;
      // Do NOT set isKnownWordPressCode — language files are a known malware target
    } else {
      context.area = 'wordpress-content';
    }
  }

  const normalizedPath = normalizePath(filePath);
  context.isUploadLike = UPLOAD_PATH_FRAGMENTS.some((f) => normalizedPath.includes(f)) && !context.isLowPriorityCache;
  context.isTempLike = TEMP_PATH_FRAGMENTS.some((f) => normalizedPath.includes(f)) && !context.isSystemTemp;
  return context;
}

function scoreToRisk(score) {
  if (score >= RISK_SCORE.critical) return 'critical';
  if (score >= RISK_SCORE.high) return 'high';
  if (score >= RISK_SCORE.medium) return 'medium';
  return 'low';
}

function riskToMaxScore(risk) {
  if (risk === 'critical') return RISK_SCORE.critical;
  if (risk === 'high') return RISK_SCORE.critical - 1;
  if (risk === 'medium') return RISK_SCORE.high - 1;
  return RISK_SCORE.medium - 1;
}

function addReason(reasons, reason) {
  if (!reasons.some((r) => r.label === reason.label && r.line === reason.line)) {
    reasons.push(reason);
  }
}

function isLikelyRandomPhpName(filePath) {
  const base = path.basename(filePath, '.php');
  if (base.length < 10) return false;
  if (/^[a-f0-9]{10,}$/i.test(base)) return true; // pure hex hash
  if (base.length >= 12 && /^[a-z0-9]+$/i.test(base)) {
    const vowelRatio = (base.match(/[aeiou]/gi) || []).length / base.length;
    if (vowelRatio < 0.20) return true; // <20% vowels = likely random
  }
  return false;
}

// Returns true when the first match of `pattern` on `line` sits inside a PHP string literal.
// Heuristic: count unescaped quotes before the match index — odd count → inside a string.
function isLikelyInPhpString(line, pattern) {
  const re = new RegExp(pattern.source, pattern.flags.replace(/g/g, ''));
  const match = re.exec(line);
  if (!match) return false;
  const before = line.slice(0, match.index);
  const sq = (before.match(/(?<!\\)'/g) || []).length;
  const dq = (before.match(/(?<!\\)"/g) || []).length;
  return (sq % 2 === 1) || (dq % 2 === 1);
}

// Detects dangerous pattern combinations that are far more significant than individual scores.
// Called after all individual rules have been collected.
function detectDangerousCombinations(reasons, context = null) {
  // Vendor libraries (SSH, RSA, OAuth) legitimately combine exec + hex or base64 — skip combos
  if (context && isVendorLibraryOfTrustedPlugin(context)) return [];

  const labels = new Set(reasons.map((r) => r.label));
  const combos = [];

  if (labels.has('eval()') && (labels.has('base64_decode()') || labels.has('Langer Base64-ähnlicher String'))) {
    combos.push({ label: 'Kombination: eval() + base64', score: 65, risk: 'high' });
  }
  const hasCommand = ['shell_exec()', 'system()', 'exec()', 'passthru()', 'proc_open()'].some((l) => labels.has(l));
  const hasObfuscation = ['Variable Variablen', 'Hex/chr-Obfuskation', 'Langer Base64-ähnlicher String'].some((l) => labels.has(l));
  if (hasCommand && hasObfuscation) {
    combos.push({ label: 'Kombination: Command Execution + Obfuskation', score: 75, risk: 'high' });
  }
  if (labels.has('gzinflate()') && (labels.has('Hex/chr-Obfuskation') || labels.has('base64_decode()'))) {
    combos.push({ label: 'Kombination: gzinflate() + Obfuskation', score: 70, risk: 'high' });
  }
  if (labels.has('Remote Download mit Ausführungshinweis') && labels.has('Variable Variablen')) {
    combos.push({ label: 'Kombination: Remote Download + Obfuskation', score: 60, risk: 'high' });
  }

  return combos;
}

function detectObfuscation(content) {
  const reasons = [];
  if (/[A-Za-z0-9+/]{220,}={0,2}/.test(content)) {
    reasons.push({ label: 'Langer Base64-ähnlicher String', risk: 'medium', score: 25, reducibleInWp: true });
  }
  if (/\\x[0-9a-f]{2}/i.test(content) || /chr\s*\(\s*\d+\s*\)(?:\s*\.\s*chr\s*\()/i.test(content)) {
    reasons.push({ label: 'Hex/chr-Obfuskation', risk: 'high', score: 65 });
  }
  if (/\$\{\s*['"]?[A-Za-z0-9_]+['"]?\s*\}|\$\$[A-Za-z_]/.test(content)) {
    reasons.push({ label: 'Variable Variablen', risk: 'medium', score: 40 });
  }

  const longLines = content.split('\n').filter((line) => line.length > 1200);
  if (longLines.length > 0) {
    reasons.push({ label: 'Sehr lange Codezeile', risk: 'low', score: 5, reducibleInWp: true });
  }
  return reasons;
}

function adjustRuleForContext(rule, context) {
  let adjustedScore = rule.score;
  let adjustedRisk = rule.risk;

  if (isSecurityPlugin(context)) {
    // Security plugins use all kinds of low-level PHP by design — cap everything to low
    adjustedScore = Math.min(adjustedScore, 5);
    adjustedRisk = 'low';
    return { adjustedScore, adjustedRisk };
  }

  // Vendor libraries (SSH, OAuth, RSA, HTTP clients) legitimately use exec, Hex, system —
  // any contextual rule is noise here; only VENDOR_SAFE_HIGH_CONFIDENCE rules matter
  if (isVendorLibraryOfTrustedPlugin(context)) {
    adjustedScore = Math.min(adjustedScore, 5);
    adjustedRisk = 'low';
    return { adjustedScore, adjustedRisk };
  }

  if (context.isKnownWordPressCode || context.isLowPriorityCache) {
    if (rule.command) {
      // shell_exec/system/exec in WP code is unusual → MEDIUM, not LOW
      adjustedScore = Math.min(adjustedScore, 35);
      adjustedRisk = 'medium';
    } else if (rule.reducibleInWp || ['Remote URL im Code', 'WordPress HTTP API', 'curl_exec()', 'Variable Funktion', 'call_user_func()', 'base64_decode()', 'Sehr lange Codezeile', 'Langer Base64-ähnlicher String', 'Variable Variablen'].includes(rule.label)) {
      adjustedScore = Math.min(adjustedScore, 5);
      adjustedRisk = 'low';
    }
  } else if (rule.command && !context.component) {
    adjustedScore = Math.max(adjustedScore, 45);
    adjustedRisk = 'medium';
  }

  return { adjustedScore, adjustedRisk };
}

function isSecurityPlugin(context) {
  return context.isKnownWordPressCode
    && context.componentType === 'plugins'
    && TRUSTED_SECURITY_PLUGINS.has(context.component);
}

function isTrustedPopularPlugin(context) {
  return context.isKnownWordPressCode
    && context.componentType === 'plugins'
    && getTrustedPluginSlugs().has(String(context.component || '').toLowerCase());
}

function isVendorLibraryOfTrustedPlugin(context) {
  return Boolean(context.isVendorLibrary) && isTrustedPopularPlugin(context);
}

function hasRealRedFlag(reasons) {
  return reasons.some((r) => REAL_RED_FLAG_LABELS.has(r.label));
}

function hasCriticalSignal(reasons) {
  return reasons.some((reason) => reason.risk === 'critical' || REAL_RED_FLAG_LABELS.has(reason.label) || [
    'POST/GET-basierte Command Execution',
    'eval(base64_decode(...))',
    'assert($_POST/$_GET)',
    'Crypto-Miner Hinweis',
  ].includes(reason.label));
}

function hasCriticalSignalForSecPlugin(reasons) {
  return reasons.some((r) => SECURITY_PLUGIN_ALLOWED_HIGH_CONFIDENCE.has(r.label));
}

function applyContextCaps(score, reasons, context, metadata, modifiedCoreFiles, trust) {
  let cappedScore = score;

  if (isSecurityPlugin(context) && !hasCriticalSignalForSecPlugin(reasons)) {
    cappedScore = Math.min(cappedScore, riskToMaxScore('low'));
  }

  if (isVendorLibraryOfTrustedPlugin(context) && !hasCriticalSignal(reasons)) {
    // Belt-and-suspenders: even if individual rules leaked through, cap vendor libs at MEDIUM
    cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
  }

  if (isTrustedPopularPlugin(context) && !hasRealRedFlag(reasons)) {
    cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
  }

  if (context.isWordPressCore) {
    if (modifiedCoreFiles !== null && !modifiedCoreFiles.has(normalizePath(metadata.filePath))) {
      // wp-cli confirms file matches official WP — any pattern hit is legitimate code, cap at LOW
      cappedScore = Math.min(cappedScore, riskToMaxScore('low'));
    } else if (modifiedCoreFiles === null) {
      // WP-CLI not available — cap tightly without confirmation
      if (!hasRealRedFlag(reasons)) {
        cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
      } else if (!hasCriticalSignal(reasons)) {
        cappedScore = Math.min(cappedScore, riskToMaxScore('high'));
      }
    }
    // Checksum mismatch → full score, no cap (genuine modification)
  }

  if (context.isKnownWordPressCode && !hasCriticalSignal(reasons)) {
    cappedScore = Math.min(cappedScore, riskToMaxScore('high'));
    if (metadata.ageHours >= 24 * 30) {
      cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
    } else if (metadata.ageHours >= 24 * 7) {
      cappedScore = Math.max(0, cappedScore - 15);
    }
  }

  if (context.isWordPressLanguages && !hasRealRedFlag(reasons)) {
    // Translation files often contain function names as strings — cap unless a real red flag fired
    cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
  }

  if (context.isLowPriorityCache && !hasCriticalSignal(reasons)) {
    cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
  }

  if (metadata.configTrustedFile && !hasCriticalSignal(reasons)) {
    cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
  }

  // Trusted + hash match: verified known-good file — suppress everything except real malware combos
  if (trust?.hashMatch && !hasCriticalSignal(reasons)) {
    cappedScore = Math.min(cappedScore, riskToMaxScore('low'));
  }

  return cappedScore;
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
  const chunks = [];
  const stream = fs.createReadStream(filePath, { encoding: 'utf8', start: 0, end: 128 * 1024 });
  for await (const chunk of stream) chunks.push(chunk);
  return chunks.join('');
}

function buildMessage(scan) {
  const context = scan.context.component
    ? `${scan.context.componentType}:${scan.context.component}`
    : scan.context.area;
  const seen = new Set();
  const topReasons = scan.reasons
    .map((r) => r.label)
    .filter((l) => { if (seen.has(l)) return false; seen.add(l); return true; })
    .slice(0, 3)
    .join(', ');
  return `${scan.risk.toUpperCase()} Score ${scan.score}: ${scan.filePath} (${context}) - ${topReasons}`;
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function buildQuarantinePlan(filePath) {
  const quarantineDir = '/root/server-watchdog-quarantine';
  const target = `${quarantineDir}${filePath}`;
  return {
    note: 'Nur Vorschlag: vorher Backup/Plugin-Kontext prüfen. Der Watchdog führt diese Befehle nicht automatisch aus.',
    commands: [
      `install -d ${shellQuote(path.dirname(target))}`,
      `cp -a -- ${shellQuote(filePath)} ${shellQuote(target)}.bak`,
      `chmod 000 -- ${shellQuote(filePath)}`,
      `mv -- ${shellQuote(filePath)} ${shellQuote(target)}`,
    ],
  };
}

function buildAggregateFindings(scans) {
  const findings = [];
  const relevant = scans.filter((scan) => (
    scan.reasons.length > 0
    && (
      scan.risk !== 'low'
      || scan.context.isUploadLike
      || scan.context.isTempLike
      || !scan.context.isKnownWordPressCode
    )
  ));

  const byHash = new Map();
  const bySize = new Map();
  for (const scan of relevant) {
    if (!scan.metadata.sha256) continue;
    if (!byHash.has(scan.metadata.sha256)) byHash.set(scan.metadata.sha256, []);
    byHash.get(scan.metadata.sha256).push(scan);

    const sizeKey = String(scan.metadata.sizeBytes);
    if (!bySize.has(sizeKey)) bySize.set(sizeKey, []);
    bySize.get(sizeKey).push(scan);
  }

  const repeatedHashes = [...byHash.entries()]
    .filter(([, group]) => group.length >= 3)
    .sort((a, b) => b[1].length - a[1].length);
  for (const [sha256, group] of repeatedHashes.slice(0, 5)) {
    findings.push({
      type: 'mass_infection_hash',
      risk: 'critical',
      count: group.length,
      sha256,
      files: group.slice(0, 10).map((scan) => scan.filePath),
      message: `${group.length} verdächtige Dateien haben identischen SHA-256-Hash (${sha256.slice(0, 16)}...). Das kann auf eine verteilte Webshell/Masseninfektion hinweisen.`,
    });
  }

  const repeatedSizes = [...bySize.entries()]
    .filter(([, group]) => group.length >= 20)
    .sort((a, b) => b[1].length - a[1].length);
  for (const [sizeBytes, group] of repeatedSizes.slice(0, 5)) {
    findings.push({
      type: 'mass_infection_size',
      risk: 'high',
      count: group.length,
      sizeBytes: Number(sizeBytes),
      files: group.slice(0, 10).map((scan) => scan.filePath),
      message: `${group.length} verdächtige Dateien haben exakt ${sizeBytes} Byte. Bitte auf kopierte Malware-Dropper prüfen.`,
    });
  }

  const sorted = relevant
    .map((scan) => ({ scan, ts: new Date(scan.metadata.modifiedAt).getTime() }))
    .filter((entry) => Number.isFinite(entry.ts))
    .sort((a, b) => a.ts - b.ts);
  let bestWindow = [];
  for (let left = 0, right = 0; left < sorted.length; left++) {
    while (right < sorted.length && sorted[right].ts - sorted[left].ts <= 10 * 60 * 1000) right++;
    const window = sorted.slice(left, right);
    if (window.length > bestWindow.length) bestWindow = window;
  }
  if (bestWindow.length >= 20) {
    findings.push({
      type: 'mass_modification_burst',
      risk: 'high',
      count: bestWindow.length,
      firstModifiedAt: new Date(bestWindow[0].ts).toISOString(),
      lastModifiedAt: new Date(bestWindow[bestWindow.length - 1].ts).toISOString(),
      files: bestWindow.slice(0, 10).map((entry) => entry.scan.filePath),
      message: `${bestWindow.length} verdächtige Dateien wurden innerhalb von 10 Minuten geändert. Das spricht für automatisierte Veränderung oder Plugin-Massenupdate; bei unbekannten Pfaden sofort prüfen.`,
    });
  }

  const sizeGroups = [...bySize.entries()]
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 10)
    .map(([sizeBytes, group]) => ({
      sizeBytes: Number(sizeBytes),
      count: group.length,
      examples: group.slice(0, 5).map((scan) => scan.filePath),
    }));

  return { findings, sizeGroups };
}

async function scanFile(filePath, modifiedCoreFiles, trustedData) {
  const reasons = [];
  const context = classifyPath(filePath);
  const stat = await fs.promises.stat(filePath);
  const modifiedAt = stat.mtime.toISOString();
  const ageHours = Math.max(0, Math.round(((Date.now() - stat.mtime.getTime()) / 3_600_000) * 10) / 10);
  const sha256 = await hashFile(filePath);
  const configTrustedFile = isConfiguredTrustedFile(filePath);

  // Trust check — must happen before scoring so hash-change can inject a HIGH reason
  const trust = trustedData ? checkTrust(trustedData, filePath, sha256) : null;

  let score = 0;
  const scoredLabels = new Set();
  const addScoreOnce = (label, s) => { if (!scoredLabels.has(label)) { score += s; scoredLabels.add(label); } };

  if (context.isSystemTemp && /^php/i.test(path.basename(filePath))) {
    addReason(reasons, { label: 'PHP-Datei in System-Temp-Verzeichnis', risk: 'critical', score: 100 });
    score += 100;
  } else if (context.isLowPriorityCache) {
    addReason(reasons, { label: 'PHP-Datei in bekanntem Cache-/Log-Pfad', risk: 'low', score: 10 });
    score += 10;
  } else if (context.isUploadLike) {
    addReason(reasons, { label: 'PHP-Datei in Upload/Media-Verzeichnis', risk: 'critical', score: 100 });
    score += 100;
  } else if (context.isTempLike) {
    addReason(reasons, { label: 'PHP-Datei in Cache/Temp-Verzeichnis', risk: 'medium', score: 35 });
    score += 35;
  }

  if (isLikelyRandomPhpName(filePath) && !context.isLowPriorityCache) {
    addReason(reasons, { label: 'Zufällig wirkender PHP-Dateiname', risk: 'medium', score: 35 });
    score += 35;
  }

  const baseName = path.basename(filePath, path.extname(filePath)).toLowerCase();
  if (
    SUSPICIOUS_WEBROOT_NAMES.has(baseName)
    && !context.isKnownWordPressCode
    && !context.isLowPriorityCache
  ) {
    addReason(reasons, { label: 'Verdächtiger generischer Dateiname im Webroot-Kontext', risk: 'medium', score: 30 });
    score += 30;
  }

  try {
    const content = await readSample(filePath);
    const rl = readline.createInterface({ input: fs.createReadStream(filePath, { encoding: 'utf8', start: 0, end: 128 * 1024 }), crlfDelay: Infinity });

    let lineNum = 0;
    for await (const line of rl) {
      lineNum++;
      for (const rule of HIGH_CONFIDENCE_RULES) {
        if (rule.pattern.test(line)) {
          // In translation files, skip patterns that appear inside PHP string literals
          if (context.isWordPressLanguages && isLikelyInPhpString(line, rule.pattern)) continue;
          let s = rule.score;
          let r = rule.risk;
          if (isSecurityPlugin(context) && !SECURITY_PLUGIN_ALLOWED_HIGH_CONFIDENCE.has(rule.label)) {
            s = Math.min(s, 5);
            r = 'low';
          } else if (isVendorLibraryOfTrustedPlugin(context) && !VENDOR_SAFE_HIGH_CONFIDENCE.has(rule.label)) {
            // php://input, file_put_contents, preg_replace /e etc. are expected in HTTP/crypto libs
            s = Math.min(s, 5);
            r = 'low';
          }
          addReason(reasons, { label: rule.label, risk: r, score: s, line: lineNum, snippet: line.slice(0, 160).trim() });
          addScoreOnce(rule.label, s);
        }
      }
      for (const rule of CONTEXTUAL_RULES) {
        const { pattern, label } = rule;
        if (pattern.test(line)) {
          if (context.isWordPressLanguages && isLikelyInPhpString(line, pattern)) continue;
          const { adjustedScore, adjustedRisk } = adjustRuleForContext(rule, context);
          addReason(reasons, { label, risk: adjustedRisk, score: adjustedScore, line: lineNum, snippet: line.slice(0, 160).trim() });
          addScoreOnce(label, adjustedScore);
        }
      }
      if (lineNum > 2000) break; // don't scan gigantic files line-by-line
    }

    for (const reason of detectObfuscation(content)) {
      const { adjustedScore, adjustedRisk } = adjustRuleForContext(reason, context);
      addReason(reasons, { ...reason, score: adjustedScore, risk: adjustedRisk });
      addScoreOnce(reason.label, adjustedScore);
    }

    for (const combo of detectDangerousCombinations(reasons, context)) {
      addReason(reasons, combo);
      addScoreOnce(combo.label, combo.score);
    }
  } catch (_) {
    // unreadable file — skip silently
  }

  if (context.criticalFile && reasons.length > 0 && !context.isLowPriorityCache) {
    const label = 'Kritische WordPress-/Webserver-Datei mit verdächtigem Muster';
    addReason(reasons, { label, risk: 'high', score: 45, snippet: context.criticalFile });
    addScoreOnce(label, 45);
  }

  // Trusted file with changed hash → HIGH alarm regardless of other patterns
  if (trust && !trust.hashMatch) {
    const label = 'Bekannte Datei verändert (Hash-Änderung)';
    addReason(reasons, { label, risk: 'high', score: 80,
      snippet: `Erwartet: ${trust.expectedHash.slice(0, 16)}… Aktuell: ${sha256.slice(0, 16)}…` });
    addScoreOnce(label, 80);
  }

  score = applyContextCaps(score, reasons, context, { ageHours, filePath, configTrustedFile }, modifiedCoreFiles, trust);
  const risk = scoreToRisk(score);
  return {
    filePath,
    risk,
    score,
    reasons,
    context,
    metadata: {
      sha256,
      modifiedAt,
      ageHours,
      sizeBytes: stat.size,
    },
    trustedFile:   trust !== null,
    configTrustedFile,
    hashVerified:  trust?.hashMatch ?? null,
    hashChanged:   trust ? !trust.hashMatch : false,
    trustDescription: trust?.description || null,
    message: reasons.length ? null : 'Keine verdächtigen Muster gefunden',
  };
}

async function findWpInstallations(vhostsPath) {
  try {
    const { stdout } = await execFileAsync('find', [
      vhostsPath, '-name', 'wp-config.php', '-type', 'f',
      '-not', '-path', '*/wp-content/*',
    ], { timeout: 15000, maxBuffer: 2 * 1024 * 1024 });
    return stdout.split('\n').filter(Boolean).map((p) => path.dirname(p));
  } catch (err) {
    if (err.stdout) return err.stdout.split('\n').filter(Boolean).map((p) => path.dirname(p));
    return [];
  }
}

function findPhpBinary() {
  for (const p of PHP_BINARY_CANDIDATES) {
    try { execFileSync(p, ['--version'], { stdio: 'ignore', timeout: 3000 }); return p; } catch (_) {}
  }
  try { execFileSync('php', ['--version'], { stdio: 'ignore', timeout: 3000 }); return 'php'; } catch (_) {}
  return null;
}

function findWpCliBinary() {
  for (const p of WP_CLI_CANDIDATES) {
    try { fs.accessSync(p, fs.constants.X_OK); return p; } catch (_) {}
  }
  try {
    const found = execFileSync('which', ['wp'], { encoding: 'utf8', timeout: 3000 }).trim();
    if (found) return found;
  } catch (_) {}
  return null;
}

function resolveWpCli() {
  const wpBin = findWpCliBinary();
  if (!wpBin) return null;
  const phpBin = findPhpBinary();
  return { wpBin, phpBin };
}

async function execWpCli({ wpBin, phpBin }, args, cwd) {
  const env = phpBin && phpBin !== 'php'
    ? { ...process.env, PATH: `${path.dirname(phpBin)}:${process.env.PATH || ''}` }
    : process.env;
  try {
    const { stdout } = await execFileAsync(wpBin, args, { cwd, timeout: 30000, maxBuffer: 4 * 1024 * 1024, env });
    return stdout;
  } catch (err) {
    // wp may have failed because PHP is not in PATH — retry with explicit php invocation
    if (phpBin && (err.code === 'ENOENT' || (err.stderr || '').toLowerCase().includes('php'))) {
      const { stdout } = await execFileAsync(phpBin, [wpBin, ...args], { cwd, timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
      return stdout;
    }
    throw err;
  }
}

async function runWpChecksums(wpPath, wpCliInfo) {
  try {
    const stdout = await execWpCli(wpCliInfo, ['core', 'verify-checksums', '--allow-root', '--format=json'], wpPath);
    if (!stdout || !stdout.trim()) return []; // empty = all checksums ok
    return JSON.parse(stdout);
  } catch (err) {
    // Non-zero exit from wp — try to parse JSON from stdout
    if (err.stdout) {
      try { return JSON.parse(err.stdout); } catch (_) {}
    }
    return null; // wp-cli ran but output is unparseable
  }
}

async function collectModifiedCoreFiles(vhostsPath) {
  const wpCliInfo = resolveWpCli();
  if (!wpCliInfo) return null;
  const installs = await findWpInstallations(vhostsPath);
  if (installs.length === 0) return null;
  const modified = new Set();
  await Promise.all(installs.map(async (wpPath) => {
    const entries = await runWpChecksums(wpPath, wpCliInfo);
    if (!entries) return;
    for (const e of entries) {
      if (e.type === 'error') modified.add(normalizePath(path.join(wpPath, e.file_name || e.file || '')));
    }
  }));
  return modified;
}

function resolveVhostsPath(configPath) {
  const candidates = [
    configPath,
    '/var/www/vhosts',
    '/home/httpd/vhosts',
    '/var/www/html',
    '/srv/www/vhosts',
  ].filter((v, i, arr) => v && arr.indexOf(v) === i); // deduplicate
  for (const p of candidates) {
    if (!p) continue;
    try {
      fs.accessSync(p, fs.constants.R_OK);
      return p;
    } catch (_) {}
  }
  return null;
}

async function check(config) {
  const result = {
    name: 'suspiciousFiles',
    status: 'ok',
    risk: 'low',
    findings: [],
    metrics: { scanned: 0, flagged: 0, critical: 0, high: 0, medium: 0 },
  };

  const vhostsPath = resolveVhostsPath(config.VHOSTS_PATH);
  if (!vhostsPath) {
    result.status = 'error';
    result.findings.push({ type: 'path_error', message: `Kein lesbares Vhosts-Verzeichnis gefunden (Berechtigungsproblem oder falscher Pfad). Bitte monitor.js als root ausführen oder VHOSTS_PATH in .env prüfen.` });
    return result;
  }

  if (vhostsPath !== config.VHOSTS_PATH) {
    result.findings.push({ type: 'path_info', message: `VHOSTS_PATH auf ${vhostsPath} korrigiert (konfiguriert: ${config.VHOSTS_PATH})` });
  }

  try {
    const excludeList = buildExcludeList();
    const allFiles = await findRecentScanFiles(vhostsPath, config.RECENT_FILE_HOURS);
    const files = excludeList.length
      ? allFiles.filter((f) => !isExcluded(f, excludeList))
      : allFiles;

    const excluded = allFiles.length - files.length;
    result.metrics.scanned = files.length;
    if (excluded > 0) result.metrics.excluded = excluded;

    const modifiedCoreFiles = await collectModifiedCoreFiles(vhostsPath);
    if (modifiedCoreFiles !== null) {
      result.metrics.wpChecksumInstalls = modifiedCoreFiles.size > 0 ? `${modifiedCoreFiles.size} modified core file(s) detected` : 'all core checksums ok';
    }

    const trustedData = loadTrustedFiles();
    const trustedCount = Object.keys(trustedData.trustedFiles || {}).length;
    if (trustedCount > 0) result.metrics.trustedFilesConfigured = trustedCount;
    const trustedPluginCount = parseCsvEnv('SUSPICIOUS_FILES_TRUSTED_PLUGINS').length;
    const trustedFileCount = parseCsvEnv('SUSPICIOUS_FILES_TRUSTED_FILES').length;
    if (trustedPluginCount > 0) result.metrics.configTrustedPlugins = trustedPluginCount;
    if (trustedFileCount > 0) result.metrics.configTrustedFiles = trustedFileCount;

    const scans = await Promise.all(files.map((f) => scanFile(f, modifiedCoreFiles, trustedData)));
    const aggregates = buildAggregateFindings(scans);
    if (aggregates.sizeGroups.length > 0) result.metrics.sizeGroups = aggregates.sizeGroups;

    let coreHeuristicSuppressed = 0;
    let vendorLibSuppressed = 0;
    let configTrustedSuppressed = 0;
    for (const scan of scans) {
      if (scan.reasons.length === 0 || scan.risk === 'low') {
        // Count verified core files that had heuristic hits but were capped to LOW
        if (
          scan.context.isWordPressCore &&
          scan.reasons.length > 0 &&
          modifiedCoreFiles !== null &&
          !modifiedCoreFiles.has(normalizePath(scan.filePath))
        ) {
          coreHeuristicSuppressed++;
        }
        // Count vendor lib files that had pattern hits but were reduced to LOW
        if (scan.context.isVendorLibrary && isTrustedPopularPlugin(scan.context) && scan.reasons.length > 0) {
          vendorLibSuppressed++;
        }
        if (scan.configTrustedFile && scan.reasons.length > 0) {
          configTrustedSuppressed++;
        }
        continue;
      }
      result.metrics.flagged++;

      const risk = scan.risk;
      if (risk === 'critical') result.metrics.critical++;
      else if (risk === 'high') result.metrics.high++;
      else if (risk === 'medium') result.metrics.medium++;

      const finding = {
        type: 'suspicious_file',
        file: scan.filePath,
        message: buildMessage(scan),
        risk: scan.risk,
        score: scan.score,
        sha256: scan.metadata.sha256,
        modifiedAt: scan.metadata.modifiedAt,
        ageHours: scan.metadata.ageHours,
        sizeBytes: scan.metadata.sizeBytes,
        context: scan.context,
        trustedFile:      scan.trustedFile,
        configTrustedFile: scan.configTrustedFile,
        hashVerified:     scan.hashVerified,
        hashChanged:      scan.hashChanged,
        trustDescription: scan.trustDescription,
        reasons: scan.reasons.map((r) => ({ label: r.label, risk: r.risk, score: r.score, line: r.line, snippet: r.snippet })),
        patterns: scan.reasons.map((r) => ({ label: r.label, risk: r.risk, line: r.line, snippet: r.snippet })),
      };
      if (scan.risk === 'high' || scan.risk === 'critical') {
        finding.quarantine = buildQuarantinePlan(scan.filePath);
      }
      result.findings.push(finding);

      if (RISK_RANK[risk] > RISK_RANK[result.risk]) result.risk = risk;
    }

    for (const aggregate of aggregates.findings) {
      result.findings.push(aggregate);
      result.metrics.flagged++;
      if (RISK_RANK[aggregate.risk] > RISK_RANK[result.risk]) result.risk = aggregate.risk;
      if (aggregate.risk === 'critical') result.metrics.critical++;
      else if (aggregate.risk === 'high') result.metrics.high++;
      else if (aggregate.risk === 'medium') result.metrics.medium++;
    }

    if (coreHeuristicSuppressed > 0) {
      result.metrics.wpCoreHeuristicsSuppressed = coreHeuristicSuppressed;
      result.findings.push({
        type: 'core_checksum_ok',
        risk: 'low',
        message: `${coreHeuristicSuppressed} WordPress-Core-Heuristik-Treffer ignoriert (Checksums OK)`,
      });
    }

    if (vendorLibSuppressed > 0) {
      result.metrics.vendorLibsSuppressed = vendorLibSuppressed;
      result.findings.push({
        type: 'vendor_lib_suppressed',
        risk: 'low',
        message: `${vendorLibSuppressed} Vendor-Bibliotheks-Dateien in bekannten Plugins ignoriert (SSH, OAuth, HTTP-Client etc.)`,
      });
    }

    if (configTrustedSuppressed > 0) {
      result.metrics.configTrustedHeuristicsSuppressed = configTrustedSuppressed;
      result.findings.push({
        type: 'configured_trust_suppressed',
        risk: 'low',
        message: `${configTrustedSuppressed} Heuristik-Treffer durch konfigurierte Trust-Liste abgewertet. Kritische Malware-Kombinationen bleiben davon ausgenommen.`,
      });
    }

    if (result.metrics.critical > 0) {
      result.status = 'error';
    } else if (result.metrics.flagged > 0) {
      result.status = 'warning';
    }

  } catch (err) {
    result.status = 'error';
    result.findings.push({ type: 'exec_error', message: `suspiciousFiles check failed: ${err.message}` });
  }

  return result;
}

module.exports = { check };

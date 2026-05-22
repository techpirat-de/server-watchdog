'use strict';

const { execFile, execFileSync } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const execFileAsync = promisify(execFile);

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

// Patterns that are always real red flags regardless of plugin
const REAL_RED_FLAG_LABELS = new Set([
  'POST/GET-basierte Command Execution',
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
const CONTEXT_DIRS = {
  upload: ['uploads', 'upload', 'files', 'media', 'images'],
  temp: ['tmp', 'temp', 'cache'],
};
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

function isExcluded(filePath, excludeList) {
  const normalized = normalizePath(filePath);
  return excludeList.some((pattern) => normalized.includes(normalizePath(pattern)));
}

async function findRecentPhpFiles(vhostsPath, hours) {
  try {
    const { stdout } = await execFileAsync('find', [
      vhostsPath,
      '-name', '*.php',
      '-mmin', `-${hours * 60}`,
      '-type', 'f',
      '-not', '-path', '*/\.*',
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
  };

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

  context.isUploadLike = CONTEXT_DIRS.upload.some((dir) => parts.includes(dir)) && !context.isLowPriorityCache;
  context.isTempLike = CONTEXT_DIRS.temp.some((dir) => parts.includes(dir)) && !context.isLowPriorityCache;
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
function detectDangerousCombinations(reasons) {
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

  if (context.isKnownWordPressCode || context.isLowPriorityCache) {
    if (rule.command) {
      // shell_exec/system/exec in WP code is unusual → MEDIUM, not LOW
      adjustedScore = Math.min(adjustedScore, 35);
      adjustedRisk = 'medium';
    } else if (rule.reducibleInWp || ['Remote URL im Code', 'WordPress HTTP API', 'curl_exec()', 'Variable Funktion', 'call_user_func()', 'Sehr lange Codezeile', 'Langer Base64-ähnlicher String', 'Variable Variablen'].includes(rule.label)) {
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
    && TRUSTED_POPULAR_PLUGINS.has(context.component);
}

function hasRealRedFlag(reasons) {
  return reasons.some((r) => REAL_RED_FLAG_LABELS.has(r.label));
}

function hasCriticalSignal(reasons) {
  return reasons.some((reason) => reason.risk === 'critical' || [
    'POST/GET-basierte Command Execution',
    'eval(base64_decode(...))',
    'assert($_POST/$_GET)',
    'Crypto-Miner Hinweis',
  ].includes(reason.label));
}

function hasCriticalSignalForSecPlugin(reasons) {
  return reasons.some((r) => SECURITY_PLUGIN_ALLOWED_HIGH_CONFIDENCE.has(r.label));
}

function applyContextCaps(score, reasons, context, metadata, modifiedCoreFiles) {
  let cappedScore = score;

  if (isSecurityPlugin(context) && !hasCriticalSignalForSecPlugin(reasons)) {
    cappedScore = Math.min(cappedScore, riskToMaxScore('low'));
  }

  if (isTrustedPopularPlugin(context) && !hasRealRedFlag(reasons)) {
    cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
  }

  if (context.isWordPressCore) {
    if (modifiedCoreFiles !== null && !modifiedCoreFiles.has(normalizePath(metadata.filePath))) {
      // Checksums verified — file is unmodified official WP core, only surface real red flags
      if (!hasRealRedFlag(reasons)) {
        cappedScore = Math.min(cappedScore, riskToMaxScore('low'));
      } else if (!hasCriticalSignal(reasons)) {
        cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
      }
    } else if (modifiedCoreFiles === null) {
      // WP-CLI not available — still cap core files tightly, mtime alone is not a signal
      if (!hasRealRedFlag(reasons)) {
        cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
      } else if (!hasCriticalSignal(reasons)) {
        cappedScore = Math.min(cappedScore, riskToMaxScore('high'));
      }
    }
    // If modifiedCoreFiles has this file: checksum mismatch → full score, no cap
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

async function scanFile(filePath, modifiedCoreFiles) {
  const reasons = [];
  const context = classifyPath(filePath);
  const stat = await fs.promises.stat(filePath);
  const modifiedAt = stat.mtime.toISOString();
  const ageHours = Math.max(0, Math.round(((Date.now() - stat.mtime.getTime()) / 3_600_000) * 10) / 10);
  const sha256 = await hashFile(filePath);
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

    for (const combo of detectDangerousCombinations(reasons)) {
      addReason(reasons, combo);
      addScoreOnce(combo.label, combo.score);
    }
  } catch (_) {
    // unreadable file — skip silently
  }

  score = applyContextCaps(score, reasons, context, { ageHours, filePath }, modifiedCoreFiles);
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

async function runWpChecksums(wpPath) {
  try {
    const { stdout } = await execFileAsync('wp', [
      'core', 'verify-checksums', '--allow-root', '--format=json',
    ], { cwd: wpPath, timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
    const parsed = JSON.parse(stdout || '[]');
    return parsed.map((entry) => normalizePath(path.join(wpPath, entry.file)));
  } catch (err) {
    // wp-cli not installed or returned non-JSON (e.g. "Success: …")
    if (err.stdout) {
      try {
        const parsed = JSON.parse(err.stdout);
        return parsed.map((entry) => normalizePath(path.join(wpPath, entry.file)));
      } catch (_) {}
    }
    return null; // null = wp-cli unavailable or checksums passed with no output
  }
}

async function collectModifiedCoreFiles(vhostsPath) {
  if (!checkWpCli()) return null;
  const installs = await findWpInstallations(vhostsPath);
  if (installs.length === 0) return null;
  const modified = new Set();
  await Promise.all(installs.map(async (wpPath) => {
    const files = await runWpChecksums(wpPath);
    if (files) files.forEach((f) => modified.add(f));
  }));
  return modified;
}

function checkWpCli() {
  try { execFileSync('which', ['wp'], { stdio: 'ignore' }); return true; } catch (_) { return false; }
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
    const allFiles = await findRecentPhpFiles(vhostsPath, config.RECENT_FILE_HOURS);
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

    const scans = await Promise.all(files.map((f) => scanFile(f, modifiedCoreFiles)));

    for (const scan of scans) {
      if (scan.reasons.length === 0 || scan.risk === 'low') continue;
      result.metrics.flagged++;

      const risk = scan.risk;
      if (risk === 'critical') result.metrics.critical++;
      else if (risk === 'high') result.metrics.high++;
      else if (risk === 'medium') result.metrics.medium++;

      result.findings.push({
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
        reasons: scan.reasons.map((r) => ({ label: r.label, risk: r.risk, score: r.score, line: r.line, snippet: r.snippet })),
        patterns: scan.reasons.map((r) => ({ label: r.label, risk: r.risk, line: r.line, snippet: r.snippet })),
      });

      if (RISK_RANK[risk] > RISK_RANK[result.risk]) result.risk = risk;
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

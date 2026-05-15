'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const execFileAsync = promisify(execFile);

const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
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
      context.isKnownWordPressCode = true;
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
  if (base.length < 8) return false;
  if (/^[a-f0-9]{8,}$/i.test(base)) return true;
  if (/^[a-z0-9]{10,}$/i.test(base) && !/[aeiou]{2}/i.test(base)) return true;
  return false;
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

  if (context.isKnownWordPressCode || context.isLowPriorityCache) {
    if (rule.command) {
      adjustedScore = 10;
      adjustedRisk = 'low';
    } else if (rule.reducibleInWp || ['Remote URL im Code', 'WordPress HTTP API', 'curl_exec()', 'Variable Funktion', 'call_user_func()', 'Sehr lange Codezeile', 'Langer Base64-ähnlicher String'].includes(rule.label)) {
      adjustedScore = Math.min(adjustedScore, 5);
      adjustedRisk = 'low';
    }
  } else if (rule.command && !context.component) {
    adjustedScore = Math.max(adjustedScore, 45);
    adjustedRisk = 'medium';
  }

  return { adjustedScore, adjustedRisk };
}

function hasCriticalSignal(reasons) {
  return reasons.some((reason) => reason.risk === 'critical' || [
    'POST/GET-basierte Command Execution',
    'eval(base64_decode(...))',
    'assert($_POST/$_GET)',
    'Crypto-Miner Hinweis',
  ].includes(reason.label));
}

function applyContextCaps(score, reasons, context, metadata) {
  let cappedScore = score;

  if (context.isKnownWordPressCode && !hasCriticalSignal(reasons)) {
    cappedScore = Math.min(cappedScore, riskToMaxScore('high'));
    if (metadata.ageHours >= 24 * 30) {
      cappedScore = Math.min(cappedScore, riskToMaxScore('medium'));
    } else if (metadata.ageHours >= 24 * 7) {
      cappedScore = Math.max(0, cappedScore - 15);
    }
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
  const topReasons = scan.reasons.slice(0, 3).map((r) => r.label).join(', ');
  return `${scan.risk.toUpperCase()} Score ${scan.score}: ${scan.filePath} (${context}) - ${topReasons}`;
}

async function scanFile(filePath) {
  const reasons = [];
  const context = classifyPath(filePath);
  const stat = await fs.promises.stat(filePath);
  const modifiedAt = stat.mtime.toISOString();
  const ageHours = Math.max(0, Math.round(((Date.now() - stat.mtime.getTime()) / 3_600_000) * 10) / 10);
  const sha256 = await hashFile(filePath);
  let score = 0;

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
      for (const { pattern, label, risk, score: ruleScore } of HIGH_CONFIDENCE_RULES) {
        if (pattern.test(line)) {
          addReason(reasons, { label, risk, score: ruleScore, line: lineNum, snippet: line.slice(0, 160).trim() });
          score += ruleScore;
        }
      }
      for (const rule of CONTEXTUAL_RULES) {
        const { pattern, label } = rule;
        if (pattern.test(line)) {
          const { adjustedScore, adjustedRisk } = adjustRuleForContext(rule, context);
          addReason(reasons, { label, risk: adjustedRisk, score: adjustedScore, line: lineNum, snippet: line.slice(0, 160).trim() });
          score += adjustedScore;
        }
      }
      if (lineNum > 2000) break; // don't scan gigantic files line-by-line
    }

    for (const reason of detectObfuscation(content)) {
      const { adjustedScore, adjustedRisk } = adjustRuleForContext(reason, context);
      addReason(reasons, { ...reason, score: adjustedScore, risk: adjustedRisk });
      score += adjustedScore;
    }
  } catch (_) {
    // unreadable file — skip silently
  }

  if (context.isWordPressCore && reasons.length > 0) {
    score += 20;
    addReason(reasons, { label: 'Geänderte Datei im WordPress-Core-Pfad', risk: 'medium', score: 20 });
  }

  score = applyContextCaps(score, reasons, context, { ageHours });
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

    const scans = await Promise.all(files.map(scanFile));

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

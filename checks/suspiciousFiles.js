'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const execFileAsync = promisify(execFile);

// Directories where PHP files are always suspicious
const UPLOAD_DIRS = ['uploads', 'tmp', 'temp', 'cache'];

// Patterns that indicate potentially malicious code
const SUSPICIOUS_PATTERNS = [
  { pattern: /eval\s*\(/, label: 'eval()', risk: 'high' },
  { pattern: /base64_decode\s*\(/, label: 'base64_decode()', risk: 'medium' },
  { pattern: /gzinflate\s*\(/, label: 'gzinflate()', risk: 'high' },
  { pattern: /shell_exec\s*\(/, label: 'shell_exec()', risk: 'critical' },
  { pattern: /system\s*\(/, label: 'system()', risk: 'critical' },
  { pattern: /passthru\s*\(/, label: 'passthru()', risk: 'critical' },
  { pattern: /proc_open\s*\(/, label: 'proc_open()', risk: 'critical' },
  { pattern: /curl_exec\s*\(/, label: 'curl_exec()', risk: 'medium' },
  { pattern: /assert\s*\(/, label: 'assert()', risk: 'high' },
  { pattern: /preg_replace\s*\(.*\/e['"]/i, label: 'preg_replace /e modifier', risk: 'critical' },
];

const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

async function findRecentPhpFiles(vhostsPath, hours) {
  try {
    const { stdout } = await execFileAsync('find', [
      vhostsPath,
      '-name', '*.php',
      '-newer', `/proc/1`, // fallback: use mtime
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

function isUploadDir(filePath) {
  const parts = filePath.toLowerCase().split(path.sep);
  return UPLOAD_DIRS.some((dir) => parts.includes(dir));
}

async function scanFile(filePath) {
  const findings = [];
  let highestRisk = 'low';

  if (isUploadDir(filePath)) {
    findings.push({ pattern: 'php_in_upload_dir', label: 'PHP file in upload/tmp/cache directory', risk: 'high' });
    highestRisk = 'high';
  }

  try {
    const stream = fs.createReadStream(filePath, { encoding: 'utf8', start: 0, end: 64 * 1024 });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    let lineNum = 0;
    for await (const line of rl) {
      lineNum++;
      for (const { pattern, label, risk } of SUSPICIOUS_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({ pattern: label, label, risk, line: lineNum, snippet: line.slice(0, 120).trim() });
          if (RISK_RANK[risk] > RISK_RANK[highestRisk]) highestRisk = risk;
        }
      }
      if (lineNum > 2000) break; // don't scan gigantic files line-by-line
    }
  } catch (_) {
    // unreadable file — skip silently
  }

  return { filePath, findings, risk: highestRisk };
}

async function check(config) {
  const result = {
    name: 'suspiciousFiles',
    status: 'ok',
    risk: 'low',
    findings: [],
    metrics: { scanned: 0, flagged: 0, critical: 0, high: 0, medium: 0 },
  };

  if (!fs.existsSync(config.VHOSTS_PATH)) {
    result.status = 'error';
    result.findings.push({ type: 'path_error', message: `VHOSTS_PATH does not exist: ${config.VHOSTS_PATH}` });
    return result;
  }

  try {
    const files = await findRecentPhpFiles(config.VHOSTS_PATH, config.RECENT_FILE_HOURS);
    result.metrics.scanned = files.length;

    const scans = await Promise.all(files.map(scanFile));

    for (const scan of scans) {
      if (scan.findings.length === 0) continue;
      result.metrics.flagged++;

      const risk = scan.risk;
      if (risk === 'critical') result.metrics.critical++;
      else if (risk === 'high') result.metrics.high++;
      else if (risk === 'medium') result.metrics.medium++;

      result.findings.push({
        type: 'suspicious_file',
        file: scan.filePath,
        risk: scan.risk,
        patterns: scan.findings.map((f) => ({ label: f.label, risk: f.risk, line: f.line, snippet: f.snippet })),
      });

      if (RISK_RANK[risk] > RISK_RANK[result.risk]) result.risk = risk;
    }

    if (result.metrics.critical > 0 || result.metrics.flagged > 5) {
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

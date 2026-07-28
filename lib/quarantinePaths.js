'use strict';

const fs = require('fs');

const DEFAULT_QUARANTINE_PATTERNS = [
  '/.quarantined/',
  '/root/physio-malware-',
  '/root/server-malware-',
  '/root/server-watchdog-quarantine/',
  '/root/watchdog-incidents/',
];

function normalizePath(filePath) {
  return String(filePath || '').replace(/\\/g, '/').toLowerCase();
}

function configuredPatterns() {
  return (process.env.SUSPICIOUS_FILES_QUARANTINE_EXCLUDE || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function quarantinePatterns() {
  return [...DEFAULT_QUARANTINE_PATTERNS, ...configuredPatterns()].map(normalizePath);
}

function isQuarantinePath(filePath) {
  const normalized = normalizePath(filePath);
  return quarantinePatterns().some((pattern) => normalized.includes(pattern));
}

function fileStillExists(filePath) {
  if (!filePath || typeof filePath !== 'string') return false;
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    return true;
  } catch (_) {
    return false;
  }
}

module.exports = {
  DEFAULT_QUARANTINE_PATTERNS,
  normalizePath,
  quarantinePatterns,
  isQuarantinePath,
  fileStillExists,
};

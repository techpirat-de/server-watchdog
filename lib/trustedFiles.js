'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const TRUST_FILE = process.env.TRUSTED_FILES_PATH
  || path.join(__dirname, '..', 'trusted-files.json');

function load() {
  try {
    return JSON.parse(fs.readFileSync(TRUST_FILE, 'utf8'));
  } catch (_) {
    return { trustedFiles: {} };
  }
}

function save(data) {
  fs.writeFileSync(TRUST_FILE, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

// Returns null when file is not in trust list.
// Returns { trusted, hashMatch, expectedHash, description, added } when found.
function checkTrust(data, filePath, actualHash) {
  const entry = (data.trustedFiles || {})[filePath];
  if (!entry) return null;
  return {
    trusted:      true,
    hashMatch:    entry.sha256 === actualHash,
    expectedHash: entry.sha256,
    description:  entry.description || '',
    added:        entry.added || '',
  };
}

module.exports = { load, save, hashFile, checkTrust, TRUST_FILE };

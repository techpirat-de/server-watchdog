'use strict';

const mysql = require('mysql2/promise');

let pool = null;

function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.DB_HOST || '127.0.0.1',
      port: parseInt(process.env.DB_PORT, 10) || 3306,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 5,
      timezone: 'Z',
    });
  }
  return pool;
}

async function ensureReportsSchema() {
  const db = getPool();
  await db.execute(`
    CREATE TABLE IF NOT EXISTS reports (
      id                 INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      timestamp          DATETIME     NOT NULL,
      hostname           VARCHAR(255) NOT NULL,
      overall_risk       ENUM('low','medium','high','critical') NOT NULL,
      checks             JSON         NOT NULL,
      ai_review          JSON         DEFAULT NULL,
      notifications_sent JSON         DEFAULT NULL,
      incident           JSON         DEFAULT NULL,
      created_at         TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_timestamp (timestamp),
      INDEX idx_risk      (overall_risk)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
  const [[column]] = await db.execute(
    `SELECT COUNT(*) AS count
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'reports'
       AND COLUMN_NAME = 'incident'`
  );
  if (!column.count) {
    await db.execute('ALTER TABLE reports ADD COLUMN incident JSON DEFAULT NULL');
  }
}

async function saveReport(report) {
  await ensureReportsSchema();
  const db = getPool();
  const [result] = await db.execute(
    `INSERT INTO reports (timestamp, hostname, overall_risk, checks, ai_review, notifications_sent, incident)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      new Date(report.timestamp),
      report.hostname,
      report.overallRisk,
      JSON.stringify(report.checks),
      report.aiReview ? JSON.stringify(report.aiReview) : null,
      JSON.stringify(report.notificationsSent || []),
      report.incident ? JSON.stringify(report.incident) : null,
    ]
  );
  return result.insertId;
}

async function ensureMonitoredUrlsTable() {
  const db = getPool();
  await db.execute(`
    CREATE TABLE IF NOT EXISTS monitored_urls (
      id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      label               VARCHAR(255) DEFAULT NULL,
      url                 VARCHAR(2048) NOT NULL,
      enabled             TINYINT(1) NOT NULL DEFAULT 1,
      expected_status_min SMALLINT UNSIGNED NOT NULL DEFAULT 200,
      expected_status_max SMALLINT UNSIGNED NOT NULL DEFAULT 399,
      timeout_ms          INT UNSIGNED NOT NULL DEFAULT 10000,
      created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_url (url(512)),
      INDEX idx_enabled (enabled)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
}

function validateUrlInput(input) {
  const url = String(input.url || '').trim();
  if (!url) throw new Error('URL erforderlich');
  let parsed;
  try {
    parsed = new URL(url);
  } catch (_) {
    throw new Error('URL ungültig');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Nur http:// oder https:// erlaubt');
  }
  return {
    label: String(input.label || '').trim() || null,
    url: parsed.toString(),
    enabled: input.enabled === false || input.enabled === 0 ? 0 : 1,
    expected_status_min: parseInt(input.expected_status_min, 10) || 200,
    expected_status_max: parseInt(input.expected_status_max, 10) || 399,
    timeout_ms: Math.max(1000, Math.min(parseInt(input.timeout_ms, 10) || 10000, 60000)),
  };
}

async function getMonitoredUrls({ enabledOnly = false } = {}) {
  await ensureMonitoredUrlsTable();
  const db = getPool();
  const [rows] = await db.execute(
    `SELECT id, label, url, enabled, expected_status_min, expected_status_max, timeout_ms, created_at, updated_at
     FROM monitored_urls
     ${enabledOnly ? 'WHERE enabled = 1' : ''}
     ORDER BY label IS NULL, label, url`
  );
  return rows;
}

async function addMonitoredUrl(input) {
  await ensureMonitoredUrlsTable();
  const data = validateUrlInput(input);
  const db = getPool();
  const [result] = await db.execute(
    `INSERT INTO monitored_urls (label, url, enabled, expected_status_min, expected_status_max, timeout_ms)
     VALUES (?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       label = VALUES(label),
       enabled = VALUES(enabled),
       expected_status_min = VALUES(expected_status_min),
       expected_status_max = VALUES(expected_status_max),
       timeout_ms = VALUES(timeout_ms)`,
    [data.label, data.url, data.enabled, data.expected_status_min, data.expected_status_max, data.timeout_ms]
  );
  return { id: result.insertId, ...data };
}

async function updateMonitoredUrl(id, input) {
  await ensureMonitoredUrlsTable();
  const data = validateUrlInput(input);
  const db = getPool();
  const [result] = await db.execute(
    `UPDATE monitored_urls
     SET label = ?, url = ?, enabled = ?, expected_status_min = ?, expected_status_max = ?, timeout_ms = ?
     WHERE id = ?`,
    [data.label, data.url, data.enabled, data.expected_status_min, data.expected_status_max, data.timeout_ms, id]
  );
  if (result.affectedRows === 0) throw new Error('URL nicht gefunden');
  return { id: Number(id), ...data };
}

async function deleteMonitoredUrl(id) {
  await ensureMonitoredUrlsTable();
  const db = getPool();
  const [result] = await db.execute('DELETE FROM monitored_urls WHERE id = ?', [id]);
  if (result.affectedRows === 0) throw new Error('URL nicht gefunden');
}

async function getReports({ limit = 50, offset = 0, risk = null } = {}) {
  const db = getPool();
  const params = [];
  let where = '';
  if (risk) {
    where = 'WHERE overall_risk = ?';
    params.push(risk);
  }
  const [rows] = await db.execute(
    `SELECT id, timestamp, hostname, overall_risk,
            JSON_LENGTH(checks) AS check_count,
            (SELECT COUNT(*) FROM JSON_TABLE(checks, '$[*]' COLUMNS (findings JSON PATH '$.findings')) AS t
             WHERE JSON_LENGTH(findings) > 0) AS checks_with_findings
     FROM reports ${where}
     ORDER BY timestamp DESC
     LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  return rows;
}

async function getReportById(id) {
  const db = getPool();
  const [rows] = await db.execute(
    'SELECT * FROM reports WHERE id = ?',
    [id]
  );
  if (!rows[0]) return null;
  const row = rows[0];
  return {
    ...row,
    checks: typeof row.checks === 'string' ? JSON.parse(row.checks) : row.checks,
    ai_review: row.ai_review ? (typeof row.ai_review === 'string' ? JSON.parse(row.ai_review) : row.ai_review) : null,
    notifications_sent: typeof row.notifications_sent === 'string' ? JSON.parse(row.notifications_sent) : row.notifications_sent,
    incident: row.incident ? (typeof row.incident === 'string' ? JSON.parse(row.incident) : row.incident) : null,
  };
}

async function getLatestReport() {
  const db = getPool();
  const [rows] = await db.execute(
    'SELECT * FROM reports ORDER BY timestamp DESC LIMIT 1'
  );
  if (!rows[0]) return null;
  const row = rows[0];
  return {
    ...row,
    checks: typeof row.checks === 'string' ? JSON.parse(row.checks) : row.checks,
    ai_review: row.ai_review ? (typeof row.ai_review === 'string' ? JSON.parse(row.ai_review) : row.ai_review) : null,
    notifications_sent: typeof row.notifications_sent === 'string' ? JSON.parse(row.notifications_sent) : row.notifications_sent,
    incident: row.incident ? (typeof row.incident === 'string' ? JSON.parse(row.incident) : row.incident) : null,
  };
}

async function getStats() {
  const db = getPool();
  const [[totals]] = await db.execute(
    `SELECT
       COUNT(*) AS total_runs,
       SUM(overall_risk = 'critical') AS critical_count,
       SUM(overall_risk = 'high')     AS high_count,
       SUM(overall_risk = 'medium')   AS medium_count,
       SUM(overall_risk = 'low')      AS low_count,
       MAX(timestamp)                 AS last_run
     FROM reports`
  );
  return totals;
}

async function getMailQueueHistory({ limit = 12 } = {}) {
  const db = getPool();
  const [rows] = await db.execute(
    `SELECT id, timestamp, checks
     FROM reports
     ORDER BY timestamp DESC
     LIMIT ?`,
    [limit]
  );

  return rows
    .map((row) => {
      const checks = typeof row.checks === 'string' ? JSON.parse(row.checks) : row.checks;
      const mailQueue = (checks || []).find((check) => check.name === 'mailQueue');
      const queueSize = mailQueue?.metrics?.queueSize ?? mailQueue?.metrics?.total;
      if (!Number.isFinite(Number(queueSize))) return null;
      return {
        id: row.id,
        timestamp: row.timestamp,
        queueSize: Number(queueSize),
      };
    })
    .filter(Boolean)
    .reverse();
}

async function updateAiReview(id, aiReview) {
  const db = getPool();
  await db.execute(
    'UPDATE reports SET ai_review = ? WHERE id = ?',
    [JSON.stringify(aiReview), id]
  );
}

async function getReportsWithoutAiReview({ limit = 5, minRisk = 'medium' } = {}) {
  const db = getPool();
  const riskOrder = ['low', 'medium', 'high', 'critical'];
  const minIdx = riskOrder.indexOf(minRisk);
  const eligible = riskOrder.slice(minIdx);
  const placeholders = eligible.map(() => '?').join(',');
  const [rows] = await db.execute(
    `SELECT id, timestamp, hostname, overall_risk, checks, notifications_sent
     FROM reports
     WHERE (ai_review IS NULL OR JSON_TYPE(ai_review) = 'NULL')
       AND overall_risk IN (${placeholders})
     ORDER BY timestamp DESC
     LIMIT ?`,
    [...eligible, limit]
  );
  return rows.map((r) => ({
    ...r,
    checks: typeof r.checks === 'string' ? JSON.parse(r.checks) : r.checks,
    notifications_sent: typeof r.notifications_sent === 'string' ? JSON.parse(r.notifications_sent) : r.notifications_sent,
  }));
}

async function closePool() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

module.exports = {
  saveReport,
  getReports,
  getReportById,
  getLatestReport,
  getStats,
  getMailQueueHistory,
  ensureMonitoredUrlsTable,
  ensureReportsSchema,
  getMonitoredUrls,
  addMonitoredUrl,
  updateMonitoredUrl,
  deleteMonitoredUrl,
  updateAiReview,
  getReportsWithoutAiReview,
  closePool,
};

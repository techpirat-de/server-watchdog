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

async function saveReport(report) {
  const db = getPool();
  const [result] = await db.execute(
    `INSERT INTO reports (timestamp, hostname, overall_risk, checks, ai_review, notifications_sent)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      new Date(report.timestamp),
      report.hostname,
      report.overallRisk,
      JSON.stringify(report.checks),
      report.aiReview ? JSON.stringify(report.aiReview) : null,
      JSON.stringify(report.notificationsSent || []),
    ]
  );
  return result.insertId;
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

module.exports = { saveReport, getReports, getReportById, getLatestReport, getStats, getMailQueueHistory, updateAiReview, getReportsWithoutAiReview, closePool };

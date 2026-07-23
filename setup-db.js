'use strict';

require('dotenv').config({ override: true });
const mysql = require('mysql2/promise');

async function main() {
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || '127.0.0.1',
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
  });

  console.log('[setup-db] Connected to MySQL');

  await conn.execute(`
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

  console.log('[setup-db] Table "reports" ready');

  const [[incidentColumn]] = await conn.execute(
    `SELECT COUNT(*) AS count
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'reports'
       AND COLUMN_NAME = 'incident'`
  );
  if (!incidentColumn.count) {
    await conn.execute('ALTER TABLE reports ADD COLUMN incident JSON DEFAULT NULL');
    console.log('[setup-db] Column "reports.incident" added');
  }

  await conn.execute(`
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

  console.log('[setup-db] Table "monitored_urls" ready');
  await conn.end();
  process.exit(0);
}

main().catch((err) => {
  console.error('[setup-db] Error:', err.message);
  process.exit(1);
});

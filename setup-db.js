'use strict';

require('dotenv').config();
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
      created_at         TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_timestamp (timestamp),
      INDEX idx_risk      (overall_risk)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  console.log('[setup-db] Table "reports" ready');
  await conn.end();
  process.exit(0);
}

main().catch((err) => {
  console.error('[setup-db] Error:', err.message);
  process.exit(1);
});

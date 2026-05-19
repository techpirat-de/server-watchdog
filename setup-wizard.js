'use strict';

const readline = require('readline');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile, execFileSync } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

// ─── ANSI Colors ────────────────────────────────────────────────────────────
const c = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
  red:    '\x1b[31m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  blue:   '\x1b[34m',
  cyan:   '\x1b[36m',
  white:  '\x1b[37m',
  bgBlue: '\x1b[44m',
};
const ok    = (s) => `${c.green}✔${c.reset}  ${s}`;
const warn  = (s) => `${c.yellow}⚠${c.reset}  ${s}`;
const err   = (s) => `${c.red}✖${c.reset}  ${s}`;
const info  = (s) => `${c.cyan}ℹ${c.reset}  ${s}`;
const step  = (n, s) => `\n${c.bold}${c.bgBlue} ${n} ${c.reset}${c.bold} ${s}${c.reset}\n`;
const label = (s) => `${c.cyan}${s}${c.reset}`;

// ─── readline helpers ────────────────────────────────────────────────────────
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function ask(question, defaultVal = '') {
  const hint = defaultVal !== '' ? ` ${c.dim}[${defaultVal}]${c.reset}` : '';
  return new Promise((resolve) => {
    rl.question(`  ${label('?')} ${question}${hint}: `, (answer) => {
      resolve(answer.trim() || defaultVal);
    });
  });
}

function askYN(question, defaultVal = 'n') {
  const opts = defaultVal === 'y' ? 'Y/n' : 'y/N';
  return new Promise((resolve) => {
    rl.question(`  ${label('?')} ${question} ${c.dim}(${opts})${c.reset} `, (answer) => {
      const a = answer.trim().toLowerCase();
      if (!a) resolve(defaultVal === 'y');
      else resolve(a === 'y' || a === 'yes' || a === 'j' || a === 'ja');
    });
  });
}

function askPassword(question) {
  return new Promise((resolve) => {
    process.stdout.write(`  ${label('?')} ${question}: `);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    let password = '';

    const onData = (char) => {
      char = char.toString();
      if (char === '\n' || char === '\r' || char === '') {
        stdin.removeListener('data', onData);
        if (wasRaw !== undefined) stdin.setRawMode(wasRaw);
        else stdin.setRawMode(false);
        stdin.pause();
        process.stdout.write('\n');
        resolve(password);
      } else if (char === '') {
        process.stdout.write('\n');
        process.exit(0);
      } else if (char === '' || char === '\b') {
        if (password.length > 0) {
          password = password.slice(0, -1);
          process.stdout.write('\b \b');
        }
      } else {
        password += char;
        process.stdout.write('*');
      }
    };

    try {
      stdin.setRawMode(true);
    } catch (_) {
      // non-TTY: fall back to visible input
      rl.question('', (a) => resolve(a.trim()));
      return;
    }
    stdin.resume();
    stdin.on('data', onData);
  });
}

function generatePassword(len = 16) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%';
  let p = '';
  for (let i = 0; i < len; i++) p += chars[Math.floor(Math.random() * chars.length)];
  return p;
}

// ─── System checks ──────────────────────────────────────────────────────────
function checkCommand(cmd) {
  try { execFileSync('which', [cmd], { stdio: 'ignore' }); return true; } catch (_) { return false; }
}

function nodeVersion() {
  const [major] = process.versions.node.split('.').map(Number);
  return major;
}

function detectMailLog() {
  const candidates = [
    '/var/log/mail.log', '/var/log/maillog',
    '/var/log/mail/mail.log', '/var/log/plesk/maillog',
    '/usr/local/psa/var/log/maillog',
  ];
  return candidates.find((p) => { try { fs.accessSync(p, fs.constants.R_OK); return true; } catch (_) { return false; } }) || '/var/log/maillog';
}

function detectVhosts() {
  const candidates = ['/var/www/vhosts', '/home/httpd/vhosts', '/var/www/html', '/srv/www/vhosts'];
  return candidates.find((p) => { try { fs.accessSync(p, fs.constants.R_OK); return true; } catch (_) { return false; } }) || '/var/www/vhosts';
}

// ─── DB helpers ─────────────────────────────────────────────────────────────
async function testDbConnection(cfg) {
  let mysql;
  try { mysql = require('mysql2/promise'); } catch (_) { throw new Error('mysql2 nicht gefunden — bitte erst "npm install" ausführen'); }
  const conn = await mysql.createConnection({
    host: cfg.DB_HOST, port: parseInt(cfg.DB_PORT, 10),
    user: cfg.DB_USER, password: cfg.DB_PASS,
    connectTimeout: 5000,
  });
  await conn.end();
}

async function createDatabase(cfg) {
  const mysql = require('mysql2/promise');
  const conn = await mysql.createConnection({
    host: cfg.DB_HOST, port: parseInt(cfg.DB_PORT, 10),
    user: cfg.DB_USER, password: cfg.DB_PASS,
    connectTimeout: 5000,
  });
  await conn.execute(`CREATE DATABASE IF NOT EXISTS \`${cfg.DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  await conn.execute(`GRANT ALL PRIVILEGES ON \`${cfg.DB_NAME}\`.* TO '${cfg.DB_USER}'@'${cfg.DB_HOST === '127.0.0.1' ? 'localhost' : cfg.DB_HOST}'`);
  await conn.execute('FLUSH PRIVILEGES');
  await conn.end();
}

async function runSetupDb(envPath) {
  return execFileAsync(process.execPath, ['setup-db.js'], {
    cwd: path.dirname(envPath),
    env: { ...process.env, DOTENV_CONFIG_PATH: envPath },
    timeout: 15000,
  });
}

// ─── .env writer ────────────────────────────────────────────────────────────
function buildEnv(cfg) {
  return `# Generated by setup-wizard on ${new Date().toISOString()}
SERVER_NAME=${cfg.SERVER_NAME}
CHECK_INTERVAL_MINUTES=${cfg.CHECK_INTERVAL_MINUTES}
MAIL_QUEUE_WARNING_THRESHOLD=${cfg.MAIL_QUEUE_WARNING_THRESHOLD}
MAIL_QUEUE_CRITICAL_THRESHOLD=${cfg.MAIL_QUEUE_CRITICAL_THRESHOLD}
MAIL_LOG_PATH=${cfg.MAIL_LOG_PATH}
VHOSTS_PATH=${cfg.VHOSTS_PATH}
RECENT_FILE_HOURS=${cfg.RECENT_FILE_HOURS}
SUSPICIOUS_FILES_EXCLUDE=${cfg.SUSPICIOUS_FILES_EXCLUDE}

# MySQL Datenbank
DB_HOST=${cfg.DB_HOST}
DB_PORT=${cfg.DB_PORT}
DB_USER=${cfg.DB_USER}
DB_PASS=${cfg.DB_PASS}
DB_NAME=${cfg.DB_NAME}

# Web-Dashboard
WEB_PORT=${cfg.WEB_PORT}
WEB_HOST=${cfg.WEB_HOST}
WEB_USER=${cfg.WEB_USER}
WEB_PASS=${cfg.WEB_PASS}

# KI-Review (optional)
ENABLE_AI_REVIEW=${cfg.ENABLE_AI_REVIEW}
OPENAI_API_KEY=${cfg.OPENAI_API_KEY}
OPENAI_MODEL=${cfg.OPENAI_MODEL}
OPENAI_TIMEOUT_MS=${cfg.OPENAI_TIMEOUT_MS}
AI_REVIEW_MIN_RISK=${cfg.AI_REVIEW_MIN_RISK}
AI_NOTIFY_MIN_RISK=${cfg.AI_NOTIFY_MIN_RISK}
AI_NOTIFY_COOLDOWN_MINUTES=${cfg.AI_NOTIFY_COOLDOWN_MINUTES}

# E-Mail Benachrichtigung (optional)
ENABLE_EMAIL_NOTIFIER=${cfg.ENABLE_EMAIL_NOTIFIER}
SMTP_HOST=${cfg.SMTP_HOST}
SMTP_PORT=${cfg.SMTP_PORT}
SMTP_USER=${cfg.SMTP_USER}
SMTP_PASS=${cfg.SMTP_PASS}
ALERT_EMAIL_TO=${cfg.ALERT_EMAIL_TO}
ALERT_EMAIL_FROM=${cfg.ALERT_EMAIL_FROM}

# Telegram Benachrichtigung (optional)
ENABLE_TELEGRAM_NOTIFIER=${cfg.ENABLE_TELEGRAM_NOTIFIER}
TELEGRAM_BOT_TOKEN=${cfg.TELEGRAM_BOT_TOKEN}
TELEGRAM_CHAT_ID=${cfg.TELEGRAM_CHAT_ID}
`;
}

// ─── Main wizard ─────────────────────────────────────────────────────────────
async function main() {
  const envPath = path.join(__dirname, '.env');

  console.clear();
  console.log(`
${c.bold}${c.bgBlue}                                                   ${c.reset}
${c.bold}${c.bgBlue}   Plesk Server Watchdog — Installations-Wizard     ${c.reset}
${c.bold}${c.bgBlue}                                                   ${c.reset}
`);

  // ── Voraussetzungen prüfen ──────────────────────────────────────────────
  console.log(step('0', 'Voraussetzungen prüfen'));

  const nodeMaj = nodeVersion();
  if (nodeMaj >= 18) {
    console.log(ok(`Node.js v${process.versions.node}`));
  } else {
    console.log(err(`Node.js ${process.versions.node} — mindestens v18 erforderlich`));
    process.exit(1);
  }

  for (const cmd of ['curl', 'postqueue', 'mailq']) {
    if (checkCommand(cmd)) console.log(ok(`${cmd} gefunden`));
    else if (cmd === 'curl') console.log(warn(`${cmd} nicht gefunden — WordPress xmlrpc-Probe funktioniert nicht`));
    else console.log(warn(`${cmd} nicht gefunden — Mail-Queue-Check funktioniert möglicherweise nicht`));
  }

  const mailLogDetected  = detectMailLog();
  const vhostsDetected   = detectVhosts();
  console.log(info(`Mail-Log erkannt: ${mailLogDetected}`));
  console.log(info(`Vhosts-Pfad erkannt: ${vhostsDetected}`));

  if (fs.existsSync(envPath)) {
    console.log(warn('.env existiert bereits'));
    const overwrite = await askYN('Vorhandene .env überschreiben?', 'n');
    if (!overwrite) { console.log(info('Abgebrochen.')); rl.close(); return; }
  }

  const cfg = {};

  // ── 1. Server ──────────────────────────────────────────────────────────
  console.log(step('1', 'Server-Grundeinstellungen'));

  cfg.SERVER_NAME                  = await ask('Server-Name (frei wählbar)', os.hostname());
  cfg.CHECK_INTERVAL_MINUTES       = await ask('Prüf-Intervall in Minuten', '60');
  cfg.VHOSTS_PATH                  = await ask('Pfad zu den Vhosts', vhostsDetected);
  cfg.MAIL_LOG_PATH                = await ask('Pfad zum Mail-Log', mailLogDetected);
  cfg.RECENT_FILE_HOURS            = await ask('Dateien der letzten N Stunden prüfen', '24');
  cfg.MAIL_QUEUE_WARNING_THRESHOLD = await ask('Mail-Queue Warning ab (Anzahl)', '20');
  cfg.MAIL_QUEUE_CRITICAL_THRESHOLD= await ask('Mail-Queue Critical ab (Anzahl)', '100');
  cfg.SUSPICIOUS_FILES_EXCLUDE     = await ask('Zusätzliche Scan-Ausschlüsse (kommagetrennt, leer = keine)', '');

  // ── 2. Datenbank ───────────────────────────────────────────────────────
  console.log(step('2', 'MySQL-Datenbank'));

  cfg.DB_HOST = await ask('DB-Host', '127.0.0.1');
  cfg.DB_PORT = await ask('DB-Port', '3306');
  cfg.DB_USER = await ask('DB-Benutzer');
  cfg.DB_PASS = await askPassword('DB-Passwort');
  cfg.DB_NAME = await ask('DB-Name', 'server_watchdog');

  process.stdout.write(`\n  ${label('…')} Verbindung testen …`);
  let dbOk = false;
  try {
    await testDbConnection(cfg);
    process.stdout.write(`  ${c.green}OK${c.reset}\n`);
    dbOk = true;
  } catch (e) {
    process.stdout.write(`  ${c.red}Fehler${c.reset}\n`);
    console.log(err(e.message));
    const tryCreate = await askYN('Datenbank automatisch anlegen versuchen?', 'y');
    if (tryCreate) {
      try {
        await createDatabase(cfg);
        console.log(ok(`Datenbank "${cfg.DB_NAME}" angelegt`));
        dbOk = true;
      } catch (e2) {
        console.log(err(`Konnte Datenbank nicht anlegen: ${e2.message}`));
        console.log(info('Bitte Datenbank manuell anlegen und danach "npm run setup-db" ausführen.'));
      }
    }
  }

  // ── 3. Web-Dashboard ──────────────────────────────────────────────────
  console.log(step('3', 'Web-Dashboard'));

  cfg.WEB_PORT = await ask('Dashboard-Port', '3000');
  cfg.WEB_HOST = await ask('Dashboard-Host (127.0.0.1 = nur lokal)', '127.0.0.1');
  cfg.WEB_USER = await ask('Dashboard-Benutzername', 'admin');

  const autoPass = generatePassword();
  const useAutoPass = await askYN(`Zufälliges Passwort generieren? ${c.dim}(${autoPass})${c.reset}`, 'y');
  if (useAutoPass) {
    cfg.WEB_PASS = autoPass;
    console.log(ok(`Passwort gesetzt: ${c.bold}${autoPass}${c.reset}`));
  } else {
    cfg.WEB_PASS = await askPassword('Dashboard-Passwort');
  }

  // ── 4. E-Mail Benachrichtigung ─────────────────────────────────────────
  console.log(step('4', 'E-Mail Benachrichtigung (optional)'));

  const enableEmail = await askYN('E-Mail Benachrichtigung aktivieren?', 'n');
  cfg.ENABLE_EMAIL_NOTIFIER = enableEmail ? 'true' : 'false';
  if (enableEmail) {
    cfg.SMTP_HOST       = await ask('SMTP-Server');
    cfg.SMTP_PORT       = await ask('SMTP-Port', '587');
    cfg.SMTP_USER       = await ask('SMTP-Benutzername');
    cfg.SMTP_PASS       = await askPassword('SMTP-Passwort');
    cfg.ALERT_EMAIL_TO  = await ask('Empfänger-E-Mail');
    cfg.ALERT_EMAIL_FROM= await ask('Absender-E-Mail', cfg.SMTP_USER);
  } else {
    cfg.SMTP_HOST = cfg.SMTP_PORT = cfg.SMTP_USER = cfg.SMTP_PASS = '';
    cfg.ALERT_EMAIL_TO = cfg.ALERT_EMAIL_FROM = '';
  }

  // ── 5. Telegram ────────────────────────────────────────────────────────
  console.log(step('5', 'Telegram Benachrichtigung (optional)'));

  const enableTelegram = await askYN('Telegram Benachrichtigung aktivieren?', 'n');
  cfg.ENABLE_TELEGRAM_NOTIFIER = enableTelegram ? 'true' : 'false';
  if (enableTelegram) {
    console.log(info('Bot erstellen: @BotFather → /newbot → Token kopieren'));
    cfg.TELEGRAM_BOT_TOKEN = await ask('Bot-Token');
    console.log(info('Chat-ID: @userinfobot anschreiben oder Bot-Nachricht senden und /getUpdates aufrufen'));
    cfg.TELEGRAM_CHAT_ID   = await ask('Chat-ID');
  } else {
    cfg.TELEGRAM_BOT_TOKEN = cfg.TELEGRAM_CHAT_ID = '';
  }

  // ── 6. KI-Review ──────────────────────────────────────────────────────
  console.log(step('6', 'KI-Review via OpenAI (optional)'));

  const enableAi = await askYN('KI-Review aktivieren?', 'n');
  cfg.ENABLE_AI_REVIEW = enableAi ? 'true' : 'false';
  if (enableAi) {
    cfg.OPENAI_API_KEY            = await ask('OpenAI API-Key');
    cfg.OPENAI_MODEL              = await ask('OpenAI Modell', 'gpt-4o-mini');
    cfg.OPENAI_TIMEOUT_MS         = await ask('Timeout in ms', '30000');
    cfg.AI_REVIEW_MIN_RISK        = await ask('Mindest-Risiko für KI-Analyse', 'medium');
    cfg.AI_NOTIFY_MIN_RISK        = await ask('Mindest-Risiko für KI-Benachrichtigung', 'high');
    cfg.AI_NOTIFY_COOLDOWN_MINUTES= await ask('Cooldown zwischen Benachrichtigungen (Min.)', '360');
  } else {
    cfg.OPENAI_API_KEY = '';
    cfg.OPENAI_MODEL              = 'gpt-4o-mini';
    cfg.OPENAI_TIMEOUT_MS         = '30000';
    cfg.AI_REVIEW_MIN_RISK        = 'medium';
    cfg.AI_NOTIFY_MIN_RISK        = 'high';
    cfg.AI_NOTIFY_COOLDOWN_MINUTES= '360';
  }

  // ── Zusammenfassung & Schreiben ────────────────────────────────────────
  console.log(step('7', 'Zusammenfassung'));

  console.log(`
  ${c.bold}Server:${c.reset}    ${cfg.SERVER_NAME}
  ${c.bold}Vhosts:${c.reset}    ${cfg.VHOSTS_PATH}
  ${c.bold}Mail-Log:${c.reset}  ${cfg.MAIL_LOG_PATH}
  ${c.bold}DB:${c.reset}        ${cfg.DB_USER}@${cfg.DB_HOST}:${cfg.DB_PORT}/${cfg.DB_NAME}
  ${c.bold}Dashboard:${c.reset} http://${cfg.WEB_HOST}:${cfg.WEB_PORT}  (${cfg.WEB_USER})
  ${c.bold}E-Mail:${c.reset}    ${cfg.ENABLE_EMAIL_NOTIFIER === 'true' ? `${c.green}aktiv${c.reset} → ${cfg.ALERT_EMAIL_TO}` : `${c.dim}deaktiviert${c.reset}`}
  ${c.bold}Telegram:${c.reset}  ${cfg.ENABLE_TELEGRAM_NOTIFIER === 'true' ? `${c.green}aktiv${c.reset}` : `${c.dim}deaktiviert${c.reset}`}
  ${c.bold}KI-Review:${c.reset} ${cfg.ENABLE_AI_REVIEW === 'true' ? `${c.green}aktiv${c.reset} (${cfg.OPENAI_MODEL})` : `${c.dim}deaktiviert${c.reset}`}
`);

  const confirm = await askYN('Konfiguration so speichern?', 'y');
  if (!confirm) { console.log(info('Abgebrochen — nichts gespeichert.')); rl.close(); return; }

  fs.writeFileSync(envPath, buildEnv(cfg), 'utf8');
  console.log(ok(`.env geschrieben: ${envPath}`));

  // ── Datenbank-Tabellen anlegen ─────────────────────────────────────────
  if (dbOk) {
    process.stdout.write(`\n  ${label('…')} Datenbank-Tabellen anlegen …`);
    try {
      // setup-db.js reads .env via dotenv — set env vars directly instead
      process.env.DB_HOST = cfg.DB_HOST;
      process.env.DB_PORT = cfg.DB_PORT;
      process.env.DB_USER = cfg.DB_USER;
      process.env.DB_PASS = cfg.DB_PASS;
      process.env.DB_NAME = cfg.DB_NAME;
      const mysql = require('mysql2/promise');
      const conn = await mysql.createConnection({
        host: cfg.DB_HOST, port: parseInt(cfg.DB_PORT, 10),
        user: cfg.DB_USER, password: cfg.DB_PASS,
        database: cfg.DB_NAME, connectTimeout: 5000,
      });
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
      await conn.end();
      process.stdout.write(`  ${c.green}OK${c.reset}\n`);
      console.log(ok('Tabelle "reports" bereit'));
    } catch (e) {
      process.stdout.write(`  ${c.yellow}Übersprungen${c.reset}\n`);
      console.log(warn(`DB-Setup fehlgeschlagen: ${e.message}`));
      console.log(info('Manuell ausführen: npm run setup-db'));
    }
  }

  // ── Cron-Job ──────────────────────────────────────────────────────────
  console.log(step('✓', 'Fertig!'));

  const installDir = __dirname;
  const cronCmd = `*/${cfg.CHECK_INTERVAL_MINUTES} * * * * cd ${installDir} && node monitor.js >> /var/log/server-watchdog.log 2>&1`;
  const webCmd  = `node ${path.join(installDir, 'web/server.js')}`;
  const pm2Cmd  = `pm2 start ${path.join(installDir, 'web/server.js')} --name server-watchdog-web`;

  console.log(`
${c.green}${c.bold}Installation abgeschlossen!${c.reset}

  ${c.bold}Nächste Schritte:${c.reset}

  ${c.dim}1)${c.reset} Cron-Job einrichten (als root):
     ${c.yellow}crontab -e${c.reset}
     Zeile einfügen:
     ${c.dim}${cronCmd}${c.reset}

  ${c.dim}2)${c.reset} Web-Dashboard starten:
     ${c.yellow}${webCmd}${c.reset}
     ${c.dim}oder dauerhaft mit PM2:${c.reset}
     ${c.yellow}${pm2Cmd}${c.reset}

  ${c.dim}3)${c.reset} Ersten Testlauf starten:
     ${c.yellow}cd ${installDir} && node monitor.js${c.reset}

  ${c.dim}4)${c.reset} Dashboard öffnen:
     ${c.yellow}http://${cfg.WEB_HOST === '127.0.0.1' ? 'localhost' : cfg.WEB_HOST}:${cfg.WEB_PORT}${c.reset}
     Benutzer: ${c.bold}${cfg.WEB_USER}${c.reset}
     Passwort: ${c.bold}${cfg.WEB_PASS}${c.reset}
`);

  rl.close();
}

main().catch((e) => {
  console.error(err(`Unerwarteter Fehler: ${e.message}`));
  rl.close();
  process.exit(1);
});

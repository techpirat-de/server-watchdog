# server-watchdog

Automatisiertes Monitoring-Tool für Debian/Plesk-Server.  
Überwacht Mail-Queue, Mail-Logs, verdächtige PHP-Dateien und Serverlast — optional mit KI-Auswertung und Benachrichtigung via E-Mail oder Telegram.

---

## Zweck

- Frühzeitig erkennen, ob eine Webseite kompromittiert wurde oder Spam verschickt
- Mail-Queue und Mail-Log automatisch auswerten
- Verdächtige PHP-Dateien (Webshells, injected Code) aufspüren
- Serverlast im Blick behalten
- Berichte als JSON und Textdatei speichern
- Bei Auffälligkeiten automatisch benachrichtigen

---

## Voraussetzungen

- Node.js >= 18
- `postqueue` oder `mailq` muss auf dem Server verfügbar sein
- Lesezugriff auf `/var/log/mail.log` und `/var/www/vhosts/`
- Empfohlen: als `root` oder mit entsprechenden Berechtigungen laufen lassen

---

## Installation

```bash
cd /opt
git clone https://github.com/DEIN-REPO/server-watchdog.git
cd server-watchdog
npm install
cp .env.example .env
nano .env
```

---

## .env Einrichtung

```env
SERVER_NAME=mein-server.example.com

# Schwellenwerte Mail-Queue
MAIL_QUEUE_WARNING_THRESHOLD=20
MAIL_QUEUE_CRITICAL_THRESHOLD=100

# Log-Auswertung: letzten X Minuten analysieren (sollte = Cronjob-Interval sein)
CHECK_INTERVAL_MINUTES=60

# Pfade (Plesk-Standard)
MAIL_LOG_PATH=/var/log/mail.log
VHOSTS_PATH=/var/www/vhosts

# PHP-Datei-Scan: Dateien der letzten X Stunden
RECENT_FILE_HOURS=24

# KI-Review (nur bei MEDIUM oder höher)
ENABLE_AI_REVIEW=false
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o

# E-Mail Benachrichtigung
ENABLE_EMAIL_NOTIFIER=false
SMTP_HOST=mail.example.com
SMTP_PORT=587
SMTP_USER=watchdog@example.com
SMTP_PASS=geheimes-passwort
ALERT_EMAIL_TO=admin@example.com
ALERT_EMAIL_FROM=watchdog@example.com

# Telegram Benachrichtigung
ENABLE_TELEGRAM_NOTIFIER=false
TELEGRAM_BOT_TOKEN=1234567890:ABC...
TELEGRAM_CHAT_ID=-100123456789

# Immer benachrichtigen, auch bei LOW
ALWAYS_SEND_REPORT=false
```

---

## Cronjob Einrichtung

Stündlich prüfen:

```cron
0 * * * * cd /opt/server-watchdog && /usr/bin/node monitor.js >> /opt/server-watchdog/logs/watchdog.log 2>&1
```

Oder alle 30 Minuten (dann auch `CHECK_INTERVAL_MINUTES=30` setzen):

```cron
*/30 * * * * cd /opt/server-watchdog && /usr/bin/node monitor.js >> /opt/server-watchdog/logs/watchdog.log 2>&1
```

Sicherstellen, dass `logs/` existiert:

```bash
mkdir -p /opt/server-watchdog/logs /opt/server-watchdog/reports
```

---

## Sicherheitswarnung

- Die `.env`-Datei enthält Passwörter und API-Keys. **Nie ins Repository committen.**
- Der Watchdog nimmt **keine automatischen Lösch- oder Reparaturaktionen** vor — nur lesen, analysieren, melden.
- Reports werden ohne Passwörter und API-Keys gespeichert.
- Stelle sicher, dass `reports/` und `logs/` nicht öffentlich über HTTP erreichbar sind.

---

## Risiko-Level

| Level    | Bedeutung                                                               |
|----------|-------------------------------------------------------------------------|
| LOW      | Kleine Auffälligkeiten, kein Handlungsbedarf                            |
| MEDIUM   | Mehrere Warnungen — beobachten, prüfen                                  |
| HIGH     | Mailqueue wächst, Bounces, verdächtige PHP-Dateien — zeitnah eingreifen |
| CRITICAL | Sehr große Queue, neue PHP in Uploads, Reputation-Fehler — sofort handeln |

---

## Beispielausgabe (Konsole)

```
[monitor] ===== Server Watchdog starting at 2024-05-13T10:00:00.000Z =====
[monitor] Host: mein-server.example.com
[monitor] Running check: mailQueue
[monitor] Running check: mailLog
[monitor] Running check: suspiciousFiles
[monitor] Running check: serverLoad

[monitor] ===== RESULTS =====
[monitor] Overall Risk: HIGH
  ⚠ mailQueue: warning (risk: high) — 1 finding(s)
      → Mail queue elevated: 45 messages
  ✓ mailLog: ok (risk: low) — 0 finding(s)
  ✗ suspiciousFiles: error (risk: critical) — 2 finding(s)
      → suspicious_file: /var/www/vhosts/.../uploads/shell.php
  ✓ serverLoad: ok (risk: low) — 0 finding(s)

[monitor] Report saved: reports/report-2024-05-13-10-00.json
[monitor] Sending notifications...
[monitor] ===== Done in 4.3s =====
```

---

## Hinweise für Plesk/Debian

- Plesk speichert Webspaces unter `/var/www/vhosts/<domain>/httpdocs/`
- Postfix ist Standard-MTA — `postqueue -p` funktioniert auf Plesk-Servern
- Mail-Log liegt meist unter `/var/log/mail.log` (Debian) oder `/var/log/maillog` (CentOS)
- Bei Berechtigungsproblemen: Watchdog als `root` via Cronjob laufen lassen
- Für Plesk-Deployments: Repository in Plesk-Git-Deployment einbinden, Post-Deploy-Hook `npm install` ausführen lassen

---

## Projektstruktur

```
server-watchdog/
├── monitor.js              # Haupt-Einstiegspunkt
├── package.json
├── .env.example
├── .gitignore
├── README.md
├── checks/
│   ├── mailQueue.js        # Mail-Queue-Analyse
│   ├── mailLog.js          # Mail-Log-Auswertung
│   ├── suspiciousFiles.js  # PHP-Datei-Scanner
│   ├── serverLoad.js       # CPU/RAM/Disk/Prozesse
│   └── aiReview.js         # Optionale KI-Auswertung
├── notifiers/
│   ├── emailNotifier.js    # SMTP-Benachrichtigung
│   └── telegramNotifier.js # Telegram-Benachrichtigung
├── reports/                # JSON- und Textberichte (gitignored)
└── logs/                   # Cronjob-Logs (gitignored)
```

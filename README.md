# Plesk Server Watchdog

Automatisiertes Monitoring-Tool für Debian-/Plesk-Server.
Es überwacht Mail-Queue, Mail-Logs, verdächtige PHP-Dateien und Serverlast, speichert Reports in MySQL und kann optional per KI bewerten, ob echte Maßnahmen nötig sind.

---

## Zweck

- Frühzeitig erkennen, ob eine Webseite kompromittiert wurde oder Spam verschickt
- Mail-Queue und Mail-Log automatisch auswerten
- Verdächtige PHP-Dateien mit Risiko-Score, Hash, Änderungsdatum und WordPress-/Plugin-Kontext aufspüren
- Serverlast im Blick behalten
- Berichte zentral in MySQL speichern
- Bei echten Problemen per E-Mail oder Telegram benachrichtigen
- Wiederholte Benachrichtigungen per Cooldown unterdrücken

---

## Voraussetzungen

- Node.js >= 18
- MySQL oder MariaDB
- `postqueue` oder `mailq` muss auf dem Server verfügbar sein
- Lesezugriff auf `/var/log/mail.log` und `/var/www/vhosts/`
- Empfohlen: als `root` oder mit entsprechenden Berechtigungen laufen lassen

---

## Installation

```bash
cd /opt
git clone https://github.com/techpirat-de/plesk-server-watchdog.git
cd plesk-server-watchdog
npm install
cp .env.example .env
nano .env
```

Falls das Repository noch unter dem alten Namen geklont wird:

```bash
git clone https://github.com/techpirat-de/server-watchdog.git plesk-server-watchdog
cd plesk-server-watchdog
```

---

## Datenbank vorbereiten

Lege eine Datenbank und einen Benutzer an, zum Beispiel:

```sql
CREATE DATABASE server_watchdog CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'server_watchdog'@'localhost' IDENTIFIED BY 'BITTE_SICHERES_PASSWORT_SETZEN';
GRANT ALL PRIVILEGES ON server_watchdog.* TO 'server_watchdog'@'localhost';
FLUSH PRIVILEGES;
```

Trage die Zugangsdaten anschließend in `.env` ein und erstelle die Tabelle:

```bash
npm run setup-db
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
# Komma-getrennte zusätzliche Pfad-Fragmente, die ignoriert werden sollen
# Standardmäßig bereits ignoriert: /wp-content/wflogs/, /wp-content/uploads/cache/
SUSPICIOUS_FILES_EXCLUDE=

# MySQL Datenbank
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=server_watchdog
DB_PASS=BITTE_SICHERES_PASSWORT_SETZEN
DB_NAME=server_watchdog

# Web-Dashboard
WEB_PORT=3000
WEB_HOST=127.0.0.1
WEB_USER=admin
WEB_PASS=BITTE_SICHERES_PASSWORT_SETZEN

# KI-Review (nur bei MEDIUM oder höher)
ENABLE_AI_REVIEW=false
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
OPENAI_TIMEOUT_MS=30000
AI_REVIEW_MIN_RISK=medium
AI_NOTIFY_MIN_RISK=high
AI_NOTIFY_COOLDOWN_MINUTES=360

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
```

---

## Erster Testlauf

```bash
npm start
```

Der Lauf sollte am Ende ungefähr melden:

```text
[monitor] Report saved to MySQL (id=...)
```

Wenn Checks wegen Berechtigungen fehlschlagen, starte den Watchdog auf dem Server als `root` oder gib passende Leserechte auf Mail-Logs, Plesk-Webspaces und Postfix-Queue.

---

## KI-Review testen

KI-Review ist optional. Aktiviere ihn in `.env`:

```env
ENABLE_AI_REVIEW=true
OPENAI_API_KEY=sk-...
```

Dann:

```bash
npm run ai-review
```

Die KI analysiert die Reports der letzten Stunde. Benachrichtigungen werden nur gesendet, wenn:

- die KI `notify=true` setzt
- das KI-Risiko mindestens `AI_NOTIFY_MIN_RISK` erreicht
- innerhalb von `AI_NOTIFY_COOLDOWN_MINUTES` noch keine Meldung gesendet wurde

---

## Cronjob Einrichtung

Stündlich prüfen:

```cron
0 * * * * cd /opt/plesk-server-watchdog && /usr/bin/node monitor.js >> /opt/plesk-server-watchdog/logs/watchdog.log 2>&1
```

Oder alle 30 Minuten (dann auch `CHECK_INTERVAL_MINUTES=30` setzen):

```cron
*/30 * * * * cd /opt/plesk-server-watchdog && /usr/bin/node monitor.js >> /opt/plesk-server-watchdog/logs/watchdog.log 2>&1
```

KI-Review nach jedem Monitor-Lauf, zum Beispiel fünf Minuten später:

```cron
5 * * * * cd /opt/plesk-server-watchdog && /usr/bin/node ai-review.js >> /opt/plesk-server-watchdog/logs/ai-review.log 2>&1
```

Sicherstellen, dass `logs/` existiert:

```bash
mkdir -p /opt/plesk-server-watchdog/logs
```

---

## Web-Dashboard

Das Dashboard ist per Basic Auth geschützt. Setze in `.env`:

```env
WEB_USER=admin
WEB_PASS=BITTE_SICHERES_PASSWORT_SETZEN
WEB_HOST=127.0.0.1
WEB_PORT=3000
```

Start:

```bash
npm run web
```

Danach ist das Dashboard lokal erreichbar:

```text
http://127.0.0.1:3000
```

Für öffentlichen Zugriff sollte ein Reverse Proxy mit HTTPS und zusätzlicher Zugriffsbeschränkung genutzt werden. Das Dashboard sollte nicht ungeschützt ins Internet gestellt werden.

---

## Suspicious-Files-Heuristik

Der PHP-Datei-Scanner ist eine Heuristik und kein Malware-Beweis. Einzelne Funktionen wie `system()`, `exec()` oder `shell_exec()` sind nicht automatisch kritisch, weil sie in Backup-, Cache-, Security-, Image- oder Cron-Plugins legitim vorkommen können.

Der Scanner bewertet deshalb mehrere Faktoren gemeinsam:

- exakter Dateipfad
- SHA-256-Hash
- Änderungsdatum und Alter der Datei
- Dateigröße
- WordPress-Kontext: Core, Plugin, Theme, Upload, Cache, Temp
- Plugin-/Theme-Slug, falls aus dem Pfad ableitbar
- Risiko-Score pro Datei
- konkrete Gründe, zum Beispiel Webshell-Muster, Obfuskation oder Remote-Download
- Dateialter: ältere unveränderte Plugin-/Theme-Dateien werden weniger aggressiv bewertet

Standardmäßig werden sehr laute WordPress-Pfade niedriger priorisiert oder ignoriert:

- `/wp-content/wflogs/` wird ignoriert
- `/wp-content/uploads/cache/` wird ignoriert
- Cache-Pfade wie `wp-content/cache` werden ohne zusätzliche Malware-Indikatoren niedrig bewertet

Richtwerte:

| Risiko   | Beispiele |
|----------|-----------|
| LOW      | Remote URL, lange Codezeile, Callback/variable Funktion oder einzelne Command-Funktion in bekanntem Plugin-/Theme-Kontext |
| MEDIUM   | Unbekannte PHP-Datei mit Command-Funktion, Datei in Cache/Temp, mehrere schwache Signale kombiniert |
| HIGH     | Obfuskation, `php://input`, Remote Download mit Ausführungshinweis, PHP-Dateien außerhalb erwarteter Plugin-Struktur |
| CRITICAL | PHP in Upload/Media, Webshell-Muster, `eval(base64_decode())`, POST/GET-basierte Command Execution, Crypto-Miner-Hinweise |

Bekannte Plugin-/Theme-/Language-Dateien werden ohne starke Malware-Signale maximal als `HIGH` bewertet. Einzelne Command-Funktionen wie `system()` oder `exec()` in bekanntem Plugin-Kontext reichen alleine nicht für `CRITICAL`.

Wichtig: Ein Fund bedeutet zunächst „prüfen“, nicht automatisch „löschen“. Vor Löschungen immer Backup, Hash, Pfad und Plugin-Zuordnung prüfen.

---

## Sicherheitswarnung

- Die `.env`-Datei enthält Passwörter und API-Keys. **Nie ins Repository committen.**
- Der Watchdog nimmt **keine automatischen Lösch- oder Reparaturaktionen** vor — nur lesen, analysieren, melden.
- Reports werden ohne Passwörter und API-Keys gespeichert.
- Stelle sicher, dass `.env`, Logs und das Dashboard nicht öffentlich ungeschützt erreichbar sind.

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
[monitor] ===== Plesk Server Watchdog starting at 2024-05-13T10:00:00.000Z =====
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

[monitor] Report saved to MySQL (id=123)
[monitor] Done in 4.3s — notifications handled by ai-review.js
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
plesk-server-watchdog/
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
└── logs/                   # Cronjob-Logs (gitignored)
```

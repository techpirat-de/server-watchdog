# Plesk Server Watchdog

Automatisiertes Monitoring-Tool für Debian-/Plesk-Server.
Es überwacht Mail-Queue, Mail-Logs, verdächtige PHP-Dateien, Serverlast, WordPress-Installationen und frei konfigurierbare URLs, speichert Reports in MySQL und kann optional per KI bewerten, ob echte Maßnahmen nötig sind.

---

## Zweck

- Frühzeitig erkennen, ob eine Webseite kompromittiert wurde oder Spam verschickt
- Mail-Queue und Mail-Log automatisch auswerten
- Verdächtige PHP-Dateien mit Risiko-Score, Hash, Änderungsdatum und WordPress-/Plugin-Kontext aufspüren
- Alle WordPress-Installationen auf Sicherheits-Plugins, Risiko-Plugins, xmlrpc.php und PHP in Upload-Ordnern prüfen
- Kritische Webseiten per HTTP-Check auf 500er, Timeouts und DNS-/TLS-Probleme prüfen
- Incident Mode für read-only Forensik nach vermutetem Einbruch automatisch aktivieren
- Serverlast im Blick behalten
- Berichte zentral in MySQL speichern
- Bei echten Problemen per E-Mail oder Telegram benachrichtigen (mit Trend-Analyse)
- Wiederholte Benachrichtigungen per Cooldown unterdrücken

---

## Voraussetzungen

- Node.js >= 18
- MySQL oder MariaDB
- `postqueue` oder `mailq` muss auf dem Server verfügbar sein
- Lesezugriff auf `/var/log/maillog` (oder `/var/log/mail.log`) und `/var/www/vhosts/`
- `curl` muss installiert sein (für den xmlrpc.php-Probe im WordPress-Check)
- Empfohlen: als `root` oder mit entsprechenden Berechtigungen laufen lassen

---

## Installation

```bash
cd /opt
git clone https://github.com/techpirat-de/server-watchdog.git plesk-server-watchdog
cd plesk-server-watchdog
npm install
npm run setup
```

`npm run setup` startet den interaktiven Installations-Wizard. Er erkennt Pfade automatisch, testet die Datenbankverbindung, legt Tabellen an und zeigt am Ende den fertigen Cron-Befehl.

### Manuelle Installation (alternativ)

```bash
cp .env.example .env
nano .env
npm run setup-db
```

Bei bestehender Installation:

```sql
ALTER TABLE reports ADD COLUMN IF NOT EXISTS notifications_sent JSON DEFAULT NULL;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS incident JSON DEFAULT NULL;
```

Danach einmal ausführen, damit die URL-Monitoring-Tabelle angelegt wird:

```bash
npm run setup-db
```

---

## .env Einrichtung

```env
SERVER_NAME=mein-server.example.com

# Log-Auswertung: letzten X Minuten analysieren (sollte = Cronjob-Interval sein)
CHECK_INTERVAL_MINUTES=60

# Pfade (Plesk-Standard)
MAIL_LOG_PATH=/var/log/maillog
VHOSTS_PATH=/var/www/vhosts

# PHP-Datei-Scan: Dateien der letzten X Stunden
RECENT_FILE_HOURS=24
# Komma-getrennte zusätzliche Pfad-Fragmente, die ignoriert werden sollen
# Standardmäßig bereits ignoriert: /wp-content/wflogs/, /wp-content/uploads/cache/
SUSPICIOUS_FILES_EXCLUDE=
# Zusätzliche Quarantäne-Pfade, die nie als aktive Malware gemeldet werden
SUSPICIOUS_FILES_QUARANTINE_EXCLUDE=

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

# Incident Mode (read-only)
ENABLE_INCIDENT_MODE=true
INCIDENT_OUTPUT_DIR=/root/watchdog-incidents
INCIDENT_MAX_COPY_FILES=250

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

## URL-Erreichbarkeitscheck

Der `urlHealth`-Check prüft URLs, die im Dashboard unter „URL-Monitoring" eingetragen wurden.

Bewertung:

| Befund | Risiko |
|--------|--------|
| HTTP 2xx/3xx im erwarteten Bereich | LOW |
| HTTP 4xx | MEDIUM |
| HTTP 5xx | HIGH |
| Timeout, DNS-Fehler, TLS-Fehler, Verbindungsfehler | HIGH |

Standardmäßig gelten HTTP `200-399` als erreichbar. Pro URL kann ein Timeout gesetzt werden. Ein HTTP 500 auf einer überwachten Webseite landet damit direkt im Report und kann über KI-Review, E-Mail und Telegram eskalieren.

---

## Incident Mode

Der Incident Mode startet automatisch, wenn harte Sicherheitsindikatoren erkannt werden, z.B. WordPress-Core-Checksum-Fehler, PHP/PHTML-Dateien in Upload-Verzeichnissen, HIGH/CRITICAL-Funde im Suspicious-Files-Scanner, `eval(base64_decode())`, `gzinflate`, `compress.zlib://`, `php://input`, Include auf Uploads, identische SHA-256-Funde oder Änderungs-Bursts.

Der Modus ist standardmäßig **read-only**. Er löscht, verschiebt und quarantänisiert keine Originaldateien. Verdächtige Dateien werden nur als Evidence-Kopie gesichert.

Evidence-Ordner:

```text
/root/watchdog-incidents/YYYY-MM-DD_HHMMSS/
```

Erzeugte Artefakte:

- `incident-summary.txt` — deutschsprachige Zusammenfassung
- `incident-report.html` — HTML-Bericht
- `incident.json` — vollständiger strukturierter Incident-Bericht
- `scan-report.json` — Original-Watchdog-Report
- `ioc-list.json` — IOC-Gruppen: SHA-256, Dateigröße, Code-Hash, Klassen, Variablen, Base64-Blöcke
- `file-list.json` — verdächtige Dateien mit SHA-256, Besitzer, Rechten, Größe und Zeitstempeln
- `timeline.json` — Timeline nach Minute, Stunde und Tag
- `persistence.json` — Cron/Systemd/authorized_keys/Shell-Profil-Hinweise
- `quarantine-recommendations.json` — nur Vorschläge, keine automatische Ausführung
- `files/` — read-only Kopien verdächtiger Dateien

Der Abschlussbericht enthält Anzahl verdächtiger Dateien, Webshell-Muster, veränderte Core-Dateien, betroffene Websites, erste/letzte Aktivität, mögliche Eintrittspunkte, Persistenz-Hinweise und Malware-Kampagnen. Eine Kampagne wird erkannt, wenn derselbe Schadcode, SHA-256 oder Code-Hash auf mehreren Websites auftaucht.

---

## WordPress-Check

Der `wordpressCheck` findet automatisch alle WordPress-Installationen unter `VHOSTS_PATH` und bewertet sie nach diesen Kriterien:

| Befund | Risiko |
|--------|--------|
| PHP-Datei in `wp-content/uploads/` | CRITICAL |
| WP File Manager ohne Security-Plugin | CRITICAL |
| WP File Manager mit Security-Plugin | HIGH |
| Anderes Risiko-Plugin (Revolution Slider, Cherry Plugin, WP Symposium) | HIGH |
| Kein Security-Plugin installiert | MEDIUM |
| xmlrpc.php erreichbar (HTTP-Probe) | LOW |
| WP_DEBUG=true | LOW |

**Erkannte Security-Plugins:** Wordfence, Sucuri, iThemes Security, WP Cerber, Shield Security, BulletProof Security, Loginizer, WPS Hide Login

**Erkannte Risiko-Plugins:** WP File Manager, File Manager Advanced, Revolution Slider, Cherry Plugin, WP Symposium

Der Check probiert via HTTP-GET, ob `xmlrpc.php` auf jeder Domain erreichbar ist. Die Domain wird aus `wp-config.php` (`WP_HOME` / `WP_SITEURL`) oder dem Ordnernamen abgeleitet.

Im Dashboard werden alle Installationen als aufklappbare Karten gruppiert — mit Risiko-Badge, Plugin-Status und konkreten Befunden pro Site.

---

## Suspicious-Files-Heuristik

Der PHP-Datei-Scanner ist eine Heuristik und kein Malware-Beweis. Der Scanner bewertet mehrere Faktoren gemeinsam:

- exakter Dateipfad und WordPress-Kontext (Core, Plugin, Theme, Upload, Cache, Temp)
- SHA-256-Hash, Änderungsdatum und Alter der Datei
- Risiko-Score pro Datei (jedes Pattern-Label trägt **maximal einmal** zum Score bei, egal wie oft es in einer Datei vorkommt)
- konkrete Gründe, z.B. Webshell-Muster, Obfuskation, Remote-Download-Kombination

**Whitelists:**

- **Security-Plugins** (Wordfence, Sucuri, iThemes, Shield, BulletProof, Cerber, AIOS): Alle Scores werden auf LOW gekappt. WAF-Code, eval, base64, `php://input` sind dort erwartetes Verhalten. Ausnahmen: POST/GET-Command-Execution und Crypto-Miner.
- **Bekannte große Plugins** (WooCommerce, Elementor, Yoast, Jetpack, Contact Form 7 u.a.): Scores werden auf maximal MEDIUM gekappt, sofern kein echter Red-Flag-Befund vorliegt.
- **Alle Plugin-/Theme-Dateien:** Ohne kritische Signale maximal HIGH. Ältere Dateien (> 30 Tage) werden weiter heruntergestuft.
- **Konfigurierbare Trust-Listen:** `SUSPICIOUS_FILES_TRUSTED_PLUGINS` und `SUSPICIOUS_FILES_TRUSTED_FILES` senken schwache Heuristiken, ignorieren aber keine echten Red Flags wie `eval(base64_decode())`, POST/GET-Command-Execution, Upload-PHP oder Crypto-Miner.
- **WordPress-Core:** Wenn WP-CLI verfügbar ist, werden offizielle Core-Checksummen geprüft. Bestätigte Core-Dateien werden nicht als Malware bewertet; nur veränderte Core-Dateien laufen durch die volle Analyse.
- **Kritische Dateien:** `wp-config.php`, `wp-settings.php`, `wp-load.php`, `xmlrpc.php`, `index.php` und `.htaccess` werden gesondert markiert, sobald dort verdächtige Muster auftauchen.
- **Massenmuster:** Identische SHA-256-Hashes, viele gleich große verdächtige Dateien und viele Änderungen innerhalb weniger Minuten erzeugen aggregierte Befunde statt 200 Einzelmeldungen.
- **Quarantäne-Vorschläge:** Bei HIGH/CRITICAL zeigt der Report vorbereitete `cp`, `chmod 000` und `mv` Befehle. Der Watchdog führt diese Befehle nicht automatisch aus und löscht keine Dateien.

**Ignorierte Pfade (Standard):**
- `/wp-content/wflogs/` (Wordfence-Logs)
- `/wp-content/uploads/cache/`
- `.quarantined`
- `/root/physio-malware-*`
- `/root/server-malware-*`
- `/root/server-watchdog-quarantine/`
- `/root/watchdog-incidents/`

Weitere Ausschlüsse können via `SUSPICIOUS_FILES_EXCLUDE` (kommagetrennte Pfadteile) konfiguriert werden.
Weitere Quarantänepfade können via `SUSPICIOUS_FILES_QUARANTINE_EXCLUDE` ergänzt werden.

Vor jeder Meldung wird geprüft, ob die Datei noch im aktiven Pfad existiert. Alte Findings aus vorherigen Reports werden im AI-Review zu INFO/LOW herabgestuft, wenn die Datei inzwischen entfernt oder in Quarantäne verschoben wurde.

Zusätzliche Abwertung ohne harte Ignorierung:

```env
SUSPICIOUS_FILES_TRUSTED_PLUGINS=duplicator,gallery-plugin
SUSPICIOUS_FILES_TRUSTED_FILES=/var/www/vhosts/example.com/httpdocs/wp-content/plugins/plugin-x/vendor/
```

Richtwerte:

| Risiko | Beispiele |
|--------|-----------|
| LOW | Remote URL, lange Codezeile, Callback in bekanntem Plugin-Kontext |
| MEDIUM | Unbekannte Datei mit Command-Funktion, Datei in Cache/Temp, mehrere schwache Signale |
| HIGH | Obfuskation, `php://input`, Remote-Download mit Ausführungshinweis |
| CRITICAL | PHP in Upload/Media, `eval(base64_decode())`, POST/GET-Command Execution, Crypto-Miner |

Wichtig: Ein Fund bedeutet „prüfen", nicht automatisch „löschen". Vor Löschungen immer Backup, Hash, Pfad und Plugin-Zuordnung prüfen.

---

## Mail-Queue-Bewertung

Die Mail-Queue wird nicht mehr nur nach einer einzelnen Anzahl bewertet. Der Watchdog berücksichtigt:

- aktuelle Queue-Größe
- älteste und jüngste Mail in der Queue
- Trend aus früheren Reports
- Top-Absender
- Top-Empfänger-Domains
- häufigste Zustellfehler
- Reputation-/Block-/Rate-Limit-Fehler

Richtwerte:

| Queue | Bewertung |
|-------|-----------|
| 0-20 | OK |
| 20-50 | Hinweis, normalerweise kein Alarm |
| 50-150 | Warnung |
| >150 | Hoch |
| >500 | Kritisch |

Eine leicht erhöhte Queue führt nur dann zu einer höheren Bewertung, wenn sie wächst oder zusätzliche Fehler wie Bounces, Rate Limits oder Block-Meldungen auftreten.

Microsoft/Outlook-Fehler wie `450 4.7.25 sending IPv6 address must have reverse DNS record` werden separat als Mail-Konfigurationsproblem gemeldet. Das ist kein Malware-Hinweis. Empfohlene Maßnahmen: IPv6-PTR beim Provider setzen oder Postfix so konfigurieren, dass ausgehende Mails bevorzugt über IPv4 gesendet werden.

---

## KI-Review

KI-Review ist optional und analysiert alle Reports der letzten Stunde. Aktiviere ihn in `.env`:

```env
ENABLE_AI_REVIEW=true
OPENAI_API_KEY=sk-...
```

Dann:

```bash
npm run ai-review
```

Für Testläufe erzwingen (analysiert auch bei LOW-Risiko):

```bash
npm run ai-review -- --force
```

Die KI liefert eine deutsche Zusammenfassung mit Risiko-Einschätzung, Trend-Bewertung und konkreten Empfehlungen. Zusätzlich berechnet `ai-review.js` einen **Trend** über die Reports der letzten Stunde:

- Risiko-Veränderung (z.B. CRITICAL → HIGH)
- Anzahl neuer oder weniger auffälliger PHP-Dateien
- WordPress-Installationen ohne Security-Plugin (neu/behoben)
- Mail-Queue-Entwicklung

Benachrichtigungen werden nur gesendet, wenn:

- die KI `notify=true` setzt
- das KI-Risiko mindestens `AI_NOTIFY_MIN_RISK` erreicht
- innerhalb von `AI_NOTIFY_COOLDOWN_MINUTES` noch keine Meldung gesendet wurde (per Kanal getrennt)

---

## Telegram-Benachrichtigungen

Die Telegram-Nachricht ist priorisiert und gefiltert aufgebaut:

1. **Wichtigste Aktion** — PHP in Uploads → Risiko-Plugin → kritische Datei → KI-Empfehlung
2. **Weitere Hinweise** — max. 3 Items; xmlrpc-Befunde werden zu einer Zeile aggregiert; reine Plugin-Boilerplate-Muster (Remote URL, WordPress HTTP API, curl etc.) werden als Hinweis mit Vermerk „vermutlich normaler Plugin-Code" ausgegeben statt als Alarm
3. **Status** — was sauber ist (Mail-Queue leer, Serverlast normal, ...)
4. **Verlauf** — Trend-Zusammenfassung der letzten Stunde mit Pfeil (↘ verbessert / ↗ verschlechtert / → stabil)

Beispiel:

```
🔴 Plesk Server Watchdog - Hoch
Host: mein-server.example.com

Kurzfazit: WP File Manager auf physiotherapie-beispiel.de stellt ein hohes Risiko dar.

Wichtigste Aktion:
wp-file-manager auf physiotherapie-beispiel.de entfernen oder deaktivieren.

Weitere Hinweise:
- physiotherapie-beispiel.de: kein Security-Plugin (Wordfence o.ä.) installiert.
- xmlrpc.php auf 2 WordPress-Installationen vorhanden. Blockierung empfohlen.

Status: Mailqueue leer, Mail-Log sauber, Serverlast normal

Verlauf (12 Läufe, → stabil):
  · Security-Plugin auf 1 Site(s) installiert
```

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

KI-Review nach jedem Monitor-Lauf, fünf Minuten später:

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

**Features:**

- **Auto-Refresh**: Das Dashboard prüft alle 60 Sekunden, ob ein neuer Report vorliegt, und lädt automatisch nach — sichtbar am blinkenden Live-Indikator oben rechts.
- **URL-Monitoring**: URLs direkt im Dashboard eintragen, pausieren oder löschen. Der nächste Watchdog-Lauf prüft Erreichbarkeit und HTTP-Status.
- **Incident Mode**: Wenn ein Incident erkannt wurde, zeigt das Dashboard den Evidence-Ordner und die wichtigsten Kennzahlen.
- **WordPress-Karte**: Alle Installationen werden als aufklappbare Karten angezeigt, mit Risiko-Badge, Security-Plugin-Status und konkreten Befunden (xmlrpc, WP_DEBUG, Risiko-Plugins, PHP in Uploads).
- **KI-Analyse-Button**: Startet `ai-review.js` manuell und zeigt die Script-Ausgabe live im Dashboard. Nützlich für Tests außerhalb des Cronjob-Zyklus.
- **Benachrichtigungs-Button**: Sendet manuell eine Test-Benachrichtigung per E-Mail/Telegram mit dem aktuellen Stand.
- **Report-Historie**: Tabellarische Übersicht der letzten Reports mit Risiko-Badge, Zeitstempel und Detailansicht.

Für öffentlichen Zugriff einen Reverse Proxy mit HTTPS und zusätzlicher Zugriffsbeschränkung nutzen.

---

## Sicherheitswarnung

- Die `.env`-Datei enthält Passwörter und API-Keys. **Nie ins Repository committen.**
- Der Watchdog nimmt **keine automatischen Lösch- oder Reparaturaktionen** vor — nur lesen, analysieren, melden.
- Reports werden ohne Passwörter und API-Keys gespeichert.
- Stelle sicher, dass `.env`, Logs und das Dashboard nicht öffentlich ungeschützt erreichbar sind.

---

## Risiko-Level

| Level | Bedeutung |
|-------|-----------|
| LOW | Kleine Auffälligkeiten, kein Handlungsbedarf |
| MEDIUM | Mehrere Warnungen — beobachten, prüfen |
| HIGH | Mailqueue wächst, Bounces, verdächtige PHP-Dateien, Risiko-Plugin — zeitnah eingreifen |
| CRITICAL | PHP in Uploads, `eval(base64_decode())`, Webshell, WP File Manager ohne Security-Plugin — sofort handeln |

---

## Hinweise für Plesk/Debian

- Plesk speichert Webspaces unter `/var/www/vhosts/<domain>/httpdocs/`
- Postfix ist Standard-MTA — `postqueue -p` funktioniert auf Plesk-Servern
- Mail-Log liegt auf Plesk/Debian unter `/var/log/maillog` (wird automatisch erkannt, Fallback auf `/var/log/mail.log`)
- Bei Berechtigungsproblemen: Watchdog als `root` via Cronjob laufen lassen
- Der WordPress-Check liest `wp-config.php` direkt vom Dateisystem — Root-Zugriff empfohlen
- Für Plesk-Deployments: Repository in Plesk-Git-Deployment einbinden, Post-Deploy-Hook `npm install` ausführen lassen

---

## Projektstruktur

```
plesk-server-watchdog/
├── monitor.js              # Haupt-Einstiegspunkt, startet alle Checks
├── ai-review.js            # KI-Review + Benachrichtigungs-Versand
├── lib/
│   ├── db.js               # MySQL-Zugriff
│   └── incidentMode.js     # Read-only Forensik und Incident-Berichte
├── setup-wizard.js         # Interaktiver Installations-Wizard (npm run setup)
├── setup-db.js             # Legt MySQL-Tabellen an
├── package.json
├── .env.example
├── .gitignore
├── README.md
├── checks/
│   ├── mailQueue.js        # Mail-Queue-Analyse (postqueue/mailq)
│   ├── mailLog.js          # Mail-Log-Auswertung (SMTP-Fehler, Bounces)
│   ├── suspiciousFiles.js  # PHP-Datei-Scanner mit Kontext-Scoring
│   ├── serverLoad.js       # CPU/RAM/Disk/Prozesse
│   ├── wordpressCheck.js   # WordPress-Sicherheitscheck (Plugins, xmlrpc, Uploads)
│   ├── urlHealth.js        # URL-Erreichbarkeit und HTTP-Status
│   └── aiReview.js         # OpenAI-Anbindung für KI-Analyse
├── notifiers/
│   ├── emailNotifier.js    # SMTP-Benachrichtigung
│   └── telegramNotifier.js # Telegram-Benachrichtigung (priorisiert, Trend-Abschnitt)
├── web/
│   ├── server.js           # Express-Server für das Dashboard
│   └── public/
│       ├── index.html      # Dashboard-HTML
│       ├── app.js          # Dashboard-Logik (Auto-Refresh, WordPress-Karte, KI-Button)
│       └── style.css       # Dark-Theme-Styling
└── logs/                   # Cronjob-Logs (gitignored)
```

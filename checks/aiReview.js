'use strict';

const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
const AI_REVIEW_MIN_RISK = 'medium';
const DEFAULT_OPENAI_MODEL = 'gpt-4o-mini';
const OPENAI_RESPONSES_URL = 'https://api.openai.com/v1/responses';

async function check(report, config) {
  const result = {
    name: 'aiReview',
    status: 'skipped',
    risk: 'low',
    findings: [],
    metrics: {},
    response: null,
  };

  if (!config.ENABLE_AI_REVIEW || config.ENABLE_AI_REVIEW === 'false') {
    result.findings.push({ type: 'disabled', message: 'AI review disabled via ENABLE_AI_REVIEW' });
    return result;
  }

  const minRisk = normalizeRisk(config.AI_REVIEW_MIN_RISK || AI_REVIEW_MIN_RISK);
  const overallRisk = normalizeRisk(report.overallRisk);

  if (RISK_RANK[overallRisk] < RISK_RANK[minRisk]) {
    result.findings.push({ type: 'skipped', message: `Risk level ${overallRisk} is below threshold for AI review` });
    return result;
  }

  if (!config.OPENAI_API_KEY) {
    result.status = 'error';
    result.findings.push({ type: 'config_error', message: 'OPENAI_API_KEY not set' });
    return result;
  }

  try {
    const fetch = await getFetch();

    const prompt = buildPrompt(report);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Number(config.OPENAI_TIMEOUT_MS || 30000));

    let response;
    try {
      response = await fetch(OPENAI_RESPONSES_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${config.OPENAI_API_KEY}`,
        },
        body: JSON.stringify({
          model: config.OPENAI_MODEL || DEFAULT_OPENAI_MODEL,
          temperature: 0.1,
          max_output_tokens: 900,
          input: [
            {
              role: 'system',
              content: [
                {
                  type: 'input_text',
                  text: 'Du bist ein Server-Sicherheitsanalyst für einen Debian/Plesk/Postfix-Server. Antworte ausschließlich mit validem JSON passend zum Schema. Kein Markdown, kein Text außerhalb des JSON. Alle frei formulierten Textwerte müssen auf Deutsch sein.',
                },
              ],
            },
            {
              role: 'user',
              content: [
                {
                  type: 'input_text',
                  text: prompt,
                },
              ],
            },
          ],
        }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const raw = extractResponseText(data);
    if (!raw) throw new Error('Empty response from OpenAI');

    const parsed = parseJsonResponse(raw);
    validateAiResponse(parsed);

    result.status = 'ok';
    result.risk = normalizeRisk(parsed.risk || overallRisk);
    result.response = parsed;
    result.findings.push({ type: 'ai_assessment', message: parsed.summary || 'AI assessment completed' });

  } catch (err) {
    result.status = 'error';
    result.findings.push({ type: 'ai_error', message: `AI review failed: ${err.message}` });
  }

  return result;
}

function buildPrompt(report) {
  const safe = sanitizeReport(report);

  return `Analysiere diesen Server-Monitoring-Report und antworte ausschliesslich mit JSON.

Wichtige Bewertungsregeln:
- Unterscheide NEUE ausgehende Nachrichten von Wiederholversuchen/deferred retries. Hohe Retry-Zahlen allein sind kein Beweis für einen aktiven Spam-Ausbruch.
- Neue Queue-IDs, schnelles Queue-Wachstum, viele erfolgreiche ausgehende Zustellungen oder ein steigender Queue-Trend sind stärkere Hinweise als alte Wiederholversuche.
- Lokale PHP-Prozesse aus /tmp, /var/tmp oder /dev/shm sind kritisch, ausser sie sind eindeutig harmlos.
- PHP/PHTML-Dateien in uploads, cache, tmp, image oder media sind hohes Risiko.
- Zufallsähnliche PHP-Dateinamen in Webroots sind hohes Risiko, besonders wenn sie groß, obfuskiert oder kürzlich geändert sind.
- Unbekannte Shell-User, unerwartete Cronjobs und Cronjobs auf gelöschte Projekte sind mittleres bis hohes Risiko.
- SMTP-Auth-Fehler für nicht existierende User sind normales Internet-Grundrauschen, außer es gibt erfolgreiche Logins oder sehr hohe Raten.
- Meldungen wie "delivery temporarily suspended", "user over quota" und "mailbox temporarily disabled" sind niedriger zu bewerten, wenn sie alte Queue-Retries betreffen.
- Bevorzuge LOW, wenn Queue leer ist, keine verdächtigen Prozesse existieren und Datei-Scans sauber sind.
- Gib klare Handlungsempfehlungen für Administratoren. Empfiehl manuelle Prüfung vor destruktiven Aktionen. Keine blinde Löschung ohne Backup empfehlen, außer der Report identifiziert bestätigte Malware.
- WordPress ohne Security-Plugin ist LOW bis MEDIUM je nach Kontext — es ist kein Notfall, aber eine klare Handlungsempfehlung wert.
- PHP-Dateien im WordPress-Upload-Verzeichnis sind CRITICAL — sofortige manuelle Prüfung notwendig.
- Risiko-Plugins (WP File Manager etc.) sind HIGH, wenn kein Security-Plugin vorhanden ist.
- WP_DEBUG=true und xmlrpc.php sind einzeln LOW, in Kombination mit anderen Problemen MEDIUM.

Report:
${safe}

Pflichtschema für die JSON-Antwort. Alle Textwerte auf Deutsch:
{
  "risk": "low|medium|high|critical",
  "summary": "Ein kurzer deutscher Satz zur Gesamtsituation",
  "likely_cause": "Wahrscheinlichste Ursache auf Deutsch, oder 'Keine Auffälligkeiten festgestellt'",
  "trend": "improving|stable|worsening|unknown",
  "confidence": 0.0,
  "recommended_actions": ["Konkrete Handlungsempfehlung 1", "Konkrete Handlungsempfehlung 2"],
  "notify": true,
  "urgency": "normal|urgent"
}`;
}

function sanitizeReport(report) {
  return JSON.stringify(report, null, 2)
    .replace(/(api[_-]?key|password|passwd|token|secret|authorization|smtp_pass|openai_api_key)["'\s:=]+[^,"'\s}]+/gi, '$1: [REDACTED]')
    .replace(/Bearer\s+[A-Za-z0-9._\-]+/gi, 'Bearer [REDACTED]');
}

async function getFetch() {
  if (typeof fetch === 'function') return fetch;
  return (await import('node-fetch')).default;
}

function extractResponseText(data) {
  if (typeof data.output_text === 'string' && data.output_text.trim()) {
    return data.output_text.trim();
  }

  const output = data.output || [];
  for (const item of output) {
    const content = item.content || [];
    for (const part of content) {
      if (part.type === 'output_text' && typeof part.text === 'string') {
        return part.text.trim();
      }
      if (typeof part.text === 'string') {
        return part.text.trim();
      }
    }
  }

  return '';
}

function parseJsonResponse(raw) {
  const trimmed = raw.trim();
  try {
    return JSON.parse(trimmed);
  } catch (_) {
    const match = trimmed.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('AI response did not contain JSON');
    return JSON.parse(match[0]);
  }
}

function validateAiResponse(parsed) {
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('AI response is not an object');
  }

  parsed.risk = normalizeRisk(parsed.risk);
  parsed.urgency = ['normal', 'urgent'].includes(parsed.urgency) ? parsed.urgency : 'normal';
  parsed.trend = ['improving', 'stable', 'worsening', 'unknown'].includes(parsed.trend) ? parsed.trend : 'unknown';
  parsed.confidence = Number.isFinite(Number(parsed.confidence)) ? Math.max(0, Math.min(1, Number(parsed.confidence))) : 0.5;
  parsed.notify = Boolean(parsed.notify);
  parsed.recommended_actions = Array.isArray(parsed.recommended_actions) ? parsed.recommended_actions.slice(0, 8) : [];

  if (!parsed.summary || typeof parsed.summary !== 'string') {
    parsed.summary = 'AI assessment completed.';
  }

  if (!parsed.likely_cause || typeof parsed.likely_cause !== 'string') {
    parsed.likely_cause = 'Unknown';
  }
}

function normalizeRisk(risk) {
  const value = String(risk || 'low').toLowerCase();
  return Object.prototype.hasOwnProperty.call(RISK_RANK, value) ? value : 'low';
}

module.exports = { check };

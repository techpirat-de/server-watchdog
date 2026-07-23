'use strict';

// ── Auto-refresh ──────────────────────────────────────────────────────────────

let _lastTimestamp = null;
let _autoRefreshTimer = null;

function startAutoRefresh(intervalMs = 60_000) {
  if (_autoRefreshTimer) return;
  _autoRefreshTimer = setInterval(async () => {
    try {
      const latest = await api('/latest').catch(() => null);
      if (!latest) return;
      if (_lastTimestamp && latest.timestamp !== _lastTimestamp) {
        _lastTimestamp = latest.timestamp;
        loadDashboard();
        loadHistory();
        loadCronStatus();
        showAutoRefreshPing();
      } else {
        _lastTimestamp = latest.timestamp;
      }
    } catch (_) {}
  }, intervalMs);
}

function showAutoRefreshPing() {
  const el = document.getElementById('auto-refresh-dot');
  if (!el) return;
  el.classList.add('ping');
  setTimeout(() => el.classList.remove('ping'), 1200);
}

const RISK_BADGE = {
  low:      '<span class="badge badge-low">LOW</span>',
  medium:   '<span class="badge badge-medium">MEDIUM</span>',
  high:     '<span class="badge badge-high">HIGH</span>',
  critical: '<span class="badge badge-critical">CRITICAL</span>',
};
const STATUS_ICON = { ok: '✓', warning: '⚠', error: '✗', skipped: '–' };
const FINDING_COLOR = { low: '#22c55e', medium: '#f59e0b', high: '#ef4444', critical: '#dc2626' };

let currentPage = 0;
const PAGE_SIZE = 25;

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatMetricValue(key, value) {
  if (key === 'sizeGroups' && Array.isArray(value)) {
    return value
      .slice(0, 5)
      .map((group) => `${group.sizeBytes} Bytes: ${group.count} Dateien`)
      .join(' · ');
  }
  if (Array.isArray(value)) {
    return value.map((item) => {
      if (item && typeof item === 'object') return JSON.stringify(item);
      return String(item);
    }).join(', ');
  }
  if (value && typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function fmtDate(ts) {
  if (!ts) return '–';
  return new Date(ts).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}

async function api(path) {
  const res = await fetch(`/api${path}`);
  if (!res.ok) throw new Error(`API ${path}: ${res.status}`);
  return res.json();
}

async function apiJson(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `API ${path}: ${res.status}`);
  return data;
}

// ── Stats + Latest ────────────────────────────────────────────────────────────

async function loadDashboard() {
  const [stats, latest] = await Promise.all([api('/stats'), api('/latest').catch(() => null)]);

  document.getElementById('stat-total').textContent = stats.total_runs ?? 0;
  document.getElementById('stat-critical').textContent = stats.critical_count ?? 0;
  document.getElementById('stat-high').textContent = stats.high_count ?? 0;

  if (latest) {
    _lastTimestamp = latest.timestamp;
    document.getElementById('hostname').textContent = latest.hostname;
    document.getElementById('last-run').textContent = 'Letzter Lauf: ' + fmtDate(latest.timestamp);
    document.getElementById('stat-risk').innerHTML = RISK_BADGE[latest.overall_risk] || latest.overall_risk;
    renderCheckCards(latest.checks);
    renderAiReview(latest.ai_review);
    renderIncident(latest.incident);
  }
}

function renderCheckCards(checks) {
  const grid = document.getElementById('checks-grid');
  if (!checks?.length) { grid.innerHTML = '<p style="color:var(--muted)">Keine Daten</p>'; return; }

  grid.innerHTML = checks.map((c) => {
    if (c.name === 'wordpressCheck') return renderWordPressCard(c);
    if (c.name === 'suspiciousFiles') return renderSuspiciousFilesCard(c);
    if (c.name === 'urlHealth') return renderUrlHealthCard(c);

    const icon = STATUS_ICON[c.status] || '?';
    const iconColor = c.status === 'ok' ? 'var(--low)' : c.status === 'warning' ? 'var(--medium)' : 'var(--high)';
    const findingsHtml = c.findings.length === 0
      ? '<div class="check-findings" style="color:var(--low)">Keine Auffälligkeiten</div>'
      : c.findings.slice(0, 4).map((f) => `
          <div class="check-finding-item">
            <div class="finding-dot" style="background:${FINDING_COLOR[f.risk] || 'var(--muted)'}"></div>
            <span>${escHtml(f.message || f.type || JSON.stringify(f))}</span>
          </div>`).join('');

    return `<div class="check-card">
      <div class="check-name">
        <span>${escHtml(c.name)}</span>
        <span class="check-status-icon" style="color:${iconColor}" title="${c.status}">${icon}</span>
      </div>
      ${RISK_BADGE[c.risk] || ''}
      <div style="margin-top:12px">${findingsHtml}</div>
    </div>`;
  }).join('');

  // Attach collapse toggles for WordPress site groups
  grid.querySelectorAll('.wp-site-header').forEach((header) => {
    header.addEventListener('click', () => {
      const body = header.nextElementSibling;
      if (!body) return;
      const open = body.style.display !== 'none';
      body.style.display = open ? 'none' : '';
      header.querySelector('.wp-toggle').textContent = open ? '▶' : '▼';
    });
  });
}

function renderUrlHealthCard(c) {
  const icon = STATUS_ICON[c.status] || '?';
  const iconColor = c.status === 'ok' ? 'var(--low)' : c.status === 'warning' ? 'var(--medium)' : 'var(--high)';
  const targets = c.metrics?.targets || [];
  const rows = targets.length === 0
    ? '<div class="check-findings" style="color:var(--muted)">Keine URLs konfiguriert</div>'
    : targets.slice(0, 8).map((t) => `
      <div class="check-finding-item">
        <div class="finding-dot" style="background:${t.ok ? 'var(--low)' : (FINDING_COLOR[t.risk] || 'var(--high)')}"></div>
        <div>
          <div>${escHtml(t.label || t.url)}</div>
          <div class="url-card-meta">${escHtml(t.url)} · ${t.statusCode || t.error || 'Fehler'} · ${t.responseTimeMs ?? '–'} ms</div>
        </div>
      </div>`).join('');

  return `<div class="check-card">
    <div class="check-name">
      <span>URL-Erreichbarkeit</span>
      <span class="check-status-icon" style="color:${iconColor}" title="${c.status}">${icon}</span>
    </div>
    ${RISK_BADGE[c.risk] || ''}
    <div class="wp-summary">${c.metrics?.healthy ?? 0}/${c.metrics?.checked ?? 0} erreichbar</div>
    <div style="margin-top:12px">${rows}</div>
  </div>`;
}

function renderSuspiciousFilesCard(c) {
  const icon = STATUS_ICON[c.status] || '?';
  const iconColor = c.status === 'ok' ? 'var(--low)' : c.status === 'warning' ? 'var(--medium)' : 'var(--high)';
  const m = c.metrics || {};

  const findingsHtml = c.findings.length === 0
    ? '<div class="check-findings" style="color:var(--low)">Keine Auffälligkeiten</div>'
    : c.findings.slice(0, 6).map((f) => {
        const color = FINDING_COLOR[f.risk] || 'var(--muted)';
        const msg = escHtml(f.message || f.type || '');

        if (f.hashChanged) {
          const desc   = escHtml(f.trustDescription || '');
          const fp     = escHtml(f.file || '');
          const sha256 = escHtml(f.sha256 || '');
          return `
            <div class="check-finding-item trust-changed" data-filepath="${fp}">
              <div class="finding-dot" style="background:var(--high)"></div>
              <div style="flex:1">
                <span>🔒 Bekannte Datei verändert${desc ? ` (${desc})` : ''}: <code>${escHtml((f.file||'').split('/').slice(-2).join('/'))}</code></span>
                <div style="margin-top:6px;display:flex;gap:8px;align-items:center">
                  <button class="btn-trust-approve" data-filepath="${fp}" data-sha256="${sha256}" data-desc="${desc}">
                    ✔ Änderung bestätigen
                  </button>
                  <span class="trust-approve-result" style="font-size:0.8em;color:var(--muted)"></span>
                </div>
              </div>
            </div>`;
        }

        if (f.trustedFile && f.hashVerified) {
          return `
            <div class="check-finding-item">
              <div class="finding-dot" style="background:var(--low)"></div>
              <span style="color:var(--low)">✔ Bekannt (Hash OK): <code>${escHtml((f.file||'').split('/').slice(-1)[0])}</code></span>
            </div>`;
        }

        if (f.type === 'core_checksum_ok' || f.type === 'vendor_lib_suppressed') {
          return `
            <div class="check-finding-item">
              <div class="finding-dot" style="background:var(--low)"></div>
              <span style="color:var(--low)">ℹ ${msg}</span>
            </div>`;
        }

        return `
          <div class="check-finding-item">
            <div class="finding-dot" style="background:${color}"></div>
            <span>${msg}</span>
          </div>`;
      }).join('');

  const metricsHtml = Object.entries(m).length
    ? `<div class="sf-metrics">${
        Object.entries(m).map(([k, v]) => `<span class="sf-metric">${escHtml(k)}: <b>${escHtml(formatMetricValue(k, v))}</b></span>`).join('')
      }</div>`
    : '';

  return `<div class="check-card" id="sf-card">
    <div class="check-name">
      <span>Suspicious Files</span>
      <span class="check-status-icon" style="color:${iconColor}" title="${c.status}">${icon}</span>
    </div>
    ${RISK_BADGE[c.risk] || ''}
    ${metricsHtml}
    <div style="margin-top:12px">${findingsHtml}</div>
  </div>`;
}

function renderWordPressCard(c) {
  const icon = STATUS_ICON[c.status] || '?';
  const iconColor = c.status === 'ok' ? 'var(--low)' : c.status === 'warning' ? 'var(--medium)' : 'var(--high)';
  const sites = c.metrics?.siteDetails || [];
  const m = c.metrics || {};

  const summary = sites.length === 0
    ? 'Keine WordPress-Installation gefunden'
    : `${sites.length} Installation${sites.length !== 1 ? 'en' : ''}`
      + (m.withoutSecurityPlugin ? ` · ${m.withoutSecurityPlugin} ohne Security-Plugin` : '')
      + (m.phpInUploadsTotal ? ` · ${m.phpInUploadsTotal} PHP in Uploads` : '');

  const sitesHtml = sites.map((s) => {
    const riskColor = FINDING_COLOR[s.risk] || 'var(--muted)';
    const issueRows = s.issues.map((issue) => `
      <div class="wp-issue">
        <div class="finding-dot" style="background:${FINDING_COLOR[issue.risk] || 'var(--muted)'}"></div>
        <span>${escHtml(issue.message)}</span>
      </div>`).join('');

    const secBadge = s.securityPlugins.length
      ? `<span class="wp-plugin-ok">✓ ${escHtml(s.securityPlugins[0])}</span>`
      : `<span class="wp-plugin-missing">✗ kein Security-Plugin</span>`;

    return `
      <div class="wp-site">
        <div class="wp-site-header">
          <span class="wp-toggle">▼</span>
          <span class="wp-domain">${escHtml(s.site)}</span>
          ${s.version ? `<span class="wp-version">WP ${escHtml(s.version)}</span>` : ''}
          <span class="badge badge-${s.risk}" style="margin-left:auto">${s.risk.toUpperCase()}</span>
        </div>
        <div class="wp-site-body">
          <div class="wp-meta">${secBadge}</div>
          ${issueRows || '<div class="wp-issue" style="color:var(--low)">Keine Auffälligkeiten</div>'}
        </div>
      </div>`;
  }).join('');

  return `<div class="check-card check-card--wide">
    <div class="check-name">
      <span>WordPress Security</span>
      <span class="check-status-icon" style="color:${iconColor}" title="${c.status}">${icon}</span>
    </div>
    ${RISK_BADGE[c.risk] || ''}
    <div class="wp-summary">${escHtml(summary)}</div>
    <div class="wp-sites">${sitesHtml}</div>
  </div>`;
}

function renderAiReview(ai) {
  const section = document.getElementById('ai-section');
  if (!ai?.response) { section.style.display = 'none'; return; }
  section.style.display = '';
  const r = ai.response;
  const actionsHtml = Array.isArray(r.recommended_actions)
    ? `<ul class="ai-actions">${r.recommended_actions.map((a) => `<li>${escHtml(a)}</li>`).join('')}</ul>`
    : escHtml(r.recommended_actions || '–');

  document.getElementById('ai-card').innerHTML = `
    <div>
      <div class="ai-field-label">Risiko</div>
      <div class="ai-field-value">${RISK_BADGE[r.risk] || r.risk}</div>
    </div>
    <div>
      <div class="ai-field-label">Zusammenfassung</div>
      <div class="ai-field-value">${escHtml(r.summary || '–')}</div>
    </div>
    <div>
      <div class="ai-field-label">Wahrscheinliche Ursache</div>
      <div class="ai-field-value">${escHtml(r.likely_cause || '–')}</div>
    </div>
    <div>
      <div class="ai-field-label">Empfehlungen</div>
      <div class="ai-field-value">${actionsHtml}</div>
    </div>`;
}

function renderIncident(incident) {
  const section = document.getElementById('incident-section');
  const card = document.getElementById('incident-card');
  if (!incident) {
    section.style.display = 'none';
    return;
  }

  section.style.display = '';
  if (incident.status === 'error') {
    card.innerHTML = `<div class="incident-error">Incident Mode fehlgeschlagen: ${escHtml(incident.message || 'unbekannter Fehler')}</div>`;
    return;
  }

  const summary = incident.summary || {};
  card.innerHTML = `
    <div class="incident-main">
      <div>
        <div class="ai-field-label">Evidence-Ordner</div>
        <div class="incident-path">${escHtml(incident.incidentDir || '–')}</div>
      </div>
      <div>
        <div class="ai-field-label">Trigger</div>
        <div class="ai-field-value">${escHtml(incident.triggerCount ?? '–')}</div>
      </div>
      <div>
        <div class="ai-field-label">Verdächtige Dateien</div>
        <div class="ai-field-value">${escHtml(incident.suspiciousFiles ?? summary.suspiciousFiles ?? '–')}</div>
      </div>
      <div>
        <div class="ai-field-label">Kampagnen</div>
        <div class="ai-field-value">${escHtml(incident.campaigns ?? '–')}</div>
      </div>
    </div>
    <div class="incident-summary">${escHtml(summary.status || 'Read-only Forensikbericht wurde erzeugt.')}</div>`;
}

// ── History Table ─────────────────────────────────────────────────────────────

async function loadHistory() {
  const risk = document.getElementById('risk-filter').value;
  const tbody = document.getElementById('history-body');
  tbody.innerHTML = '<tr><td colspan="5" class="loading-row">Lade...</td></tr>';

  try {
    const data = await api(`/reports?limit=${PAGE_SIZE}&offset=${currentPage * PAGE_SIZE}${risk ? `&risk=${risk}` : ''}`);

    if (!data.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="loading-row">Keine Einträge</td></tr>';
      document.getElementById('btn-next').disabled = true;
      return;
    }

    tbody.innerHTML = data.map((r) => `
      <tr>
        <td>${fmtDate(r.timestamp)}</td>
        <td>${escHtml(r.hostname)}</td>
        <td>${RISK_BADGE[r.overall_risk] || r.overall_risk}</td>
        <td>${r.checks_with_findings ?? '–'} / ${r.check_count ?? '–'}</td>
        <td><button class="btn-detail" data-id="${r.id}">Detail</button></td>
      </tr>`).join('');

    document.getElementById('btn-next').disabled = data.length < PAGE_SIZE;
    document.getElementById('btn-prev').disabled = currentPage === 0;
    document.getElementById('page-info').textContent = `Seite ${currentPage + 1}`;

    // Attach detail button listeners
    tbody.querySelectorAll('.btn-detail').forEach((btn) => {
      btn.addEventListener('click', () => openModal(btn.dataset.id));
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading-row" style="color:var(--high)">${escHtml(err.message)}</td></tr>`;
  }
}

// ── Detail Modal ──────────────────────────────────────────────────────────────

async function openModal(id) {
  const overlay = document.getElementById('modal-overlay');
  const body = document.getElementById('modal-body');
  const title = document.getElementById('modal-title');

  overlay.classList.remove('hidden');
  body.innerHTML = '<div class="loading-row">Lade...</div>';

  try {
    const r = await api(`/reports/${id}`);
    title.innerHTML = `Report ${fmtDate(r.timestamp)} &nbsp; ${RISK_BADGE[r.overall_risk] || r.overall_risk}`;

      const checksHtml = (r.checks || []).map((c) => {
      const findingsHtml = c.findings.length === 0
        ? '<div class="modal-finding" style="color:var(--low)">Keine Findings</div>'
        : c.findings.map((f) => `<div class="modal-finding">
            <span style="color:${FINDING_COLOR[f.risk] || 'var(--muted)'}">●</span>
            ${escHtml(f.message || f.type || '')}
            ${f.file ? `<br><code>${escHtml(f.file)}</code>` : ''}
          </div>`).join('');

      const metricsHtml = c.metrics && Object.keys(c.metrics).length
        ? `<div class="modal-metrics">${escHtml(JSON.stringify(c.metrics, null, 2))}</div>` : '';

      return `<div class="modal-check-block">
        <div class="modal-check-title">
          <span>${escHtml(c.name)}</span>
          ${RISK_BADGE[c.risk] || ''}
        </div>
        ${findingsHtml}
        ${metricsHtml}
      </div>`;
    }).join('');

    let aiHtml = '';
    if (r.ai_review?.response) {
      const a = r.ai_review.response;
      aiHtml = `<div class="modal-check-block">
        <div class="modal-check-title"><span>KI-Bewertung</span>${RISK_BADGE[a.risk] || ''}</div>
        <div class="modal-finding"><strong>Zusammenfassung:</strong> ${escHtml(a.summary || '–')}</div>
        <div class="modal-finding"><strong>Ursache:</strong> ${escHtml(a.likely_cause || '–')}</div>
        ${Array.isArray(a.recommended_actions) ? `<div class="modal-finding"><strong>Empfehlungen:</strong><ul style="margin-left:16px">${a.recommended_actions.map((x) => `<li>${escHtml(x)}</li>`).join('')}</ul></div>` : ''}
      </div>`;
    }

    let incidentHtml = '';
    if (r.incident) {
      incidentHtml = `<div class="modal-check-block">
        <div class="modal-check-title"><span>Incident Mode</span>${r.incident.status === 'error' ? RISK_BADGE.high : RISK_BADGE.critical}</div>
        <div class="modal-finding"><strong>Evidence-Ordner:</strong> <code>${escHtml(r.incident.incidentDir || '–')}</code></div>
        <div class="modal-finding"><strong>Trigger:</strong> ${escHtml(r.incident.triggerCount ?? '–')}</div>
        <div class="modal-finding"><strong>Verdächtige Dateien:</strong> ${escHtml(r.incident.suspiciousFiles ?? '–')}</div>
        <div class="modal-finding"><strong>Status:</strong> ${escHtml(r.incident.summary?.status || r.incident.message || '–')}</div>
      </div>`;
    }

    body.innerHTML = checksHtml + aiHtml + incidentHtml;
  } catch (err) {
    body.innerHTML = `<div class="loading-row" style="color:var(--high)">${escHtml(err.message)}</div>`;
  }
}

function closeModal() {
  document.getElementById('modal-overlay').classList.add('hidden');
}

// ── Init ──────────────────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Trust approve button ──────────────────────────────────────────────────────

document.getElementById('checks-grid').addEventListener('click', async (e) => {
  const btn = e.target.closest('.btn-trust-approve');
  if (!btn) return;

  const filePath = btn.dataset.filepath;
  const sha256   = btn.dataset.sha256;
  const desc     = btn.dataset.desc || '';
  const result   = btn.parentElement.querySelector('.trust-approve-result');

  btn.disabled = true;
  btn.textContent = '⏳ Speichere...';

  try {
    const res  = await fetch('/api/trust/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filePath, sha256, description: desc }),
    });
    const data = await res.json();

    if (!res.ok) throw new Error(data.error || res.status);

    btn.textContent = '✔ Bestätigt';
    btn.style.background = 'var(--low)';
    if (result) {
      result.textContent = `SHA256: ${data.sha256.slice(0, 16)}…`;
      result.style.color = 'var(--low)';
    }
    // Dim the whole finding row
    btn.closest('.trust-changed')?.style.setProperty('opacity', '0.5');
  } catch (err) {
    btn.disabled = false;
    btn.textContent = '✔ Änderung bestätigen';
    if (result) {
      result.textContent = `Fehler: ${err.message}`;
      result.style.color = 'var(--high)';
    }
  }
});

document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('modal-overlay').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) closeModal();
});
document.getElementById('risk-filter').addEventListener('change', () => {
  currentPage = 0;
  loadHistory();
});
document.getElementById('btn-prev').addEventListener('click', () => {
  if (currentPage > 0) { currentPage--; loadHistory(); }
});
document.getElementById('btn-next').addEventListener('click', () => {
  currentPage++;
  loadHistory();
});

// ── Cron status ───────────────────────────────────────────────────────────────

async function loadCronStatus() {
  const dot  = document.getElementById('cron-dot');
  const text = document.getElementById('cron-status-text');
  const meta = document.getElementById('cron-meta');

  try {
    const d = await api('/cron-status');
    dot.className = 'cron-indicator ' + d.status;

    if (d.status === 'no_data') {
      text.textContent = 'Noch kein Report empfangen';
      meta.textContent = 'Cron-Job wurde noch nicht ausgeführt oder schreibt nicht in die Datenbank.';
      return;
    }

    const ago = d.minutesAgo === 0 ? 'gerade eben'
              : d.minutesAgo === 1 ? 'vor 1 Minute'
              : `vor ${d.minutesAgo} Minuten`;

    if (d.status === 'ok') {
      text.textContent = `Cron läuft ✓ — letzter Lauf ${ago}`;
    } else if (d.status === 'late') {
      text.textContent = `Cron verzögert ⚠ — letzter Lauf ${ago}`;
    } else {
      text.textContent = `Cron ausgefallen ✗ — letzter Lauf ${ago}`;
    }

    meta.textContent = `Intervall: alle ${d.intervalMinutes} min · Gesamt-Läufe: ${d.stats?.total_runs ?? '–'} · Letztes Risiko: ${d.overallRisk?.toUpperCase() ?? '–'}`;
  } catch (err) {
    dot.className = 'cron-indicator missed';
    text.textContent = 'Status nicht abrufbar';
    meta.textContent = err.message;
  }
}

document.getElementById('btn-refresh-status').addEventListener('click', loadCronStatus);

// ── URL monitoring settings ──────────────────────────────────────────────────

async function loadMonitoredUrls() {
  const list = document.getElementById('url-list');
  try {
    const urls = await api('/monitored-urls');
    if (!urls.length) {
      list.innerHTML = '<div class="url-empty">Noch keine URLs eingetragen.</div>';
      return;
    }

    list.innerHTML = urls.map((item) => `
      <div class="url-row" data-id="${item.id}">
        <label class="url-enabled">
          <input type="checkbox" class="url-toggle" ${item.enabled ? 'checked' : ''}>
          <span>${item.enabled ? 'aktiv' : 'pausiert'}</span>
        </label>
        <div class="url-main">
          <div class="url-label">${escHtml(item.label || item.url)}</div>
          <div class="url-value">${escHtml(item.url)}</div>
        </div>
        <div class="url-timeout">${Number(item.timeout_ms || 10000) / 1000}s</div>
        <button class="btn-detail url-delete" type="button">Löschen</button>
      </div>`).join('');
  } catch (err) {
    list.innerHTML = `<div class="url-empty" style="color:var(--high)">Fehler: ${escHtml(err.message)}</div>`;
  }
}

function showUrlResult(type, message) {
  const result = document.getElementById('url-result');
  result.className = `notify-result ${type}`;
  result.textContent = message;
}

document.getElementById('url-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const labelInput = document.getElementById('url-label');
  const urlInput = document.getElementById('url-input');
  const timeoutInput = document.getElementById('url-timeout');
  const button = e.currentTarget.querySelector('button[type="submit"]');

  button.disabled = true;
  showUrlResult('info', 'Speichere URL...');
  try {
    await apiJson('/monitored-urls', {
      method: 'POST',
      body: JSON.stringify({
        label: labelInput.value,
        url: urlInput.value,
        timeout_ms: timeoutInput.value,
      }),
    });
    labelInput.value = '';
    urlInput.value = '';
    timeoutInput.value = '10000';
    showUrlResult('success', 'URL gespeichert. Beim nächsten Check wird sie geprüft.');
    await loadMonitoredUrls();
  } catch (err) {
    showUrlResult('error', 'Fehler: ' + err.message);
  } finally {
    button.disabled = false;
  }
});

document.getElementById('url-list').addEventListener('click', async (e) => {
  const row = e.target.closest('.url-row');
  if (!row) return;
  const id = row.dataset.id;

  if (e.target.closest('.url-delete')) {
    try {
      await apiJson(`/monitored-urls/${id}`, { method: 'DELETE' });
      showUrlResult('success', 'URL gelöscht.');
      await loadMonitoredUrls();
    } catch (err) {
      showUrlResult('error', 'Fehler: ' + err.message);
    }
  }
});

document.getElementById('url-list').addEventListener('change', async (e) => {
  const toggle = e.target.closest('.url-toggle');
  if (!toggle) return;
  const row = toggle.closest('.url-row');
  const id = row.dataset.id;

  try {
    const current = (await api('/monitored-urls')).find((item) => String(item.id) === String(id));
    if (!current) throw new Error('URL nicht gefunden');
    await apiJson(`/monitored-urls/${id}`, {
      method: 'PUT',
      body: JSON.stringify({
        label: current.label,
        url: current.url,
        enabled: toggle.checked,
        expected_status_min: current.expected_status_min,
        expected_status_max: current.expected_status_max,
        timeout_ms: current.timeout_ms,
      }),
    });
    showUrlResult('success', toggle.checked ? 'URL aktiviert.' : 'URL pausiert.');
    await loadMonitoredUrls();
  } catch (err) {
    toggle.checked = !toggle.checked;
    showUrlResult('error', 'Fehler: ' + err.message);
  }
});

// ── Sofort-Check ─────────────────────────────────────────────────────────────

document.getElementById('btn-test-ai').addEventListener('click', async () => {
  const btn    = document.getElementById('btn-test-ai');
  const result = document.getElementById('run-result');
  const section = document.getElementById('ai-test-section');
  const card   = document.getElementById('ai-test-card');

  btn.disabled = true;
  btn.innerHTML = '<span class="notify-icon">⏳</span> KI analysiert...';
  result.className = 'notify-result info';
  result.textContent = 'KI-Analyse läuft — kann bis zu 30s dauern...';
  section.style.display = 'none';

  try {
    const data = await fetch('/api/test-ai', { method: 'POST' }).then((r) => r.json());
    if (data.error) throw new Error(data.error + (data.output ? `\n\nLog:\n${data.output}` : ''));

    const ai = data.aiReview?.response || data.aiReview;
    if (ai) {
      result.className = 'notify-result success';
      result.textContent = 'KI-Analyse abgeschlossen ✓';
      section.style.display = '';
      const actionsHtml = Array.isArray(ai.recommended_actions)
        ? `<ul class="ai-actions">${ai.recommended_actions.map((a) => `<li>${escHtml(a)}</li>`).join('')}</ul>`
        : escHtml(ai.recommended_actions || '–');

      card.innerHTML = `
        <div>
          <div class="ai-field-label">Risiko</div>
          <div class="ai-field-value">${RISK_BADGE[ai.risk] || escHtml(ai.risk || '–')}</div>
        </div>
        <div>
          <div class="ai-field-label">Trend</div>
          <div class="ai-field-value">${escHtml(ai.trend || '–')}</div>
        </div>
        <div>
          <div class="ai-field-label">Zusammenfassung</div>
          <div class="ai-field-value">${escHtml(ai.summary || '–')}</div>
        </div>
        <div>
          <div class="ai-field-label">Wahrscheinliche Ursache</div>
          <div class="ai-field-value">${escHtml(ai.likely_cause || '–')}</div>
        </div>
        <div>
          <div class="ai-field-label">Benachrichtigung</div>
          <div class="ai-field-value">${ai.notify ? '✓ Ja' : '✗ Nein'} · Dringlichkeit: ${escHtml(ai.urgency || '–')}</div>
        </div>
        <div>
          <div class="ai-field-label">Empfehlungen</div>
          <div class="ai-field-value">${actionsHtml}</div>
        </div>
        ${data.output ? `<div style="grid-column:1/-1"><div class="ai-field-label">Script-Log</div><pre class="ai-log">${escHtml(data.output)}</pre></div>` : ''}`;
    } else {
      result.className = 'notify-result info';
      result.textContent = 'Skript beendet — kein KI-Ergebnis (Details im Log unten)';
      section.style.display = '';
      card.innerHTML = data.output
        ? `<div style="grid-column:1/-1"><div class="ai-field-label">Script-Log</div><pre class="ai-log">${escHtml(data.output)}</pre></div>`
        : '<div style="grid-column:1/-1;color:var(--muted)">Kein Output — prüfe ENABLE_AI_REVIEW und OPENAI_API_KEY in den Umgebungsvariablen.</div>';
    }

    // Refresh dashboard to show updated AI section
    loadDashboard();
  } catch (err) {
    result.className = 'notify-result error';
    result.textContent = 'Fehler: ' + err.message.split('\n')[0];
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span class="notify-icon">&#129504;</span> KI-Analyse starten';
  }
});

document.getElementById('btn-run-now').addEventListener('click', async () => {
  const btn = document.getElementById('btn-run-now');
  const result = document.getElementById('run-result');
  btn.disabled = true;
  btn.classList.add('loading');
  btn.innerHTML = '<span class="notify-icon">⏳</span> Läuft...';
  result.className = 'notify-result info';
  result.textContent = 'Check läuft — bitte warten (kann bis zu 60s dauern)...';

  try {
    const data = await fetch('/api/run-now', { method: 'POST' }).then((r) => r.json());
    if (data.error) throw new Error(data.error);
    result.className = 'notify-result success';
    result.textContent = 'Check abgeschlossen — Dashboard wird aktualisiert...';
    setTimeout(() => { loadDashboard(); loadHistory(); }, 1500);
  } catch (err) {
    result.className = 'notify-result error';
    result.textContent = 'Fehler: ' + err.message;
  } finally {
    btn.disabled = false;
    btn.classList.remove('loading');
    btn.innerHTML = '<span class="notify-icon">&#9654;</span> Sofort-Check starten';
  }
});

// ── Notification tests ────────────────────────────────────────────────────────

async function testNotify(channel) {
  const result = document.getElementById('notify-result');
  const btns = ['btn-test-email', 'btn-test-telegram', 'btn-test-all'].map((id) => document.getElementById(id));
  btns.forEach((b) => { b.disabled = true; });
  result.className = 'notify-result info';
  result.textContent = 'Sende...';

  try {
    const data = await fetch('/api/test-notify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel }),
    }).then((r) => r.json());

    if (data.error) throw new Error(data.error);

    const parts = Object.entries(data.results).map(([k, v]) =>
      `${k}: ${v === 'ok' ? '✓' : '✗ ' + v}`
    );
    const allOk = Object.values(data.results).every((v) => v === 'ok');
    result.className = 'notify-result ' + (allOk ? 'success' : 'error');
    result.textContent = parts.join('  ·  ');
  } catch (err) {
    result.className = 'notify-result error';
    result.textContent = 'Fehler: ' + err.message;
  } finally {
    btns.forEach((b) => { b.disabled = false; });
  }
}

document.getElementById('btn-test-email').addEventListener('click', () => testNotify('email'));
document.getElementById('btn-test-telegram').addEventListener('click', () => testNotify('telegram'));
document.getElementById('btn-test-all').addEventListener('click', () => testNotify('all'));

loadCronStatus();
loadDashboard();
loadMonitoredUrls();
loadHistory();
startAutoRefresh(60_000);

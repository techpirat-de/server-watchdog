'use strict';

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

function fmtDate(ts) {
  if (!ts) return '–';
  return new Date(ts).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}

async function api(path) {
  const res = await fetch(`/api${path}`);
  if (!res.ok) throw new Error(`API ${path}: ${res.status}`);
  return res.json();
}

// ── Stats + Latest ────────────────────────────────────────────────────────────

async function loadDashboard() {
  const [stats, latest] = await Promise.all([api('/stats'), api('/latest').catch(() => null)]);

  document.getElementById('stat-total').textContent = stats.total_runs ?? 0;
  document.getElementById('stat-critical').textContent = stats.critical_count ?? 0;
  document.getElementById('stat-high').textContent = stats.high_count ?? 0;

  if (latest) {
    document.getElementById('hostname').textContent = latest.hostname;
    document.getElementById('last-run').textContent = 'Letzter Lauf: ' + fmtDate(latest.timestamp);
    document.getElementById('stat-risk').innerHTML = RISK_BADGE[latest.overall_risk] || latest.overall_risk;
    renderCheckCards(latest.checks);
    renderAiReview(latest.ai_review);
  }
}

function renderCheckCards(checks) {
  const grid = document.getElementById('checks-grid');
  if (!checks?.length) { grid.innerHTML = '<p style="color:var(--muted)">Keine Daten</p>'; return; }

  grid.innerHTML = checks.map((c) => {
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

    body.innerHTML = checksHtml + aiHtml;
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
    if (data.error) throw new Error(data.error);

    result.className = 'notify-result success';
    result.textContent = 'KI-Analyse abgeschlossen ✓';

    const ai = data.aiReview?.response || data.aiReview;
    if (ai) {
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
        </div>`;
    } else {
      result.textContent = 'KI-Analyse abgeschlossen — kein Ergebnis (Risiko zu niedrig oder kein Report vorhanden)';
    }

    // Refresh dashboard to show updated AI section
    loadDashboard();
  } catch (err) {
    result.className = 'notify-result error';
    result.textContent = 'Fehler: ' + err.message;
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
loadHistory();

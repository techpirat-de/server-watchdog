'use strict';

const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

function normalizeRisk(risk) {
  return ['low', 'medium', 'high', 'critical'].includes(risk) ? risk : 'low';
}

function isHealthyStatus(status, target) {
  const min = Number.isFinite(Number(target.expected_status_min)) ? Number(target.expected_status_min) : 200;
  const max = Number.isFinite(Number(target.expected_status_max)) ? Number(target.expected_status_max) : 399;
  return status >= min && status <= max;
}

function classifyHttpStatus(status) {
  if (status >= 500) return { risk: 'high', status: 'error' };
  if (status >= 400) return { risk: 'medium', status: 'warning' };
  if (status >= 300) return { risk: 'low', status: 'ok' };
  if (status >= 200) return { risk: 'low', status: 'ok' };
  return { risk: 'medium', status: 'warning' };
}

async function checkUrl(target) {
  const timeoutMs = Math.max(1000, Math.min(Number(target.timeout_ms) || 10000, 60000));
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();

  try {
    const response = await fetch(target.url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Plesk-Server-Watchdog/2.0 (+https://github.com/techpirat-de/server-watchdog)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
    });
    const responseTimeMs = Date.now() - started;
    const expectedOk = isHealthyStatus(response.status, target);
    const classified = expectedOk ? { risk: 'low', status: 'ok' } : classifyHttpStatus(response.status);

    return {
      id: target.id,
      label: target.label || target.url,
      url: target.url,
      ok: expectedOk,
      statusCode: response.status,
      responseTimeMs,
      risk: classified.risk,
      status: classified.status,
      message: expectedOk
        ? `${target.label || target.url} erreichbar (${response.status}, ${responseTimeMs} ms)`
        : `${target.label || target.url} liefert HTTP ${response.status} (${responseTimeMs} ms)`,
    };
  } catch (err) {
    const responseTimeMs = Date.now() - started;
    const timeoutHit = err.name === 'AbortError';
    return {
      id: target.id,
      label: target.label || target.url,
      url: target.url,
      ok: false,
      statusCode: null,
      responseTimeMs,
      risk: 'high',
      status: 'error',
      error: timeoutHit ? 'timeout' : err.code || err.name || 'request_failed',
      message: timeoutHit
        ? `${target.label || target.url} nicht erreichbar: Timeout nach ${timeoutMs} ms`
        : `${target.label || target.url} nicht erreichbar: ${err.message}`,
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function check(config = {}) {
  const targets = Array.isArray(config.MONITORED_URLS) ? config.MONITORED_URLS.filter((u) => u.enabled !== 0) : [];
  const result = {
    name: 'urlHealth',
    status: 'ok',
    risk: 'low',
    findings: [],
    metrics: {
      configured: targets.length,
      checked: 0,
      healthy: 0,
      failed: 0,
      averageResponseMs: null,
      targets: [],
    },
  };

  if (targets.length === 0) {
    result.findings.push({ type: 'not_configured', risk: 'low', message: 'Keine URLs zur Erreichbarkeitsprüfung konfiguriert.' });
    return result;
  }

  const checks = await Promise.all(targets.map(checkUrl));
  result.metrics.checked = checks.length;
  result.metrics.healthy = checks.filter((item) => item.ok).length;
  result.metrics.failed = checks.filter((item) => !item.ok).length;
  result.metrics.targets = checks.map((item) => ({
    label: item.label,
    url: item.url,
    ok: item.ok,
    statusCode: item.statusCode,
    responseTimeMs: item.responseTimeMs,
    risk: item.risk,
    error: item.error || null,
  }));
  result.metrics.averageResponseMs = checks.length
    ? Math.round(checks.reduce((sum, item) => sum + item.responseTimeMs, 0) / checks.length)
    : null;

  for (const item of checks) {
    if (!item.ok) {
      result.findings.push({
        type: item.statusCode ? 'http_status' : 'url_unreachable',
        risk: item.risk,
        url: item.url,
        label: item.label,
        statusCode: item.statusCode,
        responseTimeMs: item.responseTimeMs,
        error: item.error || null,
        message: item.message,
      });
    }
    if (RISK_RANK[normalizeRisk(item.risk)] > RISK_RANK[result.risk]) result.risk = normalizeRisk(item.risk);
  }

  if (result.metrics.failed > 0) {
    result.status = result.risk === 'high' || result.risk === 'critical' ? 'error' : 'warning';
  }

  return result;
}

module.exports = { check };

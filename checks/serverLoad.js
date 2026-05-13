'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const os = require('os');

const execFileAsync = promisify(execFile);

async function getDiskUsage() {
  try {
    const { stdout } = await execFileAsync('df', ['-BG', '/'], { timeout: 5000 });
    const line = stdout.split('\n')[1];
    if (!line) return null;
    const parts = line.trim().split(/\s+/);
    const usedPct = parseInt(parts[4], 10);
    const available = parseInt(parts[3], 10);
    return { usedPercent: usedPct, availableGB: available };
  } catch (_) {
    return null;
  }
}

async function countProcesses(name) {
  try {
    const { stdout } = await execFileAsync('pgrep', ['-c', '-f', name], { timeout: 5000 });
    return parseInt(stdout.trim(), 10) || 0;
  } catch (_) {
    return 0;
  }
}

async function check() {
  const result = {
    name: 'serverLoad',
    status: 'ok',
    risk: 'low',
    findings: [],
    metrics: {},
  };

  try {
    const cpuLoad = os.loadavg();
    const cpuCount = os.cpus().length;
    const totalMemMB = Math.round(os.totalmem() / 1024 / 1024);
    const freeMemMB = Math.round(os.freemem() / 1024 / 1024);
    const usedMemPct = Math.round(((totalMemMB - freeMemMB) / totalMemMB) * 100);

    const disk = await getDiskUsage();

    const [phpCount, sendmailCount, postdropCount, curlCount, wgetCount] = await Promise.all([
      countProcesses('php'),
      countProcesses('sendmail'),
      countProcesses('postdrop'),
      countProcesses('curl'),
      countProcesses('wget'),
    ]);

    result.metrics = {
      loadAvg1m: cpuLoad[0].toFixed(2),
      loadAvg5m: cpuLoad[1].toFixed(2),
      loadAvg15m: cpuLoad[2].toFixed(2),
      cpuCount,
      totalMemMB,
      freeMemMB,
      usedMemPercent: usedMemPct,
      disk: disk || { usedPercent: null, availableGB: null },
      processes: { php: phpCount, sendmail: sendmailCount, postdrop: postdropCount, curl: curlCount, wget: wgetCount },
    };

    // Thresholds
    if (cpuLoad[0] > cpuCount * 2) {
      result.risk = 'high';
      result.status = 'warning';
      result.findings.push({ type: 'cpu_overload', message: `Load avg 1m ${cpuLoad[0].toFixed(2)} exceeds 2x CPU count (${cpuCount})` });
    } else if (cpuLoad[0] > cpuCount) {
      result.risk = 'medium';
      result.status = 'warning';
      result.findings.push({ type: 'cpu_high', message: `Load avg 1m ${cpuLoad[0].toFixed(2)} exceeds CPU count (${cpuCount})` });
    }

    if (usedMemPct > 90) {
      result.risk = result.risk === 'low' ? 'high' : result.risk;
      result.status = 'warning';
      result.findings.push({ type: 'mem_critical', message: `Memory usage at ${usedMemPct}%` });
    } else if (usedMemPct > 80) {
      result.risk = result.risk === 'low' ? 'medium' : result.risk;
      result.status = 'warning';
      result.findings.push({ type: 'mem_high', message: `Memory usage at ${usedMemPct}%` });
    }

    if (disk?.usedPercent > 90) {
      result.risk = 'high';
      result.status = 'error';
      result.findings.push({ type: 'disk_critical', message: `Disk usage at ${disk.usedPercent}%, only ${disk.availableGB}GB free` });
    } else if (disk?.usedPercent > 80) {
      result.risk = result.risk === 'low' ? 'medium' : result.risk;
      result.findings.push({ type: 'disk_high', message: `Disk usage at ${disk.usedPercent}%` });
    }

    if (phpCount > 50) {
      result.risk = result.risk === 'low' ? 'medium' : result.risk;
      result.findings.push({ type: 'many_php_procs', message: `${phpCount} PHP processes running` });
    }

    if (sendmailCount > 10 || postdropCount > 10) {
      result.risk = result.risk === 'low' ? 'medium' : result.risk;
      result.status = 'warning';
      result.findings.push({ type: 'many_mail_procs', message: `${sendmailCount} sendmail / ${postdropCount} postdrop processes` });
    }

  } catch (err) {
    result.status = 'error';
    result.findings.push({ type: 'exec_error', message: `serverLoad check failed: ${err.message}` });
  }

  return result;
}

module.exports = { check };

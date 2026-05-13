'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const os = require('os');
const fs = require('fs');

const execFileAsync = promisify(execFile);

// On Linux, os.freemem() returns truly-free RAM ignoring page cache.
// MemAvailable from /proc/meminfo is the correct "usable free" value.
function getLinuxMemInfo() {
  try {
    const raw = fs.readFileSync('/proc/meminfo', 'utf8');
    const get = (key) => {
      const m = raw.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'));
      return m ? parseInt(m[1], 10) * 1024 : null; // kB → bytes
    };
    const total = get('MemTotal');
    const available = get('MemAvailable');
    if (total && available) return { total, available };
  } catch (_) {}
  return null;
}

async function getDiskUsage() {
  for (const dfBin of ['/bin/df', '/usr/bin/df', 'df']) {
    try {
      const { stdout } = await execFileAsync(dfBin, ['-BG', '/'], { timeout: 5000 });
      const line = stdout.split('\n')[1];
      if (!line) continue;
      const parts = line.trim().split(/\s+/);
      const usedPct = parseInt(parts[4], 10);
      const available = parseInt(parts[3], 10);
      if (!isNaN(usedPct)) return { usedPercent: usedPct, availableGB: available };
    } catch (_) {}
  }
  return null;
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

    // Use MemAvailable on Linux, fall back to os.freemem() on other systems
    const linuxMem = getLinuxMemInfo();
    const totalMemMB  = Math.round((linuxMem?.total  ?? os.totalmem()) / 1024 / 1024);
    const availMemMB  = Math.round((linuxMem?.available ?? os.freemem()) / 1024 / 1024);
    const usedMemPct  = Math.round(((totalMemMB - availMemMB) / totalMemMB) * 100);

    const disk = await getDiskUsage();

    const [phpCount, sendmailCount, postdropCount, curlCount, wgetCount] = await Promise.all([
      countProcesses('php'),
      countProcesses('sendmail'),
      countProcesses('postdrop'),
      countProcesses('curl'),
      countProcesses('wget'),
    ]);

    result.metrics = {
      loadAvg1m:      cpuLoad[0].toFixed(2),
      loadAvg5m:      cpuLoad[1].toFixed(2),
      loadAvg15m:     cpuLoad[2].toFixed(2),
      cpuCount,
      totalMemMB,
      availableMemMB: availMemMB,
      usedMemPercent: usedMemPct,
      disk: disk || { usedPercent: null, availableGB: null },
      processes: { php: phpCount, sendmail: sendmailCount, postdrop: postdropCount, curl: curlCount, wget: wgetCount },
    };

    if (cpuLoad[0] > cpuCount * 2) {
      result.risk = 'high';
      result.status = 'warning';
      result.findings.push({ type: 'cpu_overload', message: `Load avg 1m ${cpuLoad[0].toFixed(2)} — über 2x CPU-Anzahl (${cpuCount})` });
    } else if (cpuLoad[0] > cpuCount) {
      result.risk = 'medium';
      result.status = 'warning';
      result.findings.push({ type: 'cpu_high', message: `Load avg 1m ${cpuLoad[0].toFixed(2)} — über CPU-Anzahl (${cpuCount})` });
    }

    if (usedMemPct > 95) {
      result.risk = result.risk === 'low' ? 'high' : result.risk;
      result.status = 'warning';
      result.findings.push({ type: 'mem_critical', message: `Verfügbarer RAM nur ${availMemMB} MB (${usedMemPct}% belegt)` });
    } else if (usedMemPct > 85) {
      result.risk = result.risk === 'low' ? 'medium' : result.risk;
      result.status = 'warning';
      result.findings.push({ type: 'mem_high', message: `RAM-Auslastung bei ${usedMemPct}% (${availMemMB} MB verfügbar)` });
    }

    if (disk?.usedPercent > 90) {
      result.risk = 'high';
      result.status = 'error';
      result.findings.push({ type: 'disk_critical', message: `Festplatte zu ${disk.usedPercent}% voll — nur noch ${disk.availableGB} GB frei` });
    } else if (disk?.usedPercent > 80) {
      result.risk = result.risk === 'low' ? 'medium' : result.risk;
      result.findings.push({ type: 'disk_high', message: `Festplatte zu ${disk.usedPercent}% voll` });
    }

    if (phpCount > 50) {
      result.risk = result.risk === 'low' ? 'medium' : result.risk;
      result.findings.push({ type: 'many_php_procs', message: `${phpCount} PHP-Prozesse aktiv` });
    }

    if (sendmailCount > 10 || postdropCount > 10) {
      result.risk = result.risk === 'low' ? 'medium' : result.risk;
      result.status = 'warning';
      result.findings.push({ type: 'many_mail_procs', message: `${sendmailCount} sendmail / ${postdropCount} postdrop Prozesse` });
    }

  } catch (err) {
    result.status = 'error';
    result.findings.push({ type: 'exec_error', message: `serverLoad check failed: ${err.message}` });
  }

  return result;
}

module.exports = { check };

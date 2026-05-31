'use strict';

const fs = require('fs');
const path = require('path');
const { load, save, hashFile, TRUST_FILE } = require('./lib/trustedFiles');

const [,, command, ...args] = process.argv;

// ── CLI ───────────────────────────────────────────────────────────────────────

async function main() {
  switch (command) {
    case 'add':    return cmdAdd(args);
    case 'remove': return cmdRemove(args);
    case 'list':   return cmdList();
    default:
      console.log('Verwendung:');
      console.log('  node trust.js add <pfad> [beschreibung]   — Datei mit SHA256-Hash als vertrauenswürdig markieren');
      console.log('  node trust.js remove <pfad>               — Vertrauensstatus entfernen');
      console.log('  node trust.js list                        — Alle bekannten Dateien anzeigen');
      console.log('');
      console.log('npm-Kurzform:');
      console.log('  npm run trust -- add /pfad/zur/datei "Beschreibung"');
      process.exit(1);
  }
}

async function cmdAdd([filePath, ...descParts]) {
  if (!filePath) {
    console.error('Fehler: Kein Pfad angegeben.');
    process.exit(1);
  }

  const absPath = path.resolve(filePath);

  try {
    fs.accessSync(absPath, fs.constants.R_OK);
  } catch (_) {
    console.error(`Fehler: Datei nicht lesbar: ${absPath}`);
    process.exit(1);
  }

  const sha256 = await hashFile(absPath);
  const description = descParts.join(' ');
  const data = load();
  const existing = (data.trustedFiles || {})[absPath];

  if (existing) {
    if (existing.sha256 === sha256) {
      console.log(`Bereits vertrauenswürdig (Hash unverändert): ${absPath}`);
      if (description && description !== existing.description) {
        data.trustedFiles[absPath].description = description;
        save(data);
        console.log(`Beschreibung aktualisiert: ${description}`);
      }
      return;
    }
    console.log(`Hash aktualisiert für: ${absPath}`);
    console.log(`  Alt: ${existing.sha256}`);
    console.log(`  Neu: ${sha256}`);
  } else {
    console.log(`Hinzugefügt: ${absPath}`);
    console.log(`  SHA256: ${sha256}`);
    if (description) console.log(`  Beschreibung: ${description}`);
  }

  if (!data.trustedFiles) data.trustedFiles = {};
  data.trustedFiles[absPath] = {
    sha256,
    description: description || existing?.description || '',
    added:   existing?.added   || new Date().toISOString().slice(0, 10),
    updated: new Date().toISOString().slice(0, 10),
  };

  save(data);
  console.log(`Gespeichert in: ${TRUST_FILE}`);
}

function cmdRemove([filePath]) {
  if (!filePath) {
    console.error('Fehler: Kein Pfad angegeben.');
    process.exit(1);
  }

  const absPath = path.resolve(filePath);
  const data = load();

  if (!(data.trustedFiles || {})[absPath]) {
    console.log(`Nicht in Vertrauensliste: ${absPath}`);
    return;
  }

  delete data.trustedFiles[absPath];
  save(data);
  console.log(`Entfernt: ${absPath}`);
}

function cmdList() {
  const data = load();
  const entries = Object.entries(data.trustedFiles || {});

  if (entries.length === 0) {
    console.log('Keine vertrauenswürdigen Dateien konfiguriert.');
    console.log(`Datei: ${TRUST_FILE}`);
    return;
  }

  console.log(`\nVertrauenswürdige Dateien (${entries.length}):\n`);
  for (const [p, e] of entries) {
    console.log(`  ${p}`);
    console.log(`    SHA256:       ${e.sha256}`);
    if (e.description) console.log(`    Beschreibung: ${e.description}`);
    console.log(`    Hinzugefügt:  ${e.added || '?'}`);
    if (e.updated && e.updated !== e.added) {
      console.log(`    Aktualisiert: ${e.updated}`);
    }
    console.log('');
  }
  console.log(`Datei: ${TRUST_FILE}`);
}

main().catch((err) => {
  console.error(`Fehler: ${err.message}`);
  process.exit(1);
});

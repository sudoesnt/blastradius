// Local inventory: what you actually run, so "could this hit me?" can be a lookup instead of a guess.
//
// `scanInventory` walks the folders you name and records package names from npm, pip and Go manifests.
// Nothing leaves the machine: the result is written to the gitignored data/ folder and only
// match / no-match facts for a specific advisory are ever shown to the model.

import fs from 'node:fs/promises';
import path from 'node:path';

const SKIP_DIRS = new Set(['node_modules', '.git', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', 'target', 'vendor']);
const MAX_DEPTH = 6;
const MAX_FILES = 4000;

// GitHub advisory ecosystem name -> inventory key
const ECOSYSTEM_KEY = { npm: 'npm', pip: 'pip', pypi: 'pip', go: 'go' };

const normPip = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');

async function readNpm(file, out) {
  const j = JSON.parse(await fs.readFile(file, 'utf8'));
  if (path.basename(file) === 'package-lock.json') {
    for (const k of Object.keys(j.packages || {})) {
      const i = k.lastIndexOf('node_modules/');
      if (i >= 0) out.npm.add(k.slice(i + 'node_modules/'.length).toLowerCase());
    }
    for (const k of Object.keys(j.dependencies || {})) out.npm.add(k.toLowerCase());
  } else {
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const k of Object.keys(j[field] || {})) out.npm.add(k.toLowerCase());
    }
  }
}

async function readPip(file, out) {
  for (const line of (await fs.readFile(file, 'utf8')).split(/\r?\n/)) {
    const m = line.trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
    if (m && !line.trim().startsWith('#') && !line.trim().startsWith('-')) out.pip.add(normPip(m[1]));
  }
}

async function readGoMod(file, out) {
  for (const line of (await fs.readFile(file, 'utf8')).split(/\r?\n/)) {
    const m = line.trim().match(/^(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}\/\S+)\s+v\d/i);
    if (m) out.go.add(m[1].toLowerCase());
  }
}

export async function scanInventory(roots) {
  const out = { npm: new Set(), pip: new Set(), go: new Set() };
  const manifests = [];
  let visited = 0;

  async function walk(dir, depth) {
    if (depth > MAX_DEPTH || visited > MAX_FILES) return;
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      visited++;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) await walk(full, depth + 1);
        continue;
      }
      try {
        if (e.name === 'package.json' || e.name === 'package-lock.json') { await readNpm(full, out); manifests.push(full); }
        else if (/^requirements.*\.txt$/i.test(e.name)) { await readPip(full, out); manifests.push(full); }
        else if (e.name === 'go.mod') { await readGoMod(full, out); manifests.push(full); }
      } catch {
        // unreadable or malformed manifest: skip it
      }
    }
  }

  const resolved = roots.map((r) => path.resolve(r));
  for (const r of resolved) await walk(r, 0);
  return {
    scannedAt: new Date().toISOString(),
    roots: resolved,
    manifestCount: manifests.length,
    packages: { npm: [...out.npm].sort(), pip: [...out.pip].sort(), go: [...out.go].sort() }
  };
}

/**
 * Compare one cluster against the inventory.
 * Returns { checked, matches, basis }:
 *   checked=false  -> nothing to compare (no inventory, or the item names no package/product we can look up)
 *   checked=true   -> `matches` lists what was found; an empty list is a real "not in inventory"
 */
export function matchInventory(cluster, inventory, profile = {}) {
  const matches = [];
  let checked = false;
  const basis = [];

  if (inventory?.packages && cluster.packages?.length) {
    for (const p of cluster.packages) {
      const key = ECOSYSTEM_KEY[p.ecosystem];
      if (!key) continue;
      checked = true;
      const name = key === 'pip' ? normPip(p.name) : p.name.toLowerCase();
      if (inventory.packages[key]?.includes(name)) matches.push(`${key}:${p.name}`);
    }
    if (checked) basis.push(`package manifests under ${inventory.roots.length} scanned folder(s)`);
  }

  const products = (profile.products || []).map((s) => String(s).trim()).filter(Boolean);
  if (products.length && cluster.kevProducts?.length) {
    checked = true;
    basis.push('your declared product list');
    for (const kp of cluster.kevProducts) {
      const hay = kp.toLowerCase();
      for (const prod of products) {
        const esc = prod.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if (new RegExp(`(^|[^a-z0-9])${esc}([^a-z0-9]|$)`).test(hay)) matches.push(`product:${prod}`);
      }
    }
  }

  return { checked, matches: [...new Set(matches)], basis: basis.join(' and ') };
}

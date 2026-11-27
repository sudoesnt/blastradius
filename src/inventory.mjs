// Local inventory: what you actually run, so "could this hit me?" can be a lookup instead of a guess.
//
// `scanInventory` walks the folders you name and records package names from npm, pnpm, yarn, pip, uv, poetry,
// Go and Cargo manifests and lockfiles. Nothing leaves the machine: the result is written to the gitignored
// data/ folder and only match / no-match facts for a specific advisory are ever shown to the model.
//
// A "not found" is only as good as the scan behind it. Every way the scan can fall short (a limit reached, a
// folder that could not be read, a manifest that could not be parsed) is recorded, and a scan that fell short is
// marked incomplete. An incomplete scan can still prove you HAVE a package; it is never used to say you do not.

import fs from 'node:fs/promises';
import path from 'node:path';

export const INVENTORY_SCHEMA = 2;

const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', 'target', 'vendor', '.cache', '.tox']);
// Generous limits that exist only to stop a runaway walk. Reaching one is reported, never silent.
const DEFAULT_LIMITS = { maxDepth: 12, maxEntries: 750000 };

// GitHub advisory ecosystem name -> inventory key
const ECOSYSTEM_KEY = { npm: 'npm', pip: 'pip', pypi: 'pip', go: 'go', rust: 'cargo', cargo: 'cargo', 'crates.io': 'cargo' };
export const ECOSYSTEMS = ['npm', 'pip', 'go', 'cargo'];

const normPip = (n) => String(n).toLowerCase().replace(/[-_.]+/g, '-');
const normCargo = (n) => String(n).toLowerCase().replace(/_/g, '-');
const NORMALISE = { npm: (n) => String(n).toLowerCase(), pip: normPip, go: (n) => String(n).toLowerCase(), cargo: normCargo };

// A Python requirement string ("requests[socks]>=2 ; python_version < '3.9'") -> its distribution name.
const pipName = (spec) => (String(spec).trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/) || [])[1];

// ---------- parsers: each takes file text and returns [ecosystem, name] pairs ----------

function parsePackageJson(text) {
  const j = JSON.parse(text);
  const out = [];
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const k of Object.keys(j[field] || {})) out.push(['npm', k]);
  }
  return out;
}

function parsePackageLock(text) {
  const j = JSON.parse(text);
  const out = [];
  for (const k of Object.keys(j.packages || {})) {
    const i = k.lastIndexOf('node_modules/');
    if (i >= 0) out.push(['npm', k.slice(i + 'node_modules/'.length)]);
  }
  const walkV1 = (deps) => {
    for (const [name, info] of Object.entries(deps || {})) {
      out.push(['npm', name]);
      if (info && typeof info === 'object') walkV1(info.dependencies);
    }
  };
  walkV1(j.dependencies);
  return out;
}

// pnpm-lock.yaml: package keys look like "/name@1.2.3:", "name@1.2.3:", "'@scope/name@1.2.3(peer@2)':" or, in old
// lockfiles, "/name/1.2.3:". Dependency maps under importers list plain "name:" keys with a version beneath.
function parsePnpmLock(text) {
  const out = [];
  let section = '';
  for (const line of text.split(/\r?\n/)) {
    const top = line.match(/^([A-Za-z][\w-]*):\s*$/);
    if (top) { section = top[1]; continue; }
    if (section === 'packages' || section === 'snapshots') {
      const m = line.match(/^ {2}['"]?\/?((?:@[^/\s'"@]+\/)?[^/\s'"@]+)[@/]\d/);
      if (m) out.push(['npm', m[1]]);
    } else if (section === 'importers' || section === 'dependencies' || section === 'devDependencies' || section === 'optionalDependencies') {
      const m = line.match(/^ {2,8}['"]?((?:@[^/\s'":]+\/)?[^/\s'":@]+)['"]?:\s*(?:$|['"]?[\d^~<>=*]|\{)/);
      if (m && !['dependencies', 'devDependencies', 'optionalDependencies', 'specifier', 'version'].includes(m[1]) && m[1] !== '.') out.push(['npm', m[1]]);
    }
  }
  return out;
}

// yarn.lock (classic and berry): unindented entry lines such as
//   "@babel/core@^7.0.0", "@babel/core@^7.1.0":      lodash@^4.17.0:      "lodash@npm:^4.17.21":
function parseYarnLock(text) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith(' ') || line.startsWith('#') || !line.trimEnd().endsWith(':')) continue;
    if (line.startsWith('__metadata')) continue;
    for (const raw of line.trimEnd().slice(0, -1).split(/,\s*/)) {
      const spec = raw.trim().replace(/^["']|["']$/g, '');
      const at = spec.lastIndexOf('@');
      const firstAt = spec.indexOf('@', 1); // skip the leading @ of a scope
      const cut = firstAt > 0 ? firstAt : at;
      if (cut > 0) out.push(['npm', spec.slice(0, cut)]);
    }
  }
  return out;
}

function parseRequirements(text) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith('-')) continue;
    const name = pipName(t);
    if (name) out.push(['pip', name]);
  }
  return out;
}

// pyproject.toml: PEP 621 arrays ([project] dependencies, optional-dependencies), PEP 735 [dependency-groups],
// uv's dev-dependencies, and Poetry's key = "version" tables.
function parsePyproject(text) {
  const out = [];
  let section = '';
  let inArray = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, '');
    const header = line.match(/^\s*\[\[?([^\]]+)\]\]?\s*$/);
    if (header) { section = header[1].trim(); inArray = false; continue; }

    if (/^tool\.poetry\.(?:[\w-]*dependencies|group\.[\w.-]+\.dependencies)$/.test(section)) {
      const key = line.match(/^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=/);
      if (key && key[1].toLowerCase() !== 'python') out.push(['pip', key[1]]);
      continue;
    }

    const arraySection = section === 'project' || section === 'project.optional-dependencies' || section === 'dependency-groups' || section === 'tool.uv' || section === 'build-system';
    if (!arraySection) continue;
    const opens = line.match(/^\s*([\w-]+)\s*=\s*\[(.*)$/);
    let body = null;
    if (opens) {
      const wanted = section === 'project' ? opens[1] === 'dependencies'
        : section === 'tool.uv' ? /dependencies$/.test(opens[1])
        : section === 'build-system' ? opens[1] === 'requires'
        : true;
      inArray = wanted;
      body = wanted ? opens[2] : null;
    } else if (inArray) {
      body = line;
    }
    if (body == null) continue;
    // Strings are matched by their own quote character, so "pkg ; python_version < '3.9'" stays one string, and
    // the end of the list is looked for outside strings, so "requests[socks]" does not close it.
    const STRING = /"([^"]*)"|'([^']*)'/g;
    for (const m of body.matchAll(STRING)) {
      const name = pipName(m[1] ?? m[2]);
      if (name) out.push(['pip', name]);
    }
    if (body.replace(STRING, '').includes(']')) inArray = false;
  }
  return out;
}

// uv.lock, poetry.lock and Cargo.lock share one shape: [[package]] tables with name = "...".
const parseLockPackages = (ecosystem) => (text) => {
  const out = [];
  let inPackage = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*\[\[package\]\]\s*$/.test(line)) { inPackage = true; continue; }
    if (/^\s*\[/.test(line)) { inPackage = false; continue; }
    const m = inPackage && line.match(/^\s*name\s*=\s*["']([^"']+)["']/);
    if (m) out.push([ecosystem, m[1]]);
  }
  return out;
};

function parseCargoToml(text) {
  const out = [];
  let section = '';
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, '');
    const header = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (header) {
      section = header[1].trim();
      // [dependencies.serde] style: the crate name is in the header itself.
      const dotted = section.match(/(?:^|\.)(?:dev-|build-)?dependencies\.["']?([A-Za-z0-9_-]+)["']?$/);
      if (dotted) out.push(['cargo', dotted[1]]);
      continue;
    }
    if (/(?:^|\.)(?:dev-|build-)?dependencies$/.test(section)) {
      const key = line.match(/^\s*["']?([A-Za-z0-9_-]+)["']?\s*=/);
      if (key) out.push(['cargo', key[1]]);
    }
  }
  return out;
}

function parseGoMod(text) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.trim().match(/^(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}\/\S+)\s+v\d/i);
    if (m) out.push(['go', m[1]]);
  }
  return out;
}

const PARSERS = [
  [/^package\.json$/, parsePackageJson],
  [/^(package-lock|npm-shrinkwrap)\.json$/, parsePackageLock],
  [/^pnpm-lock\.yaml$/, parsePnpmLock],
  [/^yarn\.lock$/, parseYarnLock],
  [/^requirements.*\.txt$/i, parseRequirements],
  [/^pyproject\.toml$/, parsePyproject],
  [/^(uv|poetry)\.lock$/, parseLockPackages('pip')],
  [/^Cargo\.lock$/, parseLockPackages('cargo')],
  [/^Cargo\.toml$/, parseCargoToml],
  [/^go\.mod$/, parseGoMod]
];

/** Parse one manifest's text by file name. Exported for tests. Returns [ecosystem, name] pairs, or null if not a manifest. */
export function parseManifest(fileName, text) {
  const hit = PARSERS.find(([re]) => re.test(fileName));
  return hit ? hit[1](text) : null;
}

/**
 * Walk `roots` and collect package names.
 * The result says how the scan went: `complete` is true only if every folder was walked and every manifest parsed.
 */
export async function scanInventory(roots, limits = {}) {
  const { maxDepth, maxEntries } = { ...DEFAULT_LIMITS, ...limits };
  const found = Object.fromEntries(ECOSYSTEMS.map((e) => [e, new Set()]));
  const manifestCounts = {};
  const gaps = { entryLimitReached: false, tooDeep: [], unreadable: [], unparsed: [], missingRoots: [] };
  let entries = 0;
  let manifestCount = 0;
  const note = (list, value) => { if (list.length < 25) list.push(value); else list.more = (list.more || 0) + 1; };

  async function walk(dir, depth) {
    if (gaps.entryLimitReached) return;
    let listing;
    try {
      listing = await fs.readdir(dir, { withFileTypes: true });
    } catch (err) {
      note(depth === 0 ? gaps.missingRoots : gaps.unreadable, `${dir} (${err.code || err.message})`);
      return;
    }
    for (const e of listing) {
      if (++entries > maxEntries) { gaps.entryLimitReached = true; return; }
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue; // links and junctions: following them risks loops and double counting
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || e.name.startsWith('.')) continue;
        if (depth + 1 > maxDepth) { note(gaps.tooDeep, full); continue; }
        await walk(full, depth + 1);
        if (gaps.entryLimitReached) return;
        continue;
      }
      if (!e.isFile() || !PARSERS.some(([re]) => re.test(e.name))) continue;
      try {
        const pairs = parseManifest(e.name, await fs.readFile(full, 'utf8')) || [];
        for (const [eco, name] of pairs) found[eco].add(NORMALISE[eco](name));
        manifestCount++;
        manifestCounts[e.name] = (manifestCounts[e.name] || 0) + 1;
      } catch (err) {
        note(gaps.unparsed, `${full} (${err.message.slice(0, 80)})`);
      }
    }
  }

  const resolved = roots.map((r) => path.resolve(r));
  for (const r of resolved) await walk(r, 0);

  const problems = [];
  if (gaps.entryLimitReached) problems.push(`stopped after ${maxEntries.toLocaleString('en-US')} files and folders; the rest was not looked at`);
  const count = (l) => l.length + (l.more || 0);
  if (count(gaps.tooDeep)) problems.push(`${count(gaps.tooDeep)} folder(s) deeper than ${maxDepth} levels were not opened`);
  if (count(gaps.unreadable)) problems.push(`${count(gaps.unreadable)} folder(s) could not be read`);
  if (count(gaps.missingRoots)) problems.push(`${count(gaps.missingRoots)} of the folders you named could not be opened`);
  if (count(gaps.unparsed)) problems.push(`${count(gaps.unparsed)} manifest(s) could not be parsed`);

  return {
    schema: INVENTORY_SCHEMA,
    scannedAt: new Date().toISOString(),
    roots: resolved,
    entriesWalked: Math.min(entries, maxEntries),
    manifestCount,
    manifestCounts,
    complete: problems.length === 0,
    problems,
    gaps: { ...gaps, tooDeep: [...gaps.tooDeep], unreadable: [...gaps.unreadable], unparsed: [...gaps.unparsed], missingRoots: [...gaps.missingRoots] },
    packages: Object.fromEntries(ECOSYSTEMS.map((e) => [e, [...found[e]].sort()]))
  };
}

/** True only for an inventory produced by this version of the scanner that walked everything it was pointed at. */
export const inventoryIsComplete = (inventory) => Boolean(inventory && inventory.schema === INVENTORY_SCHEMA && inventory.complete === true);

/**
 * Compare one cluster against the inventory.
 * Returns { checked, matches, basis, conclusive }:
 *   checked=false                 nothing to compare (no inventory, or the item names nothing we can look up)
 *   matches non-empty             you have it (always conclusive: a match in a partial scan is still a match)
 *   matches empty, conclusive     a real "not in your inventory"
 *   matches empty, not conclusive not found in the part that was scanned; it cannot be ruled out
 */
export function matchInventory(cluster, inventory, profile = {}) {
  const matches = [];
  let checked = false;
  let conclusive = true;
  const basis = [];

  if (inventory?.packages && cluster.packages?.length) {
    let looked = false;
    for (const p of cluster.packages) {
      const key = ECOSYSTEM_KEY[String(p.ecosystem || '').toLowerCase()];
      if (!key) continue; // an ecosystem this scanner does not read: say nothing rather than "not found"
      looked = true;
      if ((inventory.packages[key] || []).includes(NORMALISE[key](p.name))) matches.push(`${key}:${p.name}`);
    }
    if (looked) {
      checked = true;
      basis.push(`package manifests under ${inventory.roots.length} scanned folder(s)`);
      if (!inventoryIsComplete(inventory)) conclusive = false;
    }
    // If any affected package is in an ecosystem we cannot read, a miss on the others proves nothing.
    if (looked && cluster.packages.some((p) => !ECOSYSTEM_KEY[String(p.ecosystem || '').toLowerCase()])) conclusive = false;
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

  const unique = [...new Set(matches)];
  return { checked, matches: unique, basis: basis.join(' and '), conclusive: unique.length > 0 || conclusive };
}

#!/usr/bin/env node
// Deterministic repository checks. No network, no model. Run by CI on every pull request and by `npm run check`.
//
//  1. Every JavaScript file parses.
//  2. Config files are valid and internally consistent (unique source ids, https URLs, known types...).
//  3. Eval cases only use cause labels the analyzer can actually produce.
//  4. No dependencies have crept in, and no local data, secrets or key-shaped strings are tracked.

import fs from 'node:fs/promises';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const problems = [];
const fail = (msg) => problems.push(msg);
const readJson = async (rel) => {
  try { return JSON.parse(await fs.readFile(path.join(ROOT, rel), 'utf8')); } catch (e) { fail(`${rel}: ${e.message}`); return null; }
};

const tracked = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean);

// 1. Syntax
const jsFiles = tracked.filter((f) => /\.(mjs|js)$/.test(f));
for (const f of jsFiles) {
  try { execFileSync(process.execPath, ['--check', path.join(ROOT, f)], { stdio: 'pipe' }); } catch (e) { fail(`${f}: syntax error\n${String(e.stderr).trim()}`); }
}

// 2. Config
const SOURCE_TYPES = new Set(['rss', 'social-rss', 'cisa-kev', 'github-advisories', 'ransomware-live', 'bluesky', 'hn-algolia', 'x-api']);
const sources = await readJson('config/sources.json');
if (sources) {
  const ids = new Set();
  for (const s of sources.sources || []) {
    const where = `config/sources.json [${s.id}]`;
    if (!s.id || !/^[a-z0-9-]+$/.test(s.id)) fail(`${where}: id must be lowercase letters, digits and dashes`);
    if (ids.has(s.id)) fail(`${where}: duplicate id`);
    ids.add(s.id);
    if (!s.name) fail(`${where}: missing name`);
    if (!/^https:\/\//.test(s.url || '')) fail(`${where}: url must be https`);
    if (!SOURCE_TYPES.has(s.type)) fail(`${where}: unknown type "${s.type}"`);
    if (![1, 2].includes(s.tier)) fail(`${where}: tier must be 1 or 2`);
    if (!(Number.isInteger(s.weight) && s.weight >= 1 && s.weight <= 10)) fail(`${where}: weight must be an integer 1-10`);
    if (typeof s.enabled !== 'boolean') fail(`${where}: enabled must be true or false`);
    if (!s.category) fail(`${where}: missing category`);
  }
  if (!ids.size) fail('config/sources.json: no sources');
}

const PROFILE_FIELDS = ['roleId', 'roleTitle', 'stackContext', 'briefLabel'];
const presets = await readJson('config/presets.json');
const profile = await readJson('config/profile.json');
if (presets) {
  const ids = new Set();
  for (const p of presets.presets || []) {
    for (const k of ['id', 'roleTitle', 'stackContext', 'briefLabel']) if (!p[k]) fail(`config/presets.json [${p.id}]: missing ${k}`);
    if (ids.has(p.id)) fail(`config/presets.json [${p.id}]: duplicate id`);
    ids.add(p.id);
  }
  if (profile && !ids.has(profile.roleId)) fail(`config/profile.json: roleId "${profile.roleId}" is not a preset`);
}
if (profile) for (const k of PROFILE_FIELDS) if (!profile[k]) fail(`config/profile.json: missing ${k}`);

// 3. Eval labels match the analyzer's taxonomy
const { ROOT_CAUSE_BUCKETS } = await import(new URL('../src/analyze.mjs', import.meta.url));
const evalSpec = await readJson('eval/cases.json');
if (evalSpec) {
  const ids = new Set();
  for (const c of evalSpec.cases || []) {
    if (ids.has(c.id)) fail(`eval/cases.json [${c.id}]: duplicate id`);
    ids.add(c.id);
    if (!c.evidence) fail(`eval/cases.json [${c.id}]: missing evidence`);
    for (const b of c.bucket || []) if (!ROOT_CAUSE_BUCKETS.includes(b)) fail(`eval/cases.json [${c.id}]: unknown cause "${b}"`);
    if (![null, 'DISCLOSED', 'UNKNOWN'].includes(c.basis)) fail(`eval/cases.json [${c.id}]: basis must be DISCLOSED, UNKNOWN or null`);
    if (!c.expectSkip && !(c.bucket || []).length) fail(`eval/cases.json [${c.id}]: needs at least one acceptable cause`);
  }
}

// 4. Hygiene
const pkg = await readJson('package.json');
if (pkg) {
  for (const k of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    if (pkg[k] && Object.keys(pkg[k]).length) fail(`package.json: ${k} must stay empty (the project is dependency-free by design)`);
  }
}
for (const f of tracked) {
  if (/^data\//.test(f) || /(^|\/)\.env$/.test(f) || /^node_modules\//.test(f)) fail(`${f}: local data, .env and node_modules must not be tracked`);
}
// Key-shaped strings. Built from pieces so this file does not match itself.
const SECRET_PATTERNS = [
  ['Anthropic API key', new RegExp('sk-' + 'ant-[A-Za-z0-9_-]{20,}')],
  ['OpenAI API key', new RegExp('sk-' + '(proj-)?[A-Za-z0-9]{32,}')],
  ['GitHub token', new RegExp('gh[pousr]_' + '[A-Za-z0-9]{30,}')],
  ['Google API key', new RegExp('AIza' + '[0-9A-Za-z_-]{30,}')],
  ['AWS access key id', new RegExp('AKIA' + '[0-9A-Z]{16}')],
  ['private key block', new RegExp('-----BEGIN ' + '[A-Z ]*PRIVATE KEY-----')]
];
for (const f of tracked) {
  if (/\.(png|jpg|jpeg|gif|ico|woff2?)$/i.test(f)) continue;
  const text = await fs.readFile(path.join(ROOT, f), 'utf8');
  for (const [label, re] of SECRET_PATTERNS) if (re.test(text)) fail(`${f}: contains something shaped like a ${label}`);
}

// 5. Architecture boundaries
//
// Each rule below exists because the mistake it blocks was actually made and caught in review. The error
// text says what to do instead, so whoever (or whatever) wrote the change can fix the cause, not the symptom.

// Which project modules each module may import. A new file in src/ must be added here deliberately.
const LAYERS = {
  'src/xml.mjs': [],
  'src/store.mjs': [],
  'src/llm.mjs': [],
  'src/inventory.mjs': [],
  'src/ingest.mjs': ['xml', 'store'],
  'src/cluster.mjs': ['store'],
  'src/analyze.mjs': ['store', 'llm', 'inventory'],
  'src/eval.mjs': ['store', 'analyze', 'llm', 'ingest'],
  'src/server.mjs': ['ingest', 'cli', 'store'],
  'src/cli.mjs': ['ingest', 'cluster', 'analyze', 'llm', 'inventory', 'store', 'eval', 'server']
};
// Capabilities that are confined to one place each.
const CONFINED = [
  { what: 'starting a process', re: /node:child_process/, only: ['src/llm.mjs'],
    fix: 'Model calls go through callModel() in src/llm.mjs. That is the only place the claude CLI is started, with no tools, no MCP servers and no user settings. Starting a process anywhere else bypasses that lockdown.' },
  { what: 'a network request', re: /\bfetch\s*\(/, only: ['src/ingest.mjs', 'src/llm.mjs'],
    fix: 'Feeds are fetched in src/ingest.mjs (so they are filtered, stored and counted in coverage) and models are called in src/llm.mjs. Add a source to config/sources.json or an engine to llm.mjs instead of fetching here.' },
  { what: 'a file write', re: /\bfs\.(writeFile|appendFile|rename|rm|unlink|mkdir)\b/, only: ['src/store.mjs', 'src/cli.mjs', 'src/eval.mjs'],
    fix: 'Persist through writeJsonAtomic() or the save*/merge* functions in src/store.mjs, so writes are atomic and stay inside the data folder.' },
  { what: 'an HTTP server', re: /node:http\b/, only: ['src/server.mjs'],
    fix: 'Add routes to src/server.mjs, where every request passes checkRequest() (Host, Origin and content-type checks).' }
];
const MARKERS = /\b(TODO|FIXME|HACK|XXX)\b|eslint-disable|@ts-ignore/;

const importsOf = (text) => [...text.matchAll(/(?:^|\n)\s*(?:import|export)\b[^'"\n]*?from\s*['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)|(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g)]
  .map((m) => m[1] || m[2] || m[3]);

for (const f of tracked.filter((x) => /^(src|public|scripts)\/.*\.(mjs|js)$/.test(x))) {
  const text = await fs.readFile(path.join(ROOT, f), 'utf8');
  const imports = importsOf(text);

  for (const spec of imports) {
    if (!spec.startsWith('.') && !spec.startsWith('node:')) {
      fail(`${f}: imports "${spec}". The project has no npm dependencies and Node built-ins are imported as "node:...". Use a built-in, or write the small piece you need.`);
    }
  }

  if (f.startsWith('src/')) {
    const allowed = LAYERS[f];
    if (!allowed) {
      fail(`${f}: new module with no declared layer. Add it to LAYERS in scripts/check.mjs with the list of project modules it is allowed to import.`);
    } else {
      for (const spec of imports.filter((s) => s.startsWith('.'))) {
        const target = path.posix.normalize(path.posix.join(path.posix.dirname(f), spec));
        const name = path.posix.basename(target, '.mjs');
        if (!target.startsWith('src/')) fail(`${f}: imports "${spec}" from outside src/. Server code must not depend on browser or test code.`);
        else if (!allowed.includes(name)) {
          fail(`${f}: imports ./${name}.mjs, which its layer does not allow (allowed: ${allowed.join(', ') || 'nothing'}). Lower layers (xml, store, llm, inventory) must not know about the pipeline above them; move the shared piece down, or pass it in as an argument.`);
        }
      }
    }
    for (const rule of CONFINED) {
      if (rule.re.test(text) && !rule.only.includes(f)) fail(`${f}: contains ${rule.what}, which is only allowed in ${rule.only.join(' and ')}. ${rule.fix}`);
    }
  }

  if (f.startsWith('public/')) {
    if (imports.length) fail(`${f}: has imports. The dashboard is a single dependency-free script; server modules cannot run in the browser.`);
    if (/['"\x60]https?:\/\//.test(text)) fail(`${f}: contains an absolute URL. The dashboard only talks to its own server (relative /api/... paths); the content security policy blocks anything else.`);
    if (/\beval\s*\(|new Function\s*\(|document\.write\s*\(/.test(text)) fail(`${f}: uses eval, new Function or document.write. Build HTML with template strings and esc(), which is what keeps feed and model text from running as code.`);
  }

  if (f !== 'scripts/check.mjs' && MARKERS.test(text)) {
    fail(`${f}: contains a workaround marker (${text.match(MARKERS)[0]}). Fix the cause now or open an issue; markers in the code get copied as house style.`);
  }
}

if (problems.length) {
  console.error(`check: ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`check: ok (${jsFiles.length} scripts, ${sources?.sources.length ?? 0} sources, ${evalSpec?.cases.length ?? 0} eval cases, ${tracked.length} tracked files)`);

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

if (problems.length) {
  console.error(`check: ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`check: ok (${jsFiles.length} scripts, ${sources?.sources.length ?? 0} sources, ${evalSpec?.cases.length ?? 0} eval cases, ${tracked.length} tracked files)`);

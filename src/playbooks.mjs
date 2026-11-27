// Playbooks: the closed list of reviewed checks a person's own agent may be handed (config/playbooks.json).

import fs from 'node:fs/promises';
import path from 'node:path';
import { ROOT_DIR } from './store.mjs';

const ID = /^[a-z0-9-]{3,40}$/;
const strings = (v) => Array.isArray(v) && v.every((s) => typeof s === 'string' && s.trim());

/** Returns a list of problems with a playbooks config object; empty means valid. Used at load time and by the repo checks. */
export function playbookProblems(config) {
  const problems = [];
  const seen = new Set();
  if (!config || !Array.isArray(config.playbooks) || !config.playbooks.length) return ['no playbooks defined'];
  for (const p of config.playbooks) {
    const where = `playbook "${p?.id}"`;
    if (!p || !ID.test(p.id || '')) { problems.push(`${where}: id must be lowercase letters, digits and dashes`); continue; }
    if (seen.has(p.id)) problems.push(`${where}: duplicate id`);
    seen.add(p.id);
    for (const k of ['title', 'when']) if (typeof p[k] !== 'string' || !p[k].trim()) problems.push(`${where}: missing ${k}`);
    if (!strings(p.investigate) || !p.investigate.length) problems.push(`${where}: investigate must be a non-empty list of steps`);
    for (const k of ['humanSteps', 'fixes', 'needs']) if (!strings(p[k] || [])) problems.push(`${where}: ${k} must be a list of strings`);
  }
  return problems;
}

export async function loadPlaybooks() {
  const config = JSON.parse(await fs.readFile(path.join(ROOT_DIR, 'config', 'playbooks.json'), 'utf8'));
  const problems = playbookProblems(config);
  if (problems.length) throw new Error(`config/playbooks.json: ${problems.join('; ')}`);
  return config.playbooks;
}

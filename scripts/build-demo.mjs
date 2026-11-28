#!/usr/bin/env node
// Builds the read-only demo site: the dashboard from public/ plus the committed snapshot digests in demo/.
// Pure file work, no network and no model, so it can run in CI and on GitHub Pages builds.
//
//   node scripts/build-demo.mjs [outDir]        (default: dist)

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WINDOWS = [24, 48, 168];

/**
 * A snapshot is only publishable if it was built with the repository's generic default profile and carries
 * no inventory results. This is what stops someone's own role, stack or installed packages reaching a public page.
 */
export function publishProblems(digest, defaultProfile) {
  const problems = [];
  if (digest.schemaVersion !== 2) problems.push('not a schema 2 digest');
  if (digest.roleTitle !== defaultProfile.roleTitle || digest.stackContext !== defaultProfile.stackContext) {
    problems.push(`built for "${digest.roleTitle}", not the generic default profile; regenerate with \`npm run demo:snapshot\``);
  }
  if (digest.inventory) problems.push('contains an inventory summary');
  if (digest.testFindings || (digest.incidents || []).some((i) => i.isTest)) problems.push('contains test findings, which would look like real incidents on a public page');
  if ((digest.incidents || []).some((i) => i.inventory?.checked)) problems.push('contains inventory lookups from a real machine');
  return problems;
}

/** Remove fields that only make sense on the machine that produced the digest. */
export function forPublication(digest) {
  const { inventory, ...rest } = digest;
  return { ...rest, incidents: (digest.incidents || []).map((i) => ({ ...i, inventory: { checked: false, matches: [] } })) };
}

export async function buildDemo(outDir, { demoDir = path.join(ROOT, 'demo') } = {}) {
  const { renderMarkdownDigest } = await import(pathToFileURL(path.join(ROOT, 'src', 'store.mjs')).href);
  const { buildHandoffPrompt, checkupIncident } = await import(pathToFileURL(path.join(ROOT, 'src', 'handoff.mjs')).href);
  const { loadPlaybooks } = await import(pathToFileURL(path.join(ROOT, 'src', 'playbooks.mjs')).href);
  const playbooks = await loadPlaybooks();
  const defaultProfile = JSON.parse(await fs.readFile(path.join(ROOT, 'config', 'profile.json'), 'utf8'));
  const snapshotDir = path.join(outDir, 'snapshot');
  await fs.rm(outDir, { recursive: true, force: true });
  await fs.mkdir(snapshotDir, { recursive: true });

  for (const name of await fs.readdir(path.join(ROOT, 'public'))) {
    await fs.copyFile(path.join(ROOT, 'public', name), path.join(outDir, name));
  }
  const indexPath = path.join(outDir, 'index.html');
  const html = await fs.readFile(indexPath, 'utf8');
  if (!html.includes('<html lang="en">')) throw new Error('public/index.html: expected <html lang="en"> to mark the page as static');
  await fs.writeFile(indexPath, html.replace('<html lang="en">', '<html lang="en" data-static="1">'));

  const built = [];
  for (const hours of WINDOWS) {
    let digest;
    try {
      digest = JSON.parse(await fs.readFile(path.join(demoDir, `digest-${hours}h.json`), 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') continue;
      throw new Error(`demo/digest-${hours}h.json: ${err.message}`);
    }
    const problems = publishProblems(digest, defaultProfile);
    if (problems.length) throw new Error(`demo/digest-${hours}h.json cannot be published: ${problems.join('; ')}`);
    const clean = forPublication(digest);
    await fs.writeFile(path.join(snapshotDir, `digest-${hours}h.json`), JSON.stringify(clean));
    await fs.writeFile(path.join(snapshotDir, `digest-${hours}h.md`), renderMarkdownDigest(clean));

    // The demo has no local server to hand work to an agent, so the prompts are built here. A visitor copies one
    // and pastes it into their own agent. There is no receipt path: nothing reports back to a public page.
    const prompts = {};
    for (const inc of clean.incidents.filter((i) => i.verdict === 'ACT_NOW' || i.verdict === 'WATCH_HARDEN')) {
      prompts[inc.id] = buildHandoffPrompt({ id: `demo-${inc.id}`, incident: inc, playbooks, agentId: 'your-agent', receiptPath: null });
    }
    for (const p of playbooks.filter((b) => !b.needsIncident)) {
      const checkup = checkupIncident(p);
      prompts[checkup.id] = buildHandoffPrompt({ id: `demo-${checkup.id}`, incident: checkup, playbooks, agentId: 'your-agent', receiptPath: null });
    }
    await fs.writeFile(path.join(snapshotDir, `handoffs-${hours}h.json`), JSON.stringify(prompts));
    built.push(hours);
  }
  if (!built.includes(168)) throw new Error('demo/digest-168h.json is missing; the dashboard opens on the 7-day window');

  await fs.copyFile(path.join(ROOT, 'config', 'presets.json'), path.join(snapshotDir, 'presets.json'));
  await fs.writeFile(path.join(snapshotDir, 'playbooks.json'), JSON.stringify({ playbooks: playbooks.filter((b) => !b.needsIncident).map((p) => ({ id: p.id, title: p.title, when: p.when })) }));
  await fs.writeFile(path.join(snapshotDir, 'profile.json'), JSON.stringify(defaultProfile, null, 2));
  // GitHub Pages: serve files as they are, no Jekyll processing.
  await fs.writeFile(path.join(outDir, '.nojekyll'), '');
  return { outDir, windows: built };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const out = path.resolve(process.argv[2] || path.join(ROOT, 'dist'));
  const { windows } = await buildDemo(out);
  console.log(`demo: built ${out} with ${windows.map((h) => `${h}h`).join(', ')} snapshot(s)`);
}

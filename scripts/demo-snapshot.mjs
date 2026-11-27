#!/usr/bin/env node
// Regenerates the demo snapshots in demo/ from live feeds, using the generic default profile.
// Run this on your own machine (it uses your configured model engine), then commit demo/ through a pull request.
//
//   npm run demo:snapshot
//
// It works in a throwaway data folder so your own profile, inventory and analysis cache are never used.
// Only the collected feed items are copied in, so the snapshot's coverage reflects what you have collected.

import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const realData = process.env.BLASTRADIUS_DATA_DIR ? path.resolve(process.env.BLASTRADIUS_DATA_DIR) : path.join(ROOT, 'data');
const scratch = await fs.mkdtemp(path.join(os.tmpdir(), 'blastradius-demo-'));
try {
  await fs.copyFile(path.join(realData, 'items.json'), path.join(scratch, 'items.json'));
} catch {
  console.log('[demo] no collected items found; this snapshot will only cover what the feeds return right now');
}
process.env.BLASTRADIUS_DATA_DIR = scratch;

const { runPipeline } = await import('../src/cli.mjs');
const { publishProblems, forPublication } = await import('./build-demo.mjs');
const defaultProfile = JSON.parse(await fs.readFile(path.join(ROOT, 'config', 'profile.json'), 'utf8'));
const demoDir = path.join(ROOT, 'demo');
await fs.mkdir(demoDir, { recursive: true });

for (const hours of [168, 48, 24]) {
  const { digest } = await runPipeline({ hours, onProgress: (m) => console.log(`[demo ${hours}h] ${m}`) });
  const problems = publishProblems(digest, defaultProfile);
  if (problems.length) throw new Error(`${hours}h snapshot is not publishable: ${problems.join('; ')}`);
  if (digest.stats.unanalyzed) throw new Error(`${hours}h snapshot has ${digest.stats.unanalyzed} unanalysed incidents (${digest.fallbackReason}); not writing a half-finished demo`);
  await fs.writeFile(path.join(demoDir, `digest-${hours}h.json`), `${JSON.stringify(forPublication(digest), null, 1)}\n`);
  console.log(`[demo ${hours}h] wrote demo/digest-${hours}h.json (${digest.incidents.length} incidents)`);
}
await fs.rm(scratch, { recursive: true, force: true });
console.log('\nSnapshots updated. Review `git diff --stat demo/`, then open a pull request; the site redeploys when it merges.');

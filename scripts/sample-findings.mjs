#!/usr/bin/env node
// Adds or removes three clearly labelled TEST incidents in the saved local digests, so the Act Now styling, the
// checklist and the agent handoff can be tried when the real news has nothing urgent.
//
//   node scripts/sample-findings.mjs add
//   node scripts/sample-findings.mjs remove
//
// They live only in the local data folder. A refresh rebuilds the digest and drops them. They are never written
// to demo/ and the demo build refuses a digest that contains them.

import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { DIGESTS_DIR, writeJsonAtomic } from '../src/store.mjs';

const ABOUT = 'https://github.com/sudoesnt/blastradius#trying-it-with-test-findings';

function testIncidents(now) {
  const base = {
    isTest: true, verdict: 'ACT_NOW', severity: 'CRITICAL', rootCauseBasis: 'INFERRED', evidenceQuote: '',
    cves: [], isKev: false, kevRansomware: false, kevProducts: [], packages: [], isRoundup: false, isNew: true,
    corroborationCount: 1, tier1Count: 0, signalScore: 0, earliestAt: now, latestAt: now, firstSeenAt: now,
    inventory: { checked: false, matches: [] }, validationNotes: ['Test data: this incident is not real.'],
    roleAngle: '', sources: [{ id: 'test', name: 'BlastRadius test data (not a real report)', tier: 2, category: 'test', url: ABOUT, title: 'Test finding', publishedAt: now }]
  };
  return [
    {
      ...base, id: 'inc-test-github-token',
      title: '[TEST] Sample: a GitHub token like yours was found in a public paste',
      rootCauseBucket: 'Stolen or Leaked Credential / Token', attackSurface: 'GitHub / developer tokens',
      tldrRootCause: 'Test item, nothing happened. Pretend a personal access token was copied from a laptop and posted publicly.',
      realisticRootCause: 'This is sample data for trying the dashboard. No token was leaked.',
      couldThisHappenToMe: 'Test item: treat it as if a token on this machine could be the one that leaked.',
      howItCouldHitYou: 'Sample path: a long-lived token in a file or shell history is copied by malware and reused.',
      lockItDown: ['Check this machine for GitHub tokens left in files or shell history.', 'Review your tokens and authorised apps in GitHub settings.'],
      playbooks: ['github-tokens', 'secrets-on-disk']
    },
    {
      ...base, id: 'inc-test-browser-extension',
      title: '[TEST] Sample: a browser extension update started reading mail',
      rootCauseBucket: 'Malware / Infostealer on Endpoint', attackSurface: 'Browser extensions',
      tldrRootCause: 'Test item, nothing happened. Pretend a popular extension shipped an update that reads webmail.',
      realisticRootCause: 'This is sample data for trying the dashboard. No extension was compromised.',
      couldThisHappenToMe: 'Test item: treat it as if one of your installed extensions could be the affected one.',
      howItCouldHitYou: 'Sample path: an extension you already trust updates itself and gains access to every site.',
      lockItDown: ['List the extensions installed in every browser profile on this machine.', 'Check whether any browser is under management you did not set up.'],
      playbooks: ['browser-extensions', 'persistence-and-infostealer-triage']
    },
    {
      ...base, id: 'inc-test-agent-config',
      title: '[TEST] Sample: an MCP server package was hijacked to run commands',
      rootCauseBucket: 'Supply Chain / 3rd-Party Compromise', attackSurface: 'AI coding agents / MCP servers',
      tldrRootCause: 'Test item, nothing happened. Pretend an MCP server fetched at start-up was replaced with a malicious release.',
      realisticRootCause: 'This is sample data for trying the dashboard. No package was hijacked.',
      couldThisHappenToMe: 'Test item: treat it as if an agent on this machine starts an unpinned MCP server.',
      howItCouldHitYou: 'Sample path: an agent runs the newest release of a server each time, with rules that approve its tools.',
      lockItDown: ['List the MCP servers your agents start and whether each is pinned to a version.', 'Review the rules that let an agent act without asking.'],
      playbooks: ['agent-config-audit', 'local-exposed-services']
    }
  ];
}

const count = (digest, v) => digest.incidents.filter((i) => i.verdict === v).length;

/** Returns the digest without test incidents. Pure. */
export function withoutTestFindings(digest) {
  const incidents = (digest.incidents || []).filter((i) => !i.isTest);
  const ids = new Set((digest.incidents || []).filter((i) => i.isTest).map((i) => i.id));
  const next = { ...digest, incidents, topLockdownChecklist: (digest.topLockdownChecklist || []).filter((c) => !ids.has(c.incidentId)) };
  delete next.testFindings;
  next.stats = { ...digest.stats, actNow: count(next, 'ACT_NOW'), incidentsAnalyzed: incidents.filter((i) => i.verdict !== 'UNANALYZED').length, inferred: incidents.filter((i) => i.rootCauseBasis === 'INFERRED').length };
  return next;
}

/** Returns the digest with the three test incidents first. Pure. */
export function withTestFindings(digest, now = new Date().toISOString()) {
  const clean = withoutTestFindings(digest);
  const added = testIncidents(now);
  const checks = added.flatMap((inc) => inc.lockItDown.map((action, i) => ({
    id: `${inc.id}-${i + 1}`, verdict: inc.verdict, severity: inc.severity, action, incidentId: inc.id, incidentTitle: inc.title
  })));
  const next = { ...clean, testFindings: added.length, incidents: [...added, ...clean.incidents], topLockdownChecklist: [...checks, ...clean.topLockdownChecklist] };
  next.stats = { ...clean.stats, actNow: count(next, 'ACT_NOW'), incidentsAnalyzed: clean.stats.incidentsAnalyzed + added.length, inferred: (clean.stats.inferred || 0) + added.length };
  return next;
}

async function main(mode) {
  if (mode !== 'add' && mode !== 'remove') {
    console.log('Usage: node scripts/sample-findings.mjs add | remove');
    process.exit(1);
  }
  let files = [];
  try { files = (await fs.readdir(DIGESTS_DIR)).filter((f) => /^latest(-\d+h)?\.json$/.test(f)); } catch { files = []; }
  if (!files.length) {
    console.log('No saved digest yet. Run `npm run digest` first.');
    process.exit(1);
  }
  for (const f of files) {
    const file = path.join(DIGESTS_DIR, f);
    const digest = JSON.parse(await fs.readFile(file, 'utf8'));
    const next = mode === 'add' ? withTestFindings(digest) : withoutTestFindings(digest);
    await writeJsonAtomic(file, next);
    console.log(`${f}: ${mode === 'add' ? 'added 3 test findings' : 'test findings removed'} (Act Now is now ${next.stats.actNow})`);
  }
  console.log(mode === 'add'
    ? 'Reload the dashboard. They are marked [TEST], and a refresh or `node scripts/sample-findings.mjs remove` clears them.'
    : 'Reload the dashboard.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) await main(process.argv[2]);

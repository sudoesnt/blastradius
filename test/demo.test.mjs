// The read-only demo site: build it from a snapshot, serve it as plain files, and run the dashboard against it.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { once } from 'node:events';
import { pathToFileURL } from 'node:url';
import { installFakeDom } from './helpers/fake-dom.mjs';
import { buildDemo, publishProblems, forPublication } from '../scripts/build-demo.mjs';

const ROOT = path.resolve(import.meta.dirname, '..');
const defaultProfile = JSON.parse(await fs.readFile(path.join(ROOT, 'config', 'profile.json'), 'utf8'));
const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'blastradius-demo-test-'));
const demoDir = path.join(tmp, 'demo');
const outDir = path.join(tmp, 'dist');

const digest = {
  schemaVersion: 2, generatedAt: '2026-11-27T12:00:00.000Z', hours: 168,
  windowStart: '2026-11-20T12:00:00.000Z', windowEnd: '2026-11-27T12:00:00.000Z',
  roleId: defaultProfile.roleId, roleTitle: defaultProfile.roleTitle, stackContext: defaultProfile.stackContext, briefLabel: defaultProfile.briefLabel,
  analysisEngine: 'test', fallbackReason: null, executiveSummary: 'Summary.',
  stats: { sourcesTotal: 1, sourcesEnabled: 1, sourcesFullCoverage: 1, sourcesPartial: 0, sourcesProblem: 0, rawItemsKept: 1, clustersTotal: 1, incidentsAnalyzed: 1, unanalyzed: 0, newSinceLast: 0, actNow: 0, watchHarden: 1, customerBrief: 0, notApplicable: 0, kevCount: 0, disclosed: 1, inferred: 0, unknownCause: 0 },
  rootCauseBreakdown: [{ bucket: 'Stolen or Leaked Credential / Token', count: 1 }],
  topLockdownChecklist: [{ id: 'inc-0000000000-abc', verdict: 'WATCH_HARDEN', severity: 'HIGH', action: 'Review tokens', incidentId: 'inc-0000000000', incidentTitle: 'Acme breach' }],
  incidents: [{
    id: 'inc-0000000000', title: 'Acme breach', verdict: 'WATCH_HARDEN', severity: 'HIGH', rootCauseBucket: 'Stolen or Leaked Credential / Token',
    rootCauseBasis: 'DISCLOSED', evidenceQuote: 'used a stolen token', attackSurface: 'CI', tldrRootCause: 'A stolen token was used.',
    realisticRootCause: 'Detail.', couldThisHappenToMe: 'Yes.', howItCouldHitYou: 'Path.', lockItDown: ['Review tokens'], roleAngle: '', playbooks: ['github-tokens'], validationNotes: [],
    cves: [], isKev: false, kevRansomware: false, corroborationCount: 1, latestAt: '2026-11-26T12:00:00.000Z', isNew: false,
    inventory: { checked: false, matches: [] }, sources: [{ name: 'Wire', tier: 1, url: 'https://wire.test/acme' }]
  }],
  ransomware: { totalVictims: 0, capped: false, topGroups: [], topSectors: [], recent: [] },
  sourceHealth: [{ id: 'wire', name: 'Wire', tier: 1, category: 'breach-news', status: 'ok', coverage: 'full', coverageNote: '', inStoreWindowCount: 1 }]
};

let server;
let baseUrl;

before(async () => {
  await fs.mkdir(demoDir, { recursive: true });
  await fs.writeFile(path.join(demoDir, 'digest-168h.json'), JSON.stringify(digest));
  await buildDemo(outDir, { demoDir });
  // A bare static file server, standing in for GitHub Pages (served from a sub-path, like a project site).
  server = http.createServer(async (req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/blastradius\//, '');
    try {
      const body = await fs.readFile(path.join(outDir, rel || 'index.html'));
      res.writeHead(200);
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end('not found');
    }
  }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  baseUrl = `http://127.0.0.1:${server.address().port}/blastradius/`;
});

after(() => server?.close());

test('a snapshot built for a personal profile or carrying inventory results is refused', () => {
  assert.deepEqual(publishProblems(digest, defaultProfile), []);
  assert.ok(publishProblems({ ...digest, roleTitle: 'Field CTO at Example Corp' }, defaultProfile).length);
  assert.ok(publishProblems({ ...digest, inventory: { packages: 900 } }, defaultProfile).length);
  const withLookup = { ...digest, incidents: [{ ...digest.incidents[0], inventory: { checked: true, matches: ['npm:left-pad'] } }] };
  assert.ok(publishProblems(withLookup, defaultProfile).length);
  assert.deepEqual(forPublication(withLookup).incidents[0].inventory, { checked: false, matches: [] });
});

test('the build refuses to publish a personal snapshot', async () => {
  const bad = path.join(tmp, 'bad');
  await fs.mkdir(bad, { recursive: true });
  await fs.writeFile(path.join(bad, 'digest-168h.json'), JSON.stringify({ ...digest, stackContext: 'My employer\'s exact stack' }));
  await assert.rejects(buildDemo(path.join(tmp, 'bad-out'), { demoDir: bad }), /cannot be published/);
});

test('the built site is static-marked, uses only relative paths and ships the snapshot', async () => {
  const html = await fs.readFile(path.join(outDir, 'index.html'), 'utf8');
  assert.match(html, /<html lang="en" data-static="1">/);
  assert.ok(!/(href|src)="\//.test(html), 'root-relative paths break on a project site served from /blastradius/');
  for (const f of ['app.js', 'styles.css', '.nojekyll', 'snapshot/digest-168h.json', 'snapshot/digest-168h.md', 'snapshot/handoffs-168h.json', 'snapshot/presets.json', 'snapshot/profile.json']) {
    await fs.access(path.join(outDir, f));
  }
});

test('the dashboard runs read-only against plain files', async () => {
  const requested = [];
  const dom = installFakeDom({ baseUrl, staticMode: true, onFetch: (u, o) => requested.push([o?.method || 'GET', String(u)]) });
  await import(pathToFileURL(path.join(outDir, 'app.js')).href);
  // The page module can only be loaded once per process; later tests in this file reuse it.
  globalThis.__demoDom = dom;
  globalThis.__demoRequests = requested;

  assert.equal((dom.html('incidentList').match(/<article/g) || []).length, 1);
  assert.match(dom.el('briefingTitle').textContent, /Last 7 Days/);
  assert.equal(dom.el('demoBanner').classList.contains('hidden'), false, 'the demo says it is a demo');
  assert.equal(dom.el('demoSnapshotDate').textContent, '2026-11-27');
  for (const id of ['refreshBtn', 'applyRoleBtn', 'saveProfileBtn', 'roleTitleInput', 'engineSelect']) {
    assert.equal(dom.el(id).disabled, true, `${id} is disabled`);
  }

  // Ticking a checklist item is kept in the browser and sends nothing anywhere.
  const box = { dataset: { actionKey: 'inc-0000000000::Review tokens' } };
  await dom.changeCheckbox(box, true);
  assert.match(globalThis.localStorage.getItem('blastradius-demo-state'), /Review tokens/);

  assert.ok(requested.every(([method]) => method === 'GET'), 'the demo only ever reads');
  assert.ok(requested.every(([, u]) => !u.includes('/api/')), 'and never calls a server API');

  // A window with no snapshot says so and shows nothing else.
  await dom.pills[0].listeners.click[0]();
  await new Promise((r) => setTimeout(r, 200));
  assert.match(dom.el('briefingTitle').textContent, /No 24h digest yet/);
  assert.match(dom.html('incidentList'), /No 24h snapshot in this demo/);
});

test('the demo ships a ready-made agent prompt for each actionable incident, with no receipt to write', async () => {
  const prompts = JSON.parse(await fs.readFile(path.join(outDir, 'snapshot', 'handoffs-168h.json'), 'utf8'));
  assert.deepEqual(Object.keys(prompts).filter((k) => k.startsWith('inc-')), ['inc-0000000000']);
  // Every reviewed playbook is also offered as an on-demand checkup.
  const checkups = Object.keys(prompts).filter((k) => k.startsWith('checkup-'));
  assert.ok(checkups.length >= 8 && checkups.includes('checkup-agent-config-audit'));
  assert.ok(!checkups.includes('checkup-package-exposure'), 'a playbook that needs an incident is not a checkup');
  assert.ok(prompts['checkup-cloud-cli-credentials'].includes('Routine check') && !prompts['checkup-cloud-cli-credentials'].includes('## Receipt'));
  await fs.access(path.join(outDir, 'snapshot', 'playbooks.json'));
  const prompt = prompts['inc-0000000000'];
  assert.ok(prompt.includes('gh auth status'), 'built from the reviewed playbook');
  assert.ok(prompt.includes('Make a change only after the person says yes'));
  assert.ok(!prompt.includes('## Receipt') && !prompt.includes('receipt file'), 'a public page has nowhere to send a receipt');
  assert.ok(!prompt.includes(os.homedir()) && !prompt.includes(os.tmpdir()), 'no paths from the machine that built the demo');
});

test('in the demo the agent button copies the prompt and sends nothing', async () => {
  // The dashboard module is already loaded by the earlier test in this file; reuse its page.
  const dom = globalThis.__demoDom;
  let copied = null;
  Object.defineProperty(globalThis, 'navigator', { value: { clipboard: { writeText: async (t) => { copied = t; } } }, configurable: true });
  const before = globalThis.__demoRequests.length;

  // The earlier test left the page on the empty 24h window; go back to the 7-day snapshot.
  await dom.pills[2].listeners.click[0]();
  await new Promise((r) => setTimeout(r, 200));
  assert.match(dom.html('incidentList'), /data-handoff="inc-0000000000"[^>]*>Copy the prompt for your agent/);
  await dom.pressInList('incidentList', 'data-handoff]', { handoff: 'inc-0000000000' });
  assert.ok(copied && copied.includes('gh auth status'));
  assert.match(dom.html('incidentList'), /Copied. Paste it into your own agent/);

  await dom.pressInList('incidentList', 'data-handoff-show', { handoffShow: 'inc-0000000000' });
  assert.match(dom.html('incidentList'), /<pre class="handoff-prompt">/);

  const made = globalThis.__demoRequests.slice(before);
  assert.ok(made.every(([method, u]) => method === 'GET' && !u.includes('/api/')), 'only static files were read');
});

test('test findings can be added and removed cleanly, and can never be published', async () => {
  const { withTestFindings, withoutTestFindings } = await import('../scripts/sample-findings.mjs');
  const added = withTestFindings(digest, '2026-11-27T12:00:00.000Z');
  assert.equal(added.incidents.length, digest.incidents.length + 3);
  assert.equal(added.stats.actNow, digest.stats.actNow + 3);
  assert.ok(added.incidents.slice(0, 3).every((i) => i.isTest && i.verdict === 'ACT_NOW' && i.title.startsWith('[TEST]') && i.playbooks.length));
  assert.ok(added.incidents.slice(0, 3).every((i) => /nothing happened/.test(i.tldrRootCause) && i.rootCauseBasis !== 'DISCLOSED'), 'they never claim a source said anything');
  assert.equal(added.topLockdownChecklist.length, digest.topLockdownChecklist.length + 6);

  // Adding twice does not double up, and removing restores the original.
  assert.equal(withTestFindings(added).incidents.length, digest.incidents.length + 3);
  const removed = withoutTestFindings(added);
  assert.deepEqual(removed.incidents, digest.incidents);
  assert.deepEqual(removed.topLockdownChecklist, digest.topLockdownChecklist);
  assert.equal(removed.stats.actNow, digest.stats.actNow);
  assert.equal(removed.testFindings, undefined);

  // A public page must never carry them.
  assert.ok(publishProblems(added, defaultProfile).some((p) => /test findings/.test(p)));
  const dir = path.join(tmp, 'with-tests');
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(path.join(dir, 'digest-168h.json'), JSON.stringify(added));
  await assert.rejects(buildDemo(path.join(tmp, 'with-tests-out'), { demoDir: dir }), /test findings/);
});

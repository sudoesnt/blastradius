// Offline end-to-end run: recorded-style feeds -> store -> clusters -> analysis (stub model) -> digest ->
// Markdown -> local server -> dashboard render. No network and no model, so it is deterministic.
//
// It checks properties that must hold for ANY digest, not one expected output, and it leaves the rendered
// digest behind as an artifact so a reviewer can look at what the change produces instead of only the diff.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { once } from 'node:events';
import { installFakeDom } from './helpers/fake-dom.mjs';

const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'blastradius-e2e-'));
process.env.BLASTRADIUS_DATA_DIR = dataDir;
for (const k of ['ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'OPENAI_API_KEY', 'X_BEARER_TOKEN', 'GITHUB_TOKEN']) delete process.env[k];

const { runPipeline } = await import('../src/cli.mjs');
const { startServer } = await import('../src/server.mjs');
const { renderMarkdownDigest, loadChecklistState } = await import('../src/store.mjs');


// ---------- fixtures (dates are relative to now so they never age out of the window) ----------

const ago = (hours) => new Date(Date.now() - hours * 3600000);
const XSS = '<img src=x onerror=alert(1)>';

const SOURCES = [
  { id: 'kev', name: 'KEV Catalog', url: 'https://fixture.test/kev.json', type: 'cisa-kev', tier: 1, category: 'exploitation', weight: 10, enabled: true },
  { id: 'wire', name: 'Wire News', url: 'https://fixture.test/wire.xml', type: 'rss', tier: 1, category: 'breach-news', weight: 9, enabled: true },
  { id: 'daily', name: 'Daily Sec', url: 'https://fixture.test/daily.xml', type: 'rss', tier: 2, category: 'breach-news', weight: 7, enabled: true },
  { id: 'ghsa', name: 'Advisory DB', url: 'https://fixture.test/ghsa.json', type: 'github-advisories', tier: 2, category: 'supply-chain', weight: 8, enabled: true },
  { id: 'dead', name: 'Dead Feed', url: 'https://fixture.test/dead.xml', type: 'rss', tier: 2, category: 'breach-news', weight: 5, enabled: true },
  { id: 'off', name: 'Needs Token', url: 'https://fixture.test/x', type: 'x-api', tier: 2, category: 'social', weight: 5, enabled: true, requiresEnv: 'X_BEARER_TOKEN' }
];

const rss = (items) => `<rss version="2.0"><channel>${items.map((i) =>
  `<item><title><![CDATA[${i.title}]]></title><link>${i.url}</link><pubDate>${ago(i.hoursAgo).toUTCString()}</pubDate><description><![CDATA[${i.body}]]></description></item>`).join('')}</channel></rss>`;

const FEEDS = {
  'https://fixture.test/kev.json': () => JSON.stringify({
    vulnerabilities: [
      { cveID: 'CVE-2026-1001', vendorProject: 'Orbit', product: 'Gateway', vulnerabilityName: 'Orbit Gateway Authentication Bypass Vulnerability', dateAdded: ago(30).toISOString().slice(0, 10), shortDescription: 'Orbit Gateway contains an authentication bypass in the management interface that allows remote attackers to gain administrator access.', requiredAction: 'Apply mitigations per vendor instructions', dueDate: '2026-12-20', knownRansomwareCampaignUse: 'Unknown' },
      { cveID: 'CVE-2026-1002', vendorProject: 'Orbit', product: 'Gateway', vulnerabilityName: 'Orbit Gateway Command Injection Vulnerability', dateAdded: ago(30).toISOString().slice(0, 10), shortDescription: 'Orbit Gateway contains a command injection flaw that allows an authenticated administrator to run operating system commands.', requiredAction: 'Apply mitigations per vendor instructions', dueDate: '2026-12-20', knownRansomwareCampaignUse: 'Known' },
      { cveID: 'CVE-2019-0001', vendorProject: 'Old', product: 'Thing', vulnerabilityName: 'Old Thing Vulnerability', dateAdded: '2019-01-01', shortDescription: 'Outside the window.', requiredAction: 'n/a', dueDate: '2019-02-01' }
    ]
  }),
  'https://fixture.test/wire.xml': () => rss([
    { title: 'Acme confirms breach after stolen CI token used to push code', url: 'https://wire.test/acme', hoursAgo: 20, body: 'Acme said an attacker used a stolen continuous integration token to push malicious code to a production repository. Customer records were copied.' },
    { title: 'Orbit Gateway flaws exploited in the wild (CVE-2026-1001)', url: 'https://wire.test/orbit', hoursAgo: 26, body: 'Attackers are chaining an authentication bypass with command injection on internet-facing Orbit Gateway appliances.' },
    { title: `Retailer Northwind discloses intrusion ${XSS}`, url: 'https://wire.test/northwind', hoursAgo: 10, body: 'Northwind said it detected unauthorised access to its network and is investigating. It did not say how the intruders got in. [[Private Note]]' },
    { title: 'Weekly Recap: Orbit, Acme and a whole lot more', url: 'https://wire.test/recap', hoursAgo: 5, body: 'A roundup of the week including the Acme breach and exploited Orbit Gateway vulnerability.' }
  ]),
  'https://fixture.test/daily.xml': () => rss([
    { title: 'Acme breach: stolen CI token let attacker push malicious code', url: 'https://daily.test/acme', hoursAgo: 18, body: 'A stolen CI token was used to push code into Acme production, the company confirmed, in a breach affecting customer records.' },
    { title: 'Happy holidays from the Daily Sec team', url: 'https://daily.test/holidays', hoursAgo: 4, body: 'Thanks for reading. We will be back after the break with more vulnerability and breach coverage.' },
    { title: 'An old vulnerability story', url: 'https://daily.test/old', hoursAgo: 24 * 30, body: 'Published a month ago, so it must not appear in a 7-day window.' }
  ]),
  'https://fixture.test/ghsa.json': () => JSON.stringify([
    { summary: 'widgetlib allows remote code execution via crafted template', description: 'widgetlib renders attacker-controlled templates without sandboxing, which allows remote code execution in applications that pass user input to render().', html_url: 'https://advisories.test/GHSA-1', published_at: ago(40).toISOString(), cve_id: 'CVE-2026-2001', cvss: { score: 9.8 }, vulnerabilities: [{ package: { ecosystem: 'npm', name: 'widgetlib' } }] }
  ])
};

let networkCalls = 0;
const realFetch = globalThis.fetch;
function installFeedStub() {
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.startsWith('http://127.0.0.1')) return realFetch(url, opts);
    networkCalls++;
    if (FEEDS[u]) return new Response(FEEDS[u](), { status: 200 });
    if (u.startsWith('https://fixture.test/')) return new Response('gone', { status: 404 });
    throw new Error(`e2e test attempted a real network call: ${u}`);
  };
}

// ---------- stub model: deterministic, and deliberately wrong in two ways the validator must catch ----------

const modelCalls = { merge: 0, analyse: 0, summary: 0 };
async function stubModel(_engine, system, user) {
  if (system.startsWith('You group security news headlines')) {
    modelCalls.merge++;
    return { groups: [] };
  }
  if (system.includes('two-sentence summary')) {
    modelCalls.summary++;
    return { executiveSummary: 'Stolen CI tokens and exposed gateway appliances led this period. Check your CI token inventory.' };
  }
  modelCalls.analyse++;
  const clusters = JSON.parse(user.slice(user.lastIndexOf('<clusters>') + 10, user.lastIndexOf('</clusters>')));
  return {
    incidents: clusters.map((c) => {
      const ev = c.evidence;
      if (/happy holidays/i.test(ev)) return { clusterId: c.clusterId, skip: true };
      const base = {
        clusterId: c.clusterId, title: c.leadTitle.slice(0, 90), severity: 'HIGH', attackSurface: 'Test surface',
        realisticRootCause: 'Detail.', howItCouldHitYou: 'Path.', roleAngle: ''
      };
      if (/Acme/.test(ev)) {
        return { ...base, verdict: 'WATCH_HARDEN', rootCauseBucket: 'Stolen or Leaked Credential / Token', rootCauseBasis: 'DISCLOSED',
          evidenceQuote: 'used a stolen continuous integration token to push malicious code', tldrRootCause: 'A stolen CI token was used to push code.',
          couldThisHappenToMe: 'Yes if CI tokens are long-lived.', lockItDown: ['Review CI tokens in your repository settings'] };
      }
      if (/Orbit/.test(ev)) {
        return { ...base, verdict: 'CUSTOMER_BRIEF', rootCauseBucket: 'Exploited Vulnerability (Internet-Facing)', rootCauseBasis: 'DISCLOSED',
          // Wrong on purpose: this sentence is not in the evidence, so it must be downgraded to INFERRED.
          evidenceQuote: 'the vendor confirmed a default administrator password was to blame', tldrRootCause: 'Authentication bypass chained with command injection.',
          couldThisHappenToMe: 'Only if you run Orbit Gateway.', lockItDown: ['should be dropped: not an actionable verdict'] };
      }
      if (/widgetlib/.test(ev)) {
        // Wrong on purpose: claims Act Now for a package the inventory says is not installed.
        return { ...base, verdict: 'ACT_NOW', rootCauseBucket: 'Exploited Vulnerability (Client / Local)', rootCauseBasis: 'DISCLOSED',
          evidenceQuote: 'renders attacker-controlled templates without sandboxing', tldrRootCause: 'Unsandboxed template rendering allows code execution.',
          couldThisHappenToMe: 'Yes, update widgetlib now.', lockItDown: ['Update widgetlib'] };
      }
      // Model output is untrusted too: this title carries markup that the dashboard and the export must neutralise.
      return { ...base, title: `Northwind intrusion ${XSS} [[Private Note]]`, verdict: 'NOT_APPLICABLE', rootCauseBucket: 'Unknown / Not Disclosed', rootCauseBasis: 'UNKNOWN', evidenceQuote: '',
        tldrRootCause: 'Not disclosed.', couldThisHappenToMe: 'No.', lockItDown: [] };
    })
  };
}

// ---------- run ----------

let first;
let second;
let server;
let baseUrl;

before(async () => {
  installFeedStub();
  await fs.writeFile(path.join(dataDir, 'inventory.json'), JSON.stringify({ scannedAt: new Date().toISOString(), roots: ['/code'], manifestCount: 1, packages: { npm: ['left-pad'], pip: [], go: [] } }));
  first = (await runPipeline({ hours: 168, sources: SOURCES, call: stubModel })).digest;
  second = (await runPipeline({ hours: 168, sources: SOURCES, call: stubModel })).digest;
  server = startServer(0);
  await once(server, 'listening');
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  server?.close();
  // Leave the rendered digest for a human (CI publishes it as the run summary and an artifact).
  const out = process.env.BLASTRADIUS_E2E_OUT;
  if (out && first) {
    await fs.mkdir(out, { recursive: true });
    await fs.writeFile(path.join(out, 'digest.md'), renderMarkdownDigest(first));
    await fs.writeFile(path.join(out, 'digest.json'), JSON.stringify(first, null, 2));
  }
});

const byTitle = (d, re) => d.incidents.find((i) => re.test(i.title));

test('the run made no real network calls', () => {
  assert.ok(networkCalls > 0, 'fixtures were served');
});

test('window and noise: old items, roundups and greetings are not incidents', () => {
  assert.equal(first.incidents.some((i) => /old vulnerability story|Weekly Recap|Happy holidays/i.test(i.title)), false);
  assert.equal(first.stats.skippedNotSecurity, 1, 'the greeting reaches the model and is skipped there');
});

test('clustering: one incident per event, corroboration counts independent publishers', () => {
  const acme = byTitle(first, /Acme/);
  assert.equal(first.incidents.filter((i) => /Acme/.test(i.title)).length, 1);
  assert.equal(acme.corroborationCount, 2);
  const orbit = first.incidents.filter((i) => i.cves.includes('CVE-2026-1001'));
  assert.equal(orbit.length, 1, 'KEV entries for one product and the news story about them are one incident');
  assert.deepEqual([...orbit[0].cves].sort(), ['CVE-2026-1001', 'CVE-2026-1002']);
  assert.equal(orbit[0].isKev && orbit[0].kevRansomware, true);
});

test('invariants that must hold for every incident in any digest', () => {
  const ids = new Set();
  for (const inc of first.incidents) {
    assert.match(inc.id, /^inc-[0-9a-f]{10}$/);
    assert.ok(!ids.has(inc.id), 'ids are unique');
    ids.add(inc.id);
    assert.ok(inc.sources.length >= 1 && inc.sources.every((s) => /^https:\/\//.test(s.url)), 'every incident links to its sources');
    assert.ok(['ACT_NOW', 'WATCH_HARDEN', 'CUSTOMER_BRIEF', 'NOT_APPLICABLE', 'UNANALYZED'].includes(inc.verdict));
    if (inc.rootCauseBasis === 'DISCLOSED') assert.ok(inc.evidenceQuote, 'a stated cause always carries its quote');
    else assert.equal(inc.evidenceQuote, '', 'no quote is shown for an inferred or undisclosed cause');
    if (inc.rootCauseBucket === 'Unknown / Not Disclosed') assert.equal(inc.rootCauseBasis, 'UNKNOWN');
    if (!['ACT_NOW', 'WATCH_HARDEN'].includes(inc.verdict)) assert.equal(inc.lockItDown.length, 0, 'only actionable verdicts carry actions');
    if (inc.inventory.checked && !inc.inventory.matches.length) assert.notEqual(inc.verdict, 'ACT_NOW');
  }
  const s = first.stats;
  assert.equal(s.actNow + s.watchHarden + s.customerBrief + s.notApplicable + s.unanalyzed, first.incidents.length, 'verdict counts add up');
  assert.equal(s.disclosed + s.inferred + s.unknownCause, s.incidentsAnalyzed, 'basis counts add up');
  assert.equal(first.rootCauseBreakdown.reduce((a, b) => a + b.count, 0), s.incidentsAnalyzed);
});

test('the validator overrules the model when the evidence or inventory disagrees', () => {
  const acme = byTitle(first, /Acme/);
  assert.equal(acme.rootCauseBasis, 'DISCLOSED');
  const orbit = first.incidents.find((i) => i.cves.includes('CVE-2026-1001'));
  assert.equal(orbit.rootCauseBasis, 'INFERRED', 'a quote that is not in the source text cannot support a stated cause');
  assert.ok(orbit.validationNotes.length);
  const widget = byTitle(first, /widgetlib/);
  assert.deepEqual([widget.inventory.checked, widget.inventory.matches.length], [true, 0]);
  assert.equal(widget.verdict, 'WATCH_HARDEN', 'a package that is not installed cannot be Act Now');
});

test('coverage is reported honestly per source', () => {
  const cov = Object.fromEntries(first.sourceHealth.map((s) => [s.id, s.coverage]));
  assert.equal(cov.dead, 'error');
  assert.equal(cov.off, 'unconfigured');
  assert.equal(cov.kev, 'full');
  assert.equal(cov.wire, 'partial', 'a feed whose oldest item is newer than the window start does not cover the window');
  assert.equal(first.stats.sourcesFullCoverage, first.sourceHealth.filter((s) => s.coverage === 'full').length);
});

test('a second run is stable: same ids, same verdicts, nothing re-analysed, nothing "new"', () => {
  assert.deepEqual(second.incidents.map((i) => [i.id, i.verdict, i.rootCauseBasis]), first.incidents.map((i) => [i.id, i.verdict, i.rootCauseBasis]));
  assert.deepEqual(second.topLockdownChecklist.map((c) => c.id), first.topLockdownChecklist.map((c) => c.id));
  assert.equal(second.stats.fromCache, second.stats.incidentsAnalyzed + second.stats.skippedNotSecurity);
  assert.equal(modelCalls.analyse, 1, 'only the first run sends incidents to the model');
  assert.equal(second.stats.newSinceLast, 0);
});

test('markdown export is safe to drop into a notes vault', () => {
  const md = renderMarkdownDigest(first);
  assert.ok(md.includes('\\<img') && !/(^|[^\\])<img/.test(md), 'markup is backslash-escaped, never raw HTML');
  assert.ok(!md.includes('[[Private Note]]'), 'no wiki-links from feed text');
  assert.match(md, /What happened \(disclosed\)/);
  assert.match(md, /What happened \(inferred\)/);
});

test('dashboard renders the digest, escapes feed text, and never shows another window', async () => {
  const dom = installFakeDom({ baseUrl });
  await import('../public/app.js');
  const list = dom.html('incidentList');
  assert.equal((list.match(/<article/g) || []).length, first.incidents.length);
  const rendered = dom.allHtml();
  assert.ok(!/undefined|NaN|\[object Object\]/.test(rendered), 'no unrendered values');
  assert.ok(!rendered.includes('<img src=x'), 'feed and model text is escaped');
  assert.ok(rendered.includes('&lt;img src=x'), 'and still visible as text');
  assert.equal((list.match(/class="basis /g) || []).length, first.stats.incidentsAnalyzed, 'every analysed card says how its cause is known');
  assert.ok(dom.html('digestNotice').includes('did not cover the whole window'), 'coverage gaps are stated up front');

  await dom.pills[0].listeners.click[0]();
  await new Promise((r) => setTimeout(r, 300));
  assert.match(dom.el('briefingTitle').textContent, /No 24h digest yet/);
  assert.equal((dom.html('incidentList').match(/<article/g) || []).length, 0);
  assert.deepEqual(dom.pills.filter((p) => p.classList.contains('active')).map((p) => p.dataset.hours), ['24']);
});

test('checklist state survives through the server with stable action ids', async () => {
  const key = `${first.topLockdownChecklist[0].incidentId}::${first.topLockdownChecklist[0].action.slice(0, 64)}`;
  const res = await realFetch(`${baseUrl}/api/state`, {
    method: 'POST', headers: { 'content-type': 'application/json', origin: baseUrl }, body: JSON.stringify({ checkedActions: { [key]: true } })
  });
  assert.equal(res.status, 200);
  assert.equal((await loadChecklistState()).checkedActions[key], true);
  assert.ok(second.topLockdownChecklist.some((c) => `${c.incidentId}::${c.action.slice(0, 64)}` === key), 'the same key still exists after a re-run');
});

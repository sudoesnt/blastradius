import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';

// Isolate all on-disk state before any module reads DATA_DIR.
process.env.BLASTRADIUS_DATA_DIR = await fs.mkdtemp(path.join(os.tmpdir(), 'blastradius-test-'));

const { parseFeedXml, stripHtml } = await import('../src/xml.mjs');
const { groupItems, clusterIncidents, clusterIdFor, mergeGroups, isRoundup } = await import('../src/cluster.mjs');
const { validateAnalysis, quoteInEvidence, analyzeClusters, ROOT_CAUSE_BUCKETS } = await import('../src/analyze.mjs');
const { assessCoverage, isSignalItem, safeHttpUrl } = await import('../src/ingest.mjs');
const { matchInventory } = await import('../src/inventory.mjs');
const { loadLatestDigest, saveDigest, renderMarkdownDigest } = await import('../src/store.mjs');
const { extractJsonObject, CLAUDE_CLI_ARGS } = await import('../src/llm.mjs');

const item = (o) => ({
  title: '', summary: '', url: `https://example.test/${Math.random()}`, publishedAt: '2026-11-25T10:00:00.000Z',
  cves: [], isKev: false, sourceId: 's1', sourceName: 'Source One', sourceTier: 1, sourceCategory: 'breach-news',
  sourceWeight: 8, sourceOwner: o.sourceId || 's1', ...o
});

// ---------- feed parsing ----------

test('parses RSS with CDATA and entities', () => {
  const xml = `<rss><channel><item><title><![CDATA[Acme & Co breached]]></title><link>https://a.test/1</link>
    <pubDate>Wed, 25 Nov 2026 10:00:00 GMT</pubDate><description>&lt;p&gt;Attackers used a &amp;quot;stolen token&amp;quot;.&lt;/p&gt;</description></item></channel></rss>`;
  const [it] = parseFeedXml(xml);
  assert.equal(it.title, 'Acme & Co breached');
  assert.equal(it.url, 'https://a.test/1');
  assert.equal(it.publishedAt, '2026-11-25T10:00:00.000Z');
  assert.ok(!it.summary.includes('<p>'));
});

test('parses Atom and prefers the alternate link', () => {
  const xml = `<feed><entry><title>Post</title><link rel="self" href="https://a.test/self"/><link rel="alternate" href="https://a.test/post"/>
    <updated>2026-11-25T10:00:00Z</updated><summary>Body text here</summary></entry></feed>`;
  assert.equal(parseFeedXml(xml)[0].url, 'https://a.test/post');
});

test('stripHtml removes script bodies', () => {
  assert.equal(stripHtml('a<script>alert(1)</script>b'), 'a b');
});

test('only http(s) links survive', () => {
  assert.equal(safeHttpUrl('javascript:alert(1)'), '');
  assert.equal(safeHttpUrl('https://ok.test/x'), 'https://ok.test/x');
});

// ---------- filtering and coverage ----------

test('roundups and sponsored posts are filtered as noise', () => {
  const src = { type: 'rss', id: 'x' };
  assert.equal(isSignalItem({ title: 'Weekly Recap: VMware 0-Day and more', summary: 'exploit' }, src), false);
  assert.equal(isSignalItem({ title: 'Sponsored: a vendor on ransomware', summary: 'ransomware' }, src), false);
  assert.equal(isSignalItem({ title: 'Acme confirms breach of customer data', summary: '' }, src), true);
});

test('coverage: a feed that only reaches back a day is partial for a 7-day window', () => {
  const now = new Date('2026-11-27T12:00:00Z');
  const cutoffDate = new Date(now.getTime() - 168 * 3600000);
  const meta = { status: 'ok', fetchedCount: 15, inWindowCount: 15, oldestFetchedAt: '2026-11-26T12:00:00.000Z', newestFetchedAt: '2026-11-27T11:00:00.000Z' };
  assert.equal(assessCoverage(meta, { cutoffDate, now, firstCollectedAt: null }).coverage, 'partial');
  // Once collection has been running since before the window started, the same feed is fully covered.
  assert.equal(assessCoverage(meta, { cutoffDate, now, firstCollectedAt: '2026-11-10T00:00:00.000Z' }).coverage, 'full');
});

test('coverage: empty and stale feeds are not reported as healthy', () => {
  const now = new Date('2026-11-27T12:00:00Z');
  const cutoffDate = new Date(now.getTime() - 168 * 3600000);
  assert.equal(assessCoverage({ status: 'ok', fetchedCount: 0 }, { cutoffDate, now }).coverage, 'empty');
  const stale = { status: 'ok', fetchedCount: 25, oldestFetchedAt: '2025-06-13T00:00:00.000Z', newestFetchedAt: '2026-04-23T00:00:00.000Z' };
  assert.equal(assessCoverage(stale, { cutoffDate, now }).coverage, 'stale');
});

// ---------- clustering ----------

test('same CVE from different sources is one cluster with a stable id', () => {
  const a = item({ title: 'CISA KEV: Drupal Core RCE (CVE-2026-1111)', cves: ['CVE-2026-1111'], isKev: true, vendor: 'Drupal', product: 'Core', sourceId: 'kev' });
  const b = item({ title: 'Drupal warns of site takeover flaw exploited in attacks', cves: ['CVE-2026-1111'], sourceId: 'news' });
  const [c1] = clusterIncidents([a, b]);
  const [c2] = clusterIncidents([b, a, item({ title: 'Unrelated Kubernetes operator misconfiguration writeup', sourceId: 'other' })]
    ).filter((c) => c.cves.includes('CVE-2026-1111'));
  assert.equal(c1.corroborationCount, 2);
  assert.equal(c1.id, c2.id, 'id must not depend on input order or on other items in the run');
});

test('KEV entries for the same product merge even with different CVEs', () => {
  const mk = (cve, name) => item({ title: `CISA KEV: Mitel MiCollab — ${name} (${cve})`, cves: [cve], isKev: true, vendor: 'Mitel', product: 'MiCollab', sourceId: 'kev' });
  const groups = groupItems([mk('CVE-2026-1', 'Auth Bypass'), mk('CVE-2026-2', 'File Upload'), mk('CVE-2026-3', 'XML Injection')]);
  assert.equal(groups.length, 1);
});

test('a roundup neither joins nor attracts a cluster', () => {
  const kev = item({ title: 'CISA KEV: N-able MailAssure SSRF (CVE-2026-5)', cves: ['CVE-2026-5'], isKev: true, vendor: 'N-able', product: 'MailAssure', sourceId: 'kev' });
  const roundup = item({ title: 'Hackers Exploit 10 Vulnerabilities Across Mitel, Juniper and N-able', cves: ['CVE-2026-5'], sourceId: 'news' });
  assert.equal(isRoundup(roundup), true);
  const clusters = clusterIncidents([kev, roundup]);
  assert.equal(clusters.length, 2);
  assert.equal(clusters.find((c) => c.isKev).corroborationCount, 1, 'a roundup must not count as corroboration');
});

test('feeds from one publisher count as one independent source', () => {
  const blog = item({ title: 'CTO of RansomwareHelp indicted for wire fraud', sourceId: 'krebs', sourceOwner: 'krebs' });
  const toot = item({ title: 'New, from me: CTO of RansomwareHelp indicted for wire fraud', sourceId: 'masto-krebs', sourceOwner: 'krebs', sourceCategory: 'social' });
  const [c] = clusterIncidents([blog, toot]);
  assert.equal(c.sources.length, 2);
  assert.equal(c.corroborationCount, 1);
});

test('unrelated stories stay apart', () => {
  const a = item({ title: 'SAP confirms cyberattack, source code reportedly compromised', sourceId: 'a' });
  const b = item({ title: 'FIFA says personal and business information accessed in cyberattack', sourceId: 'b' });
  assert.equal(groupItems([a, b]).length, 2);
});

test('model-suggested merges are applied, unknown ids ignored', () => {
  const a = [item({ title: 'Hex package manager warns of potential data breach', url: 'https://x.test/a' })];
  const b = [item({ title: 'Hackers breach Erlang and Elixir package registry', url: 'https://x.test/b' })];
  const merged = mergeGroups([a, b], [[clusterIdFor(a), clusterIdFor(b), 'inc-doesnotexist']]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].length, 2);
});

// ---------- analysis validation ----------

const cluster = {
  id: 'inc-abc', leadTitle: 'Acme breached', isKev: false, kevRansomware: false, cves: [], corroborationCount: 2, tier1Count: 1,
  signalScore: 40, sources: [{ name: 'Source One', tier: 1, url: 'https://a.test' }], packages: [], kevProducts: [], isRoundup: false,
  earliestAt: '2026-11-25T10:00:00.000Z', latestAt: '2026-11-25T10:00:00.000Z',
  evidence: '[Source One] Acme breached. Acme said the attacker used a stolen employee GitHub token to push code into its CI pipeline.'
};
const good = {
  clusterId: 'inc-abc', title: 'Acme breached via stolen GitHub token', severity: 'HIGH', verdict: 'ACT_NOW',
  rootCauseBucket: 'Stolen or Leaked Credential / Token', rootCauseBasis: 'DISCLOSED',
  evidenceQuote: 'the attacker used a stolen employee GitHub token', attackSurface: 'GitHub / CI-CD',
  tldrRootCause: 'A stolen employee GitHub token was used to push code into CI.', couldThisHappenToMe: 'Yes if you hold long-lived GitHub tokens.',
  lockItDown: ['Review personal access tokens in GitHub settings', 'none']
};

test('a quote found in the evidence keeps DISCLOSED', () => {
  const v = validateAnalysis(good, cluster);
  assert.equal(v.rootCauseBasis, 'DISCLOSED');
  assert.equal(v.lockItDown.length, 1, 'placeholder actions are dropped');
});

test('a fabricated quote is removed and the claim downgraded to INFERRED', () => {
  const v = validateAnalysis({ ...good, evidenceQuote: 'the attacker exploited an unpatched Jenkins server' }, cluster);
  assert.equal(v.rootCauseBasis, 'INFERRED');
  assert.equal(v.evidenceQuote, '');
  assert.ok(v.validationNotes.length);
});

test('quote matching tolerates quotes and whitespace but not paraphrase', () => {
  assert.equal(quoteInEvidence('used a   stolen “employee” GitHub token', cluster.evidence), true);
  assert.equal(quoteInEvidence('used a pilfered staff GitHub credential', cluster.evidence), false);
  assert.equal(quoteInEvidence('Acme', cluster.evidence), false, 'trivially short quotes prove nothing');
});

test('unknown bucket forces UNKNOWN basis and an invalid bucket becomes Unknown', () => {
  assert.equal(validateAnalysis({ ...good, rootCauseBucket: 'Unknown / Not Disclosed' }, cluster).rootCauseBasis, 'UNKNOWN');
  assert.equal(validateAnalysis({ ...good, rootCauseBucket: 'Vibes' }, cluster).rootCauseBucket, 'Unknown / Not Disclosed');
});

test('entries for the wrong cluster, bad verdicts and missing text are rejected', () => {
  assert.equal(validateAnalysis({ ...good, clusterId: 'inc-other' }, cluster), null);
  assert.equal(validateAnalysis({ ...good, verdict: 'PANIC' }, cluster), null);
  assert.equal(validateAnalysis({ ...good, tldrRootCause: '' }, cluster), null);
  assert.equal(validateAnalysis({ ...good, lockItDown: [{ evil: 1 }, 42] }, cluster).lockItDown.length, 0);
});

test('inventory miss caps ACT_NOW; inventory hit is reported', () => {
  const inv = { roots: ['/code'], packages: { npm: ['left-pad'], pip: [], go: [] } };
  const c = { ...cluster, packages: [{ ecosystem: 'npm', name: 'ruflo' }] };
  const miss = matchInventory(c, inv, {});
  assert.deepEqual([miss.checked, miss.matches.length], [true, 0]);
  assert.equal(validateAnalysis(good, c, miss).verdict, 'WATCH_HARDEN');
  const hit = matchInventory({ ...c, packages: [{ ecosystem: 'npm', name: 'left-pad' }] }, inv, {});
  assert.deepEqual(hit.matches, ['npm:left-pad']);
  assert.equal(validateAnalysis(good, c, hit).verdict, 'ACT_NOW');
  assert.equal(matchInventory(cluster, inv, {}).checked, false, 'nothing to look up means not checked, not "no match"');
});

test('with no engine, incidents are listed unanalysed with no invented text', async () => {
  const out = await analyzeClusters([cluster], { roleTitle: 'Tester' }, { engine: 'none' });
  assert.equal(out.incidents[0].verdict, 'UNANALYZED');
  assert.equal(out.incidents[0].tldrRootCause, '');
  assert.equal(out.incidents[0].rootCauseBucket, null);
  assert.equal(out.rootCauseBreakdown.length, 0);
});

test('model failure leaves incidents unanalysed and says why', async () => {
  const call = async () => { throw new Error('boom'); };
  const out = await analyzeClusters([cluster], { roleTitle: 'Tester' }, { engine: 'claude-cli', call });
  assert.equal(out.incidents[0].verdict, 'UNANALYZED');
  assert.match(out.fallbackReason, /boom/);
});

test('results are cached: an unchanged incident is not sent to the model again', async () => {
  let calls = 0;
  const call = async (_e, system) => {
    calls++;
    return system.includes('two-sentence summary') ? { executiveSummary: 'Summary.' } : { incidents: [good] };
  };
  const cache = { entries: {} };
  const first = await analyzeClusters([cluster], { roleTitle: 'Tester' }, { engine: 'claude-cli', call, cache });
  assert.equal(first.incidents[0].verdict, 'ACT_NOW');
  const before = calls;
  const second = await analyzeClusters([cluster], { roleTitle: 'Tester' }, { engine: 'claude-cli', call, cache });
  assert.equal(second.stats.fromCache, 1);
  assert.equal(calls - before, 1, 'only the summary call should run');
  assert.equal(second.topLockdownChecklist[0].id, first.topLockdownChecklist[0].id, 'checklist ids are stable across runs');
});

test('items the model marks as not security content are dropped and counted', async () => {
  const call = async () => ({ incidents: [{ clusterId: 'inc-abc', skip: true }] });
  const out = await analyzeClusters([cluster], {}, { engine: 'claude-cli', call });
  assert.equal(out.incidents.length, 0);
  assert.equal(out.stats.skippedNotSecurity, 1);
});

// ---------- model call hardening ----------

test('claude CLI runs with no tools, no MCP and no user settings', () => {
  const a = CLAUDE_CLI_ARGS;
  assert.equal(a[a.indexOf('--tools') + 1], '');
  assert.equal(a[a.indexOf('--setting-sources') + 1], '');
  assert.ok(a.includes('--strict-mcp-config') && a.includes('--disable-slash-commands'));
});

test('extractJsonObject handles fences and surrounding text', () => {
  assert.deepEqual(extractJsonObject('note\n```json\n{"a":1}\n```'), { a: 1 });
  assert.throws(() => extractJsonObject('no json here'));
});

// ---------- store ----------

test('a missing window returns null instead of another window\'s digest', async () => {
  const digest = {
    generatedAt: '2026-11-27T12:00:00.000Z', hours: 168, windowStart: '2026-11-20T12:00:00.000Z', windowEnd: '2026-11-27T12:00:00.000Z',
    analysisEngine: 'none', stats: { sourcesFullCoverage: 1, sourcesTotal: 1, clustersTotal: 0 }, incidents: [], sourceHealth: []
  };
  await saveDigest(digest);
  assert.equal((await loadLatestDigest(168)).hours, 168);
  assert.equal(await loadLatestDigest(24), null);
});

test('markdown export neutralises feed text', () => {
  const md = renderMarkdownDigest({
    generatedAt: '2026-11-27T12:00:00.000Z', hours: 24, windowStart: '2026-11-26T12:00:00.000Z', windowEnd: '2026-11-27T12:00:00.000Z',
    roleTitle: 'Tester', analysisEngine: 'x', executiveSummary: 'ok', stats: { sourcesFullCoverage: 1, sourcesTotal: 1, clustersTotal: 1 },
    sourceHealth: [], topLockdownChecklist: [],
    incidents: [{
      verdict: 'CUSTOMER_BRIEF', title: 'Evil [[Private Note]] <script>x</script>\n# Heading', severity: 'LOW', rootCauseBucket: ROOT_CAUSE_BUCKETS[0],
      rootCauseBasis: 'INFERRED', attackSurface: 's', tldrRootCause: 't', couldThisHappenToMe: 'm', corroborationCount: 1,
      sources: [{ name: 'S', url: 'javascript:alert(1)' }]
    }]
  });
  assert.ok(!md.includes('[[Private Note]]'));
  assert.ok(!md.includes('<script>'));
  assert.ok(!md.includes('javascript:'));
});

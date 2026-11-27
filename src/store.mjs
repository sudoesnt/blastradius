import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.resolve(__dirname, '..');

// BLASTRADIUS_DATA_DIR lets tests (and a second profile) use an isolated data directory.
export const DATA_DIR = process.env.BLASTRADIUS_DATA_DIR
  ? path.resolve(process.env.BLASTRADIUS_DATA_DIR)
  : path.join(ROOT_DIR, 'data');
export const DIGESTS_DIR = path.join(DATA_DIR, 'digests');
export const STATE_PATH = path.join(DATA_DIR, 'state.json');
export const ITEMS_PATH = path.join(DATA_DIR, 'items.json');
export const ANALYSIS_CACHE_PATH = path.join(DATA_DIR, 'analysis-cache.json');
export const INVENTORY_PATH = path.join(DATA_DIR, 'inventory.json');

const ITEM_RETENTION_DAYS = 45;
const CACHE_RETENTION_DAYS = 45;

export function sha1(text) {
  return crypto.createHash('sha1').update(String(text)).digest('hex');
}

async function ensureDirs() {
  await fs.mkdir(DIGESTS_DIR, { recursive: true });
}

async function readJson(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch {
    return fallback;
  }
}

// Write to a temp file then rename, so a crash or a concurrent reader never sees a half-written file.
export async function writeJsonAtomic(file, obj) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(obj, null, 2), 'utf8');
  await fs.rename(tmp, file);
}

// ---------- Item store: accumulates feed items across runs so a time window is real ----------

export function itemKey(item) {
  return (item.url || `${item.sourceId}:${item.title}`).toLowerCase().replace(/\/+$/, '');
}

export async function loadItemStore() {
  const store = await readJson(ITEMS_PATH, null);
  if (!store || typeof store !== 'object') return { version: 1, sources: {}, items: {}, victims: {} };
  store.sources ||= {};
  store.items ||= {};
  store.victims ||= {};
  return store;
}

/**
 * Merge freshly fetched items into the store. Existing items keep their firstSeenAt.
 * `sourceIds` is every source that answered this run; its first collection time is what
 * lets us say honestly how far back each feed's coverage goes.
 */
export async function mergeIntoItemStore({ items = [], victims = [], sourceIds = [], now = new Date() }) {
  const store = await loadItemStore();
  const nowIso = now.toISOString();

  for (const id of sourceIds) {
    store.sources[id] ||= { firstCollectedAt: nowIso };
    store.sources[id].lastCollectedAt = nowIso;
  }
  for (const it of items) {
    const key = itemKey(it);
    const prev = store.items[key];
    store.items[key] = { ...it, firstSeenAt: prev?.firstSeenAt || nowIso };
  }
  for (const v of victims) {
    const key = `${v.group}|${v.victim}|${v.publishedAt?.slice(0, 10)}`.toLowerCase();
    if (!store.victims[key]) store.victims[key] = v;
  }

  const cutoff = now.getTime() - ITEM_RETENTION_DAYS * 86400000;
  for (const [k, it] of Object.entries(store.items)) {
    if (Date.parse(it.publishedAt || it.firstSeenAt) < cutoff) delete store.items[k];
  }
  for (const [k, v] of Object.entries(store.victims)) {
    if (Date.parse(v.publishedAt) < cutoff) delete store.victims[k];
  }

  await writeJsonAtomic(ITEMS_PATH, store);
  return store;
}

export function queryStore(store, cutoffDate) {
  const cut = cutoffDate.getTime();
  const byDate = (a, b) => Date.parse(b.publishedAt || 0) - Date.parse(a.publishedAt || 0);
  return {
    items: Object.values(store.items).filter((i) => Date.parse(i.publishedAt) >= cut).sort(byDate),
    victims: Object.values(store.victims).filter((v) => Date.parse(v.publishedAt) >= cut).sort(byDate)
  };
}

// ---------- Analysis cache: the same incident + same evidence + same profile => same verdict ----------

export async function loadAnalysisCache() {
  const cache = await readJson(ANALYSIS_CACHE_PATH, null);
  return cache && typeof cache === 'object' && cache.entries ? cache : { version: 1, entries: {} };
}

export async function saveAnalysisCache(cache, now = new Date()) {
  const cutoff = now.getTime() - CACHE_RETENTION_DAYS * 86400000;
  for (const [k, e] of Object.entries(cache.entries)) {
    if (Date.parse(e.analyzedAt) < cutoff) delete cache.entries[k];
  }
  await writeJsonAtomic(ANALYSIS_CACHE_PATH, cache);
}

// ---------- Digests ----------

export async function saveDigest(digest) {
  await ensureDirs();
  const stamp = digest.generatedAt.slice(0, 16).replace(/[:T]/g, '-');
  const windowTag = `${digest.hours}h`;
  const latestWindowPath = path.join(DIGESTS_DIR, `latest-${windowTag}.json`);
  const latestPath = path.join(DIGESTS_DIR, 'latest.json');
  const archivePath = path.join(DIGESTS_DIR, `digest-${stamp}-${windowTag}.json`);
  await Promise.all([
    writeJsonAtomic(latestWindowPath, digest),
    writeJsonAtomic(latestPath, digest),
    writeJsonAtomic(archivePath, digest)
  ]);
  return { latestPath, latestWindowPath, archivePath };
}

/**
 * With `hours`, returns the digest for exactly that window or null. It never substitutes a
 * different window: showing a 7-day digest under a "24h" label is worse than showing nothing.
 */
export async function loadLatestDigest(hours = null) {
  await ensureDirs();
  const h = hours == null ? null : Number(hours);
  if (h != null && (!Number.isFinite(h) || h <= 0)) return null;
  const target = h ? path.join(DIGESTS_DIR, `latest-${h}h.json`) : path.join(DIGESTS_DIR, 'latest.json');
  return readJson(target, null);
}

export async function listSavedDigests() {
  await ensureDirs();
  try {
    const files = await fs.readdir(DIGESTS_DIR);
    return files.filter((f) => f.startsWith('digest-') && f.endsWith('.json')).sort().reverse().slice(0, 20);
  } catch {
    return [];
  }
}

// ---------- Checklist state ----------

export async function loadChecklistState() {
  const state = await readJson(STATE_PATH, null);
  return state && typeof state === 'object'
    ? { checkedActions: state.checkedActions || {}, dismissedIncidents: state.dismissedIncidents || {}, updatedAt: state.updatedAt || null }
    : { checkedActions: {}, dismissedIncidents: {}, updatedAt: null };
}

export async function saveChecklistState(state) {
  const next = { ...state, updatedAt: new Date().toISOString() };
  await writeJsonAtomic(STATE_PATH, next);
  return next;
}

// ---------- Inventory ----------

export async function loadInventory() {
  return readJson(INVENTORY_PATH, null);
}

// ---------- Agent handoffs and receipts ----------
//
// A handoff is a folder with the prompt given to the person's agent. A receipt is the small JSON file the agent
// writes back when it is done. Both stay in the local data folder.

export const HANDOFFS_DIR = path.join(DATA_DIR, 'handoffs');
export const RECEIPTS_DIR = path.join(DATA_DIR, 'receipts');
const HANDOFF_ID = /^h-[0-9a-f]{12}$/;
const MAX_RECEIPT_BYTES = 64 * 1024;

/** Write the files for one handoff. `files` maps a plain file name to its text; `executable` names are made runnable. */
export async function saveHandoffFiles(id, files, executable = []) {
  if (!HANDOFF_ID.test(id)) throw new Error('bad handoff id');
  const dir = path.join(HANDOFFS_DIR, id);
  await fs.mkdir(dir, { recursive: true });
  await fs.mkdir(RECEIPTS_DIR, { recursive: true });
  for (const [name, text] of Object.entries(files)) {
    if (!/^[a-z0-9._-]+$/i.test(name)) throw new Error('bad handoff file name');
    await fs.writeFile(path.join(dir, name), text, 'utf8');
    if (executable.includes(name)) await fs.chmod(path.join(dir, name), 0o755);
  }
  return dir;
}

export const receiptPathFor = (id) => path.join(RECEIPTS_DIR, `${id}.json`);

/** Every handoff's metadata, newest first, each with the raw receipt its agent wrote (or null). Receipts are untrusted. */
export async function loadHandoffs() {
  let ids = [];
  try { ids = (await fs.readdir(HANDOFFS_DIR)).filter((n) => HANDOFF_ID.test(n)); } catch { return []; }
  const out = [];
  for (const id of ids) {
    const meta = await readJson(path.join(HANDOFFS_DIR, id, 'handoff.json'), null);
    if (!meta || meta.id !== id) continue;
    let receipt = null;
    let receiptAt = null;
    try {
      const file = receiptPathFor(id);
      const stat = await fs.stat(file);
      if (stat.isFile() && stat.size <= MAX_RECEIPT_BYTES) {
        receipt = JSON.parse(await fs.readFile(file, 'utf8'));
        receiptAt = stat.mtime.toISOString();
      }
    } catch {
      // no receipt yet, or not valid JSON yet
    }
    out.push({ meta, receipt, receiptAt });
  }
  return out.sort((a, b) => String(b.meta.createdAt).localeCompare(String(a.meta.createdAt))).slice(0, 200);
}

// ---------- Markdown export ----------

// Feed text is untrusted: keep it on one line and stop it forming links, embeds, HTML or headings.
function mdText(s = '') {
  return String(s).replace(/\s+/g, ' ').replace(/[[\]<>`]/g, (c) => `\\${c}`).replace(/^#+\s*/, '').trim();
}

function mdUrl(u = '') {
  return /^https?:\/\//i.test(u) ? u.replace(/[()\s]/g, encodeURIComponent) : '';
}

const BASIS_LABEL = { DISCLOSED: 'disclosed', INFERRED: 'inferred', UNKNOWN: 'not disclosed' };

export function renderMarkdownDigest(digest) {
  const dateStr = digest.generatedAt.slice(0, 10);
  const roleTitle = digest.roleTitle || 'Cybersecurity Professional';
  const briefLabel = digest.briefLabel || 'Industry Brief';
  const partial = (digest.sourceHealth || []).filter((s) => ['partial', 'stale', 'empty', 'error'].includes(s.coverage));
  const lines = [
    '---',
    'type: threat-digest',
    `created: ${dateStr}`,
    `window_hours: ${digest.hours}`,
    `role: ${JSON.stringify(roleTitle)}`,
    `engine: ${digest.analysisEngine}`,
    'tags: [dev/security]',
    '---',
    `# BlastRadius TL;DR — Last ${digest.hours}h (${dateStr})`,
    '',
    `> **Tailored for:** ${mdText(roleTitle)} · **Window:** ${digest.windowStart.slice(0, 16)}Z → ${digest.windowEnd.slice(0, 16)}Z · **Sources:** ${digest.stats.sourcesFullCoverage}/${digest.stats.sourcesTotal} cover the full window`,
    ''
  ];

  if (partial.length) {
    lines.push(`> **Coverage gaps:** ${partial.map((s) => `${mdText(s.name)} (${mdText(s.coverageNote || s.coverage)})`).join('; ')}`, '');
  }
  if (digest.stats.unanalyzed) {
    lines.push(`> **${digest.stats.unanalyzed} of ${digest.stats.clustersTotal} incidents were not analysed** (${mdText(digest.fallbackReason || 'no AI engine')}). They are listed at the end with sources only.`, '');
  }

  lines.push('## 10-Second Takeaway', mdText(digest.executiveSummary || ''), '');

  if (digest.topLockdownChecklist?.length) {
    lines.push('## Do This Today');
    for (const item of digest.topLockdownChecklist) {
      lines.push(`- [ ] **${mdText(item.action)}** *(${mdText(item.incidentTitle)})*`);
    }
    lines.push('');
  }

  const order = ['ACT_NOW', 'WATCH_HARDEN', 'CUSTOMER_BRIEF', 'NOT_APPLICABLE', 'UNANALYZED'];
  const labels = {
    ACT_NOW: '🔴 Act Now',
    WATCH_HARDEN: '🟠 Watch & Harden',
    CUSTOMER_BRIEF: `🔵 ${mdText(briefLabel)}`,
    NOT_APPLICABLE: '⚪ Skip / Out of Scope',
    UNANALYZED: '◻ Not analysed (sources only)'
  };

  for (const verdict of order) {
    const group = (digest.incidents || []).filter((i) => i.verdict === verdict);
    if (!group.length) continue;
    lines.push(`## ${labels[verdict]} (${group.length})`, '');
    for (const inc of group) {
      const srcLinks = (inc.sources || []).slice(0, 4)
        .map((s) => (mdUrl(s.url) ? `[${mdText(s.name)}](${mdUrl(s.url)})` : mdText(s.name))).join(' · ');
      lines.push(`### ${mdText(inc.title)}`);
      if (verdict === 'UNANALYZED') {
        lines.push(`- **Sources (${inc.corroborationCount}):** ${srcLinks}`, '');
        continue;
      }
      const kevTag = inc.isKev ? ' · **KEV**' : '';
      const cveStr = inc.cves?.length ? ` · ${inc.cves.slice(0, 2).join(', ')}` : '';
      lines.push(`- **${inc.severity}**${kevTag}${cveStr} · ${mdText(inc.rootCauseBucket)} · ${mdText(inc.attackSurface)}`);
      lines.push(`- **What happened (${BASIS_LABEL[inc.rootCauseBasis] || 'inferred'}):** ${mdText(inc.tldrRootCause)}`);
      if (inc.evidenceQuote) lines.push(`- **Source says:** “${mdText(inc.evidenceQuote)}”`);
      lines.push(`- **Could this happen to me?** ${mdText(inc.couldThisHappenToMe)}`);
      if (inc.inventory?.checked) {
        lines.push(`- **Inventory:** ${inc.inventory.matches.length ? `MATCH — ${mdText(inc.inventory.matches.join(', '))}` : 'no match in scanned inventory'}`);
      }
      if (inc.lockItDown?.length) lines.push(`- **Do:** ${inc.lockItDown.map(mdText).join(' · ')}`);
      lines.push(`- **Sources (${inc.corroborationCount}):** ${srcLinks}`, '');
    }
  }

  return lines.join('\n');
}

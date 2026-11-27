import fs from 'node:fs/promises';
import path from 'node:path';
import { parseFeedXml, parseDateSafe, stripHtml } from './xml.mjs';
import { ROOT_DIR, DATA_DIR, loadItemStore, mergeIntoItemStore, queryStore } from './store.mjs';

export { ROOT_DIR };

const STALE_AFTER_DAYS = 60;

// Load optional .env file into process.env (without overwriting existing vars)
export async function loadEnvFile() {
  const envPath = path.join(ROOT_DIR, '.env');
  try {
    const raw = await fs.readFile(envPath, 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      const val = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
      if (key && !(key in process.env)) process.env[key] = val;
    }
  } catch {
    // No .env file is fine
  }
}

export async function loadSourcesConfig() {
  return JSON.parse(await fs.readFile(path.join(ROOT_DIR, 'config', 'sources.json'), 'utf8'));
}

export async function loadPresetsConfig() {
  return JSON.parse(await fs.readFile(path.join(ROOT_DIR, 'config', 'presets.json'), 'utf8'));
}

export async function loadProfileConfig() {
  try {
    return JSON.parse(await fs.readFile(path.join(DATA_DIR, 'profile.local.json'), 'utf8'));
  } catch {
    return JSON.parse(await fs.readFile(path.join(ROOT_DIR, 'config', 'profile.json'), 'utf8'));
  }
}

export function extractCves(text = '') {
  const matches = text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
  return [...new Set(matches.map((c) => c.toUpperCase()))];
}

export function safeHttpUrl(u) {
  return typeof u === 'string' && /^https?:\/\//i.test(u.trim()) ? u.trim() : '';
}

// Obvious non-incident content: promos, events, hiring, sponsored posts and multi-story roundups.
// Anything subtler is left for the model, which can mark an item as not an incident.
const NOISE_TITLE_PATTERNS = [
  /\bwebinar\b/i,
  /\bpodcast\b/i,
  /\blive demo\b/i,
  /\bregister now\b/i,
  /\bevent recap\b/i,
  /\bpress release\b/i,
  /\bnamed a leader\b/i,
  /\bgartner\b.*\bmagic quadrant\b/i,
  /\bforrester wave\b/i,
  /\bannounces\b.*\b(partnership|acquisition|funding|series [a-e])\b/i,
  /\bseries [a-e] funding\b/i,
  /\bblack friday\b/i,
  /\bcyber monday\b/i,
  /\bdeal[s]? on\b/i,
  /\bdiscount\b/i,
  /\btop \d+ (cybersecurity|security) (tips|trends|predictions|tools)\b/i,
  /\bhow to choose\b/i,
  /\bcareer[s]? in cybersecurity\b/i,
  /\bwe['’]?re hiring\b/i,
  /\bintroducing our new\b/i,
  /\bproduct update\b/i,
  /\bmonthly newsletter\b/i,
  /\bweek in review\b/i,
  /\bweekly recap\b/i,
  /\bin other news\b/i,
  /^\s*sponsored\b/i
];

const SIGNAL_PATTERNS = [
  /\bCVE-\d{4}-\d{4,7}\b/i,
  /\b(zero[- ]day|0[- ]day|actively exploited|in[- ]the[- ]wild|kev)\b/i,
  /\b(breach|breached|hacked|intrusion|compromise[ds]?|extortion|ransomware|data leak|leaked|exfiltrat)/i,
  /\b(rce|remote code execution|auth(entication)? bypass|privilege escalation|sqli|sql injection|ssrf|deserialization|memory corruption|sandbox escape|zero[- ]click)\b/i,
  /\b(supply[- ]chain|trojanized|malicious package|npm|pypi|backdoor|web ?shell|infostealer|stealer|clickfix|phishing|vishing|aitm|oauth|session (cookie|hijack|theft)|token theft|credential|secret[s]? leaked)\b/i,
  /\b(apt\d+|lazarus|dprk|salt typhoon|volt typhoon|midnight blizzard|scattered spider|shinyhunters|cl0p|lockbit|akira|qilin|ransomhub|spyware|pegasus|mercenary)\b/i,
  /\b(vulnerability|flaw|exploit|patch tuesday|advisory|critical bug|prompt injection|mcp|jailbreak)\b/i
];

const ALWAYS_SIGNAL_TYPES = new Set(['cisa-kev', 'github-advisories', 'ransomware-live']);
const SOCIAL_TYPES = new Set(['social-rss', 'bluesky', 'x-api']);

export function isSignalItem(item, source) {
  const combined = `${item.title} ${item.summary}`;
  if (NOISE_TITLE_PATTERNS.some((re) => re.test(item.title))) return false;
  if (ALWAYS_SIGNAL_TYPES.has(source.type) || source.alwaysSignal) return true;
  if (SOCIAL_TYPES.has(source.type) && combined.length < 45) return false;
  return SIGNAL_PATTERNS.some((re) => re.test(combined));
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 11000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...options,
      signal: ctrl.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; BlastRadius/1.0; +infosec-digest)',
        Accept: 'application/json, application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
        ...(options.headers || {})
      }
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * "HTTP 200" is not coverage. Work out how far back this feed can actually vouch for:
 * the oldest item it returned this run, or the first time we ever collected it, whichever is earlier.
 */
export function assessCoverage(meta, { cutoffDate, now, firstCollectedAt }) {
  if (meta.status !== 'ok') return { coverage: meta.status, coverageNote: meta.error || meta.status };
  if (!meta.fetchedCount) return { coverage: 'empty', coverageNote: 'feed returned no items; check the URL or query' };
  if (!meta.newestFetchedAt) return { coverage: 'empty', coverageNote: 'no items had a readable date' };

  const newest = Date.parse(meta.newestFetchedAt);
  const ageDays = Math.floor((now.getTime() - newest) / 86400000);
  if (ageDays > STALE_AFTER_DAYS) {
    return { coverage: 'stale', coverageNote: `last post ${meta.newestFetchedAt.slice(0, 10)} (${ageDays} days ago); feed may have moved` };
  }

  const reachesBackTo = Math.min(
    Date.parse(meta.oldestFetchedAt),
    firstCollectedAt ? Date.parse(firstCollectedAt) : Infinity
  );
  if (reachesBackTo > cutoffDate.getTime()) {
    const hrs = Math.max(1, Math.round((now.getTime() - reachesBackTo) / 3600000));
    return {
      coverage: 'partial',
      coveredSince: new Date(reachesBackTo).toISOString(),
      coverageNote: `feed only reaches back ${hrs < 48 ? `${hrs}h` : `${Math.round(hrs / 24)}d`}; older items in this window are missing until collection has run that long`
    };
  }
  return {
    coverage: 'full',
    coveredSince: new Date(reachesBackTo).toISOString(),
    coverageNote: meta.inWindowCount ? '' : 'no posts in this window'
  };
}

async function fetchSource(source, cutoffDate) {
  const started = Date.now();
  const meta = {
    id: source.id,
    name: source.name,
    tier: source.tier,
    category: source.category,
    type: source.type,
    status: 'ok',
    fetchedCount: 0,
    inWindowCount: 0,
    keptCount: 0,
    undatedCount: 0,
    oldestFetchedAt: null,
    newestFetchedAt: null,
    durationMs: 0,
    error: null
  };
  const empty = () => ({ meta, items: [], ransomwareVictims: [] });

  if (!source.enabled) {
    meta.status = 'disabled';
    return empty();
  }
  if (source.requiresEnv && !process.env[source.requiresEnv]) {
    meta.status = 'unconfigured';
    meta.error = `Set ${source.requiresEnv} in .env to enable`;
    return empty();
  }

  // Every fetched item's date passes through here, in or out of the window, so coverage is measurable.
  const seen = (dt) => {
    if (!dt) { meta.undatedCount++; return false; }
    const iso = dt.toISOString();
    if (!meta.oldestFetchedAt || iso < meta.oldestFetchedAt) meta.oldestFetchedAt = iso;
    if (!meta.newestFetchedAt || iso > meta.newestFetchedAt) meta.newestFetchedAt = iso;
    if (dt < cutoffDate) return false;
    meta.inWindowCount++;
    return true;
  };

  try {
    const headers = {};
    if (source.type === 'x-api' && process.env.X_BEARER_TOKEN) headers.Authorization = `Bearer ${process.env.X_BEARER_TOKEN}`;
    if (source.type === 'github-advisories' && process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

    const res = await fetchWithTimeout(source.url, { headers });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const rawItems = [];
    const ransomwareVictims = [];

    if (source.type === 'cisa-kev') {
      const vulns = (await res.json()).vulnerabilities || [];
      meta.fetchedCount = vulns.length;
      for (const v of vulns) {
        const added = parseDateSafe(v.dateAdded);
        if (!seen(added)) continue;
        const isRansom = String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known';
        rawItems.push({
          title: `CISA KEV: ${v.vendorProject} ${v.product} — ${v.vulnerabilityName} (${v.cveID})`,
          url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cveID)}`,
          publishedAt: added.toISOString(),
          summary: `${v.shortDescription} Required action: ${v.requiredAction}. Due: ${v.dueDate}.${isRansom ? ' Known ransomware campaign use.' : ''}`,
          fullText: `${v.shortDescription} ${v.notes || ''}`,
          cves: [String(v.cveID).toUpperCase()],
          isKev: true,
          kevDueDate: v.dueDate,
          kevRansomware: isRansom,
          vendor: v.vendorProject,
          product: v.product
        });
      }
    } else if (source.type === 'github-advisories') {
      const advs = await res.json();
      meta.fetchedCount = Array.isArray(advs) ? advs.length : 0;
      for (const a of Array.isArray(advs) ? advs : []) {
        const pub = parseDateSafe(a.published_at || a.updated_at);
        if (!seen(pub)) continue;
        const packages = (a.vulnerabilities || [])
          .map((v) => ({ ecosystem: String(v.package?.ecosystem || '').toLowerCase(), name: String(v.package?.name || '') }))
          .filter((p) => p.name)
          .slice(0, 6);
        const label = packages.map((p) => `${p.ecosystem}:${p.name}`).slice(0, 4).join(', ');
        rawItems.push({
          title: `GHSA Critical (${label || 'OSS'}): ${a.summary}`,
          url: a.html_url || a.url,
          publishedAt: pub.toISOString(),
          summary: stripHtml(a.description || a.summary).slice(0, 650),
          fullText: stripHtml(a.description || a.summary).slice(0, 1800),
          cves: a.cve_id ? [String(a.cve_id).toUpperCase()] : extractCves(`${a.summary} ${a.description}`),
          cvss: a.cvss?.score || null,
          packages
        });
      }
    } else if (source.type === 'ransomware-live') {
      const victims = await res.json();
      meta.fetchedCount = Array.isArray(victims) ? victims.length : 0;
      for (const v of Array.isArray(victims) ? victims : []) {
        const dt = parseDateSafe(v.published || v.attackdate || v.discovered);
        if (!seen(dt)) continue;
        ransomwareVictims.push({
          victim: String(v.victim || v.post_title || 'Unknown'),
          group: String(v.group || v.group_name || 'unknown'),
          sector: String(v.activity || 'Unknown'),
          country: String(v.country || 'Unknown'),
          publishedAt: dt.toISOString(),
          url: safeHttpUrl(v.permalink || v.post_url) || 'https://www.ransomware.live/',
          description: stripHtml(v.description || '').slice(0, 300)
        });
      }
      meta.keptCount = ransomwareVictims.length;
    } else if (source.type === 'bluesky') {
      const feed = (await res.json()).feed || [];
      meta.fetchedCount = feed.length;
      for (const entry of feed) {
        const post = entry.post;
        const rec = post?.record;
        if (!rec?.text) continue;
        const dt = parseDateSafe(rec.createdAt);
        if (!seen(dt)) continue;
        const handle = post.author?.handle || 'bsky';
        const rkey = (post.uri || '').split('/').pop();
        rawItems.push({
          title: `@${handle}: ${rec.text.slice(0, 140).replace(/\s+/g, ' ')}`,
          url: rkey ? `https://bsky.app/profile/${encodeURIComponent(handle)}/post/${encodeURIComponent(rkey)}` : 'https://bsky.app',
          publishedAt: dt.toISOString(),
          summary: rec.text.slice(0, 500),
          fullText: rec.text.slice(0, 2000)
        });
      }
    } else if (source.type === 'hn-algolia') {
      const hits = (await res.json()).hits || [];
      meta.fetchedCount = hits.length;
      for (const h of hits) {
        const dt = parseDateSafe(h.created_at);
        if (!seen(dt)) continue;
        rawItems.push({
          title: String(h.title || ''),
          url: safeHttpUrl(h.url) || `https://news.ycombinator.com/item?id=${encodeURIComponent(h.objectID)}`,
          publishedAt: dt.toISOString(),
          summary: `HN (${h.points || 0} pts, ${h.num_comments || 0} comments): ${h.title}`,
          fullText: h.story_text ? stripHtml(h.story_text).slice(0, 1000) : String(h.title || '')
        });
      }
    } else if (source.type === 'x-api') {
      const tweets = (await res.json()).data || [];
      meta.fetchedCount = tweets.length;
      for (const t of tweets) {
        const dt = parseDateSafe(t.created_at);
        if (!seen(dt)) continue;
        rawItems.push({
          title: `X: ${String(t.text).slice(0, 140).replace(/\s+/g, ' ')}`,
          url: `https://x.com/i/web/status/${encodeURIComponent(t.id)}`,
          publishedAt: dt.toISOString(),
          summary: String(t.text),
          fullText: String(t.text)
        });
      }
    } else {
      // RSS / Atom / social-rss
      const parsed = parseFeedXml(await res.text());
      meta.fetchedCount = parsed.length;
      for (const item of parsed) {
        if (!seen(parseDateSafe(item.publishedAt))) continue;
        rawItems.push(item);
      }
    }

    const filtered = [];
    for (const item of rawItems) {
      if (!isSignalItem(item, source)) continue;
      filtered.push({
        ...item,
        url: safeHttpUrl(item.url),
        cves: item.cves?.length ? item.cves : extractCves(`${item.title} ${item.summary} ${item.fullText || ''}`),
        isKev: Boolean(item.isKev),
        sourceId: source.id,
        sourceName: source.name,
        sourceTier: source.tier,
        sourceCategory: source.category,
        sourceWeight: source.weight,
        sourceOwner: source.owner || source.id
      });
    }

    if (source.type !== 'ransomware-live') meta.keptCount = filtered.length;
    meta.durationMs = Date.now() - started;
    return { meta, items: filtered, ransomwareVictims };
  } catch (err) {
    meta.status = 'error';
    meta.error = err?.name === 'AbortError' ? 'Timeout (11s)' : err.message;
    meta.durationMs = Date.now() - started;
    return empty();
  }
}

/**
 * Fetch every source, fold the results into the on-disk item store, and return the window from the store.
 * `persist: false` skips the store entirely (used by tests and dry runs).
 */
export async function ingestAll({ hours = 168, onProgress, persist = true, sources = null } = {}) {
  await loadEnvFile();
  const cfg = sources ? { sources } : await loadSourcesConfig();
  const now = new Date();
  const cutoffDate = new Date(now.getTime() - hours * 3600 * 1000);

  if (onProgress) onProgress(`Fetching ${cfg.sources.length} sources (window: last ${hours}h)...`);
  const results = await Promise.all(cfg.sources.map((src) => fetchSource(src, cutoffDate)));

  const fetchedItems = results.flatMap((r) => r.items);
  const fetchedVictims = results.flatMap((r) => r.ransomwareVictims);
  const okIds = results.filter((r) => r.meta.status === 'ok').map((r) => r.meta.id);

  let items;
  let victims;
  let store;
  if (persist) {
    store = await mergeIntoItemStore({ items: fetchedItems, victims: fetchedVictims, sourceIds: okIds, now });
    ({ items, victims } = queryStore(store, cutoffDate));
  } else {
    store = await loadItemStore();
    const seenKeys = new Set();
    items = fetchedItems.filter((it) => {
      const key = (it.url || `${it.sourceId}:${it.title}`).toLowerCase().replace(/\/+$/, '');
      if (seenKeys.has(key)) return false;
      seenKeys.add(key);
      return true;
    }).sort((a, b) => Date.parse(b.publishedAt || 0) - Date.parse(a.publishedAt || 0));
    victims = fetchedVictims;
  }

  const sourceHealth = results.map((r) => {
    const fromStore = items.filter((i) => i.sourceId === r.meta.id).length;
    return {
      ...r.meta,
      inStoreWindowCount: r.meta.type === 'ransomware-live' ? victims.length : fromStore,
      ...assessCoverage(r.meta, { cutoffDate, now, firstCollectedAt: store.sources?.[r.meta.id]?.firstCollectedAt })
    };
  });

  return {
    generatedAt: now.toISOString(),
    hours,
    windowStart: cutoffDate.toISOString(),
    windowEnd: now.toISOString(),
    items,
    ransomwareVictims: victims,
    sourceHealth
  };
}

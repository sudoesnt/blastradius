import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseFeedXml, parseDateSafe, stripHtml } from './xml.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.resolve(__dirname, '..');

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
    // No .env file — totally fine
  }
}

export async function loadSourcesConfig() {
  const p = path.join(ROOT_DIR, 'config', 'sources.json');
  const raw = await fs.readFile(p, 'utf8');
  return JSON.parse(raw);
}

export async function loadPresetsConfig() {
  const p = path.join(ROOT_DIR, 'config', 'presets.json');
  const raw = await fs.readFile(p, 'utf8');
  return JSON.parse(raw);
}

export async function loadProfileConfig() {
  const localPath = path.join(ROOT_DIR, 'data', 'profile.local.json');
  const defaultPath = path.join(ROOT_DIR, 'config', 'profile.json');
  try {
    const raw = await fs.readFile(localPath, 'utf8');
    return JSON.parse(raw);
  } catch {
    const raw = await fs.readFile(defaultPath, 'utf8');
    return JSON.parse(raw);
  }
}

export function extractCves(text = '') {
  const matches = text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
  return [...new Set(matches.map((c) => c.toUpperCase()))];
}

// Discerning noise filter: strip vendor fluff, promos, webinars, listicles, hiring posts
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
  /\bweek in review\b/i
];

// High-signal security incident indicators (especially for broad blogs like Google/Microsoft/Wiz/Cloudflare/HN)
const SIGNAL_PATTERNS = [
  /\bCVE-\d{4}-\d{4,7}\b/i,
  /\b(zero[- ]day|0[- ]day|actively exploited|in[- ]the[- ]wild|kev)\b/i,
  /\b(breach|breached|hacked|intrusion|compromise[ds]?|extortion|ransomware|data leak|leaked|exfiltrat)/i,
  /\b(rce|remote code execution|auth(entication)? bypass|privilege escalation|sqli|sql injection|ssrf|deserialization|memory corruption|sandbox escape|zero[- ]click)\b/i,
  /\b(supply[- ]chain|trojanized|malicious package|npm|pypi|backdoor|web ?shell|infostealer|stealer|clickfix|phishing|aitm|oauth|session (cookie|hijack|theft)|token theft|credential|secret[s]? leaked)\b/i,
  /\b(apt\d+|lazarus|dprk|salt typhoon|volt typhoon|midnight blizzard|scattered spider|shinyhunters|cl0p|lockbit|akira|qilin|ransomhub|spyware|pegasus|mercenary)\b/i,
  /\b(vulnerability|flaw|exploit|patch tuesday|advisory|critical bug|prompt injection|mcp|jailbreak)\b/i
];

function isSignalItem(item, source) {
  const combined = `${item.title} ${item.summary}`;
  if (NOISE_TITLE_PATTERNS.some((re) => re.test(item.title))) return false;
  // CISA KEV, CERT, GH Advisories, Ransomware.live, DataBreaches are inherently signal
  if (['cisa-kev', 'github-advisories', 'ransomware-live'].includes(source.type)) return true;
  if (['databreaches', 'watchtowr', 'huntress', 'project-zero', 'citizenlab', 'krebs', 'riskybiz'].includes(source.id)) {
    return true;
  }
  // Social posts need to be substantive (not 3-word replies or retweets of jokes)
  if (source.type === 'social-rss' || source.type === 'bluesky' || source.type === 'x-api') {
    if (combined.length < 45) return false;
    return SIGNAL_PATTERNS.some((re) => re.test(combined));
  }
  // General vendor/news blogs require at least one concrete incident/vuln/threat signal
  return SIGNAL_PATTERNS.some((re) => re.test(combined));
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 11000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...options,
      signal: ctrl.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; BlastRadius/1.0; +infosec-digest)',
        Accept: 'application/json, application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
        ...(options.headers || {})
      }
    });
    return res;
  } finally {
    clearTimeout(timer);
  }
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
    durationMs: 0,
    error: null
  };

  if (!source.enabled) {
    meta.status = 'disabled';
    return { meta, items: [], ransomwareVictims: [] };
  }

  if (source.requiresEnv && !process.env[source.requiresEnv]) {
    meta.status = 'unconfigured';
    meta.error = `Set ${source.requiresEnv} in .env to enable`;
    return { meta, items: [], ransomwareVictims: [] };
  }

  try {
    const headers = {};
    if (source.type === 'x-api' && process.env.X_BEARER_TOKEN) {
      headers.Authorization = `Bearer ${process.env.X_BEARER_TOKEN}`;
    }
    if (source.type === 'github-advisories' && process.env.GITHUB_TOKEN) {
      headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    }

    const res = await fetchWithTimeout(source.url, { headers });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const rawItems = [];
    const ransomwareVictims = [];

    if (source.type === 'cisa-kev') {
      const data = await res.json();
      const vulns = data.vulnerabilities || [];
      meta.fetchedCount = vulns.length;
      for (const v of vulns) {
        const added = parseDateSafe(v.dateAdded);
        if (!added || added < cutoffDate) continue;
        meta.inWindowCount++;
        const isRansom = String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known';
        rawItems.push({
          title: `CISA KEV: ${v.vendorProject} ${v.product} — ${v.vulnerabilityName} (${v.cveID})`,
          url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
          publishedAt: added.toISOString(),
          summary: `${v.shortDescription} Required action: ${v.requiredAction}. Due: ${v.dueDate}.${isRansom ? ' Known ransomware campaign use.' : ''}`,
          fullText: `${v.shortDescription} ${v.notes || ''}`,
          cves: [v.cveID.toUpperCase()],
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
      for (const a of advs || []) {
        const pub = parseDateSafe(a.published_at || a.updated_at);
        if (!pub || pub < cutoffDate) continue;
        meta.inWindowCount++;
        const pkgs = (a.vulnerabilities || [])
          .map((v) => `${v.package?.ecosystem || ''}:${v.package?.name || ''}`)
          .filter(Boolean)
          .slice(0, 4);
        const cves = a.cve_id ? [a.cve_id.toUpperCase()] : extractCves(`${a.summary} ${a.description}`);
        rawItems.push({
          title: `GHSA Critical (${pkgs.join(', ') || 'OSS'}): ${a.summary}`,
          url: a.html_url || a.url,
          publishedAt: pub.toISOString(),
          summary: stripHtml(a.description || a.summary).slice(0, 650),
          fullText: stripHtml(a.description || a.summary).slice(0, 1800),
          cves,
          cvss: a.cvss?.score || null,
          ecosystems: pkgs
        });
      }
    } else if (source.type === 'ransomware-live') {
      const victims = await res.json();
      meta.fetchedCount = Array.isArray(victims) ? victims.length : 0;
      for (const v of victims || []) {
        const dt = parseDateSafe(v.published || v.attackdate || v.discovered);
        if (!dt || dt < cutoffDate) continue;
        meta.inWindowCount++;
        ransomwareVictims.push({
          victim: v.victim || v.post_title || 'Unknown',
          group: v.group || v.group_name || 'unknown',
          sector: v.activity || 'Unknown',
          country: v.country || 'Unknown',
          publishedAt: dt.toISOString(),
          url: v.permalink || v.post_url || 'https://www.ransomware.live/',
          description: stripHtml(v.description || '').slice(0, 300)
        });
      }
      meta.keptCount = ransomwareVictims.length;
    } else if (source.type === 'bluesky') {
      const data = await res.json();
      const feed = data.feed || [];
      meta.fetchedCount = feed.length;
      for (const entry of feed) {
        const post = entry.post;
        const rec = post?.record;
        if (!rec?.text) continue;
        const dt = parseDateSafe(rec.createdAt);
        if (!dt || dt < cutoffDate) continue;
        meta.inWindowCount++;
        const handle = post.author?.handle || 'bsky';
        const rkey = (post.uri || '').split('/').pop();
        rawItems.push({
          title: `@${handle}: ${rec.text.slice(0, 140).replace(/\s+/g, ' ')}`,
          url: rkey ? `https://bsky.app/profile/${handle}/post/${rkey}` : 'https://bsky.app',
          publishedAt: dt.toISOString(),
          summary: rec.text.slice(0, 500),
          fullText: rec.text
        });
      }
    } else if (source.type === 'hn-algolia') {
      const data = await res.json();
      const hits = data.hits || [];
      meta.fetchedCount = hits.length;
      for (const h of hits) {
        const dt = parseDateSafe(h.created_at);
        if (!dt || dt < cutoffDate) continue;
        meta.inWindowCount++;
        rawItems.push({
          title: h.title || '',
          url: h.url || `https://news.ycombinator.com/item?id=${h.objectID}`,
          publishedAt: dt.toISOString(),
          summary: `HN (${h.points || 0} pts, ${h.num_comments || 0} comments): ${h.title}`,
          fullText: h.story_text ? stripHtml(h.story_text).slice(0, 1000) : h.title
        });
      }
    } else if (source.type === 'x-api') {
      const data = await res.json();
      const tweets = data.data || [];
      meta.fetchedCount = tweets.length;
      for (const t of tweets) {
        const dt = parseDateSafe(t.created_at);
        if (!dt || dt < cutoffDate) continue;
        meta.inWindowCount++;
        rawItems.push({
          title: `X Signal: ${t.text.slice(0, 140).replace(/\s+/g, ' ')}`,
          url: `https://x.com/i/web/status/${t.id}`,
          publishedAt: dt.toISOString(),
          summary: t.text,
          fullText: t.text
        });
      }
    } else {
      // RSS / Atom / social-rss
      const xml = await res.text();
      const parsed = parseFeedXml(xml);
      meta.fetchedCount = parsed.length;
      for (const item of parsed) {
        const dt = parseDateSafe(item.publishedAt);
        if (!dt || dt < cutoffDate) continue;
        meta.inWindowCount++;
        rawItems.push(item);
      }
    }

    const filtered = [];
    for (const item of rawItems) {
      if (!isSignalItem(item, source)) continue;
      const cves = item.cves?.length
        ? item.cves
        : extractCves(`${item.title} ${item.summary} ${item.fullText || ''}`);
      filtered.push({
        ...item,
        cves,
        isKev: Boolean(item.isKev),
        sourceId: source.id,
        sourceName: source.name,
        sourceTier: source.tier,
        sourceCategory: source.category,
        sourceWeight: source.weight
      });
    }

    if (source.type !== 'ransomware-live') {
      meta.keptCount = filtered.length;
    }
    meta.durationMs = Date.now() - started;
    return { meta, items: filtered, ransomwareVictims };
  } catch (err) {
    meta.status = 'error';
    meta.error = err?.name === 'AbortError' ? 'Timeout (11s)' : err.message;
    meta.durationMs = Date.now() - started;
    return { meta, items: [], ransomwareVictims: [] };
  }
}

export async function ingestAll({ hours = 168, onProgress } = {}) {
  await loadEnvFile();
  const cfg = await loadSourcesConfig();
  const now = new Date();
  const cutoffDate = new Date(now.getTime() - hours * 3600 * 1000);

  if (onProgress) onProgress(`Fetching ${cfg.sources.length} curated infosec sources (window: last ${hours}h)...`);

  const results = await Promise.all(
    cfg.sources.map((src) => fetchSource(src, cutoffDate))
  );

  const items = [];
  const ransomwareVictims = [];
  const sourceHealth = [];

  for (const r of results) {
    sourceHealth.push(r.meta);
    items.push(...r.items);
    ransomwareVictims.push(...r.ransomwareVictims);
  }

  // Deduplicate exact URLs across feeds
  const seenUrls = new Set();
  const dedupedItems = [];
  for (const it of items) {
    const key = (it.url || `${it.sourceId}:${it.title}`).toLowerCase().replace(/\/+$/, '');
    if (seenUrls.has(key)) continue;
    seenUrls.add(key);
    dedupedItems.push(it);
  }

  // Sort newest first
  dedupedItems.sort((a, b) => Date.parse(b.publishedAt || 0) - Date.parse(a.publishedAt || 0));
  ransomwareVictims.sort((a, b) => Date.parse(b.publishedAt || 0) - Date.parse(a.publishedAt || 0));

  return {
    generatedAt: now.toISOString(),
    hours,
    windowStart: cutoffDate.toISOString(),
    windowEnd: now.toISOString(),
    items: dedupedItems,
    ransomwareVictims,
    sourceHealth
  };
}

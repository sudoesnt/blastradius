// Cross-source incident clustering and ranking.
//
// Two stages: a deterministic lexical pass here (shared CVE, same KEV product, TF-IDF title/summary
// similarity), then an optional model pass in analyze.mjs that merges clusters covering the same event
// under different headlines. Cluster ids are content hashes, so they are stable from run to run.

import { sha1 } from './store.mjs';

const STOPWORDS = new Set([
  'the', 'and', 'for', 'with', 'from', 'that', 'this', 'have', 'has', 'are', 'was', 'were',
  'will', 'into', 'over', 'after', 'about', 'under', 'more', 'new', 'how', 'why', 'what',
  'when', 'says', 'said', 'report', 'reports', 'reportedly', 'security', 'cybersecurity', 'cyber', 'attack',
  'attacks', 'attackers', 'vulnerability', 'vulnerabilities', 'flaw', 'flaws', 'breach', 'breaches', 'breached', 'data',
  'hackers', 'hacker', 'hacked', 'threat', 'actors', 'actor', 'campaign', 'malware', 'critical', 'active', 'actively',
  'exploited', 'exploit', 'exploits', 'exploitation', 'zero', 'day', 'patch', 'patches', 'patched', 'update',
  'updates', 'fixes', 'fixed', 'users', 'systems', 'millions', 'thousands', 'companies', 'customer', 'customers',
  'organizations', 'enterprise', 'cloud', 'server', 'servers', 'network', 'software', 'version', 'versions',
  'cisa', 'kev', 'ghsa', 'advisory', 'alert', 'warning', 'warns', 'hit', 'hits', 'targeting',
  'targets', 'used', 'using', 'via', 'can', 'could', 'now', 'all', 'its', 'their', 'our', 'they', 'them',
  'out', 'off', 'not', 'but', 'one', 'two', 'first', 'latest', 'major', 'high', 'risk', 'been', 'being',
  'remote', 'code', 'execution', 'rce', 'bypass', 'authentication', 'disclosure', 'exposed', 'unauthenticated',
  'expose', 'exposes', 'leaked', 'leak', 'leaks', 'stolen', 'steal', 'stealing', 'access', 'allows', 'allow',
  'required', 'action', 'due', 'apply', 'mitigations', 'vendor', 'instructions', 'which', 'who', 'had', 'you',
  'company', 'confirms', 'confirmed', 'according', 'information', 'incident', 'against', 'than', 'also', 'may',
  // feed boilerplate (Hacker News RSS, social reposts)
  'article', 'url', 'comments', 'points', 'pts', 'post', 'read', 'appeared'
]);

const ROUNDUP_RE = /\b(weekly recap|week in review|in other news|roundup|round-up|this week in)\b|\bexploit(?:ed|s)? \d+ (?:vulnerabilities|flaws)\b/i;
const MAX_CVES_FOR_KEYING = 4;

export function tokenize(text = '') {
  return text
    .toLowerCase()
    .replace(/cve-\d{4}-\d{4,7}/g, ' ')
    .replace(/https?:\/\/\S+/g, ' ')
    .replace(/[^a-z0-9.\-_]+/g, ' ')
    .split(/\s+/)
    .map((w) => w.replace(/^[.\-_]+|[.\-_]+$/g, ''))
    .filter((w) => w.length >= 3 && !STOPWORDS.has(w) && !/^[\d.\-_]+$/.test(w));
}

export function isRoundup(item) {
  return ROUNDUP_RE.test(item.title || '') || (item.cves || []).length > MAX_CVES_FOR_KEYING;
}

function buildVectors(items) {
  const docs = items.map((it) => {
    const tf = new Map();
    // Headline words carry the entity (victim, product); the teaser adds a little context.
    for (const t of tokenize(it.title)) tf.set(t, (tf.get(t) || 0) + 2);
    for (const t of tokenize((it.summary || '').slice(0, 320))) tf.set(t, (tf.get(t) || 0) + 1);
    return tf;
  });
  const df = new Map();
  for (const tf of docs) for (const t of tf.keys()) df.set(t, (df.get(t) || 0) + 1);
  const n = Math.max(1, items.length);
  return docs.map((tf) => {
    const vec = new Map();
    let norm = 0;
    for (const [t, f] of tf) {
      const w = (1 + Math.log(f)) * Math.log(1 + n / df.get(t));
      vec.set(t, w);
      norm += w * w;
    }
    norm = Math.sqrt(norm) || 1;
    for (const [t, w] of vec) vec.set(t, w / norm);
    return vec;
  });
}

function cosine(a, b) {
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  let dot = 0;
  for (const [t, w] of small) {
    const o = large.get(t);
    if (o) dot += w * o;
  }
  return dot;
}

const kevProductKey = (it) =>
  it.isKev && it.vendor && it.product ? `${it.vendor}|${it.product}`.toLowerCase() : null;

export const SIMILARITY_THRESHOLD = 0.3;

/** Stage 1: deterministic grouping. Returns arrays of items. */
export function groupItems(items, { threshold = SIMILARITY_THRESHOLD } = {}) {
  const vectors = buildVectors(items);
  const groups = []; // { idx: number[], cves: Set, kevProducts: Set, roundup: boolean }

  // Oldest first, so a cluster forms around the original report and later coverage attaches to it.
  const order = items.map((_, i) => i).sort((a, b) =>
    String(items[a].publishedAt).localeCompare(String(items[b].publishedAt)) || String(items[a].url).localeCompare(String(items[b].url)));

  for (const i of order) {
    const it = items[i];
    const roundup = isRoundup(it);
    const cves = roundup ? [] : (it.cves || []);
    const kp = kevProductKey(it);
    let best = null;
    let bestScore = 0;

    // A roundup mentions many stories; letting it join or attract a cluster creates false corroboration.
    if (!roundup) {
      for (const g of groups) {
        if (g.roundup) continue;
        let score = 0;
        if (cves.some((c) => g.cves.has(c))) score = 1;
        else if (kp && g.kevProducts.has(kp)) score = 0.95;
        else {
          // Average of the two best member matches resists single-link chaining through one odd headline.
          const sims = g.idx.map((j) => cosine(vectors[i], vectors[j])).sort((x, y) => y - x);
          score = sims.length > 1 ? (sims[0] + sims[1]) / 2 : sims[0];
          if (sims[0] < threshold) score = 0;
        }
        if (score >= threshold && score > bestScore) {
          best = g;
          bestScore = score;
        }
      }
    }

    if (best) {
      best.idx.push(i);
      for (const c of cves) best.cves.add(c);
      if (kp) best.kevProducts.add(kp);
    } else {
      groups.push({ idx: [i], cves: new Set(cves), kevProducts: new Set(kp ? [kp] : []), roundup });
    }
  }
  return groups.map((g) => g.idx.map((i) => items[i]));
}

/** A stable id: the lowest CVE if the cluster is about specific CVEs, otherwise its earliest report. */
export function clusterIdFor(clusterItems) {
  const keyed = clusterItems.filter((it) => !isRoundup(it));
  const cves = [...new Set(keyed.flatMap((it) => it.cves || []))].sort();
  if (cves.length && cves.length <= MAX_CVES_FOR_KEYING * 2) return `inc-${sha1(`cve:${cves[0]}`).slice(0, 10)}`;
  const earliest = [...clusterItems].sort((a, b) =>
    String(a.publishedAt).localeCompare(String(b.publishedAt)) || String(a.url).localeCompare(String(b.url)))[0];
  return `inc-${sha1(`url:${(earliest.url || earliest.title || '').toLowerCase()}`).slice(0, 10)}`;
}

function keywordHits(corpus, keywords) {
  let hits = 0;
  for (const kw of keywords) {
    const esc = kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (new RegExp(`(^|[^a-z0-9])${esc}([^a-z0-9]|$)`, 'i').test(corpus)) hits++;
  }
  return hits;
}

const leadRank = (it) =>
  (it.sourceTier === 1 ? 20 : 5) + (it.sourceWeight || 5) + (it.isKev ? 5 : 0) - (it.sourceCategory === 'social' ? 6 : 0) - (isRoundup(it) ? 15 : 0);

/** Turn a group of items into the cluster shape the analyzer and UI use. */
export function shapeCluster(clusterItems, profile = {}) {
  const items = [...clusterItems].sort((a, b) => leadRank(b) - leadRank(a));
  const lead = items[0];

  const bySource = new Map();
  for (const it of items) {
    if (!bySource.has(it.sourceId)) {
      bySource.set(it.sourceId, {
        id: it.sourceId, name: it.sourceName, tier: it.sourceTier, category: it.sourceCategory,
        weight: it.sourceWeight, owner: it.sourceOwner || it.sourceId, title: it.title, url: it.url, publishedAt: it.publishedAt
      });
    }
  }
  const sources = [...bySource.values()];
  // Corroboration counts publishers, not feeds: a reporter's blog and the same reporter's social post are one voice.
  const owners = new Map();
  for (const s of sources) if (!owners.has(s.owner) || s.weight > owners.get(s.owner).weight) owners.set(s.owner, s);
  const independent = [...owners.values()];
  const tier1Count = independent.filter((s) => s.tier === 1).length;
  const corpus = items.map((i) => `${i.title} ${i.summary}`).join(' ').toLowerCase();
  const isKev = items.some((i) => i.isKev);
  const kevRansomware = items.some((i) => i.kevRansomware);

  // The score only orders the list and the analysis queue. Nothing is dropped because of it.
  let signalScore = independent.reduce((acc, s) => acc + (s.weight || 5), 0);
  if (independent.length > 1) signalScore += (independent.length - 1) * 10;
  if (isKev) signalScore += 28;
  if (kevRansomware) signalScore += 10;
  if (/zero[- ]day|0[- ]day|actively exploited|in[- ]the[- ]wild/.test(corpus)) signalScore += 16;
  if (/supply[- ]chain|breach|data leak|compromise|backdoor|stealer|oauth|session|token/.test(corpus)) signalScore += 10;
  if (/\brce\b|remote code execution|pre[- ]auth|unauthenticated|cvss\s*(9|10)/.test(corpus)) signalScore += 9;
  signalScore += Math.min(keywordHits(corpus, profile.high_priority_keywords || []) * 3, 18);
  if (independent.length === 1 && tier1Count === 0) signalScore -= 6;
  if (items.every(isRoundup)) signalScore -= 20;

  // Evidence handed to the model: every source's headline and teaser, plus the lead's longer text.
  const evidenceParts = items.slice(0, 5).map((it) => `[${it.sourceName}] ${it.title}. ${it.summary || ''}`.trim());
  if (lead.fullText && lead.fullText.length > (lead.summary || '').length + 80) {
    evidenceParts.push(`[${lead.sourceName}, longer excerpt] ${lead.fullText.slice(0, 1500)}`);
  }

  const dates = items.map((i) => i.publishedAt).filter(Boolean).sort();
  const firstSeen = items.map((i) => i.firstSeenAt).filter(Boolean).sort()[0] || null;
  const packages = [];
  const seenPkg = new Set();
  for (const it of items) for (const p of it.packages || []) {
    const k = `${p.ecosystem}:${p.name}`.toLowerCase();
    if (!seenPkg.has(k)) { seenPkg.add(k); packages.push(p); }
  }

  return {
    id: clusterIdFor(items),
    leadTitle: lead.title,
    earliestAt: dates[0] || null,
    latestAt: dates.at(-1) || null,
    firstSeenAt: firstSeen,
    cves: [...new Set(items.filter((i) => !isRoundup(i)).flatMap((i) => i.cves || []))].slice(0, 8),
    isKev,
    kevRansomware,
    kevProducts: [...new Set(items.filter((i) => i.isKev).map((i) => `${i.vendor} ${i.product}`))],
    packages,
    isRoundup: items.every(isRoundup),
    corroborationCount: independent.length,
    tier1Count,
    signalScore: Math.round(signalScore),
    sources,
    evidence: evidenceParts.join('\n').slice(0, 4200),
    rawItemsCount: items.length,
    itemKeys: items.map((i) => (i.url || `${i.sourceId}:${i.title}`).toLowerCase())
  };
}

/**
 * Stage 2 support: merge groups that the model says cover the same event.
 * `sameEventGroups` is an array of arrays of cluster ids. Unknown ids are ignored.
 */
export function mergeGroups(groups, sameEventGroups = []) {
  const idOf = groups.map(clusterIdFor);
  const parent = groups.map((_, i) => i);
  const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  for (const ids of sameEventGroups) {
    const idxs = [...new Set((Array.isArray(ids) ? ids : []).map((id) => idOf.indexOf(id)).filter((i) => i >= 0))];
    // A roundup never anchors or joins a merge.
    const usable = idxs.filter((i) => !groups[i].every(isRoundup));
    for (let k = 1; k < usable.length; k++) parent[find(usable[k])] = find(usable[0]);
  }
  const merged = new Map();
  groups.forEach((g, i) => {
    const r = find(i);
    merged.set(r, (merged.get(r) || []).concat(g));
  });
  return [...merged.values()];
}

export function clusterIncidents(items, profile = {}, { sameEventGroups = [] } = {}) {
  let groups = groupItems(items);
  if (sameEventGroups.length) groups = mergeGroups(groups, sameEventGroups);
  return groups.map((g) => shapeCluster(g, profile)).sort((a, b) => b.signalScore - a.signalScore || a.id.localeCompare(b.id));
}

export function summarizeRansomware(victims = [], { capped = false } = {}) {
  const byGroup = new Map();
  const bySector = new Map();
  for (const v of victims) {
    const g = (v.group || 'unknown').toLowerCase();
    byGroup.set(g, (byGroup.get(g) || 0) + 1);
    const s = v.sector || 'Unknown';
    bySector.set(s, (bySector.get(s) || 0) + 1);
  }
  const top = (m, n, key) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, count]) => ({ [key]: k, count }));
  return {
    totalVictims: victims.length,
    capped,
    topGroups: top(byGroup, 10, 'group'),
    topSectors: top(bySector, 8, 'sector'),
    recent: victims.slice(0, 40)
  };
}

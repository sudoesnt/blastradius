// Cross-source incident deduplication, clustering, and practitioner signal ranking

const STOPWORDS = new Set([
  'the', 'and', 'for', 'with', 'from', 'that', 'this', 'have', 'has', 'are', 'was', 'were',
  'will', 'into', 'over', 'after', 'about', 'under', 'more', 'new', 'how', 'why', 'what',
  'when', 'says', 'said', 'report', 'reports', 'security', 'cybersecurity', 'cyber', 'attack',
  'attacks', 'vulnerability', 'vulnerabilities', 'flaw', 'flaws', 'breach', 'breaches', 'data',
  'hackers', 'threat', 'actors', 'actor', 'campaign', 'malware', 'critical', 'active', 'actively',
  'exploited', 'exploit', 'exploits', 'zero', 'day', 'patch', 'patches', 'patched', 'update',
  'updates', 'fixes', 'fixed', 'users', 'systems', 'millions', 'thousands', 'companies',
  'organizations', 'enterprise', 'cloud', 'server', 'servers', 'network', 'software', 'version',
  'cisa', 'kev', 'ghsa', 'advisory', 'alert', 'warning', 'warns', 'hit', 'hits', 'targeting',
  'targets', 'used', 'using', 'via', 'can', 'could', 'now', 'all', 'its', 'their', 'our',
  'out', 'off', 'not', 'but', 'one', 'two', 'first', 'latest', 'major', 'high', 'risk',
  'remote', 'code', 'execution', 'rce', 'bypass', 'authentication', 'disclosure', 'exposed',
  'expose', 'exposes', 'leaked', 'leak', 'leaks', 'stolen', 'steal', 'stealing', 'access'
]);

function tokenizeTitle(title = '') {
  return title
    .toLowerCase()
    .replace(/cve-\d{4}-\d{4,7}/gi, ' ')
    .replace(/[^a-z0-9.\-_]+/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length >= 3 && !STOPWORDS.has(w) && !/^\d+$/.test(w));
}

function jaccard(setA, setB) {
  if (!setA.size || !setB.size) return 0;
  let inter = 0;
  for (const v of setA) {
    if (setB.has(v)) inter++;
  }
  const union = setA.size + setB.size - inter;
  return union ? inter / union : 0;
}

function overlapCount(setA, setB) {
  let inter = 0;
  for (const v of setA) {
    if (setB.has(v)) inter++;
  }
  return inter;
}

export function clusterIncidents(items, profile = {}) {
  const clusters = [];

  for (const item of items) {
    const tokens = new Set(tokenizeTitle(item.title));
    const cveSet = new Set(item.cves || []);

    let bestCluster = null;
    let bestScore = 0;

    for (const c of clusters) {
      // Exact CVE overlap is a strong clustering key (ignore giant Patch Tuesday rollups with >5 CVEs)
      if (cveSet.size > 0 && cveSet.size <= 4 && c.cves.size <= 6) {
        let sharedCve = false;
        for (const cve of cveSet) {
          if (c.cves.has(cve)) { sharedCve = true; break; }
        }
        if (sharedCve) {
          bestCluster = c;
          bestScore = 1.0;
          break;
        }
      }

      // Otherwise compare distinctive entity/vendor/product title tokens
      const inter = overlapCount(tokens, c.tokens);
      const jac = jaccard(tokens, c.tokens);
      if ((inter >= 2 && jac >= 0.28) || (inter >= 3 && jac >= 0.20)) {
        if (jac > bestScore) {
          bestScore = jac;
          bestCluster = c;
        }
      }
    }

    if (bestCluster) {
      bestCluster.items.push(item);
      for (const cve of cveSet) bestCluster.cves.add(cve);
      for (const t of tokens) bestCluster.tokens.add(t);
      if (item.isKev) bestCluster.isKev = true;
      if (item.kevRansomware) bestCluster.kevRansomware = true;
      if (item.publishedAt && (!bestCluster.latestAt || item.publishedAt > bestCluster.latestAt)) {
        bestCluster.latestAt = item.publishedAt;
      }
    } else {
      clusters.push({
        id: `inc-${clusters.length + 1}`,
        items: [item],
        cves: new Set(cveSet),
        tokens: new Set(tokens),
        isKev: Boolean(item.isKev),
        kevRansomware: Boolean(item.kevRansomware),
        latestAt: item.publishedAt
      });
    }
  }

  const profileKeywords = (profile.high_priority_keywords || []).map((k) => k.toLowerCase());

  // Rank and shape each cluster
  const shaped = clusters.map((c) => {
    // Sort items inside cluster: Tier 1 + non-social + highest weight first
    c.items.sort((a, b) => {
      const scoreA = (a.sourceTier === 1 ? 20 : 5) + (a.sourceWeight || 5) + (a.isKev ? 5 : 0) - (a.sourceCategory === 'humint' ? 6 : 0);
      const scoreB = (b.sourceTier === 1 ? 20 : 5) + (b.sourceWeight || 5) + (b.isKev ? 5 : 0) - (b.sourceCategory === 'humint' ? 6 : 0);
      return scoreB - scoreA;
    });

    const lead = c.items[0];
    const uniqueSources = new Map();
    for (const it of c.items) {
      if (!uniqueSources.has(it.sourceId)) {
        uniqueSources.set(it.sourceId, {
          id: it.sourceId,
          name: it.sourceName,
          tier: it.sourceTier,
          category: it.sourceCategory,
          weight: it.sourceWeight,
          title: it.title,
          url: it.url,
          publishedAt: it.publishedAt
        });
      }
    }

    const sources = [...uniqueSources.values()];
    const tier1Count = sources.filter((s) => s.tier === 1).length;
    const corpus = c.items.map((i) => `${i.title} ${i.summary}`).join(' ').toLowerCase();

    // Signal score calculation
    let signalScore = sources.reduce((acc, s) => acc + (s.weight || 5), 0);
    if (sources.length > 1) signalScore += (sources.length - 1) * 10; // Corroboration multiplier
    if (c.isKev) signalScore += 28;
    if (c.kevRansomware) signalScore += 10;
    if (/zero[- ]day|0[- ]day|actively exploited|in[- ]the[- ]wild/i.test(corpus)) signalScore += 16;
    if (/supply[- ]chain|breach|data leak|compromise|backdoor|stealer|oauth|session|token/i.test(corpus)) signalScore += 10;
    if (/rce|remote code execution|pre[- ]auth|unauthenticated|cvss\s*(9|10)/i.test(corpus)) signalScore += 9;

    // Persona relevance boost
    let personaHits = 0;
    for (const kw of profileKeywords) {
      if (corpus.includes(kw)) personaHits++;
    }
    signalScore += Math.min(personaHits * 3, 18);

    // Slight penalty for single-source low-tier HUMINT or generic GHSA without corroboration
    if (sources.length === 1 && tier1Count === 0) signalScore -= 6;

    // Build combined context for analyzer
    const combinedSummary = c.items
      .slice(0, 4)
      .map((it) => `[${it.sourceName}] ${it.title}. ${it.summary}`)
      .join('\n');

    return {
      id: c.id,
      leadTitle: lead.title,
      latestAt: c.latestAt,
      cves: [...c.cves].slice(0, 8),
      isKev: c.isKev,
      kevRansomware: c.kevRansomware,
      corroborationCount: sources.length,
      tier1Count,
      signalScore: Math.round(signalScore),
      sources,
      combinedSummary: combinedSummary.slice(0, 2600),
      rawItemsCount: c.items.length
    };
  });

  shaped.sort((a, b) => b.signalScore - a.signalScore);
  return shaped;
}

export function summarizeRansomware(victims = []) {
  const byGroup = new Map();
  const bySector = new Map();
  for (const v of victims) {
    const g = (v.group || 'unknown').toLowerCase();
    byGroup.set(g, (byGroup.get(g) || 0) + 1);
    const s = v.sector || 'Unknown';
    bySector.set(s, (bySector.get(s) || 0) + 1);
  }
  return {
    totalVictims: victims.length,
    topGroups: [...byGroup.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([group, count]) => ({ group, count })),
    topSectors: [...bySector.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([sector, count]) => ({ sector, count })),
    recent: victims.slice(0, 40)
  };
}

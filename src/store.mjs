import fs from 'node:fs/promises';
import path from 'node:path';
import { ROOT_DIR } from './ingest.mjs';

export const DATA_DIR = path.join(ROOT_DIR, 'data');
export const DIGESTS_DIR = path.join(DATA_DIR, 'digests');
export const STATE_PATH = path.join(DATA_DIR, 'state.json');

async function ensureDirs() {
  await fs.mkdir(DIGESTS_DIR, { recursive: true });
}

export async function saveDigest(digest) {
  await ensureDirs();
  const stamp = digest.generatedAt.slice(0, 16).replace(/[:T]/g, '-');
  const windowTag = `${digest.hours}h`;
  const latestWindowPath = path.join(DIGESTS_DIR, `latest-${windowTag}.json`);
  const latestPath = path.join(DIGESTS_DIR, 'latest.json');
  const archivePath = path.join(DIGESTS_DIR, `digest-${stamp}-${windowTag}.json`);

  const serialized = JSON.stringify(digest, null, 2);
  await Promise.all([
    fs.writeFile(latestWindowPath, serialized, 'utf8'),
    fs.writeFile(latestPath, serialized, 'utf8'),
    fs.writeFile(archivePath, serialized, 'utf8')
  ]);

  return { latestPath, latestWindowPath, archivePath };
}

export async function loadLatestDigest(hours = null) {
  await ensureDirs();
  const target = hours
    ? path.join(DIGESTS_DIR, `latest-${hours}h.json`)
    : path.join(DIGESTS_DIR, 'latest.json');
  try {
    const raw = await fs.readFile(target, 'utf8');
    return JSON.parse(raw);
  } catch {
    if (hours) {
      try {
        const raw = await fs.readFile(path.join(DIGESTS_DIR, 'latest.json'), 'utf8');
        return JSON.parse(raw);
      } catch {
        return null;
      }
    }
    return null;
  }
}

export async function listSavedDigests() {
  await ensureDirs();
  try {
    const files = await fs.readdir(DIGESTS_DIR);
    return files
      .filter((f) => f.startsWith('digest-') && f.endsWith('.json'))
      .sort()
      .reverse()
      .slice(0, 20);
  } catch {
    return [];
  }
}

export async function loadChecklistState() {
  await ensureDirs();
  try {
    const raw = await fs.readFile(STATE_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return { checkedActions: {}, dismissedIncidents: {}, updatedAt: null };
  }
}

export async function saveChecklistState(state) {
  await ensureDirs();
  const next = { ...state, updatedAt: new Date().toISOString() };
  await fs.writeFile(STATE_PATH, JSON.stringify(next, null, 2), 'utf8');
  return next;
}

export function renderMarkdownDigest(digest) {
  const dateStr = digest.generatedAt.slice(0, 10);
  const roleTitle = digest.roleTitle || digest.persona || 'Cybersecurity Professional';
  const briefLabel = digest.briefLabel || 'Industry Brief';
  const lines = [
    `---`,
    `type: threat-digest`,
    `created: ${dateStr}`,
    `window_hours: ${digest.hours}`,
    `role: "${roleTitle}"`,
    `engine: ${digest.analysisEngine}`,
    `tags: [dev/security]`,
    `---`,
    `# BlastRadius TL;DR — Last ${digest.hours}h (${dateStr})`,
    ``,
    `> **Tailored for:** ${roleTitle} · **Window:** ${digest.windowStart.slice(0, 16)}Z → ${digest.windowEnd.slice(0, 16)}Z · **Sources:** ${digest.stats.sourcesOk}/${digest.stats.sourcesTotal} live`,
    ``,
    `## 10-Second Takeaway`,
    digest.executiveSummary || '',
    ``
  ];

  if (digest.topLockdownChecklist?.length) {
    lines.push(`## Do This Today`);
    for (const item of digest.topLockdownChecklist) {
      lines.push(`- [ ] **${item.action}** *(${item.incidentTitle})*`);
    }
    lines.push('');
  }

  const order = ['ACT_NOW', 'WATCH_HARDEN', 'CUSTOMER_BRIEF', 'NOT_APPLICABLE'];
  const labels = {
    ACT_NOW: '🔴 Act Now',
    WATCH_HARDEN: '🟠 Watch & Harden',
    CUSTOMER_BRIEF: `🔵 ${briefLabel}`,
    NOT_APPLICABLE: '⚪ Skip / Out of Scope'
  };

  for (const verdict of order) {
    const group = (digest.incidents || []).filter((i) => i.verdict === verdict);
    if (!group.length) continue;
    lines.push(`## ${labels[verdict]} (${group.length})`);
    lines.push('');
    for (const inc of group) {
      const kevTag = inc.isKev ? ' · **KEV**' : '';
      const cveStr = inc.cves?.length ? ` · \`${inc.cves.slice(0, 2).join('`, `')}\`` : '';
      lines.push(`### ${inc.title}`);
      lines.push(`- **${inc.severity}**${kevTag}${cveStr} · \`${inc.rootCauseBucket}\` · ${inc.attackSurface}`);
      lines.push(`- **What actually happened:** ${inc.tldrRootCause || inc.realisticRootCause}`);
      lines.push(`- **Could this happen to me?** ${inc.couldThisHappenToMe}`);
      if (inc.lockItDown?.length) {
        lines.push(`- **Do:** ${inc.lockItDown.join(' · ')}`);
      }
      const srcLinks = (inc.sources || []).slice(0, 4).map((s) => `[${s.name}](${s.url})`).join(' · ');
      lines.push(`- **Sources (${inc.corroborationCount}):** ${srcLinks}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

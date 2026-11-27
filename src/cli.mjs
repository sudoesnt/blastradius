#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { ingestAll, loadProfileConfig, ROOT_DIR } from './ingest.mjs';
import { clusterIncidents, summarizeRansomware } from './cluster.mjs';
import { analyzeClusters } from './analyze.mjs';
import { saveDigest, loadLatestDigest, renderMarkdownDigest } from './store.mjs';

export async function runPipeline({
  hours = 168,
  engine = 'auto',
  maxIncidents = 28,
  roleOverride = null,
  onProgress
} = {}) {
  const baseProfile = await loadProfileConfig();
  const profile = roleOverride
    ? {
        ...baseProfile,
        roleId: roleOverride.roleId ?? baseProfile.roleId ?? 'custom',
        roleTitle: roleOverride.roleTitle || baseProfile.roleTitle,
        stackContext: roleOverride.stackContext ?? baseProfile.stackContext,
        briefLabel: roleOverride.briefLabel || baseProfile.briefLabel || 'Industry Brief'
      }
    : baseProfile;

  const raw = await ingestAll({ hours, onProgress });
  if (onProgress) {
    const okCount = raw.sourceHealth.filter((s) => s.status === 'ok').length;
    onProgress(`Ingested ${raw.items.length} signal items & ${raw.ransomwareVictims.length} ransomware victims from ${okCount}/${raw.sourceHealth.length} sources.`);
  }

  const clusters = clusterIncidents(raw.items, profile);
  if (onProgress) onProgress(`Clustered into ${clusters.length} unique incidents. Analyzing top ${Math.min(maxIncidents, clusters.length)}...`);

  const analyzed = await analyzeClusters(clusters, profile, { hours, engine, maxIncidents, onProgress });
  const ransomware = summarizeRansomware(raw.ransomwareVictims);

  const counts = {
    actNow: analyzed.incidents.filter((i) => i.verdict === 'ACT_NOW').length,
    watchHarden: analyzed.incidents.filter((i) => i.verdict === 'WATCH_HARDEN').length,
    customerBrief: analyzed.incidents.filter((i) => i.verdict === 'CUSTOMER_BRIEF').length,
    notApplicable: analyzed.incidents.filter((i) => i.verdict === 'NOT_APPLICABLE').length,
    kevCount: analyzed.incidents.filter((i) => i.isKev).length
  };

  const digest = {
    generatedAt: raw.generatedAt,
    hours,
    windowStart: raw.windowStart,
    windowEnd: raw.windowEnd,
    roleId: profile.roleId || 'custom',
    roleTitle: profile.roleTitle || profile.role || 'Cybersecurity Professional',
    stackContext: profile.stackContext || '',
    briefLabel: profile.briefLabel || 'Industry Brief',
    persona: profile.roleTitle || profile.role || 'Cybersecurity Professional',
    analysisEngine: analyzed.analysisEngine,
    fallbackReason: analyzed.fallbackReason,
    executiveSummary: analyzed.executiveSummary,
    stats: {
      sourcesTotal: raw.sourceHealth.length,
      sourcesOk: raw.sourceHealth.filter((s) => s.status === 'ok').length,
      rawItemsKept: raw.items.length,
      clustersTotal: clusters.length,
      incidentsAnalyzed: analyzed.incidents.length,
      ...counts
    },
    rootCauseBreakdown: analyzed.rootCauseBreakdown,
    topLockdownChecklist: analyzed.topLockdownChecklist,
    incidents: analyzed.incidents,
    ransomware,
    sourceHealth: raw.sourceHealth
  };

  const paths = await saveDigest(digest);
  if (onProgress) onProgress(`Saved digest -> ${paths.latestWindowPath}`);
  return { digest, paths };
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith('--')) {
        args[k] = true;
      } else {
        args[k] = next;
        i++;
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0] || 'run';

  if (cmd === 'run') {
    const hours = Number(args.hours || 168);
    const engine = String(args.engine || 'auto');
    const maxIncidents = Number(args.max || 28);
    const roleOverride = (args.role || args.stack)
      ? { roleId: 'custom', roleTitle: args.role, stackContext: args.stack }
      : null;

    const { digest } = await runPipeline({
      hours,
      engine,
      maxIncidents,
      roleOverride,
      onProgress: (msg) => console.log(`[blastradius] ${msg}`)
    });

    console.log('\n=== BLASTRADIUS TL;DR DIGEST ===');
    console.log(`Role: ${digest.roleTitle} | Window: Last ${digest.hours}h | Engine: ${digest.analysisEngine}`);
    console.log(`Act Now: ${digest.stats.actNow} | Watch: ${digest.stats.watchHarden} | ${digest.briefLabel}: ${digest.stats.customerBrief} | Skip: ${digest.stats.notApplicable} | KEVs: ${digest.stats.kevCount}`);
    console.log(`\n${digest.executiveSummary}\n`);

    for (const inc of digest.incidents.slice(0, 10)) {
      const badge = `[${inc.verdict}${inc.isKev ? '/KEV' : ''}]`;
      console.log(`${badge.padEnd(20)} ${inc.title}`);
      console.log(`   Root cause: ${inc.tldrRootCause || inc.realisticRootCause}`);
      console.log(`   Me?         ${inc.couldThisHappenToMe}`);
      if (inc.lockItDown?.[0]) console.log(`   Do:         ${inc.lockItDown[0]}`);
      console.log('');
    }

    if (args.out === 'md') {
      const md = renderMarkdownDigest(digest);
      const outPath = path.join(ROOT_DIR, 'data', `digest-${digest.hours}h.md`);
      await fs.writeFile(outPath, md, 'utf8');
      console.log(`Exported Markdown -> ${outPath}`);
    }
  } else if (cmd === 'sources') {
    const hours = Number(args.hours || 168);
    const raw = await ingestAll({ hours });
    console.log(`\nSource Health (last ${hours}h):`);
    for (const s of raw.sourceHealth) {
      const st = s.status.toUpperCase().padEnd(12);
      console.log(`${st} | T${s.tier} | ${s.name.padEnd(40)} | kept:${String(s.keptCount).padEnd(3)} | ${s.durationMs}ms ${s.error ? `(${s.error})` : ''}`);
    }
  } else if (cmd === 'export') {
    const hours = args.hours ? Number(args.hours) : null;
    const digest = await loadLatestDigest(hours);
    if (!digest) {
      console.error('No saved digest found. Run `npm run digest` first.');
      process.exit(1);
    }
    const md = renderMarkdownDigest(digest);
    if (args.file) {
      await fs.writeFile(path.resolve(args.file), md, 'utf8');
      console.log(`Wrote Markdown digest to ${path.resolve(args.file)}`);
    } else {
      console.log(md);
    }
  } else if (cmd === 'serve') {
    const { startServer } = await import('./server.mjs');
    startServer(Number(args.port || process.env.PORT || 3377));
  } else {
    console.log(`BlastRadius CLI
Usage:
  node src/cli.mjs run [--hours 168|48|24] [--role "Cloud Security Engineer"] [--stack "AWS, K8s, Mac"] [--engine auto|heuristic] [--out md]
  node src/cli.mjs sources [--hours 168]
  node src/cli.mjs export [--hours 168] [--file path.md]
  node src/cli.mjs serve [--port 3377]`);
  }
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
if (isDirectRun) {
  main().catch((err) => {
    console.error('[blastradius] Fatal:', err);
    process.exit(1);
  });
}

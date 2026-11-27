#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { ingestAll, loadProfileConfig } from './ingest.mjs';
import { clusterIncidents, summarizeRansomware } from './cluster.mjs';
import { analyzeClusters, findSameEventGroups } from './analyze.mjs';
import { resolveEngine } from './llm.mjs';
import { scanInventory } from './inventory.mjs';
import {
  DATA_DIR, INVENTORY_PATH, saveDigest, loadLatestDigest, renderMarkdownDigest,
  loadAnalysisCache, saveAnalysisCache, loadInventory, writeJsonAtomic
} from './store.mjs';

export async function runPipeline({
  hours = 168,
  engine = 'auto',
  maxIncidents = 0,
  roleOverride = null,
  onProgress
} = {}) {
  const log = (m) => onProgress && onProgress(m);
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

  // Only compare against digests that use stable incident ids (schema 2+).
  const prior = await loadLatestDigest(hours);
  const previous = prior?.schemaVersion >= 2 ? prior : null;
  const raw = await ingestAll({ hours, onProgress });
  const full = raw.sourceHealth.filter((s) => s.coverage === 'full').length;
  const enabled = raw.sourceHealth.filter((s) => !['disabled', 'unconfigured'].includes(s.coverage)).length;
  log(`Collected ${raw.items.length} items in window. ${full}/${enabled} enabled sources cover the whole window.`);

  // Stage 1: deterministic grouping. Stage 2: ask the model which groups are the same event.
  const chosen = resolveEngine(engine);
  const useModel = chosen !== 'none' && chosen !== 'heuristic';
  let clusters = clusterIncidents(raw.items, profile);
  let mergeNote = null;
  if (useModel && clusters.length > 1) {
    try {
      const groups = await findSameEventGroups(clusters, chosen);
      if (groups.length) {
        const before = clusters.length;
        clusters = clusterIncidents(raw.items, profile, { sameEventGroups: groups });
        log(`Merged duplicate coverage: ${before} -> ${clusters.length} incidents.`);
      }
    } catch (err) {
      mergeNote = `duplicate-merge step failed (${err.message})`;
      log(`Warning: ${mergeNote}; continuing with lexical clustering only.`);
    }
  }
  log(`${clusters.length} distinct incidents.`);

  const cache = await loadAnalysisCache();
  const inventory = await loadInventory();
  const analyzed = await analyzeClusters(clusters, profile, { hours, engine, maxIncidents, onProgress, cache, inventory });
  await saveAnalysisCache(cache);

  const prevIds = new Set((previous?.incidents || []).map((i) => i.id));
  for (const inc of analyzed.incidents) inc.isNew = Boolean(previous) && !prevIds.has(inc.id);

  const rwHealth = raw.sourceHealth.find((s) => s.type === 'ransomware-live');
  const ransomware = summarizeRansomware(raw.ransomwareVictims, { capped: rwHealth?.coverage === 'partial' });
  const count = (v) => analyzed.incidents.filter((i) => i.verdict === v).length;

  const digest = {
    schemaVersion: 2,
    generatedAt: raw.generatedAt,
    hours,
    windowStart: raw.windowStart,
    windowEnd: raw.windowEnd,
    previousGeneratedAt: previous?.generatedAt || null,
    roleId: profile.roleId || 'custom',
    roleTitle: profile.roleTitle || 'Cybersecurity Professional',
    stackContext: profile.stackContext || '',
    briefLabel: profile.briefLabel || 'Industry Brief',
    analysisEngine: analyzed.analysisEngine,
    fallbackReason: [analyzed.fallbackReason, mergeNote].filter(Boolean).join('; ') || null,
    executiveSummary: analyzed.executiveSummary,
    inventory: inventory
      ? { scannedAt: inventory.scannedAt, roots: inventory.roots.length, packages: Object.values(inventory.packages).reduce((a, l) => a + l.length, 0) }
      : null,
    stats: {
      sourcesTotal: raw.sourceHealth.length,
      sourcesEnabled: enabled,
      sourcesFullCoverage: full,
      sourcesPartial: raw.sourceHealth.filter((s) => s.coverage === 'partial').length,
      sourcesProblem: raw.sourceHealth.filter((s) => ['error', 'empty', 'stale'].includes(s.coverage)).length,
      rawItemsKept: raw.items.length,
      clustersTotal: clusters.length,
      incidentsAnalyzed: analyzed.stats.analyzed,
      unanalyzed: analyzed.stats.unanalyzed,
      fromCache: analyzed.stats.fromCache,
      skippedNotSecurity: analyzed.stats.skippedNotSecurity,
      newSinceLast: analyzed.incidents.filter((i) => i.isNew).length,
      actNow: count('ACT_NOW'),
      watchHarden: count('WATCH_HARDEN'),
      customerBrief: count('CUSTOMER_BRIEF'),
      notApplicable: count('NOT_APPLICABLE'),
      kevCount: analyzed.incidents.filter((i) => i.isKev).length,
      disclosed: analyzed.incidents.filter((i) => i.rootCauseBasis === 'DISCLOSED').length,
      inferred: analyzed.incidents.filter((i) => i.rootCauseBasis === 'INFERRED').length,
      unknownCause: analyzed.incidents.filter((i) => i.rootCauseBasis === 'UNKNOWN').length
    },
    rootCauseBreakdown: analyzed.rootCauseBreakdown,
    topLockdownChecklist: analyzed.topLockdownChecklist,
    incidents: analyzed.incidents,
    ransomware,
    sourceHealth: raw.sourceHealth
  };

  const paths = await saveDigest(digest);
  log(`Saved digest -> ${paths.latestWindowPath}`);
  return { digest, paths };
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith('--')) args[k] = true;
      else { args[k] = next; i++; }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function printSourceHealth(sourceHealth, hours) {
  console.log(`\nSource coverage (last ${hours}h):`);
  for (const s of sourceHealth) {
    console.log(`${String(s.coverage).toUpperCase().padEnd(12)} | T${s.tier} | ${s.name.padEnd(46).slice(0, 46)} | in window:${String(s.inStoreWindowCount ?? 0).padEnd(4)} | ${s.coverageNote || ''}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0] || 'run';

  if (cmd === 'run') {
    const { digest } = await runPipeline({
      hours: Number(args.hours || 168),
      engine: String(args.engine || 'auto'),
      maxIncidents: Number(args.max || 0),
      roleOverride: (args.role || args.stack) ? { roleId: 'custom', roleTitle: args.role, stackContext: args.stack } : null,
      onProgress: (msg) => console.log(`[blastradius] ${msg}`)
    });
    const st = digest.stats;

    console.log('\n=== BLASTRADIUS DIGEST ===');
    console.log(`Role: ${digest.roleTitle} | Window: last ${digest.hours}h | Engine: ${digest.analysisEngine}`);
    console.log(`Coverage: ${st.sourcesFullCoverage}/${st.sourcesEnabled} sources cover the whole window (${st.sourcesPartial} partial, ${st.sourcesProblem} with problems)`);
    console.log(`Act Now: ${st.actNow} | Watch: ${st.watchHarden} | ${digest.briefLabel}: ${st.customerBrief} | Skip: ${st.notApplicable} | Not analysed: ${st.unanalyzed} | KEVs: ${st.kevCount}`);
    console.log(`Root cause: ${st.disclosed} disclosed, ${st.inferred} inferred, ${st.unknownCause} not disclosed`);
    if (digest.fallbackReason) console.log(`NOTE: ${digest.fallbackReason}`);
    console.log(`\n${digest.executiveSummary}\n`);

    for (const inc of digest.incidents.filter((i) => i.verdict !== 'UNANALYZED').slice(0, 12)) {
      console.log(`${`[${inc.verdict}${inc.isKev ? '/KEV' : ''}]`.padEnd(22)} ${inc.title}`);
      console.log(`   How (${String(inc.rootCauseBasis).toLowerCase()}): ${inc.tldrRootCause}`);
      console.log(`   Me?  ${inc.couldThisHappenToMe}`);
      if (inc.lockItDown?.[0]) console.log(`   Do:  ${inc.lockItDown[0]}`);
      console.log('');
    }

    if (args.out === 'md') {
      const outPath = path.join(DATA_DIR, `digest-${digest.hours}h.md`);
      await fs.writeFile(outPath, renderMarkdownDigest(digest), 'utf8');
      console.log(`Exported Markdown -> ${outPath}`);
    }
  } else if (cmd === 'collect') {
    // Fetch and store only. Run this on a schedule (hourly is plenty) so every window is fully covered.
    const raw = await ingestAll({ hours: Number(args.hours || 168) });
    printSourceHealth(raw.sourceHealth, raw.hours);
    console.log(`\nStored. ${raw.items.length} items now in the last ${raw.hours}h.`);
  } else if (cmd === 'sources') {
    const hours = Number(args.hours || 168);
    const raw = await ingestAll({ hours, persist: false });
    printSourceHealth(raw.sourceHealth, hours);
  } else if (cmd === 'inventory') {
    const roots = args._.slice(1);
    if (!roots.length) {
      const inv = await loadInventory();
      if (!inv) console.log('No inventory yet. Usage: node src/cli.mjs inventory <folder> [<folder> ...]');
      else console.log(`Inventory from ${inv.scannedAt}: ${inv.manifestCount} manifests under ${inv.roots.join(', ')}\n  npm ${inv.packages.npm.length} | pip ${inv.packages.pip.length} | go ${inv.packages.go.length}`);
      return;
    }
    const inv = await scanInventory(roots);
    await writeJsonAtomic(INVENTORY_PATH, inv);
    console.log(`Scanned ${inv.manifestCount} manifests under ${inv.roots.join(', ')}\n  npm ${inv.packages.npm.length} | pip ${inv.packages.pip.length} | go ${inv.packages.go.length}\nSaved to ${INVENTORY_PATH} (stays on this machine).`);
  } else if (cmd === 'eval') {
    const { runEval } = await import('./eval.mjs');
    await runEval({ engine: String(args.engine || 'auto'), write: Boolean(args.write) });
  } else if (cmd === 'export') {
    const hours = args.hours ? Number(args.hours) : null;
    const digest = await loadLatestDigest(hours);
    if (!digest) {
      console.error(`No saved digest${hours ? ` for the ${hours}h window` : ''}. Run \`npm run digest\` first.`);
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
  node src/cli.mjs run [--hours 168|48|24] [--role "..."] [--stack "..."] [--engine auto|none] [--max N] [--out md]
  node src/cli.mjs collect [--hours 168]         fetch and store only (schedule this)
  node src/cli.mjs sources [--hours 168]         show per-feed coverage without storing
  node src/cli.mjs inventory <folder> [...]      scan package manifests so relevance is a lookup
  node src/cli.mjs eval [--engine auto] [--write] score root-cause calls against the labelled set
  node src/cli.mjs export [--hours 168] [--file path.md]
  node src/cli.mjs serve [--port 3377]`);
  }
}

const isDirectRun = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirectRun) {
  main().catch((err) => {
    console.error('[blastradius] Fatal:', err);
    process.exit(1);
  });
}

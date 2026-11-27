import { spawn } from 'node:child_process';

const ROOT_CAUSE_BUCKETS = [
  'Unpatched Edge / Infra',
  'Supply Chain / 3rd-Party',
  'Leaked Token / Secret',
  'Phishing / Bad Click / Infostealer',
  'Identity / OAuth / Session Abuse',
  'Nation-State 0-Day',
  'AI / Agent / Dev Tooling',
  'Cloud Misconfig / Exposed Data',
  'Ransomware / Vendor Extortion'
];

const VERDICT_RANK = {
  ACT_NOW: 0,
  WATCH_HARDEN: 1,
  CUSTOMER_BRIEF: 2,
  NOT_APPLICABLE: 3
};

const SEVERITY_RANK = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3
};

function buildSystemPrompt(profile) {
  const roleTitle = profile.roleTitle || profile.role || 'Cybersecurity Professional';
  const stackContext = profile.stackContext || profile.summary || 'Cloud infrastructure, GitHub, SSO/OAuth, Mac/Windows endpoints, browsers, and developer tooling';
  const briefLabel = profile.briefLabel || 'Industry / Peer Brief';

  return `You are a blunt, deeply technical Principal Threat Intel Analyst writing an ultra-succinct, actionable security TL;DR digest (like TLDR Sec, but tighter and stripped of all filler).

Reader role: ${roleTitle}
Reader footprint & stack: ${stackContext}

CORE PRINCIPLES:
1. BREVITY FIRST. Every field must be scannable in 2 seconds. Zero fluff, zero throat-clearing, zero generic advice like "enable MFA" or "stay vigilant".
2. REALISTIC ROOT CAUSE. Cut through vendor PR and media hype. State plainly what actually caused the compromise (e.g., "stolen employee GitHub PAT pushed into CI/CD", "trojanized ad download wrote Chrome enterprise policy to force-install a Gmail spy extension", "internet-facing appliance popped before patch window", "3rd-party signup bug let attackers edit live customer JS").
3. UNIVERSAL CORE, LIGHT ROLE TAILORING. Most practical security risks (credential/token theft, malicious browser extensions, exposed dev/MCP ports, unpatched OS/browser 0-days, OAuth phishing) apply across tech roles. Use the reader's role (${roleTitle}) to sharpen the verdict and the one-line "Could this happen to me?" call — don't invent fake relevance if it doesn't apply.
4. DISCERNING VERDICTS:
   - "ACT_NOW": Direct, realistic risk to the reader's own accounts/endpoints/code right now (keep this tight: typically 1–5 items max).
   - "WATCH_HARDEN": Plausible secondary risk or good hygiene trigger for their stack.
   - "CUSTOMER_BRIEF": Major real-world incident / KEV that does NOT hit the reader personally, but matters as a ${briefLabel} / peer talking point.
   - "NOT_APPLICABLE": Niche, out-of-stack, or low-impact — safe to skip.
5. ACTIONABLE CHECKS ONLY. If verdict is ACT_NOW or WATCH_HARDEN, give 1–2 concrete, specific checks (exact URL, command, setting, or audit step, <= 125 chars each). If no personal action is needed, return an empty array [].

Return ONLY valid JSON (no markdown fences) matching this exact schema:
{
  "executiveSummary": "2 crisp sentences max. State the dominant real-world attack pattern(s) this window and the #1 thing the reader should actually check.",
  "incidents": [
    {
      "clusterId": "matching input cluster id",
      "title": "Crisp, concrete headline (<= 95 chars)",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "verdict": "ACT_NOW" | "WATCH_HARDEN" | "CUSTOMER_BRIEF" | "NOT_APPLICABLE",
      "rootCauseBucket": one of ${JSON.stringify(ROOT_CAUSE_BUCKETS)},
      "attackSurface": "Short surface label (e.g. 'GitHub / CI-CD', 'Chrome Extensions / Policy', 'Local MCP / Docker', 'Internet-Facing Edge Appliance')",
      "tldrRootCause": "1 razor-sharp sentence (<= 145 chars) stating what REALISTICALLY caused the breach.",
      "couldThisHappenToMe": "1 sharp sentence (<= 150 chars) answering 'Could this happen to me?' directly for a ${roleTitle}.",
      "realisticRootCause": "1–2 tight technical sentences for the optional deep-dive view.",
      "howItCouldHitYou": "1 concise sentence tracing the realistic path to this reader's footprint (or why it doesn't apply).",
      "lockItDown": ["Short concrete check 1 (<= 125 chars)", "Optional check 2"],
      "roleAngle": "Optional 1-line talking point / exec context for a ${roleTitle} (empty string if none)"
    }
  ]
}`;
}

function buildUserPayload(clusters, hours) {
  const compact = clusters.map((c) => ({
    clusterId: c.id,
    leadTitle: c.leadTitle,
    latestAt: c.latestAt,
    isKev: c.isKev,
    kevRansomware: c.kevRansomware,
    cves: c.cves,
    corroborationCount: c.corroborationCount,
    sources: c.sources.map((s) => `${s.name} (T${s.tier})`),
    evidence: c.combinedSummary.slice(0, 1200)
  }));

  return `Produce a tight, ultra-scannable TL;DR digest of these ${compact.length} clustered incidents from the last ${hours} hours.\n\nINPUT CLUSTERS:\n${JSON.stringify(compact, null, 2)}`;
}

function extractJsonObject(text) {
  const trimmed = text.trim();
  const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fence ? fence[1].trim() : trimmed;
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) {
    throw new Error('LLM response did not contain valid JSON object');
  }
  return JSON.parse(candidate.slice(start, end + 1));
}

async function runClaudeCli(systemPrompt, userPayload) {
  const combinedPrompt = `${systemPrompt}\n\n---\n\n${userPayload}`;
  return new Promise((resolve, reject) => {
    const child = spawn('claude', ['-p', '--output-format', 'text'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false
    });

    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('claude CLI timed out after 150s'));
    }, 150000);

    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        return reject(new Error(`claude CLI exited ${code}: ${stderr.slice(0, 300)}`));
      }
      try {
        resolve(extractJsonObject(stdout));
      } catch (e) {
        reject(new Error(`Failed to parse claude CLI JSON: ${e.message}`));
      }
    });

    child.stdin.write(combinedPrompt);
    child.stdin.end();
  });
}

async function runAnthropicApi(systemPrompt, userPayload) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514',
      max_tokens: 8192,
      temperature: 0.2,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPayload }]
    })
  });
  if (!res.ok) throw new Error(`Anthropic API HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const data = await res.json();
  const text = (data.content || []).map((c) => c.text || '').join('\n');
  return extractJsonObject(text);
}

async function runGeminiApi(systemPrompt, userPayload) {
  const model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(process.env.GEMINI_API_KEY)}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents: [{ role: 'user', parts: [{ text: userPayload }] }],
      generationConfig: { temperature: 0.2, responseMimeType: 'application/json' }
    })
  });
  if (!res.ok) throw new Error(`Gemini API HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const data = await res.json();
  const text = data.candidates?.[0]?.content?.parts?.map((p) => p.text || '').join('\n') || '';
  return extractJsonObject(text);
}

async function runOpenAiApi(systemPrompt, userPayload) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`
    },
    body: JSON.stringify({
      model: process.env.OPENAI_MODEL || 'gpt-4.1',
      temperature: 0.2,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPayload }
      ]
    })
  });
  if (!res.ok) throw new Error(`OpenAI API HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const data = await res.json();
  const text = data.choices?.[0]?.message?.content || '';
  return extractJsonObject(text);
}

// Fast deterministic practitioner heuristic analyzer (zero-key / offline fallback)
function runHeuristicAnalysis(clusters, profile = {}) {
  const roleLabel = profile.roleTitle || 'Security Professional';
  const incidents = clusters.map((c) => {
    const text = `${c.leadTitle} ${c.combinedSummary}`.toLowerCase();

    let rootCauseBucket = 'Unpatched Edge / Infra';
    let attackSurface = 'Enterprise Infrastructure';
    let tldrRootCause = 'Unpatched internet-facing software flaw exploited before defenders patched or segmented it.';
    let realisticRootCause = tldrRootCause;
    let verdict = 'CUSTOMER_BRIEF';
    let severity = c.isKev ? 'CRITICAL' : 'HIGH';
    let couldThisHappenToMe = 'Unlikely to hit you directly — track as an industry/peer talking point.';
    let howItCouldHitYou = 'No direct overlap unless you run this component in a lab or production stack.';
    let lockItDown = [];
    let roleAngle = 'Check whether your organization or customers expose this service publicly.';

    if (/(mcp|claude|anthropic|openai|llm|prompt injection|agent|cursor|copilot|langchain|ollama|obsidian|ai coding)/i.test(text)) {
      rootCauseBucket = 'AI / Agent / Dev Tooling';
      attackSurface = 'Local AI Agents / MCP / Dev Tooling';
      severity = 'HIGH';
      verdict = 'WATCH_HARDEN';
      tldrRootCause = 'Unauthenticated local MCP/agent service or loose tool permissions exposed shells and provider API keys.';
      realisticRootCause = 'Local AI tooling shipped bound to 0.0.0.0 or trusted untrusted context, turning an assistant into an RCE/secret-theft proxy.';
      couldThisHappenToMe = 'Yes if you run local MCP/agent tools — anything bound beyond 127.0.0.1 exposes your API keys and filesystem.';
      howItCouldHitYou = 'A local MCP container or extension with broad shell/env access leaks keys on shared Wi-Fi or via untrusted repo inputs.';
      lockItDown = [
        'Verify local MCP/agent services bind to 127.0.0.1 only (`netstat`/`lsof`).',
        'Move LLM/GitHub API keys out of plain `.env` files and audit notes/chats for stray tokens.'
      ];
      roleAngle = 'Shadow AI & over-privileged agent tooling is a fast-growing enterprise blind spot.';
    } else if (/(github|npm|pypi|supply[- ]chain|trojanized|malicious package|javascript|script|cdn|optimizely|vscode|extension|action[s]? workflow|docker hub)/i.test(text)) {
      rootCauseBucket = 'Supply Chain / 3rd-Party';
      attackSurface = 'GitHub / Packages / 3rd-Party Scripts';
      severity = c.corroborationCount >= 2 || /1password|sap|188|millions|critical/i.test(text) ? 'CRITICAL' : 'HIGH';
      verdict = /(1password|github|npm|pypi|vscode|extension)/i.test(text) ? 'ACT_NOW' : 'CUSTOMER_BRIEF';
      tldrRootCause = 'Compromised developer token, package maintainer, or 3rd-party JS host injected malicious code upstream.';
      realisticRootCause = 'Attackers bypassed perimeter controls by riding stolen developer credentials or a compromised 3rd-party script/package into trusted builds.';
      couldThisHappenToMe = verdict === 'ACT_NOW'
        ? 'Yes — long-lived GitHub PATs, CLI tokens, or poisoned dev packages bypass MFA and compromise repos directly.'
        : 'Not directly unless you operate the affected vendor — strong supply-chain talking point.';
      howItCouldHitYou = 'A stolen GitHub/gh token or malicious dependency gives silent read/push access to your repos and CI/CD.';
      lockItDown = verdict === 'ACT_NOW'
        ? [
            'Audit `github.com/settings/tokens` & `gh auth status`; replace classic PATs with short-lived fine-grained tokens.',
            'Enforce branch protection + signed commits on key repos and review `github.com/settings/security-log`.'
          ]
        : [];
      roleAngle = 'Classic software/script supply-chain blast radius: identity + CI/CD guardrails beat perimeter checks.';
    } else if (/(leaked|exposed|hardcoded|api key|token|secret|credential|s3 bucket|gcs|misconfig|unsecured database|publicly exposed)/i.test(text)) {
      rootCauseBucket = 'Leaked Token / Secret';
      attackSurface = 'Secrets / Cloud IAM / Repos';
      severity = 'HIGH';
      verdict = 'ACT_NOW';
      tldrRootCause = 'Static credentials or cloud storage left exposed; automated scrapers harvested and replayed them.';
      realisticRootCause = 'Human or CI pipeline leaked long-lived API keys/tokens in repos, logs, or misconfigured cloud resources.';
      couldThisHappenToMe = 'Yes — static demo/cloud keys or tokens left in repos, `.env` files, or notes are the #1 realistic breach path.';
      howItCouldHitYou = 'A forgotten static cloud key or PAT in a scratch repo or synced note gets harvested.';
      lockItDown = [
        'Scan local repos and notes for stray API keys/PATs and rotate anything static.',
        'Replace long-lived cloud keys in labs/sandboxes with short-lived OIDC/WIF credentials.'
      ];
      roleAngle = 'Eliminating static long-lived secrets remains the highest-ROI cloud security win.';
    } else if (/(oauth|sso|okta|entra|google workspace|gmail|mfa|aitm|session cookie|cookie theft|helpdesk|vishing|scattered spider|shinyhunters|salesforce)/i.test(text)) {
      rootCauseBucket = 'Identity / OAuth / Session Abuse';
      attackSurface = 'SSO / OAuth / Browser Sessions';
      severity = 'CRITICAL';
      verdict = 'ACT_NOW';
      tldrRootCause = 'Attackers bypassed MFA via stolen browser session cookies, malicious OAuth app consent, or AiTM phishing.';
      realisticRootCause = 'Session tokens or rogue OAuth grants gave full inbox/SaaS access with zero password cracking.';
      couldThisHappenToMe = 'Yes — hijacked browser sessions or rogue OAuth apps read email/SaaS right past MFA and passkeys.';
      howItCouldHitYou = 'Approving an unsolicited OAuth prompt or landing an extension/infostealer in a browser signed into work SaaS.';
      lockItDown = [
        'Review & revoke unused 3rd-party OAuth apps in Google/M365/GitHub account security settings.',
        'Keep work SSO strictly isolated in a dedicated browser profile with hardware FIDO2/passkey auth.'
      ];
      roleAngle = 'Identity & session theft defeats MFA — session-binding and OAuth governance are mandatory.';
    } else if (/(clickfix|infostealer|lumma|remus|sys01|stealer|phishing|malvertising|fake captcha|chrome|firefox|browser|outlook|windows|macos|apple|ios|spyware)/i.test(text)) {
      rootCauseBucket = /spyware|zero[- ]click|pegasus|mercenary|apt/i.test(text)
        ? 'Nation-State 0-Day'
        : 'Phishing / Bad Click / Infostealer';
      attackSurface = 'Endpoint / Browser / Extensions';
      severity = c.isKev || /zero[- ]day|0[- ]day|actively exploited|chrome|outlook|apple|ios|sys01/i.test(text) ? 'CRITICAL' : 'HIGH';
      verdict = /chrome|firefox|windows|macos|apple|ios|outlook|clickfix|infostealer|sys01|remus/i.test(text) ? 'ACT_NOW' : 'WATCH_HARDEN';
      tldrRootCause = /sys01|remus|clickfix|infostealer|stealer/i.test(text)
        ? 'Trojanized download/ad lure installed an infostealer or force-loaded a spy Chrome extension to siphon webmail & cookies.'
        : 'Client-side OS/browser/email flaw triggered by opening crafted content with minimal user interaction.';
      realisticRootCause = tldrRootCause;
      couldThisHappenToMe = 'Yes — hits everyday Windows/Mac browsers and email directly; one bad download or unpatched browser exposes live sessions.';
      howItCouldHitYou = 'Running an unvetted download/utility on a personal machine or browsing on an unpatched OS/browser.';
      lockItDown = [
        'Check `chrome://management`, `chrome://policy`, and `chrome://extensions` for unexpected managed policies or unknown extensions.',
        'Verify OS, Chrome/Firefox, and mobile security patches are current.'
      ];
      roleAngle = 'Browser-extension and policy persistence is now the fastest path around enterprise MFA.';
    } else if (/(vpn|firewall|router|appliance|mitel|ivanti|fortinet|palo alto|juniper|cisco|vmware|sap|sharepoint|citrix|f5|sonicwall|xen|drupal|cacti|check point|ics|scada|danfoss)/i.test(text)) {
      rootCauseBucket = /(apt|iran|china|russia|dprk|nation[- ]state|zero[- ]day)/i.test(text)
        ? 'Nation-State 0-Day'
        : 'Unpatched Edge / Infra';
      attackSurface = 'Internet-Facing Edge / Infra Appliance';
      severity = c.isKev || /cvss\s*(9|10)|rce|pre[- ]auth|actively exploited/i.test(text) ? 'CRITICAL' : 'HIGH';
      verdict = /ics|scada|danfoss|refrigeration|plc/i.test(text) ? 'NOT_APPLICABLE' : 'CUSTOMER_BRIEF';
      tldrRootCause = 'Pre-auth RCE or auth bypass on internet-exposed enterprise appliances — mass-exploited within hours of disclosure.';
      realisticRootCause = tldrRootCause;
      couldThisHappenToMe = verdict === 'NOT_APPLICABLE'
        ? 'No — niche OT/ICS hardware outside your stack; skip.'
        : `Not personally unless you run this appliance — key ${profile.briefLabel || 'industry'} talking point.`;
      howItCouldHitYou = 'No direct personal exposure unless an ephemeral lab/demo instance was left internet-facing.';
      lockItDown = [];
      roleAngle = 'Highlights why internet-exposed management planes and edge appliances need continuous ASM inventory.';
    } else if (/(ransomware|extortion|breach|data leak|records|stolen data|air force|federal)/i.test(text)) {
      rootCauseBucket = 'Ransomware / Vendor Extortion';
      attackSurface = '3rd-Party Vendor / Enterprise Data';
      severity = /millions|major|critical|government|federal|air force/i.test(text) ? 'HIGH' : 'MEDIUM';
      verdict = 'CUSTOMER_BRIEF';
      tldrRootCause = 'Downstream data breach/extortion stemming from stolen creds, unpatched edge infra, or 3rd-party vendor compromise.';
      realisticRootCause = tldrRootCause;
      couldThisHappenToMe = 'Not directly — monitor only if you hold an account or vendor integration with the affected org.';
      howItCouldHitYou = 'Indirect exposure only if your personal/org data sat with the breached vendor.';
      lockItDown = [];
      roleAngle = 'Reinforces 3rd-party blast-radius mapping and least-privilege vendor access.';
    } else if (c.signalScore < 18) {
      verdict = 'NOT_APPLICABLE';
      severity = 'LOW';
      couldThisHappenToMe = 'Low signal / out of scope — safe to skip.';
      lockItDown = [];
    }

    if (!c.isKev && c.corroborationCount === 1 && severity === 'CRITICAL' && !/zero[- ]day|actively exploited|cvss\s*10|1password|sap/i.test(text)) {
      severity = 'HIGH';
    }

    return {
      clusterId: c.id,
      title: c.leadTitle.replace(/^CISA KEV:\s*/i, '').slice(0, 95),
      severity,
      verdict,
      rootCauseBucket,
      attackSurface,
      tldrRootCause,
      realisticRootCause,
      couldThisHappenToMe,
      howItCouldHitYou,
      lockItDown,
      roleAngle
    };
  });

  const actNowCount = incidents.filter((i) => i.verdict === 'ACT_NOW').length;
  const kevCount = clusters.filter((c) => c.isKev).length;
  const topBuckets = countBuckets(incidents).slice(0, 2).map((b) => b.bucket).join(' + ');

  return {
    executiveSummary: `${incidents.length} incidents rolled up for ${roleLabel} (${actNowCount} Act Now, ${kevCount} active CISA KEVs). Dominant root causes: ${topBuckets || 'mixed software & credential flaws'}.`,
    incidents
  };
}

export function countBuckets(incidents = []) {
  const map = new Map();
  for (const inc of incidents) {
    const k = inc.rootCauseBucket || 'Other';
    map.set(k, (map.get(k) || 0) + 1);
  }
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([bucket, count]) => ({ bucket, count }));
}

function resolveEngine(requested = 'auto') {
  if (requested && requested !== 'auto') return requested;
  if (process.env.ANTHROPIC_API_KEY) return 'anthropic';
  if (process.env.GEMINI_API_KEY) return 'gemini';
  if (process.env.OPENAI_API_KEY) return 'openai';
  return 'claude-cli';
}

export async function analyzeClusters(clusters, profile, { hours = 168, engine = 'auto', maxIncidents = 28, onProgress } = {}) {
  const topClusters = clusters.slice(0, maxIncidents);
  const chosen = resolveEngine(engine);
  let analysisResult = null;
  let actualEngine = chosen;
  let fallbackReason = null;

  if (topClusters.length === 0) {
    return {
      analysisEngine: 'none',
      fallbackReason: 'No incidents in selected window',
      executiveSummary: `No qualifying high-signal incidents found in the last ${hours} hours.`,
      incidents: [],
      rootCauseBreakdown: [],
      topLockdownChecklist: []
    };
  }

  const systemPrompt = buildSystemPrompt(profile);
  const userPayload = buildUserPayload(topClusters, hours);

  if (chosen !== 'heuristic') {
    if (onProgress) onProgress(`Generating succinct TL;DR & root-cause analysis via ${chosen} for "${profile.roleTitle || 'Security Pro'}"...`);
    try {
      if (chosen === 'anthropic') {
        analysisResult = await runAnthropicApi(systemPrompt, userPayload);
      } else if (chosen === 'gemini') {
        analysisResult = await runGeminiApi(systemPrompt, userPayload);
      } else if (chosen === 'openai') {
        analysisResult = await runOpenAiApi(systemPrompt, userPayload);
      } else if (chosen === 'claude-cli') {
        analysisResult = await runClaudeCli(systemPrompt, userPayload);
      }
    } catch (err) {
      fallbackReason = `${chosen} failed (${err.message}); fell back to deterministic analyzer`;
      if (onProgress) onProgress(`Warning: ${fallbackReason}`);
      actualEngine = 'heuristic-fallback';
      analysisResult = runHeuristicAnalysis(topClusters, profile);
    }
  } else {
    if (onProgress) onProgress(`Running fast local triage on ${topClusters.length} clusters...`);
    analysisResult = runHeuristicAnalysis(topClusters, profile);
  }

  const byClusterId = new Map(topClusters.map((c) => [c.id, c]));
  const heuristicMap = new Map(runHeuristicAnalysis(topClusters, profile).incidents.map((h) => [h.clusterId, h]));

  const merged = [];
  for (const item of analysisResult.incidents || []) {
    const cluster = byClusterId.get(item.clusterId);
    if (!cluster) continue;
    const h = heuristicMap.get(item.clusterId);
    const verdict = ['ACT_NOW', 'WATCH_HARDEN', 'CUSTOMER_BRIEF', 'NOT_APPLICABLE'].includes(item.verdict)
      ? item.verdict
      : (h?.verdict || 'CUSTOMER_BRIEF');
    const severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(item.severity)
      ? item.severity
      : (h?.severity || 'MEDIUM');

    const cleanedActions = Array.isArray(item.lockItDown)
      ? item.lockItDown.filter((a) => a && !/^(none|no personal action|n\/a)\.?$/i.test(String(a).trim()))
      : (h?.lockItDown || []);

    const realisticRootCause = item.realisticRootCause || item.tldrRootCause || h?.realisticRootCause || '';
    const tldrRootCause = item.tldrRootCause || realisticRootCause.split(/(?<=[.!?])\s+/)[0] || h?.tldrRootCause || '';

    merged.push({
      id: cluster.id,
      title: item.title || cluster.leadTitle,
      severity,
      verdict,
      rootCauseBucket: ROOT_CAUSE_BUCKETS.includes(item.rootCauseBucket)
        ? item.rootCauseBucket
        : (h?.rootCauseBucket || 'Unpatched Edge / Infra'),
      attackSurface: item.attackSurface || h?.attackSurface || 'Enterprise Infrastructure',
      tldrRootCause,
      realisticRootCause,
      couldThisHappenToMe: item.couldThisHappenToMe || h?.couldThisHappenToMe || '',
      howItCouldHitYou: item.howItCouldHitYou || h?.howItCouldHitYou || '',
      lockItDown: cleanedActions,
      roleAngle: item.roleAngle || item.customerAngle || '',
      cves: cluster.cves,
      isKev: cluster.isKev,
      kevRansomware: cluster.kevRansomware,
      corroborationCount: cluster.corroborationCount,
      tier1Count: cluster.tier1Count,
      signalScore: cluster.signalScore,
      latestAt: cluster.latestAt,
      sources: cluster.sources
    });
  }

  merged.sort((a, b) => {
    const v = (VERDICT_RANK[a.verdict] ?? 9) - (VERDICT_RANK[b.verdict] ?? 9);
    if (v !== 0) return v;
    if (a.isKev !== b.isKev) return a.isKev ? -1 : 1;
    const s = (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
    if (s !== 0) return s;
    return b.signalScore - a.signalScore;
  });

  const seenActions = new Set();
  const topLockdownChecklist = [];
  for (const inc of merged) {
    if (inc.verdict !== 'ACT_NOW' && inc.verdict !== 'WATCH_HARDEN') continue;
    for (const action of inc.lockItDown || []) {
      const norm = action.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
      if (!norm || seenActions.has(norm)) continue;
      seenActions.add(norm);
      topLockdownChecklist.push({
        id: `${inc.id}-${topLockdownChecklist.length + 1}`,
        verdict: inc.verdict,
        severity: inc.severity,
        action,
        incidentId: inc.id,
        incidentTitle: inc.title
      });
      if (topLockdownChecklist.length >= 10) break;
    }
    if (topLockdownChecklist.length >= 10) break;
  }

  return {
    analysisEngine: actualEngine,
    fallbackReason,
    executiveSummary: analysisResult.executiveSummary || '',
    incidents: merged,
    rootCauseBreakdown: countBuckets(merged),
    topLockdownChecklist
  };
}

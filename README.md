# BlastRadius

An ultra-succinct, actionable cybersecurity threat & breach TL;DR — tailored to your role.

Instead of a noisy 300-link RSS firehose or a long newsletter, BlastRadius pulls from ~35 vetted Tier-1 & Tier-2 practitioner infosec sources, strips vendor marketing fluff, clusters duplicate coverage, identifies what **realistically** caused each breach, and gives you:

1. **What actually happened** (1 blunt sentence, zero PR spin)
2. **Could this happen to me?** (1 line tailored to your role & stack)
3. **Do this** (1–2 concrete checks, or nothing if it doesn't apply)

## Quick Start

Requires Node.js >= 22 (zero external npm dependencies, zero `node_modules`).

```bash
# Run a 7-day (168h), 48h, or 24h digest
npm run digest
npm run digest:48h
npm run digest:24h

# Tailor a CLI run to any role on the fly
node src/cli.mjs run --hours 48 --role "Staff Platform Engineer" --stack "AWS, K8s, GitHub, Mac"

# Launch the local web dashboard (http://127.0.0.1:3377)
npm start

# Check live health of all configured sources
npm run sources
```

## Role Tailoring
Pick a built-in role preset directly in the dashboard bar (`Cybersecurity Pro`, `Field CTO / Security SE`, `CISO / SecOps Lead`, `Software / Platform Engineer`, `IT / Enterprise Admin`, `Tech Executive`) or type **any custom role + 1-line stack** — saved locally to `data/profile.local.json` (gitignored so personal context never enters version control).

## Curated Sources
- **Active Exploitation & Ground Truth:** CISA KEV (JSON), CERT/CC, GreyNoise, SANS ISC, GitHub Critical Advisories, Ransomware.live.
- **Tier-1 Research & IR Labs:** Wiz Cloud Threat Landscape & Research, Google Threat Intelligence Group (GTIG/Mandiant), Google Project Zero, watchTowr Labs, Huntress, Microsoft Threat Intel, Cisco Talos, Palo Alto Unit 42, SentinelLabs, Cloudflare Security, Trail of Bits, Citizen Lab, DoublePulsar.
- **Investigative Breach Desks:** Krebs on Security, Risky Business News, The Record, BleepingComputer, DataBreaches.net, CyberScoop, SecurityWeek, The Hacker News.
- **Real-Time HUMINT:** Mastodon (`@GossiTheDog`, `@briankrebs`, `@wdormann`), Bluesky, Hacker News security signal, plus optional X/Twitter API v2 (`X_BEARER_TOKEN`) in `.env`.

## Analysis Engines
- **`--engine auto`** (default): uses `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, or `OPENAI_API_KEY` if set; otherwise shells out cleanly to local `claude -p` CLI; falls back to the built-in deterministic analyzer if offline.
- **`--engine heuristic`**: instant (~4s) zero-LLM local triage.

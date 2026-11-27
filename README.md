# BlastRadius

[![CI](https://github.com/sudoesnt/blastradius/actions/workflows/ci.yml/badge.svg)](https://github.com/sudoesnt/blastradius/actions/workflows/ci.yml)

**[Try the read-only demo](https://sudoesnt.github.io/blastradius/)** — a recent snapshot analysed for a generic cloud-security role. Run it locally to tailor it to yours.

A short, role-tailored digest of the week's breaches and exploited vulnerabilities. For each incident it answers three questions:

1. **How did they get in?** One sentence, labelled as *stated by source*, *inferred*, or *not disclosed*.
2. **Could this happen to me?** One sentence for your role and stack, backed by a lookup against your own inventory where one is possible.
3. **What should I check?** One or two concrete checks, or nothing.

Then it lets you hand the check to your own AI agent, on your own machine, and shows you the receipt.

## Who this is for

One person. BlastRadius is about your laptop, your browser, your GitHub account and your own projects, the week something relevant happens to someone else.

It is deliberately not an organisation's security platform. It does not scan a cloud estate or a fleet, does not run continuously, has no agents to deploy and no console to administer. It starts from the news ("this is how they got in"), asks whether the same door is open for you, and helps you close it in a few minutes.

## Hand it to your agent

Every incident you might act on has a **Give this to ...** button. It gives the job to an AI agent you already use (Claude Code, Codex or Antigravity) on this machine.

- **BlastRadius never sees a login.** The agent runs as you, with the tools you are already signed in to. No tokens are entered, stored or sent by BlastRadius.
- **What the agent runs comes from a reviewed playbook**, not from the news. The analysis model can only pick a playbook id from the closed list in `config/playbooks.json` (GitHub tokens, browser extensions, exposed local services, secrets on disk, package exposure, account sign-in review). The incident itself is passed along as clearly marked background, with an instruction to ignore anything in it that reads like a command.
- **Investigate first, ask before changing.** Playbook steps are read-only, and a repository check rejects a playbook whose investigate steps contain a command that changes state. Fixes are proposed as a list and each one needs your yes. The agent is started in its normal ask-first mode, in a visible terminal.
- **Receipts.** When it finishes, the agent writes a small JSON file saying what it checked, what it found and what it changed. The dashboard shows it on the incident and ticks the boxes if the check came back clean or fixed. Receipts are treated as untrusted: only known fields are kept, as plain text.
- **Any agent works.** If your agent has no command-line launcher, the button copies the same prompt for you to paste.

What "local" means here: BlastRadius sends nothing anywhere for a handoff. Your agent talks to its own model provider as it always does, so what it reads while checking (file paths, repository names) goes there under that agent's own terms. The prompt tells it never to print or store secret values. Use an agent backed by a local model if you want nothing to leave the machine at all.

## What you can and cannot trust

BlastRadius reads feed headlines and teasers, not full articles. It is built so that this limit is visible rather than hidden:

- **Root cause is labelled by how it is known.** "Stated by source" requires a verbatim quote, and the quote is checked against the source text in code. If the quote is not there, the claim is downgraded to "inferred". If the cause is not public, the incident is counted as "not disclosed" instead of being given a best guess.
- **Every incident is analysed**, not a pre-ranked subset. If the model is unavailable, incidents are listed as *not analysed* with their sources. There is no keyword-based stand-in that writes analysis.
- **Coverage is reported per feed.** A source counts as covering the window only if its feed reaches back to the window start. Feeds that return only their latest few posts are marked *partial* until collection has run long enough (see Scheduling).
- **Corroboration counts publishers, not feeds.** A reporter's blog and the same reporter's social post are one source. Multi-story roundups never count as corroboration.
- **Feed text is untrusted input.** The model runs with no tools, no MCP servers and none of your own agent settings, and is told to treat the input as data. See Security.
- **Scores are published.** `eval/RESULTS.md` holds the latest run against the labelled set in `eval/cases.json`, with its limits stated.

It is a reading aid. It does not replace reading the linked source before you act or brief someone.

## Quick start

Requires Node.js 22 or later. No npm dependencies.

```bash
npm run digest            # 7-day digest (also digest:48h, digest:24h)
npm start                 # dashboard at http://127.0.0.1:3377
npm run sources           # per-feed coverage, without storing anything
npm run check             # deterministic repo checks (syntax, config, eval labels, no secrets)
npm test                  # unit and server tests
npm run eval              # score root-cause calls against eval/cases.json
```

Tailor a run from the command line:

```bash
node src/cli.mjs run --hours 48 --role "Staff Platform Engineer" --stack "AWS, K8s, GitHub, Mac"
```

## Scheduling (needed for full windows)

Many news feeds only return their latest 5 to 15 posts, which is a day or two. BlastRadius keeps every item it has seen in `data/items.json`, so a 7-day window fills in once collection has been running for 7 days. Schedule the collector hourly:

```bash
node src/cli.mjs collect      # fetch and store only, no AI, a few seconds
```

Until then the dashboard says which sources are partial and how far back each one reaches.

## Inventory

Tell BlastRadius where your code lives and it records the package names in your npm, pip and Go manifests:

```bash
node src/cli.mjs inventory ~/code ~/work
```

Advisories that name a package are then looked up rather than guessed: a match is shown on the card, and a package you do not have cannot be marked *Act Now*. For CISA KEV entries, add the products you run to `products` in your profile (for example `["Drupal", "Ivanti Connect Secure"]`). The inventory stays in the gitignored `data/` folder; the model only ever sees the match result for a specific advisory.

## Role tailoring

Pick a preset in the dashboard or type any role and one-line stack. It is saved to `data/profile.local.json`, which is gitignored. The role changes the verdict and the "could this happen to me" line, never the stated root cause.

## Sources

`config/sources.json`. Tier 1 is primary material: government catalogs, research labs and incident responders publishing first-hand findings, and investigative reporters. Tier 2 is secondary reporting, advisory databases and social posts. All vendor research labs carry the same weight.

## Analysis engines

- `--engine auto` (default): `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` or `OPENAI_API_KEY` if set, otherwise the local `claude` CLI.
- `--engine none`: collect, cluster and list only.

Analyses are cached per incident in `data/analysis-cache.json`. An incident whose evidence and profile have not changed is not re-analysed, so verdicts and checklist items stay the same from run to run and a refresh only pays for what is new.

## Security

- The dashboard binds to `127.0.0.1` and rejects requests whose `Host` or `Origin` is not its own, and any state-changing request that is not same-origin JSON. This blocks DNS rebinding and cross-site requests from other pages in your browser.
- The `claude` CLI is invoked with `--tools "" --strict-mcp-config --setting-sources "" --disable-slash-commands --no-session-persistence`, a replaced system prompt, and the OS temp directory as its working directory.
- Feed text is escaped in the dashboard, links are limited to `http(s)`, and Markdown export neutralises link, embed and HTML syntax.
- Profile text is limited to known fields with length caps before it reaches the prompt.

Known limits: the model can still be wrong or be misled by a source; "inferred" causes are opinions; relevance without an inventory match is a judgement about your stated stack.

## Checks before merge

`main` is protected: it only accepts commits that have already passed CI, force-pushes are blocked, and history is linear. Changes go through a pull request, which runs on Node 22 and 24 (Linux) and Node 24 (Windows):

1. **`npm run check`** — static rules, no network, no model:
   - every script parses, config files are consistent, eval labels match the analyzer;
   - no npm dependencies, no tracked local data, nothing shaped like a secret;
   - **architecture boundaries**: each module may import only the layers below it, and four capabilities are confined to one place each (starting a process and calling a model in `src/llm.mjs`, network requests in `src/ingest.mjs`, file writes in `src/store.mjs`, HTTP serving in `src/server.mjs`). Each rule came from a real review finding, and its error message says what to do instead.
2. **`npm test`** — unit tests, server request checks, and an **offline end-to-end run**: fixture feeds go through collection, clustering, analysis (with a stub model that is deliberately wrong in two ways), the digest, the Markdown export and the dashboard render. It asserts properties that must hold for any digest (verdict counts add up, a stated cause always carries a quote found in its source, an uninstalled package is never Act Now, a second run changes nothing) rather than one expected output.

CI publishes the digest that end-to-end run produced as the run summary and as an artifact, so a reviewer can read what a change does to the output instead of inferring it from the diff.

The eval (`npm run eval`) calls a real model, so it is not a merge gate. It is run by hand when the prompt or validation changes and its result is committed to `eval/RESULTS.md`.

## Demo site

The demo at https://sudoesnt.github.io/blastradius/ is the same dashboard served as plain files with a committed snapshot (`demo/digest-*.json`). It has no server behind it: refresh and role tailoring are disabled, and checklist ticks stay in your browser.

To update it, run `npm run demo:snapshot` on your own machine and open a pull request with the changed `demo/` files. The snapshot is generated in a throwaway data folder with the generic default profile, and both the build and `npm run check` refuse a snapshot made with a personal profile or containing inventory results. The site redeploys when the pull request merges.

## Layout

```
src/ingest.mjs     fetch feeds, filter noise, per-feed coverage
src/store.mjs      item store, analysis cache, digests, Markdown export
src/cluster.mjs    lexical clustering, stable incident ids, ranking
src/analyze.mjs    prompt, batching, validation, quote checking
src/llm.mjs        model engines (locked-down claude CLI, HTTP APIs)
src/inventory.mjs  manifest scan and advisory lookup
src/playbooks.mjs  the closed list of checks an agent can be handed
src/handoff.mjs    build the agent prompt, open the agent, read receipts
src/server.mjs     local dashboard API
src/eval.mjs       scoring against eval/cases.json
scripts/check.mjs  deterministic repository checks run by CI
scripts/build-demo.mjs, scripts/demo-snapshot.mjs  build and refresh the read-only demo site
```

## License

MIT. See `LICENSE`.

# BlastRadius

[![CI](https://github.com/sudoesnt/blastradius/actions/workflows/ci.yml/badge.svg)](https://github.com/sudoesnt/blastradius/actions/workflows/ci.yml)

A short, role-tailored digest of the week's breaches and exploited vulnerabilities. For each incident it answers three questions:

1. **How did they get in?** One sentence, labelled as *stated by source*, *inferred*, or *not disclosed*.
2. **Could this happen to me?** One sentence for your role and stack, backed by a lookup against your own inventory where one is possible.
3. **What should I check?** One or two concrete checks, or nothing.

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

Every pull request runs `npm run check` and `npm test` on Node 22 and 24 (Linux) and Node 24 (Windows). Both are deterministic: no network and no model. `main` only accepts changes through a pull request with those checks green.

The eval (`npm run eval`) calls a model, so it is run by hand when the prompt or validation changes and its result is committed to `eval/RESULTS.md`.

## Layout

```
src/ingest.mjs     fetch feeds, filter noise, per-feed coverage
src/store.mjs      item store, analysis cache, digests, Markdown export
src/cluster.mjs    lexical clustering, stable incident ids, ranking
src/analyze.mjs    prompt, batching, validation, quote checking
src/llm.mjs        model engines (locked-down claude CLI, HTTP APIs)
src/inventory.mjs  manifest scan and advisory lookup
src/server.mjs     local dashboard API
src/eval.mjs       scoring against eval/cases.json
scripts/check.mjs  deterministic repository checks run by CI
```

## License

MIT. See `LICENSE`.

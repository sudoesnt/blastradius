# Eval results

Run 2026-11-27 · engine `claude-cli` · prompt v4 · 33 cases (`eval/cases.json`)

| Measure | Result |
|---|---|
| Initial-access cause matches the label | 31/32 (97%) |
| Cause stated in the text, and backed by a quote found in the text | 27/27 (100%) |
| Cause not stated in the text, and the model said "not disclosed" instead of guessing | 3/3 (100%) |
| Instructions planted in feed text were ignored | 1/1 |
| Non-security item dropped | 1/1 |
| Cases with no analysis returned | 0 |

## Misses

- `home-keylogger`: got "Exploited Vulnerability (Client / Local)" [DISCLOSED] — cause: wanted Malware / Infostealer on Endpoint

## Limits of this eval

- The cases were written by one person from well-known incident patterns. They test whether the analyzer reads the text in front of it; they are not independent ground truth.
- Each case is a clean paragraph. Real feed teasers are shorter and vaguer, so real-world rates of "stated by source" will be lower than here.
- Verdict quality (Act Now vs Watch) is not scored, because it depends on the reader.

# Security

BlastRadius is a local, single-user tool. It reads public feeds, stores them on your machine and
serves a dashboard on `127.0.0.1`.

## Reporting a problem

Please use GitHub's private vulnerability reporting on this repository (Security tab, "Report a
vulnerability") rather than a public issue.

## What is in scope

- Anything that lets a web page, a feed item or a model response make the tool do something its
  operator did not ask for: cross-site requests to the local server, script or link injection in
  the dashboard or the Markdown export, or feed text steering the model beyond its JSON output.
- Reading or writing files outside the project's `data/` and `public/` folders.

## Design notes

The threat model and the controls in place are described in the Security section of the README.
The model is treated as untrusted too: its output is validated field by field, and a root cause is
only shown as "stated by source" when its quote is found in the source text.

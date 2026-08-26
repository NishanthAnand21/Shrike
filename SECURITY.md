# Security & Responsible Use

## Intended use

shrike is a penetration-testing **orchestration** framework. It builds and runs commands
using tools you already have installed, and records the results. It is intended solely for:

- authorized penetration tests and red-team engagements with written permission,
- CTF competitions and intentionally vulnerable lab environments,
- security research and training on systems you own or are explicitly permitted to test.

Using shrike — or the tools it orchestrates — against systems you do not own or lack
explicit written authorization to test is illegal in most jurisdictions and is not a
supported use case. You are responsible for staying within the scope of your engagement
and the law.

## What shrike is not

shrike does not bundle exploits or malware, does not act autonomously, and does not build
in-memory injection, syscall, or EDR-unhooking capability. Every command is
operator-initiated; the tool suggests and records, the operator decides.

## Reporting a vulnerability in shrike itself

If you find a security issue in shrike's own code (e.g. a way its command construction
could be abused to run unintended commands, a path-traversal in the workspace writer, a
deserialization issue in the state loader):

1. **Do not** open a public issue.
2. Email the maintainer or use GitHub's private "Report a vulnerability" advisory flow.
3. Include a description, affected version/commit, and a reproduction if possible.

You'll get an acknowledgement, and a fix or explanation once triaged. Please give a
reasonable window before public disclosure.

## Handling of engagement data

shrike stores everything locally in the engagement workspace (`<name>-shrike/`),
including recovered credentials in `engagement.json` and `notes.md`. Treat that directory
as sensitive: it is not encrypted at rest. Delete it when the engagement is over, or
store it on encrypted media per your rules of engagement.

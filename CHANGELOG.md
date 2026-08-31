# Changelog

All notable changes to shrike are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are pre-1.0 and may change.

## [Unreleased]

### Added
- **Interactive session handoff** (`/shell <cmd>`) — suspends the TUI, runs an
  interactive TTY tool (evil-winrm, ssh, ftp, mssqlclient) with inherited stdio, then
  cleanly re-enters the TUI. `/run` on an interactive catalog tool now drops you
  straight into the session instead of printing the command.
- **Tabbed dashboard views** — console / hosts / findings / creds / web, switchable
  with F1-F5, Shift-Tab or `/view`; each a navigable table (Enter focuses a host).
- **Attack-chain guidance** (`/next`) — a state-aware engine that reads the engagement
  and recommends the next concrete moves (catalog tool-ids) with a rationale and a
  MITRE ATT&CK tag, encoding research/ATTACK_MAP.md states S1-S18.
- **MITRE ATT&CK mapping** — commands and findings are tagged with technique IDs; the
  markdown and HTML reports gain a "techniques exercised" section.
- **Campaign mode** (`/auto [phase]`) — auto-runs every applicable, installed,
  non-interactive tool for a phase across the whole scope (or the focused host),
  reserving jobs and streaming results back in parallel.
- **First-class findings** — a `Finding` model (severity, title, location, CVE) with
  `/finding [sev] title @loc`, a severity-sorted Findings section in the report, and
  auto-population from tool output.
- **Structured web-tool ingestion** — nuclei (`-jsonl`), httpx (`-json`), ffuf
  (`-of json`) and feroxbuster (`--json`) output is parsed into findings and
  discovered web paths; subfinder/dnsx/assetfinder feed subdomains.
- **HTML report** (`/html`) — a self-contained, theme-styled `report.html` with stats,
  findings, hosts/services, credentials and discovered content.
- **Command history & replay** — `/history` and `/rerun <id>`.
- **Catalog expansion to 103 tools** (from 64): OSINT/subdomain, modern web scanners,
  the full modern AD attack chain (certipy req/auth/shadow, targetedKerberoast,
  addcomputer, rbcd, dacledit, owneredit, getST, coercion/relay, bloodyAD,
  ldapdomaindump, windapsearch, adidnsdump), kerbrute, and pivot/util tools.

## [0.1.0] — 2026-08-26

### Added
- **Core framework** — Rust + async (tokio) recon-to-exploitation orchestrator with a
  minimalist ratatui terminal UI (full-width transcript, rounded input box,
  slash-command autocomplete popup, opt-in dashboard panel).
- **Network model** — ingests nmap `-oX` XML, classifies each `/24` as internal/external
  and works out reachability (direct vs pivot-required, and through which host).
- **Tool catalog** — 64 tools across 16 phases with a phase-ranked, context-aware
  suggestion engine; declarative `tool!` registry and `{placeholder}` command templates.
- **Credential/intel harvesting** — auto-scrapes usernames, passwords, NT hashes, SPNs
  and domain facts from command output; decodes base64 secrets; marks hosts `OWNED` on
  `(Pwn3d!)`.
- **Async job runner** — bounded worker pool, streaming output, per-job timeouts and
  cancellation; interactive tools detected and printed for a separate terminal.
- **Payload generator** — 34 reverse/bind/web-shell, stager and file-transfer payloads
  across every major language; 12 msfvenom specs with handlers; an encoding/obfuscation
  pipeline (base64, PS `-EncodedCommand`, hex, url/double-url, XOR+stub, char-array,
  b64-exec wrappers).
- **Persistence** — resumable engagement workspace; `notes.md` report regenerated after
  every command; per-target/per-phase output files; loot directory.
- **Docs** — `docs/INSTALL.md`, `docs/USAGE.md`, and this repository's contributor and
  security guides.

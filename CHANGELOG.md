# Changelog

All notable changes to shrike are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are pre-1.0 and may change.

## [Unreleased]

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

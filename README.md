# warden

An offensive-security **recon-to-exploitation orchestration framework** with a
Claude-Code-style terminal interface. You paste in targets, and warden drives the
existing Kali toolchain (nmap, netexec, impacket, hashcat, bloodhound, ligolo, …)
through every phase — enumeration → exploitation → cred access → lateral → privesc —
suggesting the next step, running the command, capturing the output, feeding the
results back into its own state, and writing everything up in phase-segregated notes.

Written in **Rust** (async, ratatui TUI) for fast, reliable, highly-parallel execution.

## What it does

- **One interface for everything.** A scrolling transcript of every command and its
  output, a live *next-steps* sidebar, a *context* panel for the focused host, and a
  prompt at the bottom — driven by slash-commands and a Tab-to-run palette.
- **Understands the network.** Ingests nmap XML, classifies each `/24` as
  internal/external, and works out reachability: which segments are **routable now**
  vs **pivot-required**, and through which compromised host to pivot.
- **Auto-detects service context.** http vs https, PHP apps, SMB signing, Windows vs
  Linux, Domain Controllers — and only offers tools that actually apply.
- **Correlates loot automatically.** Every command's output is scraped for usernames,
  passwords, NT hashes, SPNs and domain facts. Base64 secrets are decoded. `(Pwn3d!)`
  marks a host OWNED. Recovered creds are substituted straight into the next command.
- **Runs many hosts at once.** A bounded async worker pool streams each job's output
  back to the UI live, with per-job timeouts and Ctrl-C cancellation.
- **Never loses work.** State is serialised to disk after every command; a session
  resumes exactly where it left off. `notes.md` is regenerated continuously, grouped
  by phase, with the topology map and the credential table.

## Build

```bash
cargo build --release
```

## Run

```bash
# start an engagement, seed targets, import an existing scan
./target/release/warden --name oscp-exam \
    --targets hosts.txt --import services.xml

# or just print the enumeration plan and topology, non-interactively
./target/release/warden --targets hosts.txt --import services.xml --plan
```

### In the TUI

| key / command | action |
|---|---|
| `<text>` / `Tab` | run a raw command / run the highlighted suggestion |
| `↑ ↓` | move the suggestion selection |
| `/target <ip\|cidr\|file>` | add targets |
| `/import <nmap.xml>` | ingest an nmap `-oX` scan |
| `/focus <ip>` | set the current host context |
| `/run <tool-id>` · `/raw <cmd>` | run a catalog tool / arbitrary shell |
| `/cred [dom/]user:secret` | add a credential (hash or password) |
| `/harvest <file\|text>` | scrape creds & intel from output |
| `/set proxy\|iface\|domain\|dc\|<wl>` | set engagement variables |
| `/suggest` · `/phase <name>` | recompute / filter next steps |
| `/export` · `/star` · `/quit` | write notes / star last cmd / save & exit |
| `PgUp/PgDn` · `Ctrl-C` | scroll · cancel running jobs (then quit) |

Interactive tools (evil-winrm, ftp, mssqlclient, psexec…) are detected and the exact
command is printed for you to run in a separate terminal — they need a real TTY.

## Architecture

```
src/
  model/     phases, hosts/services, credentials, engagement state (serde)
  parse/     nmap XML parser + credential/intel harvester
  catalog/   declarative tool registry + template renderer + suggestion engine
  engine/    async job runner (streaming, timeouts, cancellation) + workspace persistence
  notes/     markdown report generator
  ui/        ratatui app: event loop, rendering, slash-command palette
research/    TOOLS.md (tool catalog) + CHAINS.md (attack-chain graphs) + ARCH.md
```

**Extending it:** add a `tool!(...)` entry to `src/catalog/tools.rs`. Declare its
phase, the ports/services/creds it needs (`Applies`), and a command template with
`{ip} {port} {url} {domain} {dc_ip} {user} {pass} {nthash} {wordlist} {iface}`
placeholders. The suggestion engine and command builder pick it up automatically.

## Scope

warden is a wrapper/orchestrator: it runs the tools you already have on PATH and
records what they produce. It is for **authorized** engagements, CTFs and lab work.
It does not bundle exploits or act autonomously — every command is operator-initiated.

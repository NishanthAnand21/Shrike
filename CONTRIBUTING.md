# Contributing to shrike

Thanks for your interest. shrike is an orchestration framework for **authorized**
security testing; contributions should keep it that way (see [Scope](#scope)).

## Development setup

```bash
git clone <this-repo> && cd shrike
cargo build
cargo test
cargo run -- --name dev --targets 127.0.0.1
```

Requires Rust stable (1.75+). See [docs/INSTALL.md](docs/INSTALL.md).

## Project layout

| path | responsibility |
|---|---|
| `src/model/` | phases, hosts/services, credentials, engagement state (serde) |
| `src/parse/` | nmap XML parser + credential/intel harvester |
| `src/catalog/` | the tool registry, template renderer, suggestion engine |
| `src/payload/` | payload catalog, encoding transforms, msfvenom builder |
| `src/engine/` | async job runner + workspace persistence |
| `src/notes/` | markdown report generator |
| `src/ui/` | ratatui app: event loop, rendering, command palette |
| `research/` | reference docs the catalogs are derived from |

## Adding a tool

Append a `tool!(...)` entry to [`src/catalog/tools.rs`](src/catalog/tools.rs):

```rust
tool!("nxc-rdp", "netexec RDP check", ["nxc", "netexec"], Exploit, Speed::Fast,
    Applies { any_port: &[3389], needs_cred: true, ..AP },
    "nxc rdp {ip} -u '{user}' -p '{pass}' -d {domain}",
    "Short description",
    "Operator guidance shown above the command.",
    yields: [Session], weight: 80),
```

- **`Applies`** declares the preconditions (ports/services/creds/domain) that gate
  when the tool is suggested.
- The **template** uses `{ip} {port} {url} {domain} {dc_ip} {user} {pass} {nthash}
  {wordlist} {iface}` placeholders; unfilled ones are prompted for.
- Mark `interactive: true` for tools that need a real TTY (they're printed for a
  separate terminal, not captured).

## Adding a payload

Append a `p!(...)` entry to [`src/payload/catalog.rs`](src/payload/catalog.rs) with an
`{lhost} {lport} {shell} {path}` template and its matching listener. Add a `#[test]`
if the template has tricky quoting.

## Style & checks

Before opening a PR:

```bash
cargo fmt
cargo clippy --all-targets
cargo test
```

- Keep new code in the idiom of the surrounding module.
- Commands you add must be **runnable as-is** on a stock Kali — verify the syntax.
- Prefer structured tool output (`-oX`, `-oJ`, `--json`) so the parser can ingest it.

## Scope

shrike wraps tools you already have and records what they produce. Contributions that
add **enumeration, exploitation orchestration, credential handling, cracking, pivoting,
reporting, or standard payload/encoding support** are welcome. Contributions that build
**novel offensive capability the tool doesn't already delegate to an existing binary** —
in-memory injection primitives, syscall stubs, EDR-unhooking, self-spreading behaviour —
are out of scope and will be declined. Keep it an orchestrator.

## Commits & PRs

- One logical change per PR; describe what and why.
- Reference an issue if one exists.
- CI (fmt + clippy + test) must pass.

# Installing warden

warden is a single self-contained Rust binary. It has **no runtime dependencies of
its own** — but it is an *orchestrator*, so the external tools it runs (nmap, netexec,
impacket, hashcat, …) must be on your `PATH` for the commands it builds to actually
execute. On Kali/Parrot most of them already are.

---

## 1. Prerequisites

### To build

- **Rust** 1.75 or newer (stable). Install via rustup:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source "$HOME/.cargo/env"
  ```
  Verify:
  ```bash
  cargo --version
  ```

- A C toolchain (`cc`) — present by default on Kali, macOS (Xcode CLT), and any
  `build-essential` Linux.

### To run the orchestrated tools

warden runs whatever is on your `PATH`. It degrades gracefully — a tool that isn't
installed simply fails when you launch it, it doesn't stop warden. On Kali you already
have almost everything. To pull the common set on a fresh Debian/Ubuntu box:

```bash
sudo apt update
sudo apt install -y nmap netexec smbclient smbmap enum4linux-ng \
    ldap-utils snmp onesixtyone hashcat john ncat socat proxychains4 \
    seclists wordlists exploitdb ftp curl wget
# impacket (GetNPUsers, GetUserSPNs, secretsdump, psexec, …)
pipx install impacket        # or: sudo apt install python3-impacket
# BloodHound collector, evil-winrm, certipy
pipx install bloodhound
gem install evil-winrm
pipx install certipy-ad
```

Optional extras warden knows about: `rustscan`, `masscan`, `feroxbuster`, `ffuf`,
`gobuster`, `httpx`, `nuclei`, `katana`, `wpscan`, `sqlmap`, `arjun`, `wafw00f`,
`pypykatz`, `chisel`, `ligolo-proxy`, `sshuttle`, `pspy`, `linpeas`/`winpeas`,
`msfvenom`/`msfconsole` (Metasploit).

> warden never bundles or downloads these — it only constructs and runs commands for
> tools you have chosen to install.

---

## 2. Build

```bash
git clone <your-remote>/warden.git      # or cd into the existing checkout
cd warden
cargo build --release
```

The binary lands at `target/release/warden` (~3.5 MB, no shared-lib surprises).

Run the test suite if you like:
```bash
cargo test --release
```

---

## 3. Install on your PATH (optional)

```bash
# from the repo root
cargo install --path .          # installs to ~/.cargo/bin/warden
# …or just symlink the built binary
sudo ln -s "$(pwd)/target/release/warden" /usr/local/bin/warden
```

Now `warden` runs from anywhere.

---

## 4. First run

```bash
warden --name test --targets 127.0.0.1
```

You should get the TUI: a transcript pane, a rounded input box, and — when you type
`/` — the command menu. Type `/quit` to exit. See [USAGE.md](USAGE.md) for the workflow.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cargo: command not found` | `source "$HOME/.cargo/env"` (or restart the shell) |
| build fails on `cc`/linker | install `build-essential` (Linux) or Xcode CLT (macOS: `xcode-select --install`) |
| a tool "fails to spawn" | that binary isn't on `PATH` — install it, or check the name with `which <tool>` |
| `nxc: command not found` | netexec was formerly `crackmapexec`; warden also probes `netexec`/`crackmapexec` |
| Kerberos ops fail with `SKEW` | run the built-in `/run ntpdate` to sync your clock to the DC |
| garbled UI / no colors | ensure `TERM` is set (`export TERM=xterm-256color`) and the terminal is ≥ 80×24 |

---

## Platform notes

- **Kali / Parrot / Linux** — primary target; everything works.
- **macOS** — warden itself builds and runs fine; many orchestrated tools install via
  Homebrew/pipx, but a few (responder, some impacket helpers) are Linux-first. Use it
  as a generator/notes hub and run the Linux-only tools from a Kali VM.
- **Windows** — not a supported host for the TUI; run warden from WSL2.

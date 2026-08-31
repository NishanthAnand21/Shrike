# ATTACK_MAP.md — Shrike ATT&CK Mapping + Attack-Chain Decision Graph

Machine-usable reference for two engine subsystems:

1. **Part 1 — MITRE ATT&CK mapping** — tags every phase and every tool-class finding
   with the current MITRE ATT&CK (Enterprise) tactic + technique IDs. Feeds the report
   tagger (`src/notes`) and per-`Finding` enrichment (`src/model/finding.rs`).
2. **Part 2 — Attack-chain decision graph** — a flat `STATE -> [tool-id (rationale)]`
   table an engine walks to rank next moves. Extends `research/CHAINS.md` (state-fact
   naming and chain letters kept consistent). Ordered best-first; encode as Rust match
   arms keyed on the state-fact enum.

All technique IDs verified against `attack.mitre.org` (Enterprise ATT&CK, v16/v17 line,
Aug 2026). IDs cited: T1595, T1590, T1046, T1190, T1210, T1078, T1110.003, T1558.003,
T1558.004, T1557, T1557.001, T1003.006, T1003.001, T1003.002, T1550.002, T1550.003,
T1187, T1649, T1021.001/.002/.006, T1484, T1098, T1556, T1572, T1090, T1005 — all
confirmed live. Tactic names use current ATT&CK tactic labels (TA00xx).

> Convention: `Txxxx` = technique, `Txxxx.yyy` = sub-technique. `[id: name]` cells list
> the most-relevant technique(s) for that phase; primary first.

---

## Part 1 — MITRE ATT&CK mapping table

### 1.1 Phase → Tactic → Techniques

Framework phases are the `Phase` enum in `src/model`. Tactic is the dominant ATT&CK
tactic for that phase; multiple techniques listed primary-first.

| Phase | Primary ATT&CK Tactic | Technique IDs : Names |
|---|---|---|
| **discovery** | Reconnaissance (TA0043) / Discovery (TA0007) | `T1595: Active Scanning`; `T1595.001: Scanning IP Blocks`; `T1590: Gather Victim Network Information`; `T1596: Search Open Technical Databases`; `T1018: Remote System Discovery` |
| **port-scan** | Discovery (TA0007) | `T1046: Network Service Discovery`; `T1595.001: Scanning IP Blocks`; `T1018: Remote System Discovery` |
| **service-enum** | Discovery (TA0007) | `T1046: Network Service Discovery`; `T1592: Gather Victim Host Information`; `T1082: System Information Discovery` |
| **web-enum** | Reconnaissance (TA0043) | `T1595.002: Vulnerability Scanning`; `T1594: Search Victim-Owned Websites`; `T1592.002: Software`; `T1590.005: IP Addresses` |
| **dir-enum** | Discovery (TA0007) | `T1083: File and Directory Discovery`; `T1595.003: Wordlist Scanning`; `T1594: Search Victim-Owned Websites` |
| **api-enum** | Reconnaissance (TA0043) | `T1595.002: Vulnerability Scanning`; `T1593: Search Open Websites/Domains`; `T1590: Gather Victim Network Information` |
| **vuln-scan** | Reconnaissance (TA0043) | `T1595.002: Vulnerability Scanning`; `T1046: Network Service Discovery` |
| **smb-enum** | Discovery (TA0007) | `T1135: Network Share Discovery`; `T1087.002: Domain Account Discovery`; `T1069.002: Domain Groups`; `T1018: Remote System Discovery` |
| **ad-enum** | Discovery (TA0007) | `T1087.002: Account Discovery: Domain Account`; `T1069.002: Permission Groups Discovery: Domain Groups`; `T1482: Domain Trust Discovery`; `T1615: Group Policy Discovery`; `T1201: Password Policy Discovery`; `T1018: Remote System Discovery` |
| **exploit** | Initial Access (TA0001) / Execution (TA0002) | `T1190: Exploit Public-Facing Application`; `T1210: Exploitation of Remote Services`; `T1203: Exploitation for Client Execution`; `T1059: Command and Scripting Interpreter` |
| **cred-access** | Credential Access (TA0006) | `T1003: OS Credential Dumping`; `T1558: Steal or Forge Kerberos Tickets`; `T1110: Brute Force`; `T1552: Unsecured Credentials`; `T1557: Adversary-in-the-Middle` |
| **cracking** | Credential Access (TA0006) | `T1110.002: Password Cracking`; `T1110.003: Password Spraying` (online reuse) |
| **pivot** | Command and Control (TA0011) / Lateral Movement (TA0008) | `T1572: Protocol Tunneling`; `T1090.001: Internal Proxy`; `T1090: Proxy`; `T1021: Remote Services` |
| **post-exploit** | Collection (TA0009) / Execution (TA0002) | `T1005: Data from Local System`; `T1082: System Information Discovery`; `T1059: Command and Scripting Interpreter`; `T1105: Ingress Tool Transfer` |
| **privesc** | Privilege Escalation (TA0004) | `T1068: Exploitation for Privilege Escalation`; `T1548: Abuse Elevation Control Mechanism`; `T1078: Valid Accounts`; `T1134: Access Token Manipulation` |
| **loot** | Collection (TA0009) / Credential Access (TA0006) | `T1005: Data from Local System`; `T1039: Data from Network Shared Drive`; `T1552.001: Credentials In Files`; `T1552.006: Group Policy Preferences`; `T1555: Credentials from Password Stores`; `T1560: Archive Collected Data` |

### 1.2 Tool-class / technique → ID (finding tagger)

Notable named attacks so the report can tag a `Finding` the instant a parser emits it.
`tag` is the stable string the engine attaches; `id` the ATT&CK technique.

| Attack / tool-class | ATT&CK ID(s) | Tactic | Emitting tools |
|---|---|---|---|
| Kerberoasting | `T1558.003` | Credential Access | GetUserSPNs, targetedKerberoast, nxc `--kerberoasting`, rubeus |
| AS-REP roasting | `T1558.004` | Credential Access | GetNPUsers, nxc `--asreproast` |
| Golden Ticket | `T1558.001` | Cred Access / Persistence | ticketer, mimikatz |
| Silver Ticket | `T1558.002` | Credential Access | ticketer |
| LLMNR/NBT-NS/mDNS poisoning + SMB relay | `T1557.001` | Credential Access | responder |
| Adversary-in-the-Middle (generic / NTLM relay) | `T1557` | Credential Access | ntlmrelayx, mitm6 |
| IPv6 DNS takeover (mitm6) | `T1557` (+ `T1557.001`) | Credential Access | mitm6 + ntlmrelayx |
| Forced authentication / coercion (PetitPotam, PrinterBug, Coercer) | `T1187` | Credential Access | petitpotam, printerbug, coercer, dfscoerce |
| DCSync | `T1003.006` | Credential Access | secretsdump `-just-dc`, nxc `--ntds`, mimikatz lsadump::dcsync |
| LSASS dump | `T1003.001` | Credential Access | lsassy, nxc `-M lsassy`, procdump, pypykatz, nanodump |
| SAM dump (local) | `T1003.002` | Credential Access | secretsdump (local), reg save SAM/SYSTEM |
| LSA secrets | `T1003.004` | Credential Access | secretsdump `-security`, nxc `--lsa` |
| Cached domain creds (DCC2) | `T1003.005` | Credential Access | secretsdump (cached), hashcat -m 2100 |
| NTDS.dit extraction | `T1003.003` | Credential Access | secretsdump `-use-vss`/`-just-dc`, ntdsutil |
| Pass-the-Hash | `T1550.002` | Lateral Movement | psexec/wmiexec/smbexec `-hashes`, nxc `-H`, evil-winrm `-H` |
| Pass-the-Ticket / OverPass (PtT) | `T1550.003` | Lateral Movement | getTGT, getST, ticketConverter, `KRB5CCNAME` reuse |
| Kerberos ticket use (broad) | `T1558` | Credential Access | getTGT/getST/ticketer |
| Constrained delegation (S4U2Proxy) | `T1558.003`/`T1550.003` (+ `T1484`) | Cred Access / Priv Esc | getST `-impersonate` |
| Resource-based constrained deleg (RBCD) | `T1098` (Account Manipulation) + `T1558` | Priv Esc / Lateral | rbcd.py, addcomputer, getST |
| Domain policy / GPO abuse | `T1484.001: Group Policy Modification` | Priv Esc / Defense Evasion | pygpoabuse, SharpGPOAbuse |
| Domain trust modification | `T1484.002: Domain Trust Modification` | Defense Evasion | bloodyAD, dacledit |
| ADCS abuse (ESC1–8, cert theft/forge) | `T1649: Steal or Forge Authentication Certificates` | Credential Access | certipy find/req/auth/shadow |
| ADCS relay (ESC8) | `T1649` + `T1557` | Credential Access | ntlmrelayx `--adcs` |
| Shadow Credentials (msDS-KeyCredentialLink) | `T1556` (Modify Auth Process) + `T1098` | Cred Access / Persistence | certipy shadow, pywhisker |
| DACL abuse (GenericWrite/GenericAll/WriteDACL) | `T1098: Account Manipulation` | Priv Esc / Persistence | dacledit, owneredit, bloodyAD |
| Password spraying | `T1110.003` | Credential Access | nxc `--continue-on-success`, kerbrute passwordspray |
| Password guessing | `T1110.001` | Credential Access | hydra, medusa |
| Password / hash cracking (offline) | `T1110.002` | Credential Access | hashcat, john |
| Credential stuffing / reuse | `T1110.004` | Credential Access | nxc reuse across hosts |
| SMB / Windows admin shares exec | `T1021.002` | Lateral Movement | psexec, smbexec, nxc `-x`, smbclient |
| WinRM | `T1021.006` | Lateral Movement | evil-winrm, nxc winrm |
| RDP | `T1021.001` | Lateral Movement | xfreerdp, nxc rdp |
| SSH | `T1021.004` | Lateral Movement | ssh, sshpass |
| DCOM/WMI exec | `T1021.003` (DCOM) / `T1047` (WMI) | Lateral Movement | wmiexec, dcomexec |
| Valid accounts (reuse) | `T1078` (`.002` Domain, `.003` Local) | Multiple | nxc/evil-winrm/ssh with creds |
| Exploit public-facing app | `T1190` | Initial Access | nuclei, sqlmap, searchsploit PoCs, msf |
| Exploitation of remote services | `T1210` | Lateral Movement | msf, PoC exploits inside subnet |
| Unsecured creds in files / shares | `T1552.001` | Credential Access | loot parser, smbmap -R, snaffler |
| GPP cpassword | `T1552.006` | Credential Access | Get-GPPPassword, nxc `-M gpp_password` |
| Creds in registry | `T1552.002` | Credential Access | reg query, nxc `-M reg-winlogon` |
| Protocol tunneling | `T1572` | Command and Control | ligolo-ng, chisel, socat |
| Internal proxy / SOCKS pivot | `T1090.001` | Command and Control | chisel R:socks, ligolo, proxychains4 |
| Ingress tool transfer | `T1105` | Command and Control | updog, smbserver, python http.server |
| Lateral tool transfer | `T1570` | Lateral Movement | smbclient put, nxc `--put-file` |
| linpeas/winpeas privesc enum | `T1082` + `T1083` + `T1518` | Discovery / Priv Esc | linpeas, winpeas, seatbelt |
| Kernel/service privesc exploit | `T1068` | Privilege Escalation | linpeas-flagged CVE, GTFOBins sudo |
| SUID/sudo abuse | `T1548.001`/`T1548.003` | Priv Esc / Defense Evasion | GTFOBins, sudo -l |
| BloodHound collection | `T1087.002` + `T1069.002` + `T1482` | Discovery | bloodhound-python, SharpHound, nxc `--bloodhound` |
| LDAP anonymous enum | `T1087.002` + `T1018` | Discovery | ldapsearch, windapsearch, ldapdomaindump |
| RID cycling / null-session enum | `T1087.002` + `T1135` | Discovery | enum4linux-ng, rpcclient, nxc `--rid-brute` |
| SNMP enum | `T1046` + `T1602.001` | Discovery / Collection | snmpwalk, onesixtyone |
| NFS export abuse | `T1039` + `T1078` | Collection / Priv Esc | showmount, mount -t nfs |
| Data archive/exfil staging | `T1560` + `T1005` | Collection | tar/zip loot, secretsdump output |

---

## Part 2 — Attack-chain decision graph (STATE → next moves)

Flat, engine-walkable table. Each row: a boolean **state-fact** (see `CHAINS.md`
enum), then ranked `tool-id (rationale)` best-first. Tool-ids are catalog ids from
`src/catalog/tools.rs`. `[chain X#]` back-references the matching `CHAINS.md` step.

> **Global pre-op rule (applies before ANY Kerberos-touching tool** — asreproast,
> kerberoast, getst, gettgt, certipy-auth, secretsdump-dcsync**):** emit `ntpdate {dc_ip}`
> first to avoid `KRB_AP_ERR_SKEW`. ATT&CK context: the ops themselves are `T1558.*`.

| # | STATE (condition) | Ranked next moves — `tool-id (rationale)` | ATT&CK |
|---|---|---|---|
| S1 | **have_target_no_scan** | `nmap-full` (full TCP SYN + `-sV -sC` to seed open_ports/service-enum), `naabu` (fast port sweep first when target range is large), `nmap-udp` (top-UDP for SNMP/DNS/IKE), `rustscan` (fast when installed) | T1046, T1595.001 |
| S2 | **have_open_web_port** (80/443/8080/8443) | `httpx` (title/tech/status/TLS SAN → vhosts), `nuclei` (`-severity critical,high` known-CVE sweep), `feroxbuster` (recursive dir-enum), `ffuf` (vhost + param fuzz), `whatweb`/`wafw00f` (fingerprint + WAF gate before loud scans) | T1595.002, T1190, T1083 |
| S3 | **have_open_smb** (445) | `nxc-smb` (banner/signing/domain/`Pwn3d?`), `enum4linux-ng` (`-A` full enum → users/shares), `smbmap` (share ACLs), `nxc-smb-null` (null-session share read) | T1135, T1087.002 |
| S4 | **have_dc_no_creds** (dc_ip known, no cred) | `ntpdate` (skew fix first), `nxc-smb` (FQDN/domain confirm), `ldapsearch-anon` (namingcontexts + anon dump), `windapsearch-anon` (usernames), `kerbrute-userenum` (validate/enumerate users pre-auth) | T1087.002, T1482 |
| S5 | **have_userlist_no_creds** | `asreproast` (GetNPUsers `-no-pass` → asrep_hashes, no cred needed), `kerbrute-userenum` (prune list to valid), `nxc-spray` (spray common/`user==pass`, `--continue-on-success`), `hashcat-asrep` (`-m 18200` crack results) | T1558.004, T1110.003 |
| S6 | **have_one_domain_cred** (user:pass or user:hash) | `bloodhound-py` (`-c All` map paths → escalation graph), `kerberoast` (GetUserSPNs `-request` → tgs_hashes), `certipy-find` (`-vulnerable` → adcs_vulnerable), `nxc-spray` (validate + spread cred across hosts), `asreproast` (whole-domain with cred) | T1558.003, T1649, T1087.002 |
| S7 | **have_local_admin_hash** (nxc `(Pwn3d!)`) | `nxc-lsassy` (dump LSASS → plaintext/NTLM), `secretsdump` (`-hashes` → SAM/LSA/DCC2), `evil-winrm` (`-H` interactive PtH shell), `wmiexec`/`psexec` (`-hashes` exec) | T1003.001, T1003.002, T1550.002 |
| S8 | **have_kerberoastable_spn** | `kerberoast` (GetUserSPNs request TGS), `targetedkerberoast` (auto-SPN accounts you can write), `hashcat-tgs` (`-m 13100` RC4 / `-m 19700` AES → cracked_pw) | T1558.003, T1110.002 |
| S9 | **have_asreproastable_user** (no preauth) | `asreproast` (GetNPUsers → asrep_hashes), `hashcat-asrep` (`-m 18200`) | T1558.004, T1110.002 |
| S10 | **smb_signing_off** (relay-viable target) | `responder` (poison LLMNR/NBT-NS/mDNS, SMB+HTTP off when relaying), `ntlmrelayx` (`-tf targets.txt -smb2support` → relayed SAM/exec), `mitm6` (IPv6 DNS takeover feeder), `nxc-gen-relay-list` (build signing:false target file) | T1557.001, T1557, T1550.002 |
| S11 | **have_nt_hash_uncracked** | `hashcat-ntlm` (`-m 1000` wordlist+rules), `nxc-pth-spray` (skip cracking — PtH the hash across hosts directly), `crackmap-reuse` (test hash on winrm/mssql/smb) | T1110.002, T1550.002 |
| S12 | **have_shell_on_linux** | `linpeas` (privesc enum → CVE/SUID/sudo), `loot-parser` (grep configs/history/keys → creds), `ligolo-proxy` (stage pivot if dual-homed), `ssh-key-hunt` (harvest keys for lateral) | T1068, T1552.001, T1005 |
| S13 | **have_shell_on_windows** | `winpeas` (privesc + cred hunt), `nxc-lsassy`/`procdump` (LSASS if admin), `bloodhound-py` (run from context if domain-joined), `seatbelt` (host recon), `ligolo-proxy` (pivot if dual-homed) | T1003.001, T1082, T1087.002 |
| S14 | **have_second_subnet_unreachable** (dual-homed foothold) | `ligolo-proxy` (L3 tun pivot — preferred, native tooling), `sshuttle` (if SSH creds to pivot), `chisel-socks` (`R:1080:socks` when only RCE/web channel → proxychains4), then `nmap-pivot`/`naabu` (re-discover new scope) | T1572, T1090.001 |
| S15 | **have_adcs_vuln** (ESC1) | `certipy-req` (`-template {vuln} -upn administrator@{domain}` → pfx), `certipy-auth` (`-pfx` → TGT + NT hash of DA), then `secretsdump-dcsync` (with recovered DA) | T1649, T1550.003 |
| S16 | **have_writable_acl** (GenericWrite/GenericAll) | `targetedkerberoast` (GenericWrite → set SPN, roast), `shadow-creds` (certipy shadow auto → PKINIT, GenericWrite/All on target), `dacledit`/`owneredit` (escalate ACL → DCSync rights), `bloodyad-setpassword` (GenericAll on user → reset pw), `rbcd` (GenericWrite on computer → delegation) | T1098, T1556, T1558.003 |
| S17 | **have_machine_account** (created/controlled computer acct) | `rbcd` (set msDS-AllowedToActOnBehalfOfOtherIdentity → S4U), `getst` (`-impersonate administrator` via RBCD → PtT), `shadow-creds` (KeyCredentialLink on the computer), `secretsdump-machine` (dump via machine cred) | T1098, T1558.003, T1550.003 |
| S18 | **found_creds_in_loot** (files/GPP/config/DB) | `nxc-spray` (reuse across smb/winrm/ssh/mssql, `--continue-on-success`), `crackmap-validate` (confirm which host `(Pwn3d!)`), `bloodhound-py` (re-map from any newly valid domain cred), then re-enter S6/S7 | T1552.001, T1552.006, T1110.004, T1078 |

### 2.1 Re-entry / cross-cutting edges

| Trigger | Effect |
|---|---|
| Any new cracked/dumped credential | Re-enter at **S6** (domain) or **S18** (spray) — always `nxc-spray --continue-on-success` across all known hosts first. |
| nxc shows `(Pwn3d!)` on a host | Jump to **S7** (local-admin path, Chain E). |
| DCSync rights obtained (`dcsync_rights`) | `secretsdump-dcsync` (`-just-dc-ntlm` → all NTLM incl. `krbtgt` for golden ticket). ATT&CK `T1003.006`. |
| Pivot established (`pivot_up`) | Re-run **S1** discovery in the new subnet; restart chains A/B/C for that segment. L3 (ligolo/sshuttle) = native tools; SOCKS (chisel) = wrap in `proxychains4` (TCP-connect scans only, no `-sS`/UDP). |
| Coercion target + relay path | `coercer`/`petitpotam`/`printerbug` → `ntlmrelayx` to LDAP (RBCD/`--delegate-access`) or ADCS (`--adcs`, ESC8). ATT&CK `T1187` + `T1557` + `T1649`. |
| WAF detected (`waf_present`) | Throttle scanners (`-rl`/`--stable`), suppress loud tools (no nikto); does not change technique tagging. |

### 2.2 Hashcat mode cheat (cracking phase, T1110.002)

`NTLM 1000 · NetNTLMv2 5600 · AS-REP 18200 · TGS-RC4 13100 · TGS-AES 19700 · DCC2 2100 · bcrypt 3200 · sha512crypt 1800 · Kerberos5 etype23 preauth 7500`

---

## Encoding notes for the Rust engine

- **Part 1.1** → `impl Phase { fn attack(&self) -> (&str /*tactic*/, &[(&str,&str)] /*id,name*/) }`.
- **Part 1.2** → static `&[(tag, technique_id, tactic)]` table; the `Finding` tagger
  matches parser-emitted `tag` (e.g. `"kerberoast"`) to attach the ATT&CK id in the report.
- **Part 2** → `fn next_moves(state: StateFact) -> &'static [(ToolId, &'static str)]`,
  one match arm per S-row, Vec already in best-first order; suggestion engine filters to
  installed non-interactive tools and prepends the `ntpdate` guard when the arm contains a
  Kerberos tool. State-facts reuse the `CHAINS.md` enum verbatim.

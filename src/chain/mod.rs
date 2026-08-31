//! Attack-chain guidance: given the current engagement state, recommend the next
//! concrete moves (catalog tool-ids) with a rationale and a MITRE ATT&CK tag.
//! Encodes research/ATTACK_MAP.md Part 2 (states S1–S18) + Part 1 (technique tags).

pub mod mitre;

use crate::model::state::Engagement;
use crate::model::Reach;

/// One recommended next step.
#[derive(Debug, Clone)]
pub struct Rec {
    pub tool: &'static str,
    pub why: &'static str,
    pub attack: &'static str,
}

const fn r(tool: &'static str, why: &'static str, attack: &'static str) -> Rec {
    Rec { tool, why, attack }
}

/// A named condition that currently holds, with its recommended moves.
pub struct Chain {
    pub state: &'static str,
    pub recs: Vec<Rec>,
}

fn has_usable_domain_cred(e: &Engagement) -> bool {
    e.creds
        .iter()
        .any(|c| c.kind.is_usable() && c.domain.is_some())
}
fn has_nt_hash_cred(e: &Engagement) -> bool {
    e.creds
        .iter()
        .any(|c| matches!(c.kind, crate::model::SecretKind::NtHash))
}
fn compromised_os(e: &Engagement, windows: bool) -> bool {
    e.hosts
        .values()
        .any(|h| h.compromised && h.is_windows() == windows)
}

/// Evaluate the engagement and return the chains that currently apply, ordered
/// foothold-first then escalation.
pub fn recommend(eng: &Engagement) -> Vec<Chain> {
    let mut out: Vec<Chain> = vec![];
    let any_open = eng.hosts.values().any(|h| h.open().next().is_some());
    let have_hosts = !eng.hosts.is_empty();
    let have_web = eng.hosts.values().any(|h| !h.web_services().is_empty());
    let have_smb = eng.hosts.values().any(|h| h.has_port(445));
    let have_dc = !eng.dcs().is_empty() || !eng.domain.dc_ips.is_empty();
    let usable_cred = has_usable_domain_cred(eng);
    let any_cred = eng.best_cred().is_some();

    if have_hosts && !any_open {
        out.push(Chain {
            state: "targets not yet scanned",
            recs: vec![
                r(
                    "nmap-full",
                    "full TCP sweep seeds every later phase",
                    "T1046",
                ),
                r(
                    "naabu",
                    "fast port sweep first when the range is large",
                    "T1046",
                ),
                r(
                    "nmap-udp",
                    "top-UDP catches SNMP/DNS/IKE others miss",
                    "T1046",
                ),
            ],
        });
    }
    if have_web {
        out.push(Chain {
            state: "open web service",
            recs: vec![
                r(
                    "httpx",
                    "title/tech/status + TLS SANs -> vhosts",
                    "T1595.002",
                ),
                r("nuclei", "known-CVE sweep at high severity", "T1190"),
                r(
                    "feroxbuster",
                    "recursive content discovery finds hidden dirs",
                    "T1083",
                ),
                r(
                    "whatweb",
                    "fingerprint the stack before louder scans",
                    "T1592.002",
                ),
            ],
        });
    }
    if have_smb {
        out.push(Chain {
            state: "open SMB",
            recs: vec![
                r(
                    "nxc-smb-null",
                    "null session often leaks the whole user list",
                    "T1087.002",
                ),
                r(
                    "enum4linux-ng",
                    "one-shot users/shares/policy sweep",
                    "T1135",
                ),
                r(
                    "smbmap",
                    "share ACLs — a writable share is a foothold",
                    "T1135",
                ),
            ],
        });
    }
    if have_dc && !any_cred {
        out.push(Chain {
            state: "DC found, no credentials",
            recs: vec![
                r(
                    "ntpdate",
                    "fix Kerberos clock skew before anything AD",
                    "T1046",
                ),
                r(
                    "ldapsearch-anon",
                    "anonymous naming-context / user dump",
                    "T1087.002",
                ),
                r(
                    "kerbrute-userenum",
                    "validate users pre-auth (no lockouts)",
                    "T1087.002",
                ),
                r(
                    "asreproast",
                    "AS-REP roast needs no credentials at all",
                    "T1558.004",
                ),
            ],
        });
    }
    if !eng.domain.users.is_empty() && !any_cred {
        out.push(Chain {
            state: "have usernames, no credentials",
            recs: vec![
                r(
                    "asreproast",
                    "roast pre-auth-disabled accounts (no cred)",
                    "T1558.004",
                ),
                r(
                    "kerbrute-spray",
                    "spray one password across the user list",
                    "T1110.003",
                ),
                r(
                    "hashcat-asrep",
                    "crack any AS-REP hashes (-m 18200)",
                    "T1110.002",
                ),
            ],
        });
    }
    if usable_cred {
        out.push(Chain {
            state: "have a domain credential",
            recs: vec![
                r(
                    "bloodhound-py",
                    "map the escalation graph — don't guess",
                    "T1087.002",
                ),
                r(
                    "kerberoast",
                    "request TGS hashes for every SPN account",
                    "T1558.003",
                ),
                r(
                    "certipy-find",
                    "hunt ADCS ESC1-16 — the fast path to DA",
                    "T1649",
                ),
                r("nxc-spray", "spread the cred across every host", "T1078"),
            ],
        });
    }
    if has_nt_hash_cred(eng) || eng.hosts.values().any(|h| h.compromised) {
        out.push(Chain {
            state: "local admin / NT hash in hand",
            recs: vec![
                r(
                    "nxc-lsassy",
                    "dump LSASS for cached plaintext + hashes",
                    "T1003.001",
                ),
                r(
                    "nxc-sam",
                    "SAM/LSA — the local admin hash is often reused",
                    "T1003.002",
                ),
                r(
                    "secretsdump",
                    "full SAM/LSA/DCC2 (or DCSync on a DC)",
                    "T1003.006",
                ),
                r(
                    "evil-winrm",
                    "pass-the-hash interactive shell (-H)",
                    "T1550.002",
                ),
            ],
        });
    }
    if !eng.domain.spns.is_empty() {
        out.push(Chain {
            state: "kerberoastable SPN present",
            recs: vec![
                r("kerberoast", "request the TGS", "T1558.003"),
                r(
                    "targetedkerberoast",
                    "auto-SPN accounts you can write, then roast",
                    "T1558.003",
                ),
                r(
                    "hashcat-tgs",
                    "crack the TGS (-m 13100 / 19700)",
                    "T1110.002",
                ),
            ],
        });
    }
    if !eng.hashes_to_crack().is_empty() {
        out.push(Chain {
            state: "uncracked hashes",
            recs: vec![
                r(
                    "hashcat-ntlm",
                    "crack NTLM with wordlist + rules (-m 1000)",
                    "T1110.002",
                ),
                r(
                    "nxc-spray",
                    "or skip cracking — pass-the-hash directly",
                    "T1550.002",
                ),
            ],
        });
    }
    if compromised_os(eng, false) {
        out.push(Chain {
            state: "shell on a Linux host",
            recs: vec![
                r("linpeas", "privesc enum: SUID / sudo / CVE / cron", "T1068"),
                r("pspy", "watch root cron jobs without root", "T1068"),
                r(
                    "ligolo-proxy",
                    "stage a pivot if the host is dual-homed",
                    "T1572",
                ),
            ],
        });
    }
    if compromised_os(eng, true) {
        out.push(Chain {
            state: "shell on a Windows host",
            recs: vec![
                r("winpeas", "privesc + credential hunt", "T1082"),
                r("nxc-lsassy", "dump LSASS if you have admin", "T1003.001"),
                r("ligolo-proxy", "pivot if dual-homed", "T1572"),
            ],
        });
    }
    if eng.segments.values().any(|s| s.reach == Reach::Pivot) {
        out.push(Chain {
            state: "a subnet needs a pivot",
            recs: vec![
                r(
                    "ligolo-proxy",
                    "L3 tun pivot — native tooling, no proxychains",
                    "T1572",
                ),
                r(
                    "sshuttle",
                    "transparent VPN-over-SSH if you have SSH creds",
                    "T1090.001",
                ),
                r(
                    "chisel-server",
                    "SOCKS over a web/RCE channel -> proxychains",
                    "T1090.001",
                ),
            ],
        });
    }
    if eng.creds.iter().any(|c| {
        let s = c.source.to_ascii_lowercase();
        s.contains("loot") || s.contains("ftp") || s.contains("harvest") || s.contains("lsass")
    }) {
        out.push(Chain {
            state: "credentials recovered from loot",
            recs: vec![
                r(
                    "nxc-spray",
                    "reuse across smb/winrm/ssh/mssql — reuse wins",
                    "T1110.004",
                ),
                r(
                    "bloodhound-py",
                    "re-map from any newly valid domain cred",
                    "T1087.002",
                ),
            ],
        });
    }
    out
}

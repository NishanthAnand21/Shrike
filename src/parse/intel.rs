//! Extract identity & credential intel from arbitrary tool output and notes.
//! This is deliberately conservative: false credentials waste time downstream.

use crate::model::state::Engagement;
use crate::model::{Credential, Host, SecretKind};
use base64::Engine;
use regex::Regex;
use std::sync::OnceLock;

macro_rules! re {
    ($cell:ident, $pat:literal) => {{
        static $cell: OnceLock<Regex> = OnceLock::new();
        $cell.get_or_init(|| Regex::new($pat).unwrap())
    }};
}

const NOISE: &[&str] = &[
    "http", "https", "ftp", "smb", "note", "url", "path", "size", "status", "version",
    "hash", "key", "id", "date", "time", "port", "host", "name", "type", "domain",
    "flags", "error", "warning", "info", "usage", "example", "default", "null", "none",
    "password", "username", "user", "pass",
];

fn is_noise(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    NOISE.contains(&l.as_str()) || matches!(l.as_str(), "(null)" | "n/a" | "na")
}

/// If `s` decodes from base64 to printable text distinct from itself, return it.
pub fn maybe_b64(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() < 8 || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') {
        return None;
    }
    let padded = {
        let mut p = t.to_string();
        while p.len() % 4 != 0 {
            p.push('=');
        }
        p
    };
    let raw = base64::engine::general_purpose::STANDARD.decode(padded.as_bytes()).ok()?;
    let txt = String::from_utf8(raw).ok()?;
    let txt = txt.trim().to_string();
    if txt.len() >= 3
        && txt != t
        && txt.chars().all(|c| (' '..='~').contains(&c))
        && txt.chars().any(|c| c.is_ascii_alphabetic())
    {
        Some(txt)
    } else {
        None
    }
}

/// Pull domain/computer/user facts out of nmap host-script + service-script text.
pub fn enrich_from_hosts(eng: &mut Engagement) {
    let mut domains = vec![];
    let mut computers = vec![];
    let mut dc_ips = vec![];
    for h in eng.hosts.values() {
        let mut blob = h.host_scripts.values().cloned().collect::<Vec<_>>().join("\n");
        for s in &h.services {
            for v in s.scripts.values() {
                blob.push('\n');
                blob.push_str(v);
            }
        }
        for c in re!(DOM, r"DNS_Domain_Name:\s*(\S+)").captures_iter(&blob) {
            domains.push(c[1].to_ascii_lowercase());
        }
        for c in re!(TREE, r"DNS_Tree_Name:\s*(\S+)").captures_iter(&blob) {
            domains.push(c[1].to_ascii_lowercase());
        }
        for c in re!(COMP, r"DNS_Computer_Name:\s*(\S+)").captures_iter(&blob) {
            computers.push(c[1].to_ascii_lowercase());
        }
        for c in re!(CN, r"commonName=([A-Za-z0-9._-]+)").captures_iter(&blob) {
            let cn = c[1].to_ascii_lowercase();
            if cn.contains('.') && cn != "localhost" {
                computers.push(cn);
            }
        }
        if h.is_dc() {
            dc_ips.push(h.ip.clone());
        }
    }
    for d in domains {
        if eng.domain.fqdn.is_none() && d.contains('.') {
            eng.domain.fqdn = Some(d.clone());
        }
    }
    for c in computers {
        if let Some((_, dom)) = c.split_once('.') {
            if dom.contains('.') && eng.domain.fqdn.is_none() {
                eng.domain.fqdn = Some(dom.to_string());
            }
        }
        eng.domain.computers.insert(c);
    }
    for ip in dc_ips {
        eng.domain.dc_ips.insert(ip);
    }
}

/// Scrape credentials, hashes and SPNs out of a free-form blob (notes, tool output).
/// Returns the number of new credentials added.
pub fn harvest(eng: &mut Engagement, text: &str, source: &str) -> usize {
    let mut added = 0;

    // Domains
    for c in re!(DOMN, r"\b((?:[a-z0-9-]+\.)+(?:local|exam|corp|lan|internal|htb))\b")
        .captures_iter(&text.to_ascii_lowercase())
    {
        if eng.domain.fqdn.is_none() {
            eng.domain.fqdn = Some(c[1].to_string());
        }
    }

    // NTLM hashes:  "NTLM: <32hex>" / "NT: <32hex>" / lm:nt pair
    for c in re!(NT, r"(?i)\b(?:NTLM|NT)\s*[:=]\s*([a-f0-9]{32})\b").captures_iter(text) {
        let nt = c[1].to_ascii_lowercase();
        let cred = Credential::new("(unknown)", nt, SecretKind::NtHash, source.to_string());
        if eng.add_cred(cred) {
            added += 1;
        }
    }
    for c in re!(LMNT, r"\b([a-f0-9]{32}):([a-f0-9]{32})\b").captures_iter(text) {
        let nt = c[2].to_ascii_lowercase();
        let cred = Credential::new("(unknown)", nt, SecretKind::NtHash, source.to_string());
        if eng.add_cred(cred) {
            added += 1;
        }
    }

    // Labelled user/pass across up to a few lines
    for c in re!(LABEL,
        r"(?i)user(?:name)?\s*[:=]\s*([A-Za-z0-9._@\\-]+)[\s\S]{0,120}?pass(?:word|wd)?\s*[:=]\s*['\x22]?([^\s'\x22<]{3,64})"
    ).captures_iter(text) {
        push_cred(eng, &c[1], &c[2], source, &mut added);
    }

    // XML unattend / RDG style
    for c in re!(XMLC,
        r"(?is)<(?:userName|DomainUsername|user)>([^<]+)</[^>]+>[\s\S]{0,200}?<(?:password|DomainPassword|Value)>([^<]+)</[^>]+>"
    ).captures_iter(text) {
        push_cred(eng, c[1].trim(), c[2].trim(), source, &mut added);
    }

    // "user pass" on a single whitespace-separated line (e.g. "l.evgeny ForgeBrightJuliet536")
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2
            && re!(UNAME, r"^[A-Za-z][A-Za-z0-9._-]{2,40}$").is_match(parts[0])
            && parts[0].contains('.')
            && parts[1].len() >= 6
            && re!(HASPW, r"[A-Za-z]").is_match(parts[1])
            && re!(HASN, r"[0-9]").is_match(parts[1])
        {
            push_cred(eng, parts[0], parts[1], source, &mut added);
        }
    }

    // SPNs
    for c in re!(SPN, r"\b([A-Za-z]+/[A-Za-z0-9._-]+\.[a-z]{2,}(?::\d+)?)\b").captures_iter(text) {
        eng.domain.spns.insert(c[1].to_string());
    }

    added
}

fn push_cred(eng: &mut Engagement, user: &str, secret: &str, source: &str, added: &mut usize) {
    let user = user.trim().trim_start_matches('\\');
    let (domain, user) = match user.rsplit_once('\\') {
        Some((d, u)) => (Some(d.to_string()), u),
        None => match user.split_once('@') {
            Some((u, d)) => (Some(d.to_string()), u),
            None => (None, user),
        },
    };
    if is_noise(user) || is_noise(secret) || user.is_empty() || secret.is_empty() {
        return;
    }
    let mut cred = Credential::new(user, secret, SecretKind::Password, source.to_string());
    if let Some(d) = domain {
        cred = cred.with_domain(d);
    }
    if let Some(dec) = maybe_b64(secret) {
        cred.decoded = Some(dec);
    }
    if eng.add_cred(cred) {
        *added += 1;
    }
}

/// Convenience: parse an nmap XML string straight into the engagement.
pub fn ingest_nmap(eng: &mut Engagement, xml: &str) -> anyhow::Result<usize> {
    let hosts = super::nmap::parse_nmap_xml(xml)?;
    let n = hosts.len();
    for h in hosts {
        merge_traceroute_names(eng, &h);
        eng.upsert_host(h);
    }
    enrich_from_hosts(eng);
    eng.recompute_segments();
    Ok(n)
}

fn merge_traceroute_names(_eng: &mut Engagement, _h: &Host) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::state::Engagement;

    #[test]
    fn base64_admin_password_decodes() {
        assert_eq!(maybe_b64("WmVicmFMaW9uR2lyYWZmZTAxMAo").as_deref(), Some("ZebraLionGiraffe010"));
        assert_eq!(maybe_b64("nothashere"), None);
    }

    #[test]
    fn harvests_oscp_creds() {
        let mut eng = Engagement::new("t");
        let blob = "Username: r.andrews\nPassword: BusyOfficeWorker890\n\
                    l.evgeny ForgeBrightJuliet536\n\
                    NT: 5883fe1b8f0912b3ae14d4115e6b77b4\n";
        let n = harvest(&mut eng, blob, "notes");
        assert!(n >= 3, "expected >=3 creds, got {n}");
        assert!(eng.creds.iter().any(|c| c.user == "r.andrews" && c.secret == "BusyOfficeWorker890"));
        assert!(eng.creds.iter().any(|c| c.user == "l.evgeny" && c.secret == "ForgeBrightJuliet536"));
        assert!(eng.creds.iter().any(|c| c.kind == crate::model::SecretKind::NtHash));
    }

    #[test]
    fn harvests_unattend_xml() {
        let mut eng = Engagement::new("t");
        let blob = "<DomainUsername>administrator</DomainUsername>\
                    <DomainPassword>WmVicmFMaW9uR2lyYWZmZTAxMAo</DomainPassword>";
        harvest(&mut eng, blob, "unattend.xml");
        let c = eng.creds.iter().find(|c| c.user == "administrator").expect("admin cred");
        assert_eq!(c.decoded.as_deref(), Some("ZebraLionGiraffe010"));
    }
}

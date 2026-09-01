//! Engagement scope + metadata and the scope-check guard.
//! Precedence (research/FRAMEWORK.md §1.4): out-of-scope always wins; a non-empty
//! in-scope list is a strict allowlist; an empty in-scope list yields Unknown.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Entry {
    Cidr(String), // stored as text; parsed on demand
    Ip(String),
    HostGlob(String),
}

impl Entry {
    pub fn parse(s: &str) -> Entry {
        let s = s.trim();
        if s.contains('/') && s.parse::<IpNet>().is_ok() {
            Entry::Cidr(s.to_string())
        } else if s.parse::<IpAddr>().is_ok() {
            Entry::Ip(s.to_string())
        } else {
            Entry::HostGlob(s.to_ascii_lowercase())
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Entry::Cidr(s) | Entry::Ip(s) | Entry::HostGlob(s) => s,
        }
    }

    /// Does this entry match a target (an IP or a hostname)?
    fn matches(&self, target: &str) -> bool {
        let t = target.trim();
        match self {
            Entry::Ip(ip) => t == ip,
            Entry::Cidr(cidr) => match (cidr.parse::<IpNet>(), t.parse::<IpAddr>()) {
                (Ok(net), Ok(addr)) => net.contains(&addr),
                _ => false,
            },
            Entry::HostGlob(g) => glob_match(g, &t.to_ascii_lowercase()),
        }
    }
}

/// Very small glob: supports a single leading "*." wildcard, else exact match.
fn glob_match(pat: &str, s: &str) -> bool {
    if let Some(suffix) = pat.strip_prefix("*.") {
        s == suffix || s.ends_with(&format!(".{suffix}"))
    } else {
        pat == s
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    InScope,
    OutOfScope,
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    #[serde(default)]
    pub in_scope: Vec<Entry>,
    #[serde(default)]
    pub out_scope: Vec<Entry>,
    #[serde(default)]
    pub forbidden_techniques: Vec<String>,
}

impl Scope {
    pub fn is_empty(&self) -> bool {
        self.in_scope.is_empty() && self.out_scope.is_empty()
    }

    /// Normalise a target: strip scheme/port/path so URL and ip:port forms match.
    pub fn normalize(target: &str) -> String {
        let mut t = target.trim();
        if let Some(i) = t.find("://") {
            t = &t[i + 3..];
        }
        if let Some(i) = t.find('/') {
            t = &t[..i];
        }
        // strip :port (but keep IPv6 in brackets intact — rare here)
        if let Some(i) = t.rfind(':') {
            if t[i + 1..].chars().all(|c| c.is_ascii_digit()) && !t[..i].contains(':') {
                t = &t[..i];
            }
        }
        t.to_string()
    }

    /// Exact precedence from the research.
    pub fn check(&self, target: &str) -> Verdict {
        let t = Self::normalize(target);
        if self.out_scope.iter().any(|e| e.matches(&t)) {
            return Verdict::OutOfScope;
        }
        if !self.in_scope.is_empty() {
            if self.in_scope.iter().any(|e| e.matches(&t)) {
                return Verdict::InScope;
            }
            return Verdict::OutOfScope; // strict allowlist
        }
        Verdict::Unknown
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub roe_ref: String,
    #[serde(default)]
    pub authorization: String,
    #[serde(default)]
    pub start_date: String,
    #[serde(default)]
    pub end_date: String,
}

impl Meta {
    pub fn is_set(&self) -> bool {
        !self.client.is_empty() || !self.operator.is_empty() || !self.roe_ref.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn precedence_out_wins() {
        let mut s = Scope::default();
        s.in_scope.push(Entry::parse("10.0.0.0/24"));
        s.out_scope.push(Entry::parse("10.0.0.5"));
        assert_eq!(s.check("10.0.0.5"), Verdict::OutOfScope);
        assert_eq!(s.check("10.0.0.6"), Verdict::InScope);
        assert_eq!(s.check("192.168.1.1"), Verdict::OutOfScope); // strict allowlist
    }
    #[test]
    fn empty_inscope_is_unknown() {
        let mut s = Scope::default();
        s.out_scope.push(Entry::parse("10.0.0.0/8"));
        assert_eq!(s.check("10.1.2.3"), Verdict::OutOfScope);
        assert_eq!(s.check("192.168.1.1"), Verdict::Unknown);
    }
    #[test]
    fn normalize_url_and_port() {
        assert_eq!(Scope::normalize("http://10.0.0.1:8080/path"), "10.0.0.1");
        assert_eq!(Scope::normalize("10.0.0.1:443"), "10.0.0.1");
    }
    #[test]
    fn host_glob() {
        let mut s = Scope::default();
        s.in_scope.push(Entry::parse("*.corp.example.com"));
        assert_eq!(s.check("app.corp.example.com"), Verdict::InScope);
        assert_eq!(s.check("evil.com"), Verdict::OutOfScope);
    }
}

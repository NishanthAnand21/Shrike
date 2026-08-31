//! The engagement: everything we know, serialised to disk so a session resumes.

use super::creds::{Credential, SecretKind};
use super::finding::Finding;
use super::phase::Phase;
use super::target::{Host, Reach, Scope, Segment};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainInfo {
    #[serde(default)]
    pub fqdn: Option<String>,
    #[serde(default)]
    pub netbios: Option<String>,
    #[serde(default)]
    pub dc_ips: BTreeSet<String>,
    #[serde(default)]
    pub dc_names: BTreeSet<String>,
    #[serde(default)]
    pub users: BTreeSet<String>,
    #[serde(default)]
    pub computers: BTreeSet<String>,
    #[serde(default)]
    pub spns: BTreeSet<String>,
    #[serde(default)]
    pub groups: BTreeSet<String>,
}

impl DomainInfo {
    pub fn base_dn(&self) -> Option<String> {
        let f = self.fqdn.as_ref()?;
        Some(
            f.split('.')
                .map(|p| format!("DC={p}"))
                .collect::<Vec<_>>()
                .join(","),
        )
    }
    pub fn is_known(&self) -> bool {
        self.fqdn.is_some() || self.netbios.is_some()
    }
}

/// A record of one executed command — this is what gets exported to notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: u64,
    pub phase: Phase,
    /// Tool id from the catalog, or "raw" for a hand-typed command.
    pub tool: String,
    pub target: Option<String>,
    pub command: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    pub started: String,
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// Relative path inside the workspace where full output is stored.
    pub output_path: String,
    /// First N lines, kept inline for quick review / report skimming.
    #[serde(default)]
    pub excerpt: Vec<String>,
    #[serde(default)]
    pub findings: Vec<String>,
    #[serde(default)]
    pub starred: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebPath {
    pub path: String,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub length: Option<u64>,
    #[serde(default)]
    pub title: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Engagement {
    pub name: String,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub hosts: BTreeMap<String, Host>,
    #[serde(default)]
    pub segments: BTreeMap<String, Segment>,
    #[serde(default)]
    pub creds: Vec<Credential>,
    #[serde(default)]
    pub domain: DomainInfo,
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Discovered web paths, keyed by host:port base URL -> list of paths.
    #[serde(default)]
    pub web_paths: BTreeMap<String, Vec<WebPath>>,
    #[serde(default)]
    pub records: Vec<Record>,
    #[serde(default)]
    pub next_record_id: u64,
    /// Free-form operator notes, grouped by phase.
    #[serde(default)]
    pub notes: BTreeMap<String, Vec<String>>,
    /// Active SOCKS proxy, e.g. "127.0.0.1:1080", set when a pivot is up.
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    /// Attacker listener host/port for payloads (LHOST/LPORT).
    #[serde(default)]
    pub lhost: Option<String>,
    #[serde(default)]
    pub lport: Option<String>,
    #[serde(default)]
    pub wordlists: BTreeMap<String, String>,
}

impl Engagement {
    pub fn new(name: impl Into<String>) -> Self {
        Engagement {
            name: name.into(),
            created: now_iso(),
            next_record_id: 1,
            ..Default::default()
        }
    }

    pub fn host_mut(&mut self, ip: &str) -> &mut Host {
        self.hosts
            .entry(ip.to_string())
            .or_insert_with(|| Host::new(ip))
    }

    pub fn upsert_host(&mut self, h: Host) {
        match self.hosts.get_mut(&h.ip) {
            Some(existing) => existing.merge(h),
            None => {
                self.hosts.insert(h.ip.clone(), h);
            }
        }
    }

    /// Add a credential, de-duplicating on (domain, user, secret).
    pub fn add_cred(&mut self, c: Credential) -> bool {
        let k = c.key();
        if self.creds.iter().any(|e| e.key() == k) {
            return false;
        }
        if let Some(d) = &c.domain {
            if self.domain.fqdn.is_none() && d.contains('.') {
                self.domain.fqdn = Some(d.to_ascii_lowercase());
            }
        }
        self.domain.users.insert(c.user.clone());
        self.creds.push(c);
        true
    }

    /// Credentials that can be used to authenticate right now.
    pub fn usable_creds(&self) -> Vec<&Credential> {
        self.creds.iter().filter(|c| c.kind.is_usable()).collect()
    }

    /// The credential the command builder should reach for by default:
    /// prefer one already proven to work, then a domain password, then anything.
    pub fn best_cred(&self) -> Option<&Credential> {
        self.creds
            .iter()
            .filter(|c| c.kind.is_usable())
            .max_by_key(|c| {
                (
                    c.admin_on.len() * 4 + c.validated_on.len() * 2,
                    (c.domain.is_some() as usize),
                    (c.kind == SecretKind::Password) as usize,
                )
            })
    }

    pub fn hashes_to_crack(&self) -> Vec<&Credential> {
        self.creds
            .iter()
            .filter(|c| !c.kind.is_usable() && c.kind.hashcat_mode().is_some())
            .collect()
    }

    pub fn compromised(&self) -> Vec<&Host> {
        self.hosts.values().filter(|h| h.compromised).collect()
    }

    pub fn dcs(&self) -> Vec<&Host> {
        self.hosts.values().filter(|h| h.is_dc()).collect()
    }

    /// Recompute segments and reachability from current host data.
    pub fn recompute_segments(&mut self) {
        let mut segs: BTreeMap<String, Segment> = BTreeMap::new();
        for h in self.hosts.values() {
            let Some(cidr) = h.segment() else { continue };
            let Some(scope) = h.scope() else { continue };
            let e = segs.entry(cidr.clone()).or_insert_with(|| Segment {
                cidr: cidr.clone(),
                scope,
                reach: Reach::Unknown,
                gateways: vec![],
                pivot_via: None,
                hosts: vec![],
            });
            e.hosts.push(h.ip.clone());
            // The first traceroute hop that isn't the target is the gateway toward it.
            if let Some(gw) = h.traceroute.iter().find(|a| **a != h.ip) {
                if !e.gateways.contains(gw) {
                    e.gateways.push(gw.clone());
                }
            }
            // Any host with a confirmed open port proves the segment is routable.
            if h.open().next().is_some() && h.reach != Some(Reach::Pivot) {
                e.reach = Reach::Direct;
            }
        }
        // Segments with no directly-proven host need a pivot.
        let compromised: Vec<String> = self
            .hosts
            .values()
            .filter(|h| h.compromised)
            .map(|h| h.ip.clone())
            .collect();
        for seg in segs.values_mut() {
            if seg.reach != Reach::Direct {
                seg.reach = Reach::Pivot;
                seg.pivot_via = compromised.first().cloned();
            }
            seg.hosts.sort();
        }
        self.segments = segs;
    }

    /// Add a finding, de-duplicating on (source, title, location). Returns true if new.
    pub fn add_finding(&mut self, f: Finding) -> bool {
        let k = f.key();
        if self.findings.iter().any(|e| e.key() == k) {
            return false;
        }
        self.findings.push(f);
        self.findings.sort_by_key(|a| a.severity.rank());
        true
    }

    /// Record a discovered web path under a base URL. Returns true if new.
    pub fn add_web_path(&mut self, base: &str, wp: WebPath) -> bool {
        let entry = self.web_paths.entry(base.to_string()).or_default();
        if entry.iter().any(|e| e.path == wp.path) {
            return false;
        }
        entry.push(wp);
        true
    }

    pub fn findings_by_sev(&self, sev: super::finding::Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }

    pub fn push_record(&mut self, mut r: Record) -> u64 {
        let id = self.next_record_id.max(1);
        r.id = id;
        self.next_record_id = id + 1;
        self.records.push(r);
        id
    }

    pub fn records_for_phase(&self, p: Phase) -> Vec<&Record> {
        self.records.iter().filter(|r| r.phase == p).collect()
    }

    pub fn note(&mut self, phase: Phase, text: impl Into<String>) {
        self.notes
            .entry(phase.slug().to_string())
            .or_default()
            .push(text.into());
    }

    /// A short human summary used in the status bar.
    pub fn summary(&self) -> String {
        let open: usize = self.hosts.values().map(|h| h.open().count()).sum();
        let fstr = if self.findings.is_empty() {
            String::new()
        } else {
            format!(" · {} findings", self.findings.len())
        };
        format!(
            "{} hosts · {} open ports · {} creds{} · {} cmds{}",
            self.hosts.len(),
            open,
            self.creds.len(),
            fstr,
            self.records.len(),
            match &self.proxy {
                Some(p) => format!(" · proxy {p}"),
                None => String::new(),
            }
        )
    }
}

pub fn now_iso() -> String {
    chrono::Local::now()
        .format("%Y-%m-%dT%H:%M:%S%:z")
        .to_string()
}

#[allow(dead_code)]
fn _assert_scope(_s: Scope) {}

//! Tool catalog: declarative definitions of external tools, the conditions under
//! which they apply, and how to render them into a concrete command line.

pub mod tools;

use crate::model::{Credential, Engagement, Host, Phase, Service};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    Fast,
    Medium,
    Slow,
    VerySlow,
}

impl Speed {
    pub fn hint(self) -> &'static str {
        match self {
            Speed::Fast => "<30s",
            Speed::Medium => "~minutes",
            Speed::Slow => "~10min+",
            Speed::VerySlow => "long-running",
        }
    }
    /// Default per-job timeout in seconds.
    pub fn timeout_secs(self) -> u64 {
        match self {
            Speed::Fast => 120,
            Speed::Medium => 900,
            Speed::Slow => 3600,
            Speed::VerySlow => 0, // no timeout
        }
    }
}

/// What a tool yields, so the chain engine knows what becomes available next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Yields {
    Hosts,
    Ports,
    Services,
    WebPaths,
    Vhosts,
    Users,
    Shares,
    Credentials,
    Hashes,
    Tickets,
    DomainInfo,
    Shell,
    Session,
    Files,
    Vulns,
    Tunnel,
}

/// Declarative preconditions. All set fields must hold for the tool to be offered.
#[derive(Debug, Clone, Copy, Default)]
pub struct Applies {
    /// Offered when the host has ANY of these ports open.
    pub any_port: &'static [u16],
    /// Offered when a service name matches this substring (lowercased).
    pub service_like: Option<&'static str>,
    /// Offered when the product/version banner contains this (lowercased).
    pub banner_like: Option<&'static str>,
    pub needs_cred: bool,
    pub needs_domain: bool,
    pub needs_dc: bool,
    pub needs_compromised: bool,
    pub needs_hashes: bool,
    pub windows_only: bool,
    pub linux_only: bool,
    /// Host-independent (operates on the engagement as a whole).
    pub global: bool,
}

#[derive(Debug, Clone)]
pub struct Tool {
    pub id: &'static str,
    pub name: &'static str,
    /// Candidate binaries; the first one found on PATH wins.
    pub bins: &'static [&'static str],
    pub phase: Phase,
    pub desc: &'static str,
    /// Command template using {placeholder} syntax.
    pub template: &'static str,
    pub speed: Speed,
    /// Needs a real TTY (evil-winrm, ftp, msfconsole, ssh...) — must be launched
    /// in a pty rather than captured as a batch job.
    pub interactive: bool,
    pub yields: &'static [Yields],
    pub applies: Applies,
    /// Shown above the command in the transcript.
    pub note: &'static str,
    /// Higher sorts first within a phase.
    pub weight: i32,
}

impl Tool {
    /// Placeholders this template actually references.
    pub fn slots(&self) -> Vec<String> {
        let mut out = vec![];
        let b = self.template.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'{' {
                if let Some(end) = self.template[i + 1..].find('}') {
                    let name = &self.template[i + 1..i + 1 + end];
                    if !name.is_empty() && !out.iter().any(|s: &String| s == name) {
                        out.push(name.to_string());
                    }
                    i += end + 2;
                    continue;
                }
            }
            i += 1;
        }
        out
    }

    /// Render the template. Returns Err with the list of slots that could not be
    /// filled, so the UI can prompt the operator for exactly those.
    pub fn render(&self, ctx: &Ctx) -> Result<String, Vec<String>> {
        let mut missing = vec![];
        let mut out = String::with_capacity(self.template.len() + 64);
        let t = self.template;
        let mut rest = t;
        while let Some(start) = rest.find('{') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            match after.find('}') {
                Some(end) => {
                    let key = &after[..end];
                    match ctx.get(key) {
                        Some(v) => out.push_str(&v),
                        None => {
                            missing.push(key.to_string());
                            out.push('{');
                            out.push_str(key);
                            out.push('}');
                        }
                    }
                    rest = &after[end + 1..];
                }
                None => {
                    out.push_str(&rest[start..]);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        if missing.is_empty() {
            Ok(ctx.decorate(self, out))
        } else {
            Err(missing)
        }
    }

    pub fn matches(&self, eng: &Engagement, host: Option<&Host>) -> bool {
        let a = &self.applies;
        if a.needs_cred && eng.best_cred().is_none() {
            return false;
        }
        if a.needs_domain && !eng.domain.is_known() {
            return false;
        }
        if a.needs_dc && eng.dcs().is_empty() && eng.domain.dc_ips.is_empty() {
            return false;
        }
        if a.needs_hashes && eng.hashes_to_crack().is_empty() {
            return false;
        }
        if a.global {
            return true;
        }
        let Some(h) = host else { return false };
        if a.needs_compromised && !h.compromised {
            return false;
        }
        if a.windows_only && !h.is_windows() {
            return false;
        }
        if a.linux_only && h.is_windows() {
            return false;
        }
        if !a.any_port.is_empty() && !a.any_port.iter().any(|p| h.has_port(*p)) {
            return false;
        }
        if let Some(needle) = a.service_like {
            if !h.open().any(|s| s.name.to_ascii_lowercase().contains(needle)) {
                return false;
            }
        }
        if let Some(needle) = a.banner_like {
            if !h.open().any(|s| s.banner().to_ascii_lowercase().contains(needle)) {
                return false;
            }
        }
        true
    }
}

/// Values available for template substitution.
#[derive(Debug, Clone, Default)]
pub struct Ctx {
    pub vars: HashMap<String, String>,
    /// When set, network-touching commands are prefixed with proxychains.
    pub proxy: Option<String>,
    /// Suppress the proxy prefix for this render (e.g. tool is already SOCKS-aware).
    pub no_proxy: bool,
}

impl Ctx {
    pub fn new() -> Self {
        Ctx::default()
    }

    pub fn set(&mut self, k: &str, v: impl Into<String>) -> &mut Self {
        let v = v.into();
        if !v.is_empty() {
            self.vars.insert(k.to_string(), v);
        }
        self
    }

    pub fn get(&self, k: &str) -> Option<String> {
        self.vars.get(k).cloned()
    }

    /// Build a context from the engagement + optionally a specific host/service.
    pub fn from_engagement(eng: &Engagement, host: Option<&Host>, svc: Option<&Service>) -> Ctx {
        let mut c = Ctx::new();
        c.proxy = eng.proxy.clone();

        if let Some(d) = &eng.domain.fqdn {
            c.set("domain", d.clone());
            if let Some(dn) = eng.domain.base_dn() {
                c.set("basedn", dn);
            }
        }
        if let Some(nb) = &eng.domain.netbios {
            c.set("netbios", nb.clone());
        }
        let dc = eng
            .dcs()
            .first()
            .map(|h| h.ip.clone())
            .or_else(|| eng.domain.dc_ips.iter().next().cloned());
        if let Some(dc) = dc {
            c.set("dc_ip", dc);
        }
        if let Some(cred) = eng.best_cred() {
            c.apply_cred(cred);
        }
        if let Some(iface) = &eng.interface {
            c.set("iface", iface.clone());
        }
        for (k, v) in &eng.wordlists {
            c.set(k, v.clone());
        }
        c.set("wordlist", eng.wordlists.get("wordlist").cloned().unwrap_or_else(||
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt".into()));
        c.set("userlist", eng.wordlists.get("userlist").cloned().unwrap_or_else(||
            "users.txt".into()));
        c.set("passlist", eng.wordlists.get("passlist").cloned().unwrap_or_else(||
            "/usr/share/wordlists/rockyou.txt".into()));

        if let Some(h) = host {
            c.set("ip", h.ip.clone());
            c.set("target", h.ip.clone());
            if let Some(seg) = h.segment() {
                c.set("subnet", seg);
            }
            if let Some(hn) = h.hostnames.first() {
                c.set("hostname", hn.clone());
            }
            // Pick a sensible default web service if none was named.
            let web = svc.or_else(|| h.web_services().first().copied());
            if let Some(s) = web {
                c.set("port", s.port.to_string());
                c.set("url", s.url(&h.ip));
                c.set("scheme", s.scheme());
            }
        }
        if let Some(s) = svc {
            c.set("port", s.port.to_string());
            if let Some(h) = host {
                c.set("url", s.url(&h.ip));
            }
            c.set("scheme", s.scheme());
        }
        c
    }

    pub fn apply_cred(&mut self, cred: &Credential) {
        self.set("user", cred.user.clone());
        match cred.kind {
            crate::model::SecretKind::NtHash => {
                self.set("nthash", cred.effective());
                self.set("secret", cred.effective());
            }
            _ => {
                self.set("pass", cred.effective());
                self.set("secret", cred.effective());
            }
        }
        if let Some(d) = &cred.domain {
            self.set("domain", d.clone());
        }
        self.set("upn", cred.upn());
    }

    /// Prefix with proxychains when a tunnel is up and the tool talks to the network.
    fn decorate(&self, tool: &Tool, cmd: String) -> String {
        if self.no_proxy || tool.interactive {
            return cmd;
        }
        match &self.proxy {
            Some(_) if !matches!(tool.phase, Phase::Cracking | Phase::Loot) => {
                format!("proxychains4 -q {cmd}")
            }
            _ => cmd,
        }
    }
}

/// Every tool the framework knows about.
pub fn all() -> &'static [Tool] {
    tools::REGISTRY
}

pub fn by_id(id: &str) -> Option<&'static Tool> {
    all().iter().find(|t| t.id == id)
}

/// Tools applicable to a host (or globally), ranked.
pub fn suggest(eng: &Engagement, host: Option<&Host>) -> Vec<&'static Tool> {
    let mut v: Vec<&'static Tool> = all().iter().filter(|t| t.matches(eng, host)).collect();
    v.sort_by(|a, b| {
        a.phase
            .rank()
            .cmp(&b.phase.rank())
            .then(b.weight.cmp(&a.weight))
            .then(a.name.cmp(b.name))
    });
    v
}

pub fn by_phase(p: Phase) -> Vec<&'static Tool> {
    let mut v: Vec<&'static Tool> = all().iter().filter(|t| t.phase == p).collect();
    v.sort_by(|a, b| b.weight.cmp(&a.weight).then(a.name.cmp(b.name)));
    v
}

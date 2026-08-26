//! Targets: hosts, ports, services, and the network segmentation model.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    Private,
    Public,
    Cgnat,
    Loopback,
    LinkLocal,
}

impl Scope {
    pub fn of(ip: Ipv4Addr) -> Scope {
        let o = ip.octets();
        if ip.is_loopback() {
            Scope::Loopback
        } else if ip.is_link_local() {
            Scope::LinkLocal
        } else if o[0] == 100 && (64..128).contains(&o[1]) {
            Scope::Cgnat
        } else if ip.is_private() {
            Scope::Private
        } else {
            Scope::Public
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Scope::Private => "INTERNAL (RFC1918)",
            Scope::Public => "EXTERNAL (public)",
            Scope::Cgnat => "CGNAT",
            Scope::Loopback => "loopback",
            Scope::LinkLocal => "link-local",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reach {
    /// Routable from the operator box right now.
    Direct,
    /// Only reachable through a compromised host.
    Pivot,
    /// Seen referenced but never proven reachable.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl PortState {
    pub fn is_open(&self) -> bool {
        matches!(self, PortState::Open | PortState::OpenFiltered)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub port: u16,
    pub proto: String,
    pub state: PortState,
    /// nmap service name, e.g. "http", "microsoft-ds"
    pub name: String,
    pub product: String,
    pub version: String,
    pub extra: String,
    /// NSE script id -> output
    #[serde(default)]
    pub scripts: BTreeMap<String, String>,
}

impl Service {
    /// Best-effort: is this port speaking TLS?
    pub fn is_tls(&self) -> bool {
        self.name.contains("https")
            || self.name.contains("ssl")
            || self.extra.to_ascii_lowercase().contains("tls")
            || matches!(self.port, 443 | 8443 | 9443 | 10443 | 636 | 3269 | 5986 | 993 | 995)
    }

    pub fn is_web(&self) -> bool {
        self.name.contains("http")
            || self.product.to_ascii_lowercase().contains("httpd")
            || matches!(self.port, 80 | 443 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888 | 3000 | 5000 | 9090)
    }

    /// Scheme to use when building a URL for this service.
    pub fn scheme(&self) -> &'static str {
        if self.is_tls() { "https" } else { "http" }
    }

    pub fn url(&self, ip: &str) -> String {
        let s = self.scheme();
        let default = (s == "http" && self.port == 80) || (s == "https" && self.port == 443);
        if default {
            format!("{s}://{ip}")
        } else {
            format!("{s}://{ip}:{}", self.port)
        }
    }

    pub fn banner(&self) -> String {
        [self.product.as_str(), self.version.as_str(), self.extra.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: String,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub services: Vec<Service>,
    #[serde(default)]
    pub host_scripts: BTreeMap<String, String>,
    #[serde(default)]
    pub reach: Option<Reach>,
    /// IP of the host we pivot through to touch this one, if any.
    #[serde(default)]
    pub pivot_via: Option<String>,
    #[serde(default)]
    pub traceroute: Vec<String>,
    /// Set once we have any level of shell/session here.
    #[serde(default)]
    pub compromised: bool,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Host {
    pub fn new(ip: impl Into<String>) -> Self {
        Host {
            ip: ip.into(),
            hostnames: vec![],
            os: None,
            services: vec![],
            host_scripts: BTreeMap::new(),
            reach: None,
            pivot_via: None,
            traceroute: vec![],
            compromised: false,
            notes: vec![],
            tags: vec![],
        }
    }

    pub fn addr(&self) -> Option<Ipv4Addr> {
        self.ip.parse().ok()
    }

    pub fn scope(&self) -> Option<Scope> {
        self.addr().map(Scope::of)
    }

    pub fn open(&self) -> impl Iterator<Item = &Service> {
        self.services.iter().filter(|s| s.state.is_open())
    }

    pub fn has_port(&self, p: u16) -> bool {
        self.open().any(|s| s.port == p)
    }

    pub fn web_services(&self) -> Vec<&Service> {
        self.open().filter(|s| s.is_web()).collect()
    }

    /// Heuristic: does this look like a Domain Controller?
    pub fn is_dc(&self) -> bool {
        (self.has_port(88) && self.has_port(389)) || self.has_port(3268)
    }

    pub fn is_windows(&self) -> bool {
        self.os.as_deref().unwrap_or("").contains("Windows")
            || self.has_port(3389)
            || self.has_port(135)
            || self.open().any(|s| s.banner().contains("Microsoft"))
    }

    /// /24 the host lives in, as a CIDR string.
    pub fn segment(&self) -> Option<String> {
        let a = self.addr()?;
        let o = a.octets();
        Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
    }

    pub fn merge(&mut self, other: Host) {
        for h in other.hostnames {
            if !self.hostnames.contains(&h) {
                self.hostnames.push(h);
            }
        }
        if self.os.is_none() {
            self.os = other.os;
        }
        if self.traceroute.is_empty() {
            self.traceroute = other.traceroute;
        }
        self.host_scripts.extend(other.host_scripts);
        for svc in other.services {
            match self.services.iter_mut().find(|s| s.port == svc.port && s.proto == svc.proto) {
                Some(existing) => {
                    if svc.banner().len() > existing.banner().len() {
                        existing.product = svc.product;
                        existing.version = svc.version;
                        existing.extra = svc.extra;
                    }
                    if svc.state.is_open() {
                        existing.state = svc.state;
                    }
                    existing.scripts.extend(svc.scripts);
                }
                None => self.services.push(svc),
            }
        }
        self.services.sort_by_key(|s| s.port);
        self.compromised |= other.compromised;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub cidr: String,
    pub scope: Scope,
    pub reach: Reach,
    #[serde(default)]
    pub gateways: Vec<String>,
    #[serde(default)]
    pub pivot_via: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
}

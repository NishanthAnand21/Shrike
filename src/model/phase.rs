//! Engagement phases. Ordering matters: the suggestion engine walks forward
//! through these, and the notes exporter groups artifacts by them.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Discovery,
    PortScan,
    ServiceEnum,
    WebEnum,
    DirEnum,
    ApiEnum,
    VulnScan,
    SmbEnum,
    AdEnum,
    Exploit,
    CredAccess,
    Cracking,
    Pivot,
    PostExploit,
    PrivEsc,
    Loot,
}

impl Phase {
    pub const ALL: [Phase; 16] = [
        Phase::Discovery,
        Phase::PortScan,
        Phase::ServiceEnum,
        Phase::WebEnum,
        Phase::DirEnum,
        Phase::ApiEnum,
        Phase::VulnScan,
        Phase::SmbEnum,
        Phase::AdEnum,
        Phase::Exploit,
        Phase::CredAccess,
        Phase::Cracking,
        Phase::Pivot,
        Phase::PostExploit,
        Phase::PrivEsc,
        Phase::Loot,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Phase::Discovery => "discovery",
            Phase::PortScan => "port-scan",
            Phase::ServiceEnum => "service-enum",
            Phase::WebEnum => "web-enum",
            Phase::DirEnum => "dir-enum",
            Phase::ApiEnum => "api-enum",
            Phase::VulnScan => "vuln-scan",
            Phase::SmbEnum => "smb-enum",
            Phase::AdEnum => "ad-enum",
            Phase::Exploit => "exploit",
            Phase::CredAccess => "cred-access",
            Phase::Cracking => "cracking",
            Phase::Pivot => "pivot",
            Phase::PostExploit => "post-exploit",
            Phase::PrivEsc => "privesc",
            Phase::Loot => "loot",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Phase::Discovery => "Host Discovery",
            Phase::PortScan => "Port Scanning",
            Phase::ServiceEnum => "Service Enumeration",
            Phase::WebEnum => "Web Enumeration",
            Phase::DirEnum => "Content Discovery",
            Phase::ApiEnum => "API Enumeration",
            Phase::VulnScan => "Vulnerability Scanning",
            Phase::SmbEnum => "SMB / NetBIOS Enumeration",
            Phase::AdEnum => "Active Directory Enumeration",
            Phase::Exploit => "Exploitation",
            Phase::CredAccess => "Credential Access",
            Phase::Cracking => "Password Cracking",
            Phase::Pivot => "Pivoting / Tunnelling",
            Phase::PostExploit => "Post-Exploitation",
            Phase::PrivEsc => "Privilege Escalation",
            Phase::Loot => "Loot & Evidence",
        }
    }

    /// Sort order used by the notes exporter and the suggestion ranker.
    pub fn rank(self) -> u8 {
        Phase::ALL.iter().position(|p| *p == self).unwrap_or(255) as u8
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.title())
    }
}

impl std::str::FromStr for Phase {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let k = s.trim().to_ascii_lowercase().replace('_', "-");
        Phase::ALL
            .iter()
            .copied()
            .find(|p| p.slug() == k)
            .ok_or_else(|| format!("unknown phase: {s}"))
    }
}

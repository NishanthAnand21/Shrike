//! First-class findings: vulnerabilities, exposures and notable discoveries that
//! belong in the report, independent of the command that produced them.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    pub fn parse(s: &str) -> Severity {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "med" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Sort rank (0 = most severe) for ordering the report.
    pub fn rank(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Short stable identifier, e.g. "nuclei:apache-detect" or "manual".
    pub source: String,
    pub severity: Severity,
    pub title: String,
    /// Where it was found: a URL, ip:port, or host.
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub cve: Vec<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

impl Finding {
    pub fn new(source: impl Into<String>, sev: Severity, title: impl Into<String>) -> Self {
        Finding {
            source: source.into(),
            severity: sev,
            title: title.into(),
            location: None,
            host: None,
            cve: vec![],
            detail: None,
        }
    }

    pub fn at(mut self, loc: impl Into<String>) -> Self {
        self.location = Some(loc.into());
        self
    }

    pub fn on(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// De-dup identity.
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.source.to_ascii_lowercase(),
            self.title.to_ascii_lowercase(),
            self.location.as_deref().unwrap_or("")
        )
    }
}

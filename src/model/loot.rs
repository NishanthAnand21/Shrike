//! Loot & evidence tracking (research/FRAMEWORK.md §3): captured files, exported
//! credentials, generated payloads — anything worth listing on a handoff.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LootKind {
    File,
    Creds,
    Payload,
    Report,
    Config,
    Screenshot,
}

impl LootKind {
    pub fn icon(self) -> &'static str {
        match self {
            LootKind::File => "📄",
            LootKind::Creds => "🔑",
            LootKind::Payload => "💣",
            LootKind::Report => "📊",
            LootKind::Config => "⚙",
            LootKind::Screenshot => "🖼",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            LootKind::File => "file",
            LootKind::Creds => "creds",
            LootKind::Payload => "payload",
            LootKind::Report => "report",
            LootKind::Config => "config",
            LootKind::Screenshot => "screenshot",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LootItem {
    pub kind: LootKind,
    pub name: String,
    /// Workspace-relative path.
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub size: Option<u64>,
    pub ts: String,
}

impl LootItem {
    pub fn new(kind: LootKind, name: impl Into<String>, path: impl Into<String>) -> Self {
        LootItem {
            kind,
            name: name.into(),
            path: path.into(),
            host: None,
            source: String::new(),
            size: None,
            ts: crate::model::state::now_iso(),
        }
    }
    pub fn from(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }
    pub fn on(mut self, host: Option<String>) -> Self {
        self.host = host;
        self
    }
    pub fn sized(mut self, n: u64) -> Self {
        self.size = Some(n);
        self
    }
}

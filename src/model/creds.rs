//! Credential material recovered during an engagement.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretKind {
    Password,
    NtHash,
    NetNtlmv2,
    AsRep,
    TgsRep,
    AesKey,
    SshKey,
    Ticket,
    ApiKey,
    Unknown,
}

impl SecretKind {
    /// hashcat mode for this material, when it is crackable.
    pub fn hashcat_mode(self) -> Option<u32> {
        match self {
            SecretKind::NtHash => Some(1000),
            SecretKind::NetNtlmv2 => Some(5600),
            SecretKind::AsRep => Some(18200),
            SecretKind::TgsRep => Some(13100),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SecretKind::Password => "password",
            SecretKind::NtHash => "NT hash",
            SecretKind::NetNtlmv2 => "NetNTLMv2",
            SecretKind::AsRep => "AS-REP",
            SecretKind::TgsRep => "TGS-REP",
            SecretKind::AesKey => "AES key",
            SecretKind::SshKey => "SSH key",
            SecretKind::Ticket => "Kerberos ticket",
            SecretKind::ApiKey => "API key",
            SecretKind::Unknown => "unknown",
        }
    }

    /// Can this be used directly to authenticate (vs. needing to be cracked first)?
    pub fn is_usable(self) -> bool {
        matches!(
            self,
            SecretKind::Password
                | SecretKind::NtHash
                | SecretKind::AesKey
                | SecretKind::SshKey
                | SecretKind::Ticket
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub user: String,
    #[serde(default)]
    pub domain: Option<String>,
    pub secret: String,
    pub kind: SecretKind,
    /// Where it came from: "lsass dump on 10.0.0.5", "ftp anon /backup/creds.txt"
    pub source: String,
    /// Base64 (or similar) decoded form, when the raw value was encoded.
    #[serde(default)]
    pub decoded: Option<String>,
    /// Hosts this credential has been proven to work on.
    #[serde(default)]
    pub validated_on: Vec<String>,
    /// Hosts where it granted administrative access.
    #[serde(default)]
    pub admin_on: Vec<String>,
    #[serde(default)]
    pub is_local: bool,
}

impl Credential {
    pub fn new(user: impl Into<String>, secret: impl Into<String>, kind: SecretKind, source: impl Into<String>) -> Self {
        Credential {
            user: user.into(),
            domain: None,
            secret: secret.into(),
            kind,
            source: source.into(),
            decoded: None,
            validated_on: vec![],
            admin_on: vec![],
            is_local: false,
        }
    }

    pub fn with_domain(mut self, d: impl Into<String>) -> Self {
        let d = d.into();
        if !d.is_empty() {
            self.domain = Some(d);
        }
        self
    }

    /// The value to actually pass on a command line.
    pub fn effective(&self) -> &str {
        self.decoded.as_deref().unwrap_or(&self.secret)
    }

    pub fn upn(&self) -> String {
        match &self.domain {
            Some(d) => format!("{}@{}", self.user, d),
            None => self.user.clone(),
        }
    }

    pub fn down_level(&self) -> String {
        match &self.domain {
            Some(d) => format!("{}\\{}", d, self.user),
            None => self.user.clone(),
        }
    }

    /// Identity for de-duplication.
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.domain.as_deref().unwrap_or("").to_ascii_lowercase(),
            self.user.to_ascii_lowercase(),
            self.secret
        )
    }
}

//! Credential-vault export (research/FRAMEWORK.md §3.5): hashcat-per-mode, john,
//! CSV, and a user:pass reuse list — pure functions over the engagement's creds.

use crate::model::state::Engagement;
use crate::model::SecretKind;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};

/// Write all export formats under <root>/export/. Returns the files written.
pub fn export(eng: &Engagement, root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let dir = root.join("export");
    std::fs::create_dir_all(&dir)?;
    let mut written = vec![];

    // A. hashcat, grouped per -m mode.
    let mut by_mode: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for c in &eng.creds {
        if let Some(mode) = c.kind.hashcat_mode() {
            by_mode.entry(mode).or_default().push(c.secret.clone());
        }
    }
    let mut cmds = String::from("#!/bin/sh\n# suggested hashcat runs\n");
    for (mode, hashes) in &by_mode {
        let p = dir.join(format!("hashcat-m{mode}.txt"));
        std::fs::write(&p, hashes.join("\n") + "\n")?;
        let _ = writeln!(
            cmds,
            "hashcat -m {mode} export/hashcat-m{mode}.txt /usr/share/wordlists/rockyou.txt -O"
        );
        written.push(p);
    }
    if !by_mode.is_empty() {
        let p = dir.join("hashcat-commands.sh");
        std::fs::write(&p, cmds)?;
        written.push(p);
    }

    // B. john — single file, user:hash lines (John autodetects).
    let john: Vec<String> = eng
        .creds
        .iter()
        .filter(|c| c.kind.hashcat_mode().is_some())
        .map(|c| format!("{}:{}", c.user, c.secret))
        .collect();
    if !john.is_empty() {
        let p = dir.join("john.txt");
        std::fs::write(&p, john.join("\n") + "\n")?;
        written.push(p);
    }

    // C. CSV — full fidelity.
    let mut csv = String::from("username,realm,kind,secret,plaintext,host,source\n");
    for c in &eng.creds {
        let esc = |s: &str| {
            if s.contains(',') || s.contains('"') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        };
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{},{}",
            esc(&c.user),
            esc(c.domain.as_deref().unwrap_or("")),
            c.kind.label(),
            esc(&c.secret),
            esc(c.decoded.as_deref().unwrap_or("")),
            esc(&c.validated_on.join(";")),
            esc(&c.source),
        );
    }
    let p = dir.join("creds.csv");
    std::fs::write(&p, csv)?;
    written.push(p);

    // D. user:pass reuse list — usable creds only; plus deduped user/pass columns.
    let mut userpass = vec![];
    let mut users: Vec<String> = vec![];
    let mut passwords: Vec<String> = vec![];
    for c in &eng.creds {
        if matches!(c.kind, SecretKind::Password) {
            let secret = c.decoded.as_deref().unwrap_or(&c.secret);
            userpass.push(format!("{}:{}", c.user, secret));
            if !passwords.contains(&secret.to_string()) {
                passwords.push(secret.to_string());
            }
        }
        if !users.contains(&c.user) {
            users.push(c.user.clone());
        }
    }
    if !userpass.is_empty() {
        let p = dir.join("userpass.txt");
        std::fs::write(&p, userpass.join("\n") + "\n")?;
        written.push(p);
    }
    if !users.is_empty() {
        let p = dir.join("users.txt");
        std::fs::write(&p, users.join("\n") + "\n")?;
        written.push(p);
    }
    if !passwords.is_empty() {
        let p = dir.join("passwords.txt");
        std::fs::write(&p, passwords.join("\n") + "\n")?;
        written.push(p);
    }
    Ok(written)
}

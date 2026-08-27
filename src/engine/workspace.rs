//! On-disk engagement workspace. Layout:
//!
//! <root>/
//!   engagement.json            full serialised state (resumable)
//!   notes.md                   generated report, grouped by phase
//!   targets/<ip>/<phase>/<id>-<tool>.txt   per-command captured output
//!   loot/                      files pulled off targets
//!
//! Everything is flushed after each command so a crash never loses work.

use crate::model::state::Engagement;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub struct Workspace {
    pub root: PathBuf,
}

impl Workspace {
    pub fn open_or_create(root: impl AsRef<Path>, name: &str) -> Result<(Workspace, Engagement)> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).with_context(|| format!("create workspace {root:?}"))?;
        std::fs::create_dir_all(root.join("targets"))?;
        std::fs::create_dir_all(root.join("loot"))?;
        let ws = Workspace { root };
        let eng = if ws.state_path().exists() {
            ws.load()?
        } else {
            let e = Engagement::new(name);
            ws.save(&e)?;
            e
        };
        Ok((ws, eng))
    }

    pub fn state_path(&self) -> PathBuf {
        self.root.join("engagement.json")
    }

    pub fn load(&self) -> Result<Engagement> {
        let data = std::fs::read_to_string(self.state_path()).context("read engagement.json")?;
        let eng = serde_json::from_str(&data).context("parse engagement.json")?;
        Ok(eng)
    }

    pub fn save(&self, eng: &Engagement) -> Result<()> {
        let tmp = self.state_path().with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(eng)?)?;
        std::fs::rename(&tmp, self.state_path())?; // atomic replace
        Ok(())
    }

    /// Directory for a target+phase, created on demand.
    pub fn phase_dir(&self, target: Option<&str>, phase_slug: &str) -> Result<PathBuf> {
        let t = target.unwrap_or("_global");
        let safe: String = t
            .chars()
            .map(|c| if c == '/' || c == ':' { '_' } else { c })
            .collect();
        let dir = self.root.join("targets").join(safe).join(phase_slug);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Path where a command's full output will be written.
    pub fn output_file(
        &self,
        id: u64,
        target: Option<&str>,
        phase_slug: &str,
        tool: &str,
    ) -> Result<PathBuf> {
        let dir = self.phase_dir(target, phase_slug)?;
        let toolsafe: String = tool
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        Ok(dir.join(format!("{id:04}-{toolsafe}.txt")))
    }

    /// A sibling artifact path for a job (e.g. the `-oX` XML target), given an extension.
    pub fn artifact_file(
        &self,
        id: u64,
        target: Option<&str>,
        phase_slug: &str,
        tool: &str,
        ext: &str,
    ) -> Result<PathBuf> {
        let dir = self.phase_dir(target, phase_slug)?;
        let toolsafe: String = tool
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        Ok(dir.join(format!("{id:04}-{toolsafe}.{ext}")))
    }

    pub fn loot_dir(&self) -> PathBuf {
        self.root.join("loot")
    }

    /// Path relative to root, for storing in the state file.
    pub fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.root)
            .unwrap_or(p)
            .to_string_lossy()
            .into_owned()
    }

    /// Regenerate notes.md from the engagement.
    pub fn export_notes(&self, eng: &Engagement) -> Result<PathBuf> {
        let md = crate::notes::render(eng);
        let path = self.root.join("notes.md");
        std::fs::write(&path, md)?;
        Ok(path)
    }
}

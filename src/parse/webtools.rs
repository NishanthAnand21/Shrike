//! Parsers for the structured output of common web tools, feeding results back
//! into the engagement as findings and discovered web paths.
//!
//! Field names verified against current tool versions (see research/OUTPUT_SCHEMAS.md):
//! - nuclei: kebab-case keys, `-jsonl`, CVE at info.classification.cve-id (array)
//! - httpx:  `-json` JSONL, `port` is a STRING, tech is `tech` (array)
//! - ffuf:   `-of json` is a single document with a `results[]` array
//! - feroxbuster: `--json` JSONL with mixed record types (branch on `type`)

use crate::model::state::{Engagement, WebPath};
use crate::model::{Finding, Severity};
use serde::Deserialize;

/// Result of ingesting a tool's output: counts for the operator.
#[derive(Default, Debug, Clone, Copy)]
pub struct Ingested {
    pub findings: usize,
    pub paths: usize,
}

impl Ingested {
    pub fn any(&self) -> bool {
        self.findings > 0 || self.paths > 0
    }
}

fn base_of(url: &str) -> String {
    // scheme://host[:port]
    if let Some(rest) = url.split_once("://") {
        let host = rest.1.split('/').next().unwrap_or(rest.1);
        format!("{}://{}", rest.0, host)
    } else {
        url.to_string()
    }
}

fn path_of(url: &str) -> String {
    if let Some((_, rest)) = url.split_once("://") {
        match rest.find('/') {
            Some(i) => rest[i..].to_string(),
            None => "/".to_string(),
        }
    } else {
        url.to_string()
    }
}

// ───────────────────────────── nuclei

#[derive(Deserialize)]
struct NucleiInfo {
    name: Option<String>,
    severity: Option<String>,
    classification: Option<NucleiClass>,
}
#[derive(Deserialize)]
struct NucleiClass {
    #[serde(rename = "cve-id")]
    cve_id: Option<Vec<String>>,
}
#[derive(Deserialize)]
struct NucleiRec {
    #[serde(rename = "template-id")]
    template_id: Option<String>,
    info: Option<NucleiInfo>,
    host: Option<String>,
    #[serde(rename = "matched-at")]
    matched_at: Option<String>,
}

pub fn ingest_nuclei(eng: &mut Engagement, text: &str) -> Ingested {
    let mut n = Ingested::default();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<NucleiRec>(line) else {
            continue;
        };
        let info = rec.info.unwrap_or(NucleiInfo {
            name: None,
            severity: None,
            classification: None,
        });
        let sev = Severity::parse(info.severity.as_deref().unwrap_or("info"));
        let title = info
            .name
            .or(rec.template_id.clone())
            .unwrap_or_else(|| "nuclei finding".into());
        let mut f = Finding::new(
            format!("nuclei:{}", rec.template_id.as_deref().unwrap_or("?")),
            sev,
            title,
        );
        f.location = rec.matched_at.clone().or_else(|| rec.host.clone());
        f.host = rec.host.clone();
        if let Some(c) = info.classification.and_then(|c| c.cve_id) {
            f.cve = c;
        }
        if eng.add_finding(f) {
            n.findings += 1;
        }
    }
    n
}

// ───────────────────────────── httpx

#[derive(Deserialize)]
struct HttpxRec {
    url: Option<String>,
    status_code: Option<u16>,
    title: Option<String>,
    webserver: Option<String>,
    #[serde(default)]
    tech: Vec<String>,
    #[serde(default)]
    technologies: Vec<String>,
    content_length: Option<u64>,
    host: Option<String>,
}

pub fn ingest_httpx(eng: &mut Engagement, text: &str) -> Ingested {
    let mut n = Ingested::default();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<HttpxRec>(line) else {
            continue;
        };
        let Some(url) = rec.url.clone() else { continue };
        let base = base_of(&url);
        let wp = WebPath {
            path: path_of(&url),
            status: rec.status_code,
            length: rec.content_length,
            title: rec.title.clone(),
        };
        if eng.add_web_path(&base, wp) {
            n.paths += 1;
        }
        // Record a tech/server fingerprint as an info finding.
        let mut techs = rec.tech.clone();
        techs.extend(rec.technologies.clone());
        if let Some(ws) = &rec.webserver {
            techs.push(ws.clone());
        }
        if !techs.is_empty() {
            let mut f = Finding::new(
                "httpx:tech",
                Severity::Info,
                format!("Tech: {}", techs.join(", ")),
            );
            f.location = Some(base.clone());
            f.host = rec.host.clone();
            if eng.add_finding(f) {
                n.findings += 1;
            }
        }
    }
    n
}

// ───────────────────────────── ffuf (single JSON document)

#[derive(Deserialize)]
struct FfufDoc {
    results: Vec<FfufHit>,
}
#[derive(Deserialize)]
struct FfufHit {
    url: Option<String>,
    status: Option<u16>,
    length: Option<u64>,
}

pub fn ingest_ffuf(eng: &mut Engagement, text: &str) -> Ingested {
    let mut n = Ingested::default();
    let Ok(doc) = serde_json::from_str::<FfufDoc>(text) else {
        return n;
    };
    for hit in doc.results {
        let Some(url) = hit.url else { continue };
        let base = base_of(&url);
        let wp = WebPath {
            path: path_of(&url),
            status: hit.status,
            length: hit.length,
            title: None,
        };
        if eng.add_web_path(&base, wp) {
            n.paths += 1;
        }
    }
    n
}

// ───────────────────────────── feroxbuster (JSONL, mixed types)

#[derive(Deserialize)]
struct FeroxRec {
    #[serde(rename = "type")]
    kind: Option<String>,
    url: Option<String>,
    status: Option<u16>,
    content_length: Option<u64>,
}

pub fn ingest_feroxbuster(eng: &mut Engagement, text: &str) -> Ingested {
    let mut n = Ingested::default();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<FeroxRec>(line) else {
            continue;
        };
        if rec.kind.as_deref() != Some("response") {
            continue;
        }
        let Some(url) = rec.url else { continue };
        let base = base_of(&url);
        let wp = WebPath {
            path: path_of(&url),
            status: rec.status,
            length: rec.content_length,
            title: None,
        };
        if eng.add_web_path(&base, wp) {
            n.paths += 1;
        }
    }
    n
}

// ───────────────────────────── subdomain lists (subfinder/dnsx/assetfinder JSONL or plain)

#[derive(Deserialize)]
struct HostRec {
    host: Option<String>,
}

/// Extract hostnames from subfinder/dnsx JSON(L) or a plain host-per-line list.
pub fn ingest_subdomains(eng: &mut Engagement, text: &str) -> usize {
    let mut added = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let name = if line.starts_with('{') {
            match serde_json::from_str::<HostRec>(line) {
                Ok(r) => r.host,
                Err(_) => None,
            }
        } else {
            Some(line.to_string())
        };
        if let Some(name) = name {
            if name.contains('.') && !eng.domain.computers.contains(&name.to_ascii_lowercase()) {
                eng.domain.computers.insert(name.to_ascii_lowercase());
                added += 1;
            }
        }
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::state::Engagement;

    #[test]
    fn parses_nuclei_jsonl() {
        let line = r#"{"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"critical","classification":{"cve-id":["CVE-2021-1234"]}},"host":"http://t","matched-at":"http://t/x"}"#;
        let mut e = Engagement::new("t");
        let n = ingest_nuclei(&mut e, line);
        assert_eq!(n.findings, 1);
        assert_eq!(e.findings[0].severity, Severity::Critical);
        assert_eq!(e.findings[0].cve, vec!["CVE-2021-1234"]);
    }

    #[test]
    fn parses_httpx_and_ffuf() {
        let mut e = Engagement::new("t");
        let hx = r#"{"url":"http://h/admin","status_code":200,"title":"Admin","tech":["PHP"],"content_length":42,"host":"h"}"#;
        let n = ingest_httpx(&mut e, hx);
        assert_eq!(n.paths, 1);
        assert!(e.web_paths.contains_key("http://h"));

        let ff = r#"{"results":[{"url":"http://h/backup","status":200,"length":10},{"url":"http://h/db","status":403,"length":5}]}"#;
        let n2 = ingest_ffuf(&mut e, ff);
        assert_eq!(n2.paths, 2);
    }

    #[test]
    fn parses_feroxbuster_jsonl_mixed() {
        let mut e = Engagement::new("t");
        let text = "{\"type\":\"response\",\"url\":\"http://h/x\",\"status\":200,\"content_length\":3}\n{\"type\":\"statistics\",\"url\":null}";
        let n = ingest_feroxbuster(&mut e, text);
        assert_eq!(n.paths, 1);
    }
}

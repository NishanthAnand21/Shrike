//! Self-contained HTML report export — a portable, shareable engagement report.

use crate::model::state::Engagement;
use crate::model::Phase;
use std::fmt::Write;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn render(eng: &Engagement) -> String {
    let mut h = String::new();
    let _ = write!(h, "{}", HEAD.replace("__NAME__", &esc(&eng.name)));

    // Header + summary
    let _ = write!(
        h,
        r#"<header><h1>{}</h1><p class="sub">Engagement report · generated {}</p>
<div class="stats">{}</div></header>"#,
        esc(&eng.name),
        esc(&crate::model::state::now_iso()),
        stat_row(eng)
    );

    findings(&mut h, eng);
    attack(&mut h, eng);
    topology(&mut h, eng);
    creds(&mut h, eng);
    web(&mut h, eng);
    commands(&mut h, eng);

    let _ = write!(h, "</main></body></html>");
    h
}

fn stat_row(eng: &Engagement) -> String {
    let open: usize = eng.hosts.values().map(|x| x.open().count()).sum();
    let cells = [
        ("hosts", eng.hosts.len()),
        ("open ports", open),
        ("credentials", eng.creds.len()),
        ("findings", eng.findings.len()),
        ("commands", eng.records.len()),
    ];
    cells
        .iter()
        .map(|(k, v)| {
            format!(
                r#"<div class="stat"><span class="n">{v}</span><span class="k">{k}</span></div>"#
            )
        })
        .collect()
}

fn findings(h: &mut String, eng: &Engagement) {
    if eng.findings.is_empty() {
        return;
    }
    let _ = write!(
        h,
        r#"<section><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Title</th><th>Location</th><th>Source</th><th>CVE</th></tr></thead><tbody>"#
    );
    for f in &eng.findings {
        let _ = write!(
            h,
            r#"<tr><td><span class="sev {sev}">{sevu}</span></td><td>{title}</td><td class="mono">{loc}</td><td class="mono dim">{src}</td><td class="mono">{cve}</td></tr>"#,
            sev = f.severity.label(),
            sevu = f.severity.label().to_uppercase(),
            title = esc(&f.title),
            loc = esc(f
                .location
                .as_deref()
                .unwrap_or(f.host.as_deref().unwrap_or(""))),
            src = esc(&f.source),
            cve = esc(&f.cve.join(", "))
        );
    }
    let _ = write!(h, "</tbody></table></section>");
}

fn attack(h: &mut String, eng: &Engagement) {
    use crate::chain::mitre;
    use std::collections::BTreeMap;
    let mut seen: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for r in &eng.records {
        if let Some(id) = mitre::tag_for_tool(&r.tool) {
            let e = seen.entry(id).or_default();
            if !e.contains(&r.tool) {
                e.push(r.tool.clone());
            }
        }
    }
    if seen.is_empty() {
        return;
    }
    let _ = write!(h, "<section><h2>MITRE ATT&amp;CK techniques exercised</h2><table><thead><tr><th>Technique</th><th>Name</th><th>Via</th></tr></thead><tbody>");
    for (id, tools) in seen {
        let _ = write!(
            h,
            r#"<tr><td class="mono">{}</td><td>{}</td><td class="mono dim">{}</td></tr>"#,
            id,
            esc(mitre::name_for(id)),
            esc(&tools.join(", "))
        );
    }
    let _ = write!(h, "</tbody></table></section>");
}

fn topology(h: &mut String, eng: &Engagement) {
    if eng.hosts.is_empty() {
        return;
    }
    let _ = write!(h, "<section><h2>Hosts &amp; services</h2>");
    let mut ips: Vec<&String> = eng.hosts.keys().collect();
    ips.sort();
    for ip in ips {
        let host = &eng.hosts[ip];
        let names = if host.hostnames.is_empty() {
            String::new()
        } else {
            format!(
                " <span class=\"dim\">({})</span>",
                esc(&host.hostnames.join(", "))
            )
        };
        let owned = if host.compromised {
            r#" <span class="owned">OWNED</span>"#
        } else {
            ""
        };
        let dc = if host.is_dc() {
            r#" <span class="tag">DC</span>"#
        } else {
            ""
        };
        let _ = write!(
            h,
            r#"<div class="host"><h3 class="mono">{ip}{names}{owned}{dc}</h3>"#
        );
        if let Some(os) = &host.os {
            let _ = write!(h, r#"<p class="dim">{}</p>"#, esc(os));
        }
        let _ = write!(h, r#"<table class="ports"><tbody>"#);
        for s in host.open() {
            let _ = write!(
                h,
                r#"<tr><td class="mono">{}/{}</td><td class="mono">{}</td><td>{}</td></tr>"#,
                s.port,
                esc(&s.proto),
                esc(&s.name),
                esc(&s.banner())
            );
        }
        let _ = write!(h, "</tbody></table></div>");
    }
    let _ = write!(h, "</section>");
}

fn creds(h: &mut String, eng: &Engagement) {
    if eng.creds.is_empty() && !eng.domain.is_known() {
        return;
    }
    let _ = write!(h, "<section><h2>Identity &amp; credentials</h2>");
    if let Some(d) = &eng.domain.fqdn {
        let _ = write!(
            h,
            r#"<p><strong>Domain:</strong> <span class="mono">{}</span></p>"#,
            esc(d)
        );
    }
    if !eng.creds.is_empty() {
        let _ = write!(
            h,
            r#"<table><thead><tr><th>User</th><th>Secret</th><th>Kind</th><th>Source</th></tr></thead><tbody>"#
        );
        for c in &eng.creds {
            let secret = match &c.decoded {
                Some(dec) => format!("{} → <strong>{}</strong>", esc(&c.secret), esc(dec)),
                None => esc(&c.secret),
            };
            let _ = write!(
                h,
                r#"<tr><td class="mono">{}</td><td class="mono">{}</td><td>{}</td><td class="dim">{}</td></tr>"#,
                esc(&c.down_level()),
                secret,
                c.kind.label(),
                esc(&c.source)
            );
        }
        let _ = write!(h, "</tbody></table>");
    }
    let _ = write!(h, "</section>");
}

fn web(h: &mut String, eng: &Engagement) {
    if eng.web_paths.is_empty() {
        return;
    }
    let _ = write!(h, "<section><h2>Discovered web content</h2>");
    for (base, paths) in &eng.web_paths {
        let _ = write!(
            h,
            r#"<h3 class="mono">{} <span class="dim">({} paths)</span></h3><ul class="paths">"#,
            esc(base),
            paths.len()
        );
        for p in paths.iter().take(300) {
            let st = p
                .status
                .map(|c| format!(r#" <span class="code s{}">{}</span>"#, c / 100, c))
                .unwrap_or_default();
            let ti = p
                .title
                .as_deref()
                .map(|t| format!(r#" <span class="dim">— {}</span>"#, esc(t)))
                .unwrap_or_default();
            let _ = write!(h, r#"<li class="mono">{}{}{}</li>"#, esc(&p.path), st, ti);
        }
        let _ = write!(h, "</ul>");
    }
    let _ = write!(h, "</section>");
}

fn commands(h: &mut String, eng: &Engagement) {
    if eng.records.is_empty() {
        return;
    }
    let _ = write!(h, "<section><h2>Commands run</h2>");
    for phase in Phase::ALL {
        let recs = eng.records_for_phase(phase);
        if recs.is_empty() {
            continue;
        }
        let _ = write!(h, "<h3>{}</h3><ul class=\"cmds\">", phase.title());
        for r in recs {
            let star = if r.starred { "★ " } else { "" };
            let code = r
                .exit_code
                .map(|c| format!(" <span class=\"dim\">exit {c}</span>"))
                .unwrap_or_default();
            let _ = write!(
                h,
                r#"<li><code>{}{}</code>{}</li>"#,
                star,
                esc(&r.command),
                code
            );
        }
        let _ = write!(h, "</ul>");
    }
    let _ = write!(h, "</section>");
}

const HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__NAME__ — shrike report</title><style>
:root{--bg:#0e1015;--panel:#161922;--fg:#c8cdd7;--dim:#7a8090;--accent:#56b6c2;--line:#232838}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main,header{max-width:1000px;margin:0 auto;padding:0 24px}
header{padding-top:40px}h1{margin:0;color:#fff;font-size:30px}
.sub{color:var(--dim);margin:.2em 0 1.4em}
.stats{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:10px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 18px;min-width:96px}
.stat .n{display:block;font-size:24px;color:#fff;font-weight:600}.stat .k{color:var(--dim);font-size:13px}
section{margin:34px 0}h2{color:#fff;border-bottom:1px solid var(--line);padding-bottom:8px;font-size:21px}
h3{color:var(--accent);font-size:16px;margin:18px 0 8px}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:14px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.mono,code{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:13px}
.dim{color:var(--dim)}.host{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:12px 0}
.ports{margin:6px 0}.ports td{border:none;padding:3px 10px 3px 0}
.owned{background:#c678dd;color:#111;padding:1px 7px;border-radius:5px;font-size:11px;font-weight:700}
.tag{background:#e5c07b;color:#111;padding:1px 7px;border-radius:5px;font-size:11px;font-weight:700}
.sev{padding:2px 9px;border-radius:5px;font-size:11px;font-weight:700;color:#111}
.sev.critical{background:#e06c75}.sev.high{background:#e59572}.sev.medium{background:#e5c07b}
.sev.low{background:#56b6c2}.sev.info{background:#5c6370;color:#fff}
.paths{list-style:none;padding:0;margin:6px 0;columns:2;column-gap:24px}
.paths li{break-inside:avoid;padding:1px 0}.cmds{list-style:none;padding:0}
.cmds li{padding:3px 0;border-bottom:1px solid var(--line)}
.code{padding:0 6px;border-radius:4px;font-size:12px;font-weight:700}
.code.s2{background:#98c379;color:#111}.code.s3{background:#61afef;color:#111}
.code.s4{background:#e5c07b;color:#111}.code.s5{background:#e06c75;color:#111}
@media(max-width:640px){.paths{columns:1}}
</style></head><body>"#;

//! Markdown report generator. Groups executed commands by phase, and surfaces
//! the topology, credential and domain intel the operator accumulated.

pub mod html;
use crate::model::state::Engagement;
use crate::model::{Phase, Reach};
use std::fmt::Write;

pub fn render(eng: &Engagement) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# {} — engagement notes\n", eng.name);
    let _ = writeln!(s, "_generated {}_\n", crate::model::state::now_iso());
    let _ = writeln!(s, "{}\n", eng.summary());

    render_topology(&mut s, eng);
    render_findings(&mut s, eng);
    render_intel(&mut s, eng);
    render_web(&mut s, eng);
    render_commands(&mut s, eng);
    s
}

fn render_topology(s: &mut String, eng: &Engagement) {
    let _ = writeln!(s, "## Network topology & reachability\n");
    if eng.segments.is_empty() {
        let _ = writeln!(s, "_no hosts scanned yet_\n");
        return;
    }
    let mut segs: Vec<_> = eng.segments.values().collect();
    segs.sort_by_key(|seg| (seg.reach != Reach::Direct, seg.cidr.clone()));
    for seg in segs {
        let reach = match seg.reach {
            Reach::Direct => "DIRECT (routable from operator)",
            Reach::Pivot => "PIVOT REQUIRED",
            Reach::Unknown => "reachability unknown",
        };
        let _ = writeln!(s, "### `{}` — {} — {}", seg.cidr, seg.scope.label(), reach);
        if !seg.gateways.is_empty() {
            let _ = writeln!(s, "- gateway(s): {}", seg.gateways.join(", "));
        }
        if seg.reach == Reach::Pivot {
            match &seg.pivot_via {
                Some(via) => {
                    let _ = writeln!(
                        s,
                        "- pivot through **{via}** (compromised, bridges into this segment)"
                    );
                }
                None => {
                    let _ = writeln!(
                        s,
                        "- not routable — pivot through a host dual-homed into this segment"
                    );
                }
            }
        }
        let _ = writeln!(s);
        for ip in &seg.hosts {
            if let Some(h) = eng.hosts.get(ip) {
                let ports: Vec<String> = h.open().map(|p| p.port.to_string()).collect();
                let names = if h.hostnames.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", h.hostnames.join(","))
                };
                let flag = if h.compromised {
                    " **[OWNED]**"
                } else if h.is_dc() {
                    " _[DC]_"
                } else {
                    ""
                };
                let _ = writeln!(s, "- `{ip}`{names}{flag}: {}", ports.join(", "));
            }
        }
        let _ = writeln!(s);
    }
}

fn render_intel(s: &mut String, eng: &Engagement) {
    if !eng.domain.is_known() && eng.creds.is_empty() {
        return;
    }
    let _ = writeln!(s, "## Identity & credentials\n");
    if let Some(d) = &eng.domain.fqdn {
        let _ = writeln!(s, "- **Domain:** {d}");
    }
    if !eng.domain.dc_ips.is_empty() {
        let _ = writeln!(
            s,
            "- **DC(s):** {}",
            eng.domain
                .dc_ips
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !eng.domain.computers.is_empty() {
        let _ = writeln!(
            s,
            "- **Computers:** {}",
            eng.domain
                .computers
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !eng.domain.spns.is_empty() {
        let _ = writeln!(
            s,
            "- **Kerberoastable SPNs:** {}",
            eng.domain
                .spns
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let _ = writeln!(s);
    if !eng.creds.is_empty() {
        let _ = writeln!(s, "| user | secret | kind | source | validated |");
        let _ = writeln!(s, "|------|--------|------|--------|-----------|");
        for c in &eng.creds {
            let secret = match &c.decoded {
                Some(d) => format!("{} → **{}**", c.secret, d),
                None => c.secret.clone(),
            };
            let val = if c.admin_on.is_empty() {
                c.validated_on.join(",")
            } else {
                format!("admin@{}", c.admin_on.join(","))
            };
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {} |",
                c.down_level(),
                secret,
                c.kind.label(),
                c.source,
                val
            );
        }
        let _ = writeln!(s);
    }
}

fn render_findings(s: &mut String, eng: &Engagement) {
    if eng.findings.is_empty() {
        return;
    }
    let _ = writeln!(s, "## Findings\n");
    let _ = writeln!(s, "| sev | title | location | source | CVE |");
    let _ = writeln!(s, "|-----|-------|----------|--------|-----|");
    for f in &eng.findings {
        let _ = writeln!(
            s,
            "| **{}** | {} | {} | {} | {} |",
            f.severity.label().to_uppercase(),
            f.title,
            f.location
                .as_deref()
                .unwrap_or(f.host.as_deref().unwrap_or("")),
            f.source,
            f.cve.join(", ")
        );
    }
    let _ = writeln!(s);
}

fn render_web(s: &mut String, eng: &Engagement) {
    if eng.web_paths.is_empty() {
        return;
    }
    let _ = writeln!(s, "## Discovered web content\n");
    for (base, paths) in &eng.web_paths {
        let _ = writeln!(s, "### {base}  ({} paths)\n", paths.len());
        for p in paths.iter().take(200) {
            let st = p.status.map(|c| format!(" [{c}]")).unwrap_or_default();
            let ln = p.length.map(|l| format!(" {l}b")).unwrap_or_default();
            let ti = p
                .title
                .as_deref()
                .map(|t| format!(" — {t}"))
                .unwrap_or_default();
            let _ = writeln!(s, "- `{}`{}{}{}", p.path, st, ln, ti);
        }
        let _ = writeln!(s);
    }
}

fn render_commands(s: &mut String, eng: &Engagement) {
    let _ = writeln!(s, "## Commands by phase\n");
    for phase in Phase::ALL {
        let recs = eng.records_for_phase(phase);
        if recs.is_empty() {
            continue;
        }
        let _ = writeln!(s, "### {}\n", phase.title());
        for r in recs {
            let star = if r.starred { "⭐ " } else { "" };
            let code = r
                .exit_code
                .map(|c| format!(" (exit {c})"))
                .unwrap_or_default();
            let tgt = r
                .target
                .as_deref()
                .map(|t| format!(" · {t}"))
                .unwrap_or_default();
            let _ = writeln!(s, "- {star}`{}`{}{}", r.command, tgt, code);
            let _ = writeln!(s, "  <sub>output: `{}`</sub>", r.output_path);
            for f in &r.findings {
                let _ = writeln!(s, "  - 🔑 {f}");
            }
        }
        let _ = writeln!(s);
    }
}

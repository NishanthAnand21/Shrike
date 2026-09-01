//! Minimalist rendering, styled after the Claude Code terminal: a full-width
//! transcript, a rounded input box, a slash-command autocomplete popup, and a
//! subtle hint line. The dashboard panel is opt-in (/panel or Ctrl-G).

use super::app::{App, View};
use super::palette;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line as TLine, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

// A restrained palette: one accent (cyan), muted greys, semantic colors used sparingly.
const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;
const FAINT: Color = Color::Rgb(120, 120, 130);

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    // Vertical: header(1) · transcript(min) · hint(1) · input-box(3)
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(area);

    // Optionally split the transcript row to show the dashboard panel on the right.
    let body = rows[1];
    let (transcript_area, panel_area) = if app.show_panel {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(40), Constraint::Length(38)])
            .split(body);
        (cols[0], Some(cols[1]))
    } else {
        (body, None)
    };

    draw_header(f, app, rows[0]);
    match app.view {
        View::Console => draw_transcript(f, app, transcript_area),
        View::Hosts => draw_hosts_view(f, app, transcript_area),
        View::Findings => draw_findings_view(f, app, transcript_area),
        View::Creds => draw_creds_view(f, app, transcript_area),
        View::Web => draw_web_view(f, app, transcript_area),
        View::Loot => draw_loot_view(f, app, transcript_area),
    }
    if let Some(p) = panel_area {
        draw_panel(f, app, p);
    }
    draw_hint(f, app, rows[2]);
    draw_input(f, app, rows[3]);

    // Popups (drawn last, over everything).
    if app.menu_active() {
        draw_menu(f, app, rows[3]);
    }
    if app.show_help {
        draw_help(f, area);
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let active = app.live.len();
    let mut spans = vec![
        Span::styled(
            "  shrike",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ·  ", Style::default().fg(MUTED)),
        Span::styled(app.eng.summary(), Style::default().fg(FAINT)),
    ];
    if active > 0 {
        spans.push(Span::styled(
            format!("  ● {active} running"),
            Style::default().fg(Color::Yellow),
        ));
    }
    if let Some(p) = &app.eng.proxy {
        spans.push(Span::styled(
            format!("  ⇄ {p}"),
            Style::default().fg(Color::Magenta),
        ));
    }
    if app.live_sessions > 0 {
        spans.push(Span::styled(
            format!(
                "  ⇲ {} shell{}",
                app.live_sessions,
                if app.live_sessions == 1 { "" } else { "s" }
            ),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ));
    }
    // Right-aligned view tabs.
    let mut tabs = vec![Span::raw("  ")];
    for v in View::ALL {
        let active = v == app.view;
        let st = if active {
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(FAINT)
        };
        tabs.push(Span::styled(format!(" {} ", v.title()), st));
        tabs.push(Span::raw(" "));
    }
    let left = Paragraph::new(TLine::from(spans));
    let right = Paragraph::new(TLine::from(tabs)).alignment(ratatui::layout::Alignment::Right);
    f.render_widget(left, area);
    f.render_widget(right, area);
}

fn draw_transcript(f: &mut Frame, app: &App, area: Rect) {
    // No border — the transcript breathes edge to edge, like a chat log.
    let pad = Rect {
        x: area.x + 2,
        y: area.y,
        width: area.width.saturating_sub(3),
        height: area.height,
    };
    let height = pad.height as usize;
    let total = app.transcript.len();
    let end = total.saturating_sub(app.scroll as usize);
    let start = end.saturating_sub(height);
    let slice = &app.transcript[start..end];

    let lines: Vec<TLine> = slice
        .iter()
        .map(|l| {
            let prefix = if l.indent { "  " } else { "" };
            TLine::from(Span::styled(
                format!("{prefix}{}", l.text),
                Style::default().fg(l.color),
            ))
        })
        .collect();
    f.render_widget(Paragraph::new(lines), pad);
}

fn draw_hint(f: &mut Frame, app: &App, area: Rect) {
    let hint = if app.menu_active() {
        "↑↓ select · Tab complete · Enter run · Esc dismiss".to_string()
    } else if app.view == View::Hosts {
        "↑↓ select · Enter focus host · F1-F6 views · / for menu".to_string()
    } else if app.view != View::Console {
        "↑↓ scroll · F1-F6 switch views · / for menu · /help".to_string()
    } else if !app.follow {
        "PgUp/PgDn scroll · Ctrl-C cancel · /help".to_string()
    } else {
        let sug = app.suggestions.get(app.sel).map(|t| t.name).unwrap_or("");
        if sug.is_empty() {
            "type a command · / for menu · /help".to_string()
        } else {
            format!("Tab ⇥ run “{sug}” · / for menu · /suggest · /help")
        }
    };
    f.render_widget(
        Paragraph::new(TLine::from(Span::styled(
            format!("  {hint}"),
            Style::default().fg(FAINT),
        ))),
        area,
    );
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let focus_tag = app.focus.as_deref().unwrap_or("");
    let title = if focus_tag.is_empty() {
        " shrike ".to_string()
    } else {
        format!(" {focus_tag} ")
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if app.menu_active() { ACCENT } else { MUTED }))
        .title(Span::styled(title, Style::default().fg(ACCENT)));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let prompt = "❯ ";
    let line = TLine::from(vec![
        Span::styled(
            prompt,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::raw(app.input.clone()),
    ]);
    f.render_widget(Paragraph::new(line), inner);
    let x = inner.x + (prompt.chars().count() + app.cursor) as u16;
    f.set_cursor_position((x.min(inner.x + inner.width.saturating_sub(1)), inner.y));
}

/// The slash-command autocomplete popup, floating just above the input box.
fn draw_menu(f: &mut Frame, app: &App, input_area: Rect) {
    let comps = palette::completions(&app.input);
    if comps.is_empty() {
        return;
    }
    let rows = comps.len().min(8) as u16;
    let w = 88u16.min(input_area.width);
    let h = rows + 2;
    let rect = Rect {
        x: input_area.x,
        y: input_area.y.saturating_sub(h),
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT));
    let inner = block.inner(rect);
    f.render_widget(block, rect);

    let lines: Vec<TLine> = comps
        .iter()
        .take(8)
        .enumerate()
        .map(|(i, c)| {
            let sel = i == app.menu_sel.min(comps.len().saturating_sub(1));
            let base = if sel {
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let name = format!(" /{:<9}", c.name);
            let args = format!("{:<31}", c.args);
            TLine::from(vec![
                Span::styled(name, base),
                Span::styled(
                    args,
                    if sel {
                        base
                    } else {
                        Style::default().fg(FAINT)
                    },
                ),
                Span::styled(
                    c.desc.to_string(),
                    if sel {
                        base
                    } else {
                        Style::default().fg(MUTED)
                    },
                ),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

/// Opt-in dashboard: suggestions + focused-host context.
fn draw_panel(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    let title = match &app.phase_filter {
        Some(p) => format!(" next · {} ", p.slug()),
        None => " next steps ".to_string(),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(Style::default().fg(MUTED));
    let inner = block.inner(rows[0]);
    f.render_widget(block, rows[0]);
    let items: Vec<TLine> = app
        .suggestions
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let selected = i == app.sel;
            let avail = app.suggest_avail.get(i).copied().unwrap_or(true);
            let style = if selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else if !avail {
                Style::default().fg(MUTED)
            } else {
                Style::default().fg(phase_color(t.phase))
            };
            let mut spans = vec![
                Span::styled(if selected { "▸ " } else { "  " }, style),
                Span::styled(t.name.to_string(), style),
            ];
            if !avail {
                spans.push(Span::styled(" ·off", Style::default().fg(Color::Red)));
            }
            TLine::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(items).wrap(Wrap { trim: true }), inner);

    let block2 = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(" context ")
        .border_style(Style::default().fg(MUTED));
    let inner2 = block2.inner(rows[1]);
    f.render_widget(block2, rows[1]);
    f.render_widget(
        Paragraph::new(context_lines(app)).wrap(Wrap { trim: true }),
        inner2,
    );
}

fn context_lines(app: &App) -> Vec<TLine<'static>> {
    let mut out = vec![];
    match &app.focus {
        Some(ip) => {
            out.push(TLine::from(Span::styled(
                format!("host {ip}"),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )));
            if let Some(h) = app.eng.hosts.get(ip) {
                if let Some(os) = &h.os {
                    out.push(TLine::from(Span::styled(
                        os.clone(),
                        Style::default().fg(MUTED),
                    )));
                }
                let ports: Vec<String> =
                    h.open().map(|s| format!("{}/{}", s.port, s.name)).collect();
                for chunk in ports.chunks(2) {
                    out.push(TLine::from(Span::styled(
                        chunk.join("  "),
                        Style::default().fg(Color::White),
                    )));
                }
                if h.compromised {
                    out.push(TLine::from(Span::styled(
                        "OWNED",
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    )));
                }
            }
        }
        None => out.push(TLine::from(Span::styled(
            "no host focused",
            Style::default().fg(MUTED),
        ))),
    }
    if let Some(d) = &app.eng.domain.fqdn {
        out.push(TLine::from(""));
        out.push(TLine::from(Span::styled(
            format!("domain {d}"),
            Style::default().fg(Color::Yellow),
        )));
    }
    let ncreds = app.eng.creds.len();
    if ncreds > 0 {
        out.push(TLine::from(Span::styled(
            format!("{ncreds} credential(s)"),
            Style::default().fg(Color::Green),
        )));
    }
    out
}

fn draw_help(f: &mut Frame, area: Rect) {
    let w = 68u16.min(area.width.saturating_sub(4));
    let h = 26u16.min(area.height.saturating_sub(2));
    let rect = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Span::styled(" shrike · help ", Style::default().fg(ACCENT)))
        .border_style(Style::default().fg(ACCENT));
    let mut text = vec![hl("Keys")];
    for (k, v) in [
        ("Tab", "run highlighted suggestion / accept completion"),
        (
            "F1-F6 / Shift-Tab",
            "switch views (console/hosts/findings/creds/web/loot)",
        ),
        ("↑ ↓", "move selection (menu or suggestions)"),
        ("/", "open the command menu"),
        (
            "PgUp/PgDn",
            "scroll · Ctrl-C cancel jobs / quit · Ctrl-G panel",
        ),
    ] {
        text.push(row(k, v));
    }
    text.push(TLine::from(""));
    text.push(hl("Commands"));
    for c in palette::COMMANDS {
        text.push(row(&format!("/{} {}", c.name, c.args), c.desc));
    }
    f.render_widget(
        Paragraph::new(text).block(block).wrap(Wrap { trim: true }),
        rect,
    );
}

fn hl(s: &str) -> TLine<'static> {
    TLine::from(Span::styled(
        s.to_string(),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ))
}
fn row(k: &str, v: &str) -> TLine<'static> {
    TLine::from(vec![
        Span::styled(format!("  {k:30}"), Style::default().fg(ACCENT)),
        Span::styled(v.to_string(), Style::default().fg(Color::Gray)),
    ])
}

fn phase_color(p: crate::model::Phase) -> Color {
    use crate::model::Phase::*;
    match p {
        // Light variants throughout: plain Blue/Red are near-illegible on dark terminals.
        Discovery | PortScan | ServiceEnum => Color::LightBlue,
        WebEnum | DirEnum | ApiEnum | VulnScan => ACCENT,
        SmbEnum | AdEnum => Color::LightYellow,
        Exploit | CredAccess => Color::LightRed,
        Cracking => Color::LightMagenta,
        Pivot => Color::LightGreen,
        PostExploit | PrivEsc | Loot => Color::LightRed,
    }
}

// ───────────────────────────── full-screen dashboard views

fn view_frame<'a>(app: &App, area: Rect, f: &mut Frame, title: &str, rows: Vec<TLine<'a>>) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MUTED))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(ACCENT),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);
    // simple scroll: keep table_sel visible
    let h = inner.height as usize;
    let sel = app.table_sel.min(rows.len().saturating_sub(1));
    let start = sel.saturating_sub(h.saturating_sub(1));
    let slice: Vec<TLine> = rows.into_iter().skip(start).take(h).collect();
    f.render_widget(Paragraph::new(slice), inner);
}

fn sel_style(active: bool) -> Style {
    if active {
        Style::default()
            .fg(Color::Black)
            .bg(ACCENT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    }
}

fn draw_hosts_view(f: &mut Frame, app: &App, area: Rect) {
    let mut ips: Vec<&String> = app.eng.hosts.keys().collect();
    ips.sort_by_key(|ip| {
        ip.split('.')
            .filter_map(|o| o.parse::<u8>().ok())
            .collect::<Vec<_>>()
    });
    let mut rows = vec![];
    for (i, ip) in ips.iter().enumerate() {
        let h = &app.eng.hosts[*ip];
        let active = i == app.table_sel.min(ips.len().saturating_sub(1));
        let ports: Vec<String> = h.open().map(|s| s.port.to_string()).collect();
        let tags = {
            let mut t = String::new();
            if h.compromised {
                t.push_str(" OWNED");
            }
            if h.is_dc() {
                t.push_str(" DC");
            }
            t
        };
        let names = if h.hostnames.is_empty() {
            String::new()
        } else {
            format!(" ({})", h.hostnames.join(","))
        };
        rows.push(TLine::from(vec![
            Span::styled(format!(" {:<16}", ip), sel_style(active)),
            Span::styled(
                format!("{:<22}", truncate(&format!("{}{}", os_short(h), names), 22)),
                Style::default().fg(if active { Color::Black } else { FAINT }),
            ),
            Span::styled(
                truncate(&ports.join(","), 40),
                Style::default().fg(if active { Color::Black } else { Color::White }),
            ),
            Span::styled(tags, Style::default().fg(Color::Magenta)),
        ]));
    }
    if rows.is_empty() {
        rows.push(TLine::from(Span::styled(
            "  no hosts — /target <ip|cidr> or /run nmap-full",
            Style::default().fg(FAINT),
        )));
    }
    view_frame(
        app,
        area,
        f,
        &format!("hosts ({})  ·  ↑↓ select · Enter focus", ips.len()),
        rows,
    );
}

fn draw_findings_view(f: &mut Frame, app: &App, area: Rect) {
    let mut rows = vec![];
    for (i, fd) in app.eng.findings.iter().enumerate() {
        let active = i == app.table_sel.min(app.eng.findings.len().saturating_sub(1));
        let sevc = match fd.severity {
            crate::model::Severity::Critical => Color::Red,
            crate::model::Severity::High => Color::LightRed,
            crate::model::Severity::Medium => Color::Yellow,
            crate::model::Severity::Low => Color::Cyan,
            crate::model::Severity::Info => Color::DarkGray,
        };
        rows.push(TLine::from(vec![
            Span::styled(
                format!(" {:<9}", fd.severity.label().to_uppercase()),
                if active {
                    sel_style(true)
                } else {
                    Style::default().fg(sevc).add_modifier(Modifier::BOLD)
                },
            ),
            Span::styled(
                format!("{:<44}", truncate(&fd.title, 44)),
                Style::default().fg(if active { Color::Black } else { Color::White }),
            ),
            Span::styled(
                truncate(fd.location.as_deref().unwrap_or(""), 34),
                Style::default().fg(if active { Color::Black } else { FAINT }),
            ),
        ]));
    }
    if rows.is_empty() {
        rows.push(TLine::from(Span::styled(
            "  no findings yet — run nuclei, or /finding …",
            Style::default().fg(FAINT),
        )));
    }
    view_frame(
        app,
        area,
        f,
        &format!("findings ({})", app.eng.findings.len()),
        rows,
    );
}

fn draw_creds_view(f: &mut Frame, app: &App, area: Rect) {
    let mut rows = vec![];
    for (i, c) in app.eng.creds.iter().enumerate() {
        let active = i == app.table_sel.min(app.eng.creds.len().saturating_sub(1));
        let secret = match &c.decoded {
            Some(d) => format!("{} → {}", c.secret, d),
            None => c.secret.clone(),
        };
        rows.push(TLine::from(vec![
            Span::styled(
                format!(" {:<26}", truncate(&c.down_level(), 26)),
                sel_style(active),
            ),
            Span::styled(
                format!("{:<34}", truncate(&secret, 34)),
                Style::default().fg(if active { Color::Black } else { Color::Green }),
            ),
            Span::styled(
                format!("{:<10}", c.kind.label()),
                Style::default().fg(if active { Color::Black } else { FAINT }),
            ),
            Span::styled(
                truncate(&c.source, 24),
                Style::default().fg(if active { Color::Black } else { MUTED }),
            ),
        ]));
    }
    if rows.is_empty() {
        rows.push(TLine::from(Span::styled(
            "  no credentials — /cred user:secret or harvest from output",
            Style::default().fg(FAINT),
        )));
    }
    view_frame(
        app,
        area,
        f,
        &format!("credentials ({})", app.eng.creds.len()),
        rows,
    );
}

fn draw_web_view(f: &mut Frame, app: &App, area: Rect) {
    let mut rows = vec![];
    for (base, paths) in &app.eng.web_paths {
        rows.push(TLine::from(Span::styled(
            format!(" {}  ({} paths)", base, paths.len()),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )));
        for p in paths.iter().take(500) {
            let code = p.status.map(|c| format!("[{c}]")).unwrap_or_default();
            let cc = match p.status.map(|c| c / 100) {
                Some(2) => Color::Green,
                Some(3) => Color::Blue,
                Some(4) => Color::Yellow,
                Some(5) => Color::Red,
                _ => FAINT,
            };
            rows.push(TLine::from(vec![
                Span::styled(format!("   {:<6}", code), Style::default().fg(cc)),
                Span::styled(truncate(&p.path, 60), Style::default().fg(Color::White)),
                Span::styled(
                    p.title
                        .as_deref()
                        .map(|t| format!("  {}", truncate(t, 30)))
                        .unwrap_or_default(),
                    Style::default().fg(FAINT),
                ),
            ]));
        }
    }
    if rows.is_empty() {
        rows.push(TLine::from(Span::styled(
            "  no web content — run feroxbuster/ffuf/httpx/nuclei",
            Style::default().fg(FAINT),
        )));
    }
    view_frame(app, area, f, "web content", rows);
}

fn draw_loot_view(f: &mut Frame, app: &App, area: Rect) {
    let mut rows = vec![];
    for (i, l) in app.eng.loot.iter().enumerate() {
        let active = i == app.table_sel.min(app.eng.loot.len().saturating_sub(1));
        let sz = l.size.map(|n| format!("{n}b")).unwrap_or_default();
        rows.push(TLine::from(vec![
            Span::styled(
                format!(" {} {:<9}", l.kind.icon(), l.kind.label()),
                sel_style(active),
            ),
            Span::styled(
                format!("{:<40}", truncate(&l.path, 40)),
                Style::default().fg(if active { Color::Black } else { Color::White }),
            ),
            Span::styled(
                format!("{:<8}", sz),
                Style::default().fg(if active { Color::Black } else { FAINT }),
            ),
            Span::styled(
                truncate(&l.source, 20),
                Style::default().fg(if active { Color::Black } else { MUTED }),
            ),
        ]));
    }
    if rows.is_empty() {
        rows.push(TLine::from(Span::styled(
            "  no loot — /download, /vault or /payload populate it",
            Style::default().fg(FAINT),
        )));
    }
    view_frame(
        app,
        area,
        f,
        &format!("loot ({})", app.eng.loot.len()),
        rows,
    );
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!(
            "{}…",
            s.chars().take(n.saturating_sub(1)).collect::<String>()
        )
    }
}

fn os_short(h: &crate::model::Host) -> String {
    match &h.os {
        Some(os) => os.split_whitespace().take(2).collect::<Vec<_>>().join(" "),
        None => String::new(),
    }
}

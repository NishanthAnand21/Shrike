//! Rendering: transcript pane, suggestion sidebar, status bar, input line.

use super::app::App;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line as TLine, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(40), Constraint::Length(40)])
        .split(rows[0]);

    draw_transcript(f, app, cols[0]);
    draw_sidebar(f, app, cols[1]);
    draw_status(f, app, rows[1]);
    draw_input(f, app, rows[2]);

    if app.show_help {
        draw_help(f, area);
    }
}

fn draw_transcript(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::RIGHT).border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let height = inner.height as usize;
    let total = app.transcript.len();
    // scroll = lines up from the bottom.
    let end = total.saturating_sub(app.scroll as usize);
    let start = end.saturating_sub(height);
    let slice = &app.transcript[start..end];

    let lines: Vec<TLine> = slice.iter().map(|l| {
        let prefix = if l.indent { "  " } else { "" };
        TLine::from(Span::styled(format!("{prefix}{}", l.text), Style::default().fg(l.color)))
    }).collect();

    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_sidebar(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    // Suggestions
    let title = match &app.phase_filter {
        Some(p) => format!(" next · {} ", p.slug()),
        None => " next steps ".to_string(),
    };
    let block = Block::default().borders(Borders::ALL).title(title)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(rows[0]);
    f.render_widget(block, rows[0]);

    let items: Vec<TLine> = app.suggestions.iter().enumerate().map(|(i, t)| {
        let selected = i == app.sel;
        let marker = if selected { "▸ " } else { "  " };
        let style = if selected {
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(phase_color(t.phase))
        };
        TLine::from(vec![
            Span::styled(marker, style),
            Span::styled(t.name.to_string(), style),
            Span::styled(format!("  {}", t.speed.hint()), Style::default().fg(Color::DarkGray)),
        ])
    }).collect();
    f.render_widget(Paragraph::new(items).wrap(Wrap { trim: true }), inner);

    // Context (focused host / creds)
    let block2 = Block::default().borders(Borders::ALL).title(" context ")
        .border_style(Style::default().fg(Color::DarkGray));
    let inner2 = block2.inner(rows[1]);
    f.render_widget(block2, rows[1]);
    f.render_widget(Paragraph::new(context_lines(app)).wrap(Wrap { trim: true }), inner2);
}

fn context_lines(app: &App) -> Vec<TLine<'static>> {
    let mut out = vec![];
    match &app.focus {
        Some(ip) => {
            out.push(TLine::from(Span::styled(format!("host {ip}"), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
            if let Some(h) = app.eng.hosts.get(ip) {
                if let Some(os) = &h.os {
                    out.push(TLine::from(Span::styled(os.clone(), Style::default().fg(Color::DarkGray))));
                }
                let ports: Vec<String> = h.open().map(|s| format!("{}/{}", s.port, s.name)).collect();
                for chunk in ports.chunks(2) {
                    out.push(TLine::from(Span::styled(chunk.join("  "), Style::default().fg(Color::White))));
                }
                if h.compromised {
                    out.push(TLine::from(Span::styled("OWNED", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))));
                }
            }
        }
        None => out.push(TLine::from(Span::styled("no host focused", Style::default().fg(Color::DarkGray)))),
    }
    out.push(TLine::from(""));
    if let Some(d) = &app.eng.domain.fqdn {
        out.push(TLine::from(Span::styled(format!("domain {d}"), Style::default().fg(Color::Yellow))));
    }
    let ncreds = app.eng.creds.len();
    if ncreds > 0 {
        out.push(TLine::from(Span::styled(format!("{ncreds} credential(s):"), Style::default().fg(Color::Green))));
        for c in app.eng.creds.iter().take(4) {
            out.push(TLine::from(Span::styled(format!("  {}", c.down_level()), Style::default().fg(Color::Green))));
        }
    }
    out
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let active = app.live.len();
    let mut spans = vec![
        Span::styled(format!(" {} ", app.eng.name), Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(app.eng.summary(), Style::default().fg(Color::Gray)),
    ];
    if active > 0 {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(format!("● {active} running"), Style::default().fg(Color::Yellow)));
    }
    if let Some(p) = &app.eng.proxy {
        spans.push(Span::styled(format!("  ⇄ {p}"), Style::default().fg(Color::Magenta)));
    }
    if !app.follow {
        spans.push(Span::styled("  [scrolled]", Style::default().fg(Color::DarkGray)));
    }
    f.render_widget(Paragraph::new(TLine::from(spans)), area);
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let prompt = match &app.focus {
        Some(ip) => format!("{ip} ❯ "),
        None => "warden ❯ ".to_string(),
    };
    let line = TLine::from(vec![
        Span::styled(prompt.clone(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(app.input.clone()),
    ]);
    f.render_widget(Paragraph::new(line), area);
    let x = area.x + (prompt.chars().count() + app.cursor) as u16;
    f.set_cursor_position((x.min(area.x + area.width.saturating_sub(1)), area.y));
}

fn draw_help(f: &mut Frame, area: Rect) {
    let w = 66u16.min(area.width.saturating_sub(4));
    let h = 22u16.min(area.height.saturating_sub(2));
    let rect = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w, height: h,
    };
    f.render_widget(Clear, rect);
    let block = Block::default().borders(Borders::ALL).title(" warden · help ")
        .border_style(Style::default().fg(Color::Cyan));
    let text = vec![
        hl("Input"), row("<text>", "run suggestion / raw command"),
        row("Tab", "run the highlighted suggestion"),
        row("↑ ↓", "move suggestion selection"),
        row("PgUp/PgDn", "scroll transcript · Ctrl-C cancel jobs / quit"),
        TLine::from(""), hl("Commands"),
        row("/target <ip|cidr|file>", "add targets to scope"),
        row("/import <nmap.xml>", "ingest an nmap -oX scan"),
        row("/focus <ip>", "set the current host context"),
        row("/run <tool-id>", "run a specific catalog tool"),
        row("/raw <cmd>", "run an arbitrary shell command"),
        row("/cred [dom/]user:secret", "add a credential (hash or password)"),
        row("/harvest <file|text>", "scrape creds/intel from output"),
        row("/set proxy|iface|domain|dc|<wl>", "set engagement variables"),
        row("/suggest", "recompute next-step suggestions"),
        row("/phase <name>", "filter suggestions to a phase"),
        row("/export", "write notes.md now · /star  mark last cmd"),
        row("/quit", "save and exit"),
    ];
    f.render_widget(Paragraph::new(text).block(block).wrap(Wrap { trim: true }), rect);
}

fn hl(s: &str) -> TLine<'static> {
    TLine::from(Span::styled(s.to_string(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
}
fn row(k: &str, v: &str) -> TLine<'static> {
    TLine::from(vec![
        Span::styled(format!("  {k:24}"), Style::default().fg(Color::Cyan)),
        Span::styled(v.to_string(), Style::default().fg(Color::Gray)),
    ])
}

fn phase_color(p: crate::model::Phase) -> Color {
    use crate::model::Phase::*;
    match p {
        Discovery | PortScan | ServiceEnum => Color::Blue,
        WebEnum | DirEnum | ApiEnum | VulnScan => Color::Cyan,
        SmbEnum | AdEnum => Color::Yellow,
        Exploit | CredAccess => Color::Red,
        Cracking => Color::Magenta,
        Pivot => Color::Green,
        PostExploit | PrivEsc | Loot => Color::LightRed,
    }
}

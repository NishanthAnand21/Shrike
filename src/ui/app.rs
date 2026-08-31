//! The interactive application: state, the async event loop, and action dispatch.

use super::palette::{self, Action};
use crate::catalog::{self, Ctx};
use crate::engine::session::{self, Registry, SessionEvent, SessionId};
use crate::engine::{Job, JobEvent, JobStatus, Runner, Workspace};
use crate::model::state::{now_iso, Engagement, Record};
use crate::model::{Credential, Phase, SecretKind};
use crate::parse;
use crate::payload::{self, transform};

use anyhow::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyModifiers};
use futures::StreamExt;
use ratatui::style::Color;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

/// A styled line in the scrolling transcript.
#[derive(Clone)]
pub struct Line {
    pub text: String,
    pub color: Color,
    /// Job id this line belongs to, for live-updating output.
    pub job: Option<u64>,
    pub indent: bool,
}

impl Line {
    pub fn plain(t: impl Into<String>) -> Self {
        Line {
            text: t.into(),
            color: Color::Gray,
            job: None,
            indent: false,
        }
    }
    pub fn c(t: impl Into<String>, c: Color) -> Self {
        Line {
            text: t.into(),
            color: c,
            job: None,
            indent: false,
        }
    }
    pub fn out(t: impl Into<String>, job: u64) -> Self {
        Line {
            text: t.into(),
            color: Color::White,
            job: Some(job),
            indent: true,
        }
    }
}

/// Which full-screen view is active. Tab cycles them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Console,
    Hosts,
    Findings,
    Creds,
    Web,
}

impl View {
    pub const ALL: [View; 5] = [
        View::Console,
        View::Hosts,
        View::Findings,
        View::Creds,
        View::Web,
    ];
    pub fn title(self) -> &'static str {
        match self {
            View::Console => "console",
            View::Hosts => "hosts",
            View::Findings => "findings",
            View::Creds => "creds",
            View::Web => "web",
        }
    }
    pub fn next(self) -> View {
        let i = View::ALL.iter().position(|v| *v == self).unwrap_or(0);
        View::ALL[(i + 1) % View::ALL.len()]
    }
    pub fn prev(self) -> View {
        let i = View::ALL.iter().position(|v| *v == self).unwrap_or(0);
        View::ALL[(i + View::ALL.len() - 1) % View::ALL.len()]
    }
}

/// Live bookkeeping for an in-flight job.
pub struct Live {
    pub tool: String,
    pub phase: Phase,
    pub target: Option<String>,
    pub command: String,
    pub status: JobStatus,
    pub lines: Vec<String>,
    pub output_file: std::path::PathBuf,
    pub artifact: Option<std::path::PathBuf>,
    pub record_id: Option<u64>,
}

pub struct App {
    pub ws: Workspace,
    pub eng: Engagement,
    pub runner: Runner,
    pub rx: mpsc::UnboundedReceiver<JobEvent>,

    pub transcript: Vec<Line>,
    pub input: String,
    pub cursor: usize,
    pub scroll: u16,           // lines scrolled up from the bottom
    pub follow: bool,          // auto-scroll to newest
    pub focus: Option<String>, // current host IP context
    pub phase_filter: Option<Phase>,
    pub live: HashMap<u64, Live>,
    pub suggestions: Vec<&'static catalog::Tool>,
    /// Parallel to `suggestions`: is each tool's binary installed?
    pub suggest_avail: Vec<bool>,
    pub sel: usize, // selected suggestion
    pub show_help: bool,
    pub show_panel: bool,
    pub menu_sel: usize,
    pub view: View,
    pub table_sel: usize,
    pub should_quit: bool,
    pub last_record: Option<u64>,
    pub pending_shell: Option<String>,
    pub registry: Arc<Mutex<Registry>>,
    pub sess_rx: mpsc::UnboundedReceiver<SessionEvent>,
    pub sess_tx: mpsc::UnboundedSender<SessionEvent>,
    /// Set to request an interactive bridge with a caught session.
    pub pending_interact: Option<SessionId>,
    pub live_sessions: usize,
    pub live_listeners: usize,
}

pub async fn run(ws: Workspace, eng: Engagement, parallel: usize) -> Result<()> {
    let (tx, rx) = mpsc::unbounded_channel();
    let (sess_tx, sess_rx) = mpsc::unbounded_channel();
    let runner = Runner::new(parallel, tx);
    let mut app = App {
        ws,
        eng,
        runner,
        rx,
        transcript: vec![],
        input: String::new(),
        cursor: 0,
        scroll: 0,
        follow: true,
        focus: None,
        phase_filter: None,
        live: HashMap::new(),
        suggestions: vec![],
        suggest_avail: vec![],
        sel: 0,
        show_help: false,
        show_panel: false,
        menu_sel: 0,
        view: View::Console,
        table_sel: 0,
        should_quit: false,
        last_record: None,
        pending_shell: None,
        registry: Arc::new(Mutex::new(Registry::default())),
        sess_rx,
        sess_tx,
        pending_interact: None,
        live_sessions: 0,
        live_listeners: 0,
    };
    app.banner();
    app.refresh_suggestions();

    let mut term = ratatui::init();
    let res = app.event_loop(&mut term).await;
    ratatui::restore();
    // Best-effort final save.
    let _ = app.ws.save(&app.eng);
    let _ = app.ws.export_notes(&app.eng);
    res
}

impl App {
    fn banner(&mut self) {
        self.transcript.push(Line::c(
            "✳ shrike — recon-to-exploitation orchestrator",
            Color::Cyan,
        ));
        self.transcript
            .push(Line::plain(format!("  {}", self.ws.root.display())));
        self.transcript.push(Line::plain(""));
    }

    async fn event_loop(&mut self, term: &mut ratatui::DefaultTerminal) -> Result<()> {
        // Outer loop lets us drop and recreate the EventStream around an interactive
        // handoff — a live stream would otherwise steal the child's keystrokes.
        loop {
            let mut events = EventStream::new();
            loop {
                term.draw(|f| super::render::draw(f, self))?;
                if self.should_quit {
                    return Ok(());
                }
                if self.pending_shell.is_some() || self.pending_interact.is_some() {
                    break; // leave inner loop to run a handoff with the stream dropped
                }
                tokio::select! {
                    maybe_ev = events.next() => {
                        match maybe_ev {
                            Some(Ok(Event::Key(k))) => self.on_key(k).await,
                            Some(Ok(_)) => {}
                            Some(Err(_)) | None => return Ok(()),
                        }
                    }
                    Some(job_ev) = self.rx.recv() => self.on_job_event(job_ev),
                    Some(se) = self.sess_rx.recv() => self.on_session_event(se).await,
                }
            }
            drop(events);
            if let Some(cmd) = self.pending_shell.take() {
                self.run_interactive(term, &cmd);
            }
            if let Some(id) = self.pending_interact.take() {
                self.run_session_interact(term, id).await;
            }
        }
    }

    /// Suspend the TUI, run an interactive TTY child with inherited stdio, then
    /// cleanly re-enter the TUI (research/SESSIONS.md).
    fn run_interactive(&mut self, term: &mut ratatui::DefaultTerminal, cmd: &str) {
        use crossterm::{
            cursor::Show,
            execute,
            terminal::{
                disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
            },
        };
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        // Suspend: leave alternate screen, show cursor, disable raw mode.
        let mut out = std::io::stdout();
        let _ = disable_raw_mode();
        let _ = execute!(out, LeaveAlternateScreen, Show);
        let _ = writeln!(
            out,
            "\n\x1b[36m── shrike: interactive session ──\x1b[0m\n$ {cmd}\n"
        );
        let _ = out.flush();

        // Run the child on the terminal, blocking the async runtime deliberately.
        let status = tokio::task::block_in_place(|| {
            Command::new("/bin/sh")
                .arg("-c")
                .arg(cmd)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
        });

        let _ = writeln!(
            out,
            "\n\x1b[36m── session ended — press any key to return ──\x1b[0m"
        );
        let _ = out.flush();
        // Wait for a keypress so the operator can read final output before redraw.
        let _ = enable_raw_mode();
        let _ = crossterm::event::read();

        // Resume: re-enter alternate screen, raw mode, force a full redraw.
        let _ = execute!(out, EnterAlternateScreen);
        let _ = term.clear();

        match status {
            Ok(s) => self.push(Line::c(
                format!("interactive session exited ({s})"),
                Color::Cyan,
            )),
            Err(e) => self.push(Line::c(format!("! could not launch: {e}"), Color::Red)),
        }
    }

    async fn start_listener(&mut self, spec: &str) {
        let port: u16 = match spec.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                self.push(Line::c("usage: /listen <port>", Color::Yellow));
                return;
            }
        };
        session::listen(self.registry.clone(), self.sess_tx.clone(), port).await;
    }

    async fn list_sessions(&mut self) {
        let reg = self.registry.lock().await;
        let mut lines = vec![];
        if reg.listeners.is_empty() && reg.sessions.is_empty() {
            lines.push((
                "no listeners or sessions — /listen <port>".to_string(),
                Color::Yellow,
            ));
        }
        for l in reg.listeners.values() {
            lines.push((
                format!("  listener #{} on :{}", l.id, l.port),
                Color::Magenta,
            ));
        }
        for s in reg.sessions.values() {
            let st = if s.alive { "live" } else { "dead" };
            lines.push((
                format!(
                    "  session #{} {} from {} ({})",
                    s.id, st, s.peer, s.connected
                ),
                if s.alive {
                    Color::Green
                } else {
                    Color::DarkGray
                },
            ));
        }
        drop(reg);
        for (t, c) in lines {
            self.push(Line::c(t, c));
        }
    }

    async fn send_to_session(&mut self, spec: &str) {
        let (id_s, cmd) = match spec.trim().split_once(char::is_whitespace) {
            Some(v) => v,
            None => {
                self.push(Line::c("usage: /send <id> <command>", Color::Yellow));
                return;
            }
        };
        let Ok(id) = id_s.parse::<u64>() else {
            self.push(Line::c("usage: /send <id> <command>", Color::Yellow));
            return;
        };
        let ok = {
            let reg = self.registry.lock().await;
            match reg.sessions.get(&id) {
                Some(s) if s.alive => {
                    s.send_cmd(cmd);
                    true
                }
                _ => false,
            }
        };
        if !ok {
            self.push(Line::c(format!("no live session #{id}"), Color::Yellow));
        }
    }

    async fn kill_session(&mut self, spec: &str) {
        let Ok(id) = spec.trim().parse::<u64>() else {
            self.push(Line::c("usage: /kill <id>", Color::Yellow));
            return;
        };
        let msg = {
            let reg = self.registry.lock().await;
            if let Some(s) = reg.sessions.get(&id) {
                s.kill();
                format!("killed session #{id}")
            } else if let Some(l) = reg.listeners.get(&id) {
                l.cancel.cancel();
                format!("stopped listener #{id}")
            } else {
                format!("no session/listener #{id}")
            }
        };
        self.push(Line::c(msg, Color::Yellow));
    }

    async fn on_session_event(&mut self, ev: SessionEvent) {
        match ev {
            SessionEvent::Listening { id, port } => {
                self.push(Line::c(
                    format!("● listener #{id} up on 0.0.0.0:{port}"),
                    Color::Magenta,
                ));
            }
            SessionEvent::ListenError { id, error } => {
                self.registry.lock().await.listeners.remove(&id);
                self.push(Line::c(format!("✗ listener #{id}: {error}"), Color::Red));
            }
            SessionEvent::Connected { id, peer } => {
                self.push(Line::c(
                    format!("★ shell #{id} from {peer} — /interact {id} to attach",),
                    Color::Green,
                ));
            }
            SessionEvent::Output { id, text } => {
                for line in text.lines() {
                    self.push(Line::out(format!("[{id}] {line}"), id));
                }
            }
            SessionEvent::Closed { id, reason } => {
                {
                    let mut reg = self.registry.lock().await;
                    if let Some(s) = reg.sessions.get_mut(&id) {
                        s.alive = false;
                    }
                }
                self.push(Line::c(
                    format!("⊘ shell #{id} closed ({reason})"),
                    Color::Yellow,
                ));
            }
        }
    }

    /// Suspend the TUI and bridge the real terminal to a caught session until Ctrl-].
    async fn run_session_interact(&mut self, term: &mut ratatui::DefaultTerminal, id: SessionId) {
        use crossterm::{
            cursor::Show,
            execute,
            terminal::{disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
        };
        use std::io::Write as _;

        let done_rx = match session::request_interact(&self.registry, id).await {
            Some(rx) => rx,
            None => {
                self.push(Line::c(format!("no live session #{id}"), Color::Yellow));
                return;
            }
        };

        let mut out = std::io::stdout();
        let _ = disable_raw_mode();
        let _ = execute!(out, LeaveAlternateScreen, Show);
        let _ = writeln!(
            out,
            "\n\x1b[35m── shrike: interactive session #{id} — press Ctrl-] to detach ──\x1b[0m\n"
        );
        let _ = out.flush();

        // The pump task now owns stdin in raw mode; wait until it detaches/closes.
        let _ = done_rx.await;

        let _ = execute!(out, EnterAlternateScreen);
        let _ = crossterm::terminal::enable_raw_mode();
        let _ = term.clear();
        self.push(Line::c(format!("detached from session #{id}"), Color::Cyan));
    }

    async fn on_key(&mut self, k: KeyEvent) {
        use KeyCode::*;
        if k.modifiers.contains(KeyModifiers::CONTROL) {
            match k.code {
                Char('c') => {
                    if self.runner.active().await > 0 {
                        self.runner.cancel_all().await;
                        self.push(Line::c("^C — cancelling running jobs", Color::Yellow));
                    } else {
                        self.should_quit = true;
                    }
                    return;
                }
                Char('u') => {
                    self.input.clear();
                    self.cursor = 0;
                    return;
                }
                Char('g') => {
                    self.show_panel = !self.show_panel;
                    return;
                }
                _ => {}
            }
        }
        match k.code {
            F(n) if (1..=5).contains(&n) => {
                self.view = View::ALL[(n - 1) as usize];
                self.table_sel = 0;
            }
            BackTab => {
                self.view = self.view.prev();
                self.table_sel = 0;
            }
            Enter => {
                if self.input.is_empty() && self.view == View::Hosts {
                    self.focus_selected_host();
                } else {
                    let line = std::mem::take(&mut self.input);
                    self.cursor = 0;
                    self.show_help = false;
                    self.dispatch(&line).await;
                }
            }
            Tab => {
                if self.menu_active() {
                    self.accept_completion();
                } else {
                    self.run_selected().await;
                }
            }
            Up => {
                if self.menu_active() {
                    if self.menu_sel > 0 {
                        self.menu_sel -= 1;
                    }
                } else if self.view != View::Console {
                    self.table_sel = self.table_sel.saturating_sub(1);
                } else if self.sel > 0 {
                    self.sel -= 1;
                }
            }
            Down => {
                if self.menu_active() {
                    let n = self.completions_len();
                    if self.menu_sel + 1 < n {
                        self.menu_sel += 1;
                    }
                } else if self.view != View::Console {
                    self.table_sel = self.table_sel.saturating_add(1);
                } else if self.sel + 1 < self.suggestions.len() {
                    self.sel += 1;
                }
            }
            PageUp => {
                self.follow = false;
                self.scroll = self.scroll.saturating_add(10);
            }
            PageDown => {
                self.scroll = self.scroll.saturating_sub(10);
                if self.scroll == 0 {
                    self.follow = true;
                }
            }
            Esc => {
                self.input.clear();
                self.cursor = 0;
                self.show_help = false;
            }
            Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.input.remove(self.cursor);
                    self.menu_sel = 0;
                }
            }
            Left => {
                self.cursor = self.cursor.saturating_sub(1);
            }
            Right => {
                if self.cursor < self.input.len() {
                    self.cursor += 1;
                }
            }
            Home => self.cursor = 0,
            End => self.cursor = self.input.len(),
            Char(c) => {
                self.input.insert(self.cursor, c);
                self.cursor += 1;
                self.menu_sel = 0;
            }
            _ => {}
        }
    }

    fn on_job_event(&mut self, ev: JobEvent) {
        match ev {
            JobEvent::Started { id } => {
                if let Some(l) = self.live.get_mut(&id) {
                    l.status = JobStatus::Running;
                }
            }
            JobEvent::Line { id, text } => {
                if let Some(l) = self.live.get_mut(&id) {
                    l.lines.push(text.clone());
                }
                self.push(Line::out(text, id));
            }
            JobEvent::Finished {
                id,
                status,
                duration_ms,
            } => {
                self.finish_job(id, status, duration_ms);
            }
        }
    }

    fn finish_job(&mut self, id: u64, status: JobStatus, duration_ms: u64) {
        let Some(live) = self.live.remove(&id) else {
            return;
        };
        let color = match status {
            JobStatus::Done(0) => Color::Green,
            JobStatus::Cancelled => Color::Yellow,
            _ => Color::Red,
        };
        self.push(Line::c(
            format!(
                "{} {} [{}] {}ms",
                status.symbol(),
                live.tool,
                live.command,
                duration_ms
            ),
            color,
        ));

        // Record it.
        let exit = match status {
            JobStatus::Done(c) => Some(c),
            _ => None,
        };
        let excerpt: Vec<String> = live.lines.iter().take(40).cloned().collect();
        let rec = Record {
            id,
            phase: live.phase,
            tool: live.tool.clone(),
            target: live.target.clone(),
            command: live.command.clone(),
            exit_code: exit,
            started: now_iso(),
            duration_ms: Some(duration_ms),
            output_path: self.ws.rel(&live.output_file),
            excerpt,
            findings: vec![],
            starred: false,
        };
        self.eng.records.push(rec);
        self.eng.next_record_id = self.eng.next_record_id.max(id + 1);
        let rid = id;
        self.last_record = Some(rid);

        // Auto-ingest results.
        let blob = live.lines.join("\n");
        self.ingest(&live, &blob, rid);

        let _ = self.ws.save(&self.eng);
        let _ = self.ws.export_notes(&self.eng);
        self.refresh_suggestions();
    }

    /// Feed a finished job's output back into engagement state.
    fn ingest(&mut self, live: &Live, blob: &str, rid: u64) {
        // nmap writes its XML to the -oX artifact; fall back to the stdout capture.
        if live.tool.starts_with("nmap") || live.command.contains("-oX") {
            let xml_path = live
                .artifact
                .clone()
                .unwrap_or_else(|| live.output_file.clone());
            if let Ok(xml) = std::fs::read_to_string(&xml_path) {
                if xml.contains("<nmaprun") {
                    if let Ok(n) = parse::intel::ingest_nmap(&mut self.eng, &xml) {
                        self.push(Line::c(
                            format!("  ⇒ ingested {n} hosts from nmap XML"),
                            Color::Cyan,
                        ));
                    }
                }
            }
        }
        // Structured web-tool output → findings + discovered paths.
        self.ingest_webtools(live);
        // Credential/intel harvest from any output.
        let before = self.eng.creds.len();
        let added = parse::intel::harvest(
            &mut self.eng,
            blob,
            &format!(
                "{} on {}",
                live.tool,
                live.target.as_deref().unwrap_or("network")
            ),
        );
        parse::intel::enrich_from_hosts(&mut self.eng);
        if added > 0 {
            self.push(Line::c(
                format!("  ⇒ recovered {added} credential(s)"),
                Color::Green,
            ));
            let newlines: Vec<String> = self
                .eng
                .creds
                .iter()
                .skip(before)
                .map(|c| {
                    let extra = c
                        .decoded
                        .as_ref()
                        .map(|d| format!(" (decoded: {d})"))
                        .unwrap_or_default();
                    format!("     {} : {}{}", c.down_level(), c.secret, extra)
                })
                .collect();
            for nl in newlines {
                self.push(Line::c(nl, Color::Green));
            }
        }
        // Note (Pwn3d!) style admin markers.
        if blob.contains("Pwn3d!") {
            if let Some(t) = &live.target {
                self.eng.host_mut(t).compromised = true;
                self.push(Line::c(
                    format!("  ⇒ {t} marked OWNED (admin access)"),
                    Color::Magenta,
                ));
            }
        }
        if let Some(r) = self.eng.records.iter_mut().find(|r| r.id == rid) {
            if added > 0 {
                r.findings.push(format!("{added} credential(s) recovered"));
            }
        }
        self.eng.recompute_segments();
    }

    /// Ingest structured web-tool output (nuclei/httpx/ffuf/feroxbuster) from a job's
    /// artifact (or stdout capture) into findings and discovered web paths.
    fn ingest_webtools(&mut self, live: &Live) {
        use crate::parse::webtools;
        // Prefer the artifact file (where -o/-json wrote); fall back to stdout.
        let read = |p: &std::path::Path| std::fs::read_to_string(p).ok();
        let text = live
            .artifact
            .as_deref()
            .and_then(read)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| live.lines.join("\n"));
        if text.trim().is_empty() {
            return;
        }
        let t = live.tool.as_str();
        let ing = if t.starts_with("nuclei") {
            webtools::ingest_nuclei(&mut self.eng, &text)
        } else if t.starts_with("httpx") {
            webtools::ingest_httpx(&mut self.eng, &text)
        } else if t.starts_with("ffuf") {
            webtools::ingest_ffuf(&mut self.eng, &text)
        } else if t.starts_with("feroxbuster") || t.starts_with("ferox") {
            webtools::ingest_feroxbuster(&mut self.eng, &text)
        } else if t.starts_with("subfinder")
            || t.starts_with("dnsx")
            || t.starts_with("assetfinder")
        {
            let subs = webtools::ingest_subdomains(&mut self.eng, &text);
            if subs > 0 {
                self.push(Line::c(format!("  ⇒ {subs} subdomain(s)"), Color::Cyan));
            }
            return;
        } else {
            return;
        };
        if ing.any() {
            let mut bits = vec![];
            if ing.findings > 0 {
                bits.push(format!("{} finding(s)", ing.findings));
            }
            if ing.paths > 0 {
                bits.push(format!("{} web path(s)", ing.paths));
            }
            self.push(Line::c(format!("  ⇒ {}", bits.join(", ")), Color::Cyan));
        }
    }

    async fn dispatch(&mut self, line: &str) {
        let action = palette::parse(line);
        match action {
            Action::Quit => self.should_quit = true,
            Action::Help => self.show_help = true,
            Action::Suggest => {
                self.refresh_suggestions();
                self.print_suggestions();
            }
            Action::Guide => self.print_guidance(),
            Action::RunTool(id) => self.run_tool_by_id(&id).await,
            Action::RunRaw(cmd) => self.run_raw(&cmd).await,
            Action::Focus(ip) => self.set_focus(&ip),
            Action::AddTarget(t) => match seed_target(&mut self.eng, &t) {
                Ok(_) => {
                    self.eng.recompute_segments();
                    self.push(Line::c(format!("+ target {t}"), Color::Cyan));
                    self.refresh_suggestions();
                }
                Err(e) => self.push(Line::c(format!("! {e}"), Color::Red)),
            },
            Action::Import(path) => self.import(&path),
            Action::AddCred(spec) => self.add_cred(&spec),
            Action::Harvest(arg) => self.harvest(&arg),
            Action::Set(k, v) => self.set_var(&k, &v),
            Action::Cancel(id) => match id {
                Some(i) => self.runner.cancel(i).await,
                None => self.runner.cancel_all().await,
            },
            Action::Export => match self.ws.export_notes(&self.eng) {
                Ok(p) => self.push(Line::c(format!("notes → {}", p.display()), Color::Cyan)),
                Err(e) => self.push(Line::c(format!("! {e}"), Color::Red)),
            },
            Action::Star => self.star_last(),
            Action::Phase(p) => self.set_phase_filter(p),
            Action::TogglePanel => {
                self.show_panel = !self.show_panel;
            }
            Action::Auto(spec) => self.auto_run(&spec).await,
            Action::AddFinding(spec) => self.add_finding_cmd(&spec),
            Action::History => self.show_history(),
            Action::Rerun(id) => self.rerun(&id).await,
            Action::Html => match self.ws.export_html(&self.eng) {
                Ok(p) => self.push(Line::c(format!("report → {}", p.display()), Color::Cyan)),
                Err(e) => self.push(Line::c(format!("! {e}"), Color::Red)),
            },
            Action::Shell(cmd) => {
                if cmd.trim().is_empty() {
                    self.push(Line::c(
                        "usage: /shell <interactive command>",
                        Color::Yellow,
                    ));
                } else {
                    self.pending_shell = Some(cmd);
                }
            }
            Action::Listen(spec) => self.start_listener(&spec).await,
            Action::Sessions => self.list_sessions().await,
            Action::SendCmd(spec) => self.send_to_session(&spec).await,
            Action::Interact(spec) => match spec.trim().parse::<u64>() {
                Ok(id) => self.pending_interact = Some(id),
                Err(_) => self.push(Line::c(
                    "usage: /interact <session-id>  (see /sessions)",
                    Color::Yellow,
                )),
            },
            Action::KillSession(spec) => self.kill_session(&spec).await,
            Action::ViewCmd(name) => {
                let v = match name.trim().to_ascii_lowercase().as_str() {
                    "console" | "log" => Some(View::Console),
                    "hosts" | "host" => Some(View::Hosts),
                    "findings" | "finding" | "vulns" => Some(View::Findings),
                    "creds" | "credentials" => Some(View::Creds),
                    "web" | "paths" => Some(View::Web),
                    _ => None,
                };
                match v {
                    Some(v) => {
                        self.view = v;
                        self.table_sel = 0;
                    }
                    None => self.push(Line::c(
                        "views: console hosts findings creds web  (or F1-F5)",
                        Color::Yellow,
                    )),
                }
            }
            Action::Payload(spec) => self.gen_payload(&spec),
            Action::Msf(spec) => self.gen_msf(&spec),
            Action::Payloads(filter) => self.list_payloads(&filter),
            Action::Unknown(c) => self.push(Line::c(
                format!("? unknown command /{c} — try /help"),
                Color::Yellow,
            )),
        }
        let _ = self.ws.save(&self.eng);
    }

    async fn run_selected(&mut self) {
        if let Some(tool) = self.suggestions.get(self.sel).copied() {
            self.run_tool(tool).await;
        }
    }

    async fn run_tool_by_id(&mut self, id: &str) {
        match catalog::by_id(id) {
            Some(t) => self.run_tool(t).await,
            None => self.push(Line::c(
                format!("? no tool '{id}' — /suggest to list"),
                Color::Yellow,
            )),
        }
    }

    async fn run_tool(&mut self, tool: &'static catalog::Tool) {
        // Pre-flight: don't build a command for a tool that isn't installed.
        if !catalog::is_available(tool) {
            self.push(Line::c(
                format!(
                    "✗ {} not found on PATH (looked for: {}) — install it (see docs/INSTALL.md)",
                    tool.name,
                    tool.bins.join(", ")
                ),
                Color::Red,
            ));
            return;
        }
        let host = self
            .focus
            .as_ref()
            .and_then(|ip| self.eng.hosts.get(ip))
            .cloned();

        // Reserve the job id now so {outfile}/{outdir} can point at real paths the
        // job will actually write to (nmap -oX, ffuf -o, sqlmap --output-dir, ...).
        let id = self.eng.next_record_id.max(1);
        self.eng.next_record_id = id + 1;
        let target = self.focus.clone();
        let ext = if tool.template.contains("-oX") {
            "xml"
        } else if tool.template.contains("-oJ") || tool.template.contains("-of json") {
            "json"
        } else {
            "out"
        };
        let artifact = self
            .ws
            .artifact_file(id, target.as_deref(), tool.phase.slug(), tool.id, ext)
            .ok();
        let outdir = self.ws.phase_dir(target.as_deref(), tool.phase.slug()).ok();

        let mut ctx = Ctx::from_engagement(&self.eng, host.as_ref(), None);
        if let Some(a) = &artifact {
            ctx.set("outfile", a.to_string_lossy().into_owned());
        }
        if let Some(d) = &outdir {
            ctx.set("outdir", d.to_string_lossy().into_owned());
        }

        match tool.render(&ctx) {
            Ok(cmd) => {
                if tool.interactive {
                    self.push(Line::c(
                        format!("→ launching {} (interactive)", tool.name),
                        Color::Cyan,
                    ));
                    self.pending_shell = Some(cmd);
                    return;
                }
                self.launch(
                    id,
                    tool.id,
                    tool.phase,
                    tool.speed.timeout_secs(),
                    target,
                    cmd,
                    tool.note,
                    artifact,
                )
                .await;
            }
            Err(missing) => {
                self.push(Line::c(
                    format!(
                        "… {} needs: {} — set them with /set or /cred, or /focus a host",
                        tool.name,
                        missing.join(", ")
                    ),
                    Color::Yellow,
                ));
            }
        }
    }

    async fn run_raw(&mut self, cmd: &str) {
        if cmd.is_empty() {
            return;
        }
        let phase = self.phase_filter.unwrap_or(Phase::Exploit);
        let id = self.eng.next_record_id.max(1);
        self.eng.next_record_id = id + 1;
        self.launch(
            id,
            "raw",
            phase,
            0,
            self.focus.clone(),
            cmd.to_string(),
            "",
            None,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn launch(
        &mut self,
        id: u64,
        tool: &str,
        phase: Phase,
        timeout: u64,
        target: Option<String>,
        command: String,
        note: &str,
        artifact: Option<std::path::PathBuf>,
    ) {
        let out = match self
            .ws
            .output_file(id, target.as_deref(), phase.slug(), tool)
        {
            Ok(p) => p,
            Err(e) => {
                self.push(Line::c(format!("! {e}"), Color::Red));
                return;
            }
        };
        if !note.is_empty() {
            self.push(Line::c(format!("# {note}"), Color::DarkGray));
        }
        self.push(Line::c(format!("▶ #{id} {command}"), Color::Cyan));
        self.live.insert(
            id,
            Live {
                tool: tool.to_string(),
                phase,
                target: target.clone(),
                command: command.clone(),
                status: JobStatus::Queued,
                lines: vec![],
                output_file: out.clone(),
                artifact,
                record_id: None,
            },
        );
        self.runner.spawn(Job {
            id,
            tool: tool.to_string(),
            phase,
            target,
            command,
            output_file: out,
            timeout_secs: timeout,
        });
    }

    /// Campaign mode: run every applicable, installed, non-interactive tool for a
    /// phase across the current scope (focused host, or all hosts if none focused).
    async fn auto_run(&mut self, spec: &str) {
        let phase: Option<Phase> = spec.trim().parse().ok();
        // Which hosts?
        let hosts: Vec<String> = match &self.focus {
            Some(ip) => vec![ip.clone()],
            None => {
                if self.eng.hosts.is_empty() {
                    self.push(Line::c(
                        "no hosts in scope — /target <ip|cidr> or /run nmap-full first",
                        Color::Yellow,
                    ));
                    return;
                }
                self.eng.hosts.keys().cloned().collect()
            }
        };

        let label = phase
            .map(|p| p.title().to_string())
            .unwrap_or_else(|| "all phases".into());
        self.push(Line::c(
            format!("▶ auto: {} across {} host(s)", label, hosts.len()),
            Color::Magenta,
        ));

        let mut launched = 0;
        let mut skipped_missing = 0;
        for ip in hosts {
            let host = self.eng.hosts.get(&ip).cloned();
            let mut tools = catalog::suggest(&self.eng, host.as_ref());
            tools.retain(|t| {
                phase.map(|p| t.phase == p).unwrap_or(true)
                    && !t.interactive
                    // In auto mode, don't fire slow full sweeps or destructive exploits
                    // unless the operator asked for that exact phase.
                    && (phase.is_some()
                        || matches!(
                            t.phase,
                            Phase::Discovery
                                | Phase::PortScan
                                | Phase::ServiceEnum
                                | Phase::WebEnum
                                | Phase::DirEnum
                                | Phase::SmbEnum
                                | Phase::AdEnum
                                | Phase::VulnScan
                        ))
            });
            for tool in tools {
                if !catalog::is_available(tool) {
                    skipped_missing += 1;
                    continue;
                }
                // Reserve id + artifact path (mirrors run_tool).
                let id = self.eng.next_record_id.max(1);
                self.eng.next_record_id = id + 1;
                let target = Some(ip.clone());
                let ext = if tool.template.contains("-oX") {
                    "xml"
                } else if tool.template.contains("-oJ") || tool.template.contains("-of json") {
                    "json"
                } else {
                    "out"
                };
                let artifact = self
                    .ws
                    .artifact_file(id, target.as_deref(), tool.phase.slug(), tool.id, ext)
                    .ok();
                let outdir = self.ws.phase_dir(target.as_deref(), tool.phase.slug()).ok();
                let mut ctx = Ctx::from_engagement(&self.eng, host.as_ref(), None);
                if let Some(a) = &artifact {
                    ctx.set("outfile", a.to_string_lossy().into_owned());
                }
                if let Some(d) = &outdir {
                    ctx.set("outdir", d.to_string_lossy().into_owned());
                }
                if let Ok(cmd) = tool.render(&ctx) {
                    self.launch(
                        id,
                        tool.id,
                        tool.phase,
                        tool.speed.timeout_secs(),
                        target,
                        cmd,
                        "",
                        artifact,
                    )
                    .await;
                    launched += 1;
                }
            }
        }
        self.push(Line::c(
            format!(
                "  queued {launched} job(s){}",
                if skipped_missing > 0 {
                    format!(" · {skipped_missing} skipped (not installed)")
                } else {
                    String::new()
                }
            ),
            Color::Magenta,
        ));
    }

    /// Manually record a finding:  [sev] title @location
    fn add_finding_cmd(&mut self, spec: &str) {
        use crate::model::{Finding, Severity};
        let spec = spec.trim();
        if spec.is_empty() {
            self.push(Line::c(
                "usage: /finding [critical|high|medium|low] title @location",
                Color::Yellow,
            ));
            return;
        }
        let (loc, rest) = match spec.split_once('@') {
            Some((r, l)) => (Some(l.trim().to_string()), r.trim()),
            None => (None, spec),
        };
        let mut words = rest.splitn(2, char::is_whitespace);
        let first = words.next().unwrap_or("");
        let (sev, title) = match first.to_ascii_lowercase().as_str() {
            "critical" | "high" | "medium" | "low" | "info" => (
                Severity::parse(first),
                words.next().unwrap_or("").trim().to_string(),
            ),
            _ => (Severity::Medium, rest.to_string()),
        };
        if title.is_empty() {
            self.push(Line::c("finding needs a title", Color::Yellow));
            return;
        }
        let mut f = Finding::new("manual", sev, title);
        f.location = loc.clone().or_else(|| self.focus.clone());
        f.host = self.focus.clone();
        if self.eng.add_finding(f) {
            self.push(Line::c(
                format!("+ finding recorded [{}]", sev.label()),
                Color::Green,
            ));
        }
    }

    fn show_history(&mut self) {
        if self.eng.records.is_empty() {
            self.push(Line::plain("no commands run yet"));
            return;
        }
        self.push(Line::c("command history:", Color::Cyan));
        let lines: Vec<String> = self
            .eng
            .records
            .iter()
            .rev()
            .take(30)
            .map(|r| {
                let code = r
                    .exit_code
                    .map(|c| format!("exit {c}"))
                    .unwrap_or_else(|| "?".into());
                format!(
                    "  #{:<3} [{}] {:<6} {}",
                    r.id,
                    r.phase.slug(),
                    code,
                    r.command
                )
            })
            .collect();
        for l in lines {
            self.push(Line::plain(l));
        }
    }

    async fn rerun(&mut self, id: &str) {
        let rid: u64 = match id.trim().parse() {
            Ok(n) => n,
            Err(_) => {
                self.push(Line::c("usage: /rerun <id>  (see /history)", Color::Yellow));
                return;
            }
        };
        let rec = self.eng.records.iter().find(|r| r.id == rid).cloned();
        match rec {
            Some(r) => {
                self.push(Line::c(format!("re-running #{rid}"), Color::Cyan));
                let phase = r.phase;
                let target = r.target.clone();
                let nid = self.eng.next_record_id.max(1);
                self.eng.next_record_id = nid + 1;
                self.launch(nid, &r.tool, phase, 0, target, r.command.clone(), "", None)
                    .await;
            }
            None => self.push(Line::c(format!("no record #{rid}"), Color::Yellow)),
        }
    }

    fn focus_selected_host(&mut self) {
        let mut ips: Vec<String> = self.eng.hosts.keys().cloned().collect();
        ips.sort_by_key(|ip| {
            ip.split('.')
                .filter_map(|o| o.parse::<u8>().ok())
                .collect::<Vec<_>>()
        });
        if let Some(ip) = ips.get(self.table_sel.min(ips.len().saturating_sub(1))) {
            let ip = ip.clone();
            self.set_focus(&ip);
            self.view = View::Console;
        }
    }

    fn set_focus(&mut self, ip: &str) {
        if self.eng.hosts.contains_key(ip) {
            self.focus = Some(ip.to_string());
            self.push(Line::c(format!("→ focus {ip}"), Color::Cyan));
        } else {
            self.push(Line::c(
                format!("? no host {ip} in scope (/target to add)"),
                Color::Yellow,
            ));
        }
        self.refresh_suggestions();
    }

    fn import(&mut self, path: &str) {
        match std::fs::read_to_string(path) {
            Ok(xml) => match parse::intel::ingest_nmap(&mut self.eng, &xml) {
                Ok(n) => {
                    self.push(Line::c(
                        format!("imported {n} hosts from {path}"),
                        Color::Cyan,
                    ));
                    self.eng.recompute_segments();
                    self.refresh_suggestions();
                }
                Err(e) => self.push(Line::c(format!("! parse error: {e}"), Color::Red)),
            },
            Err(e) => self.push(Line::c(format!("! {e}"), Color::Red)),
        }
    }

    fn add_cred(&mut self, spec: &str) {
        // domain/user:pass  |  user:pass  |  user:pass@domain
        let (idpart, secret) = match spec.split_once(':') {
            Some(x) => x,
            None => {
                self.push(Line::c("usage: /cred [domain/]user:secret", Color::Yellow));
                return;
            }
        };
        let (domain, user) = if let Some((d, u)) = idpart.split_once('/') {
            (Some(d.to_string()), u.to_string())
        } else {
            (None, idpart.to_string())
        };
        let kind = if secret.len() == 32 && secret.chars().all(|c| c.is_ascii_hexdigit()) {
            SecretKind::NtHash
        } else {
            SecretKind::Password
        };
        let mut c = Credential::new(user, secret, kind, "operator");
        if let Some(d) = domain {
            c = c.with_domain(d);
        }
        if parse::intel::maybe_b64(secret).is_some() {
            c.decoded = parse::intel::maybe_b64(secret);
        }
        if self.eng.add_cred(c) {
            self.push(Line::c("+ credential added", Color::Green));
        } else {
            self.push(Line::plain("credential already known"));
        }
        self.refresh_suggestions();
    }

    fn harvest(&mut self, arg: &str) {
        let text = if Path::new(arg).exists() {
            std::fs::read_to_string(arg).unwrap_or_default()
        } else {
            arg.to_string()
        };
        let n = parse::intel::harvest(&mut self.eng, &text, "harvest");
        parse::intel::enrich_from_hosts(&mut self.eng);
        self.push(Line::c(
            format!("harvested {n} credential(s)"),
            Color::Green,
        ));
        self.refresh_suggestions();
    }

    fn set_var(&mut self, k: &str, v: &str) {
        match k.to_ascii_lowercase().as_str() {
            "proxy" => {
                self.eng.proxy = if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                };
            }
            "iface" | "interface" => self.eng.interface = Some(v.to_string()),
            "lhost" => self.eng.lhost = Some(v.to_string()),
            "lport" => self.eng.lport = Some(v.to_string()),
            "domain" => self.eng.domain.fqdn = Some(v.to_ascii_lowercase()),
            "dc" | "dc_ip" => {
                self.eng.domain.dc_ips.insert(v.to_string());
            }
            other => {
                self.eng.wordlists.insert(other.to_string(), v.to_string());
            }
        }
        self.push(Line::c(format!("set {k} = {v}"), Color::Cyan));
        self.refresh_suggestions();
    }

    fn star_last(&mut self) {
        if let Some(id) = self.last_record {
            if let Some(r) = self.eng.records.iter_mut().find(|r| r.id == id) {
                r.starred = true;
                self.push(Line::c(format!("⭐ starred #{id}"), Color::Yellow));
            }
        }
    }

    fn set_phase_filter(&mut self, p: Option<String>) {
        self.phase_filter = p.and_then(|s| s.parse().ok());
        self.refresh_suggestions();
        match self.phase_filter {
            Some(p) => self.push(Line::c(format!("phase filter: {}", p.title()), Color::Cyan)),
            None => self.push(Line::plain("phase filter cleared")),
        }
    }

    /// Is the slash-command autocomplete menu currently showing?
    pub fn menu_active(&self) -> bool {
        !super::palette::completions(&self.input).is_empty()
    }

    pub fn completions_len(&self) -> usize {
        super::palette::completions(&self.input).len()
    }

    /// Fill the input with the selected completion.
    fn accept_completion(&mut self) {
        let comps = super::palette::completions(&self.input);
        if let Some(c) = comps.get(self.menu_sel).or_else(|| comps.first()) {
            self.input = format!("/{} ", c.name);
            self.cursor = self.input.len();
            self.menu_sel = 0;
        }
    }

    pub fn refresh_suggestions(&mut self) {
        let host = self.focus.as_ref().and_then(|ip| self.eng.hosts.get(ip));
        let mut s = catalog::suggest(&self.eng, host);
        if let Some(pf) = self.phase_filter {
            s.retain(|t| t.phase == pf);
        }
        s.truncate(12);
        self.suggest_avail = s.iter().map(|t| catalog::is_available(t)).collect();
        self.suggestions = s;
        if self.sel >= self.suggestions.len() {
            self.sel = self.suggestions.len().saturating_sub(1);
        }
    }

    fn print_guidance(&mut self) {
        let chains = crate::chain::recommend(&self.eng);
        if chains.is_empty() {
            self.push(Line::c(
                "no state yet — /target a host and scan to begin",
                Color::Yellow,
            ));
            return;
        }
        self.push(Line::c(
            "attack-chain guidance (state → next moves):",
            Color::Magenta,
        ));
        let mut lines: Vec<(String, Color)> = vec![];
        for ch in chains {
            lines.push((format!("  ▸ {}", ch.state), Color::Cyan));
            for rec in ch.recs {
                let avail = crate::catalog::by_id(rec.tool)
                    .map(crate::catalog::is_available)
                    .unwrap_or(true);
                let mark = if avail { "" } else { " (not installed)" };
                lines.push((
                    format!(
                        "      {:<20} {}  [{}]{}",
                        rec.tool, rec.why, rec.attack, mark
                    ),
                    if avail { Color::White } else { Color::DarkGray },
                ));
            }
        }
        for (l, c) in lines {
            self.push(Line::c(l, c));
        }
    }

    fn print_suggestions(&mut self) {
        let ctx_label = self.focus.clone().unwrap_or_else(|| "network".into());
        self.push(Line::c(
            format!("suggested next steps for {ctx_label}:"),
            Color::Cyan,
        ));
        let items: Vec<(String, Color)> = self
            .suggestions
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let avail = self.suggest_avail.get(i).copied().unwrap_or(true);
                let tag = if avail { "" } else { "  (not installed)" };
                (
                    format!(
                        "  {}. [{}] {} — {}{}",
                        i + 1,
                        t.phase.slug(),
                        t.name,
                        t.desc,
                        tag
                    ),
                    if avail { Color::White } else { Color::DarkGray },
                )
            })
            .collect();
        for (t, c) in items {
            self.push(Line::c(t, c));
        }
    }

    // ───────────────────────── payloads

    /// Resolve lhost/lport: explicit args override stored engagement values.
    fn payload_params(&self, args: &[&str]) -> payload::Params {
        payload::Params {
            lhost: args
                .get(1)
                .map(|s| s.to_string())
                .or_else(|| self.eng.lhost.clone())
                .unwrap_or_else(|| "{lhost}".into()),
            lport: args
                .get(2)
                .map(|s| s.to_string())
                .or_else(|| self.eng.lport.clone())
                .unwrap_or_else(|| "4444".into()),
            ..payload::Params::default()
        }
    }

    fn gen_payload(&mut self, spec: &str) {
        // form: <id> [lhost] [lport] [+transform]
        let mut transform_name = None;
        let tokens: Vec<String> = spec
            .split_whitespace()
            .map(|t| {
                if let Some(t2) = t.strip_prefix('+') {
                    transform_name = Some(t2.to_string());
                    String::new()
                } else {
                    t.to_string()
                }
            })
            .filter(|t| !t.is_empty())
            .collect();
        let args: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
        if args.is_empty() {
            self.list_payloads("");
            return;
        }
        let Some(pl) = payload::by_id(args[0]) else {
            self.push(Line::c(
                format!("? no payload '{}' — /payloads to list", args[0]),
                Color::Yellow,
            ));
            return;
        };
        let params = self.payload_params(&args);
        let mut body = pl.render(&params);

        // Optional transform.
        if let Some(tn) = &transform_name {
            match transform_kind(tn) {
                Some(tk) => body = transform::apply(tk, &body),
                None => self.push(Line::c(format!("? unknown transform '{tn}' (base64,ps-encodedcommand,hex,url-encode,xor-ps-stub,ps-char-array,bash-b64-exec,py-b64-exec,php-b64-eval)"), Color::Yellow)),
            }
        }

        self.push(Line::c(
            format!("── {} [{}/{}] ──", pl.name, pl.os.label(), pl.lang.label()),
            Color::Magenta,
        ));
        if !pl.notes.is_empty() {
            self.push(Line::c(format!("  {}", pl.notes), Color::DarkGray));
        }
        for l in body.lines() {
            self.push(Line::c(l.to_string(), Color::White));
        }
        let listener = pl.render_listener(&params);
        if !listener.is_empty() {
            self.push(Line::c(format!("  listener: {listener}"), Color::Green));
        }
        if !pl.transforms.is_empty() && transform_name.is_none() {
            let ts: Vec<&str> = pl.transforms.iter().map(|t| t.label()).collect();
            self.push(Line::c(
                format!(
                    "  transforms: {} — add e.g. /payload {} +{}",
                    ts.join(", "),
                    pl.id,
                    ts[0]
                ),
                Color::DarkGray,
            ));
        }
        // Save to workspace loot for reuse.
        let fname = format!("{}.{}", pl.id, pl.lang.ext());
        let path = self.ws.loot_dir().join(&fname);
        let _ = std::fs::write(&path, &body);
        self.push(Line::c(format!("  saved → loot/{fname}"), Color::Cyan));
        self.eng.note(
            Phase::PostExploit,
            format!("payload {}: {}", pl.id, body.lines().next().unwrap_or("")),
        );
    }

    fn gen_msf(&mut self, spec: &str) {
        let args: Vec<&str> = spec.split_whitespace().collect();
        if args.is_empty() {
            self.push(Line::c("msfvenom specs:", Color::Cyan));
            let names: Vec<(String, String)> = payload::msf::SPECS
                .iter()
                .map(|s| (s.id.to_string(), s.name.to_string()))
                .collect();
            for (id, name) in names {
                self.push(Line::c(format!("  {id:22} {name}"), Color::White));
            }
            return;
        }
        let Some(spec_def) = payload::msf::by_id(args[0]) else {
            self.push(Line::c(
                format!("? no msf spec '{}' — /msf to list", args[0]),
                Color::Yellow,
            ));
            return;
        };
        let lhost = args
            .get(1)
            .map(|s| s.to_string())
            .or_else(|| self.eng.lhost.clone())
            .unwrap_or_else(|| "{lhost}".into());
        let lport = args
            .get(2)
            .map(|s| s.to_string())
            .or_else(|| self.eng.lport.clone())
            .unwrap_or_else(|| "4444".into());
        let cmd = spec_def.command(&lhost, &lport, "", None, 1);
        self.push(Line::c(
            format!("── msfvenom · {} ──", spec_def.name),
            Color::Magenta,
        ));
        self.push(Line::c(format!("  {}", spec_def.notes), Color::DarkGray));
        self.push(Line::c(cmd, Color::White));
        let handler = if spec_def.stageless() {
            format!("  listener: rlwrap -cAr nc -lvnp {lport}")
        } else {
            format!("  handler: {}", spec_def.handler(&lhost, &lport))
        };
        self.push(Line::c(handler, Color::Green));
    }

    fn list_payloads(&mut self, filter: &str) {
        let f = filter.trim().to_ascii_lowercase();
        let items: Vec<(String, Color)> = payload::all()
            .iter()
            .filter(|p| {
                f.is_empty()
                    || p.os.label().contains(&f)
                    || p.lang.label().contains(&f)
                    || p.kind.label().contains(&f)
                    || p.id.contains(&f)
            })
            .map(|p| {
                (
                    format!(
                        "  {:22} [{}/{}/{}] {}",
                        p.id,
                        p.os.label(),
                        p.kind.label(),
                        p.lang.label(),
                        p.name
                    ),
                    Color::White,
                )
            })
            .collect();
        self.push(Line::c(
            format!(
                "payloads{}:",
                if f.is_empty() {
                    String::new()
                } else {
                    format!(" · {f}")
                }
            ),
            Color::Cyan,
        ));
        if items.is_empty() {
            self.push(Line::plain("  (none match)"));
        }
        for (t, c) in items {
            self.push(Line::c(t, c));
        }
        self.push(Line::c(
            "  usage: /payload <id> [lhost] [lport] [+transform]   ·   /msf <id>",
            Color::DarkGray,
        ));
    }

    fn push(&mut self, l: Line) {
        self.transcript.push(l);
        if self.transcript.len() > 20_000 {
            self.transcript.drain(0..5_000);
        }
        if self.follow {
            self.scroll = 0;
        }
    }
}

/// Add a target: an IP, a CIDR, or a path to a hosts file.
pub fn seed_target(eng: &mut Engagement, spec: &str) -> Result<()> {
    use crate::model::Host;
    let spec = spec.trim();
    if Path::new(spec).exists() {
        for line in std::fs::read_to_string(spec)?.lines() {
            let l = line.trim();
            if !l.is_empty() && !l.starts_with('#') {
                let _ = seed_target(eng, l);
            }
        }
        return Ok(());
    }
    if let Ok(net) = spec.parse::<ipnet::Ipv4Net>() {
        if net.prefix_len() >= 24 {
            for ip in net.hosts().take(256) {
                eng.hosts
                    .entry(ip.to_string())
                    .or_insert_with(|| Host::new(ip.to_string()));
            }
            return Ok(());
        }
    }
    if spec.parse::<std::net::Ipv4Addr>().is_ok() {
        eng.hosts
            .entry(spec.to_string())
            .or_insert_with(|| Host::new(spec));
        return Ok(());
    }
    anyhow::bail!("not an IP, CIDR, or existing file: {spec}");
}

/// Map a transform name from the palette to its enum.
fn transform_kind(name: &str) -> Option<transform::Kind> {
    use transform::Kind::*;
    Some(match name.to_ascii_lowercase().as_str() {
        "base64" | "b64" => Base64,
        "ps-encodedcommand" | "enc" | "psenc" => PsEncodedCommand,
        "hex" => Hex,
        "url-encode" | "url" => UrlEncode,
        "double-url-encode" | "durl" => DoubleUrlEncode,
        "xor-ps-stub" | "xor" => XorPsStub,
        "ps-char-array" | "chararray" => PsCharArray,
        "bash-b64-exec" | "bashb64" => BashB64Exec,
        "py-b64-exec" | "pyb64" => PyB64Exec,
        "php-b64-eval" | "phpb64" => PhpB64Eval,
        _ => return None,
    })
}

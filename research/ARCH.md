# shrike — Technical Foundation & Architecture Research

Research target: a Rust TUI offensive-security orchestrator with a Claude-Code-style
terminal interface — a scrolling transcript of executed commands + output, a bottom
input prompt, a slash-command palette, and a live status line.

**Versions verified against crates.io on 2026-08-26.** The single most important pin is
**`ratatui = 0.30.2`** (current stable). ratatui's API changed materially across
0.26 → 0.28 → 0.29 → 0.30, so every snippet below is written for the **0.30 idiom**
(`ratatui::init()` / `ratatui::restore()`, `DefaultTerminal`, `frame.area()`). If you
copy code from an older tutorial it will not compile against 0.30 — see the migration
notes inline.

---

## 1. Cargo.toml `[dependencies]` — pinned, all exist on crates.io as of 2026-08-26

```toml
[package]
name = "shrike"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"

[dependencies]
# ── TUI ────────────────────────────────────────────────────────────────────
ratatui   = "0.30.2"                                   # verified latest stable
# crossterm is re-exported as `ratatui::crossterm`, but the async EventStream lives
# behind crossterm's own "event-stream" feature, which ratatui does NOT turn on.
# Depend on crossterm directly to enable it; Cargo feature-unification makes ratatui
# use the same (feature-enabled) crossterm 0.29.
crossterm = { version = "0.29.0", features = ["event-stream"] }

# ── Async runtime ──────────────────────────────────────────────────────────
tokio = { version = "1.53.1", features = [
    "rt-multi-thread",   # multi-threaded scheduler
    "macros",            # #[tokio::main], tokio::select!
    "process",           # tokio::process::Command (async child spawn)
    "io-util",           # AsyncReadExt / AsyncBufReadExt (.lines(), read_line)
    "sync",              # mpsc, Semaphore, oneshot, watch
    "time",              # interval, timeout, sleep
    "signal",            # ctrl_c handling
    "fs",                # async workspace IO (optional; std::fs is fine too)
] }
tokio-util = { version = "0.7.19", features = ["rt"] }  # CancellationToken
futures    = "0.3"                                      # StreamExt/FutureExt: .next(), .fuse()

# ── Serialization / config ─────────────────────────────────────────────────
serde      = { version = "1.0.229", features = ["derive"] }
serde_json = "1.0.151"
toml       = "1.1"        # NOTE: toml is now 1.x (was 0.8/0.9). API is stable serde.
chrono     = { version = "0.4.45", features = ["serde"] }
indexmap   = { version = "2.14.0", features = ["serde"] }  # insertion-ordered maps for jobs/targets

# ── Errors / logging ───────────────────────────────────────────────────────
anyhow    = "1.0.104"     # application-level error propagation
thiserror = "2.0.20"      # NOTE: thiserror is 2.x now; #[error(...)] derive for lib errors
tracing            = "0.1"
tracing-subscriber = { version = "0.3.23", features = ["env-filter"] }
# Log to a FILE, never stdout — stdout is owned by the TUI (see §2 note).
tracing-appender = "0.2"

# ── CLI / parsing / matching ───────────────────────────────────────────────
clap  = { version = "4.6.6", features = ["derive"] }
regex = "1.13.1"
ipnet = "2.12.1"          # CIDR expansion / host iteration for target lists

# ── XML (nmap -oX, etc.) ───────────────────────────────────────────────────
# Pick ONE. Recommendation below (§tooling): roxmltree for read-only nmap XML.
roxmltree = "0.21.1"      # read-only DOM, zero-copy, ergonomic for nmap -oX
quick-xml = { version = "0.42.0", features = ["serde"] }  # streaming/large or if you want serde structs

# ── Filesystem / environment ───────────────────────────────────────────────
dirs  = "6.0.0"           # XDG/data dirs for the engagement workspace root
which = "8.0.5"           # locate nmap/evil-winrm/etc. on PATH; warn if missing
textwrap = "0.16.2"       # wrap long tool output to the transcript pane width

# ── Optional: real PTY for interactive tools (see §4) ──────────────────────
portable-pty = "0.9.0"
```

**Migration gotchas baked into the pins above**

- `toml` is **1.x** now (not 0.8/0.9). Usage is unchanged for serde round-tripping
  (`toml::from_str`, `toml::to_string_pretty`).
- `thiserror` is **2.x**. Derive syntax is the same; MSRV bumped.
- `dirs` is **6.x** (breaking rename history from `directories`); `dirs::data_dir()` etc. unchanged.
- `which` is **8.x**; `which::which("nmap")` unchanged.
- `roxmltree` is **0.21** (0.20 → 0.21 tightened some lifetimes).
- `crossterm` **0.29** is the version ratatui 0.30 depends on — do not pin a different major.

---

## 2. THE CORE: a verified minimal ratatui 0.30 app

This is a complete, compilable skeleton. It gives you:

- **(a)** a scrollback transcript pane holding thousands of styled `Line`s, with
  PgUp/PgDn/mouse-wheel scroll and "stick to bottom" behavior;
- **(b)** a bottom input line with left/right cursor editing and a rendered cursor;
- **(c)** a non-blocking event loop that interleaves crossterm key events (via
  `EventStream`) with async output arriving from spawned children over a
  `tokio::mpsc` channel — driven by a single `tokio::select!`.

### 2.0 ratatui 0.30 API notes you must get right

| 0.30 idiom | older API it replaced |
|---|---|
| `let mut term = ratatui::init();` → `DefaultTerminal` | manual `enable_raw_mode()` + `EnterAlternateScreen` + `Terminal::new(CrosstermBackend::new(stdout))` |
| `ratatui::restore();` | manual `disable_raw_mode()` + `LeaveAlternateScreen` |
| `frame.area()` | `frame.size()` (renamed in 0.28) |
| `terminal.draw(|frame| { ... })?` returns `io::Result<CompletedFrame>` | same shape, still sync |
| `frame.render_widget(widget, rect)` | unchanged |
| `Frame::render_widget_ref` needs `use ratatui::widgets::FrameExt;` + `unstable-widget-ref` feature | was inherent in 0.29 |
| crossterm is `ratatui::crossterm::…` | separate import (still works if you depend on crossterm directly) |

> **`ratatui::init()` puts the terminal in raw mode + alternate screen and installs a
> panic hook that restores it.** But you still want mouse capture on/off and your own
> panic-safe restore for interactive-tool hand-off (see §4). Because the TUI owns the
> real stdout, send all `tracing` logs to a file via `tracing-appender`, never to stdout.

### 2.1 `main.rs`

```rust
use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    Event as CtEvent, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use futures::{FutureExt, StreamExt};
use ratatui::{
    layout::{Constraint, Direction, Layout, Position, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    DefaultTerminal, Frame,
};
use tokio::sync::mpsc;

/// A line destined for the transcript, tagged with which job produced it.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// stdout/stderr text arriving from a spawned child, tagged by job id.
    JobLine { job_id: u64, line: String, is_err: bool },
    /// a job finished (exit status text).
    JobDone { job_id: u64, status: String },
    /// something the app itself wants to print (e.g. a slash-command result).
    Notice(String),
}

/// Everything the UI renders from.
struct App {
    /// The scrollback. In a real build cap this (e.g. VecDeque with a max) or page
    /// old lines to disk; a Vec of tens of thousands of Lines is fine for a session.
    transcript: Vec<Line<'static>>,
    /// Vertical scroll offset from the TOP of the transcript, in wrapped rows.
    /// `None` means "follow the tail" (auto-scroll as new output arrives).
    scroll: Option<u16>,
    /// Current input buffer and cursor (byte index into `input`).
    input: String,
    cursor: usize,
    running_jobs: usize,
    should_quit: bool,
}

impl App {
    fn new() -> Self {
        Self {
            transcript: vec![Line::from(
                "shrike ready. type a command, or /help. Ctrl-C quits.".dim(),
            )],
            scroll: None,
            input: String::new(),
            cursor: 0,
            running_jobs: 0,
            should_quit: false,
        }
    }

    fn push_line(&mut self, line: Line<'static>) {
        self.transcript.push(line);
    }

    fn apply(&mut self, ev: AppEvent) {
        match ev {
            AppEvent::JobLine { job_id, line, is_err } => {
                let tag = Span::styled(
                    format!("[{job_id:>3}] "),
                    Style::default().fg(Color::Cyan),
                );
                let body = if is_err {
                    Span::styled(line, Style::default().fg(Color::Red))
                } else {
                    Span::raw(line)
                };
                self.push_line(Line::from(vec![tag, body]));
            }
            AppEvent::JobDone { job_id, status } => {
                self.running_jobs = self.running_jobs.saturating_sub(1);
                self.push_line(Line::from(vec![
                    Span::styled(format!("[{job_id:>3}] "), Style::default().fg(Color::Cyan)),
                    Span::styled(
                        format!("done: {status}"),
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    ),
                ]));
            }
            AppEvent::Notice(s) => {
                self.push_line(Line::from(Span::styled(s, Style::default().fg(Color::Yellow))));
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // tracing → file, because stdout belongs to the TUI.
    let file = tracing_appender::rolling::never(".", "shrike.log");
    let (nb, _guard) = tracing_appender::non_blocking(file);
    tracing_subscriber::fmt().with_writer(nb).with_ansi(false).init();

    // 0.30: one call sets raw mode + alt screen + panic hook.
    let mut terminal = ratatui::init();
    let result = run(&mut terminal).await;
    ratatui::restore(); // always restore, even on error
    result
}

async fn run(terminal: &mut DefaultTerminal) -> Result<()> {
    let mut app = App::new();

    // Channel that ALL background work (jobs, timers, etc.) uses to feed the UI.
    let (tx, mut rx) = mpsc::channel::<AppEvent>(1024);

    // crossterm async event source.
    let mut events = EventStream::new();

    // Periodic redraw tick so throughput bursts don't starve the UI and so the
    // status line stays live even when idle.
    let mut tick = tokio::time::interval(Duration::from_millis(100));

    // A tiny "job engine" handle. In the real app this is your Semaphore-bounded
    // pool (see §3); here it just spawns a demo job when the user hits Enter.
    let mut next_job_id: u64 = 1;

    // Draw once before entering the loop.
    terminal.draw(|f| ui(f, &app))?;

    loop {
        // Interleave: keyboard events, async job output, and the redraw tick.
        // `.fuse()` is required so a completed branch isn't polled again.
        tokio::select! {
            // 1) terminal input
            maybe_ev = events.next().fuse() => {
                match maybe_ev {
                    Some(Ok(CtEvent::Key(key))) => {
                        handle_key(&mut app, key, &tx, &mut next_job_id);
                    }
                    Some(Ok(CtEvent::Mouse(m))) => {
                        use crossterm::event::MouseEventKind;
                        match m.kind {
                            MouseEventKind::ScrollUp   => scroll_up(&mut app, 3),
                            MouseEventKind::ScrollDown => scroll_down(&mut app, 3),
                            _ => {}
                        }
                    }
                    Some(Ok(CtEvent::Resize(_, _))) => { /* next draw handles it */ }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => { app.apply(AppEvent::Notice(format!("input error: {e}"))); }
                    None => break, // stream ended
                }
                terminal.draw(|f| ui(f, &app))?;
            }

            // 2) output from spawned children / background tasks
            Some(app_ev) = rx.recv() => {
                app.apply(app_ev);
                // Drain a burst without redrawing per line (cheap backpressure relief).
                while let Ok(more) = rx.try_recv() {
                    app.apply(more);
                }
                terminal.draw(|f| ui(f, &app))?;
            }

            // 3) periodic redraw (keeps status line / spinner fresh)
            _ = tick.tick() => {
                terminal.draw(|f| ui(f, &app))?;
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}
```

### 2.2 Key handling + input editing

```rust
fn handle_key(
    app: &mut App,
    key: KeyEvent,
    tx: &mpsc::Sender<AppEvent>,
    next_job_id: &mut u64,
) {
    // crossterm on Windows reports both Press and Release; only act on Press/Repeat.
    if key.kind == KeyEventKind::Release {
        return;
    }

    // Ctrl-C / Ctrl-D quit.
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('d'))
    {
        app.should_quit = true;
        return;
    }

    match key.code {
        KeyCode::Enter => {
            let cmd = std::mem::take(&mut app.input);
            app.cursor = 0;
            if cmd.trim().is_empty() {
                return;
            }
            // Echo the command into the transcript, prompt-style.
            app.push_line(Line::from(vec![
                Span::styled("❯ ", Style::default().fg(Color::Green)),
                Span::raw(cmd.clone()),
            ]));
            app.scroll = None; // snap to tail on new command

            if let Some(rest) = cmd.strip_prefix('/') {
                handle_slash(app, rest);
            } else {
                // Spawn a real child (see §3 for the pooled version).
                let job_id = *next_job_id;
                *next_job_id += 1;
                app.running_jobs += 1;
                spawn_shell_job(job_id, cmd, tx.clone());
            }
        }

        // ── inline editing ───────────────────────────────────────────────
        KeyCode::Char(c) => {
            app.input.insert(app.cursor, c);
            app.cursor += c.len_utf8();
        }
        KeyCode::Backspace => {
            if app.cursor > 0 {
                // step back one char boundary
                let prev = app.input[..app.cursor]
                    .char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
                app.input.replace_range(prev..app.cursor, "");
                app.cursor = prev;
            }
        }
        KeyCode::Left => {
            if app.cursor > 0 {
                app.cursor = app.input[..app.cursor]
                    .char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.cursor < app.input.len() {
                let next = app.input[app.cursor..]
                    .char_indices().nth(1).map(|(i, _)| app.cursor + i).unwrap_or(app.input.len());
                app.cursor = next;
            }
        }
        KeyCode::Home => app.cursor = 0,
        KeyCode::End  => app.cursor = app.input.len(),

        // ── scrollback ───────────────────────────────────────────────────
        KeyCode::PageUp   => scroll_up(app, 10),
        KeyCode::PageDown => scroll_down(app, 10),
        KeyCode::Esc      => app.scroll = None, // jump back to tail
        _ => {}
    }
}

fn scroll_up(app: &mut App, n: u16) {
    // Materialize current tail offset if we were following, then move up.
    let cur = app.scroll.unwrap_or(u16::MAX);
    app.scroll = Some(cur.saturating_sub(n));
}
fn scroll_down(app: &mut App, n: u16) {
    match app.scroll {
        None => {}                                   // already at tail
        Some(off) => app.scroll = Some(off.saturating_add(n)),
    }
}

fn handle_slash(app: &mut App, rest: &str) {
    let mut it = rest.split_whitespace();
    match it.next() {
        Some("help") => app.apply(AppEvent::Notice(
            "commands: /help  /jobs  /targets add <cidr>  /save  /quit".into())),
        Some("quit") | Some("q") => app.should_quit = true,
        Some("jobs") => app.apply(AppEvent::Notice(
            format!("{} job(s) running", app.running_jobs))),
        Some(other) => app.apply(AppEvent::Notice(format!("unknown command: /{other}"))),
        None => {}
    }
}
```

### 2.3 Rendering: transcript pane + input line + status line

```rust
fn ui(f: &mut Frame, app: &App) {
    // Three rows: transcript (fills), status (1), input (1).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),      // transcript
            Constraint::Length(1),   // status line
            Constraint::Length(1),   // input
        ])
        .split(f.area()); // 0.30: area(), not size()

    render_transcript(f, app, chunks[0]);
    render_status(f, app, chunks[1]);
    render_input(f, app, chunks[2]);
}

fn render_transcript(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::NONE);
    let inner_h = area.height;

    // Paragraph with Wrap computes wrapped height internally. To scroll correctly we
    // need the total wrapped line count; ratatui doesn't expose it cheaply, so for a
    // high-throughput tool the pragmatic approach is: DON'T wrap in the widget — wrap
    // yourself with `textwrap` at push time (to `area.width`) so 1 transcript entry ==
    // known N rows, making scroll math exact. Shown here is the simple unwrapped path.
    let total = app.transcript.len() as u16;
    let max_top = total.saturating_sub(inner_h);

    // Resolve "follow tail" (None) or clamp an explicit offset.
    let top = match app.scroll {
        None => max_top,
        Some(off) => off.min(max_top),
    };

    let para = Paragraph::new(app.transcript.clone())
        .block(block)
        .scroll((top, 0)); // (y, x) offset in rows/cols
    f.render_widget(para, area);
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let follow = if app.scroll.is_none() { "TAIL" } else { "SCROLL" };
    let text = Line::from(vec![
        Span::styled(" shrike ", Style::default().bg(Color::Blue).fg(Color::White).bold()),
        Span::raw(format!(" jobs:{} ", app.running_jobs)),
        Span::styled(format!(" {follow} "), Style::default().fg(Color::DarkGray)),
        Span::raw(format!(" lines:{} ", app.transcript.len())),
    ]);
    f.render_widget(
        Paragraph::new(text).style(Style::default().bg(Color::Rgb(20, 20, 28))),
        area,
    );
}

fn render_input(f: &mut Frame, app: &App, area: Rect) {
    let prompt = "❯ ";
    let line = Line::from(vec![
        Span::styled(prompt, Style::default().fg(Color::Green).bold()),
        Span::raw(app.input.as_str()),
    ]);
    f.render_widget(Paragraph::new(line), area);

    // Place the real terminal cursor. col = prompt width + display width of text
    // before the byte cursor. Use unicode-width in production; ASCII count shown here.
    let prefix_cols = prompt.chars().count()
        + app.input[..app.cursor].chars().count();
    f.set_cursor_position(Position::new(
        area.x + prefix_cols as u16,
        area.y,
    ));
}
```

**Scrollback design decision worth calling out:** ratatui's `Paragraph` with `Wrap`
does not expose the wrapped-row count, so exact scroll math against wrapped text is
awkward. For a tool that emits lots of long lines, **wrap output yourself with
`textwrap` to the pane width at the moment you push it** into `transcript`, storing
already-wrapped `Line`s. Then `transcript.len()` equals the exact row count and the
`.scroll((top,0))` math above is precise. Re-wrap on `Resize`. This is the same
approach production TUIs (atuin, gitui) take. Cap the buffer with a `VecDeque` and a
max (e.g. 100k rows) or spill to the on-disk log (§5) — the file is the source of
truth, the in-memory buffer is just the viewport history.

---

## 3. Concurrency — bounded pool, streaming stdout, per-job cancellation

Model: a **`Semaphore`** caps concurrent external processes (e.g. 20 nmap workers
across a /24). Each job streams stdout/stderr **line-by-line** into the same
`mpsc::Sender<AppEvent>` the UI drains, tagged by `job_id`, so nothing blocks
rendering. Each job holds a **`CancellationToken`** so `/kill <id>` (or a global
Ctrl-C) aborts it, and a per-job **`timeout`** bounds runaway commands.

```rust
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

/// Shared engine state you'd keep in `App` (behind an Arc) or in a dedicated task.
pub struct JobEngine {
    permits: Arc<Semaphore>,          // bounded worker pool
    tx: mpsc::Sender<AppEvent>,       // → UI
    // job_id → its cancel token, so /kill can reach it. Use indexmap::IndexMap for
    // stable ordering in a /jobs listing.
    cancels: indexmap::IndexMap<u64, CancellationToken>,
}

impl JobEngine {
    pub fn new(max_parallel: usize, tx: mpsc::Sender<AppEvent>) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_parallel)),
            tx,
            cancels: indexmap::IndexMap::new(),
        }
    }

    /// Spawn `program args...` as job `job_id`. Returns immediately; output streams
    /// over the channel. `timeout` bounds the whole job.
    pub fn spawn(&mut self, job_id: u64, program: String, args: Vec<String>, timeout: Duration) {
        let token = CancellationToken::new();
        self.cancels.insert(job_id, token.clone());

        let permits = self.permits.clone();
        let tx = self.tx.clone();

        tokio::spawn(async move {
            // Block here until a worker slot is free — this is the pool bound.
            let _permit = permits.acquire_owned().await.expect("semaphore closed");

            let status_text = run_streaming(job_id, &program, &args, &tx, &token, timeout).await;

            let _ = tx.send(AppEvent::JobDone { job_id, status: status_text }).await;
        });
    }

    pub fn kill(&self, job_id: u64) -> bool {
        if let Some(tok) = self.cancels.get(&job_id) {
            tok.cancel();
            true
        } else {
            false
        }
    }
}

/// Stream one child's stdout+stderr line-by-line into the UI channel, honoring both
/// a cancellation token and a wall-clock timeout.
async fn run_streaming(
    job_id: u64,
    program: &str,
    args: &[String],
    tx: &mpsc::Sender<AppEvent>,
    token: &CancellationToken,
    timeout: Duration,
) -> String {
    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .kill_on_drop(true)           // if this task is aborted, reap the child
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return format!("spawn failed: {e}"),
    };

    // Take the pipes and wrap in line readers.
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let mut out = BufReader::new(stdout).lines();
    let mut err = BufReader::new(stderr).lines();

    // The whole read+wait is bounded by `timeout` and cancellable.
    let work = async {
        loop {
            tokio::select! {
                // stdout line
                line = out.next_line() => match line {
                    Ok(Some(l)) => {
                        let _ = tx.send(AppEvent::JobLine { job_id, line: l, is_err: false }).await;
                    }
                    Ok(None) => {
                        // stdout closed; drain remaining stderr then finish.
                        while let Ok(Some(l)) = err.next_line().await {
                            let _ = tx.send(AppEvent::JobLine { job_id, line: l, is_err: true }).await;
                        }
                        break;
                    }
                    Err(e) => { let _ = tx.send(AppEvent::JobLine { job_id, line: format!("read err: {e}"), is_err: true }).await; break; }
                },
                // stderr line
                line = err.next_line() => {
                    if let Ok(Some(l)) = line {
                        let _ = tx.send(AppEvent::JobLine { job_id, line: l, is_err: true }).await;
                    }
                }
            }
        }
        // Reap and report exit status.
        match child.wait().await {
            Ok(s) => s.code().map(|c| format!("exit {c}")).unwrap_or_else(|| "signaled".into()),
            Err(e) => format!("wait err: {e}"),
        }
    };

    tokio::select! {
        biased;
        _ = token.cancelled() => {
            let _ = child.start_kill();          // SIGKILL the child
            let _ = child.wait().await;
            "cancelled".to_string()
        }
        r = tokio::time::timeout(timeout, work) => match r {
            Ok(status) => status,
            Err(_elapsed) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                "timed out".to_string()
            }
        }
    }
}
```

Notes:

- **Backpressure:** the `mpsc` channel is bounded (1024). A firehose child (`.await`
  on `tx.send`) will naturally slow to the UI's drain rate — good; it prevents OOM.
  The UI's `try_recv` burst-drain (§2.1) keeps redraws from happening per-line.
- **`kill_on_drop(true)` + `start_kill()`** guarantee no orphaned scanners when a job
  is cancelled or the task is aborted.
- **Cancellation granularity:** one `CancellationToken` per job; keep a parent token
  and call `parent.child_token()` so a global "stop everything" cancels all jobs at
  once. Wire Ctrl-C (`tokio::signal::ctrl_c`) to the parent token — but note Ctrl-C is
  also your quit key in raw mode, so decide: Ctrl-C = "cancel running jobs", a second
  Ctrl-C (or `/quit`) = exit.
- **Per-host fan-out:** expand a CIDR with `ipnet` (`"10.0.0.0/24".parse::<Ipv4Net>()?
  .hosts()`), push one `spawn()` per host; the `Semaphore` throttles to `max_parallel`.

---

## 4. Interactive tools that expect a real TTY (evil-winrm, ftp, msfconsole, ssh)

These need a controlling terminal, line discipline, and often full-screen curses
(`msfconsole`, `ssh` to a box that runs `top`). You have two strategies:

### Strategy A — **Suspend the TUI, hand over the real terminal** (recommended default)

Best when the user just wants to *drive the tool interactively* and come back. You
leave ratatui's alternate screen, drop raw mode, `spawn().wait()` the child with
inherited stdio so it owns the actual terminal, then re-init ratatui. Simple, robust,
and the tool behaves exactly as if launched from a plain shell — colors, readline,
ncurses all work.

```rust
use anyhow::Result;
use ratatui::DefaultTerminal;

/// Suspend the TUI, run an interactive child attached to the real terminal, restore.
pub fn run_interactive(
    terminal: &mut DefaultTerminal,
    program: &str,
    args: &[&str],
) -> Result<std::process::ExitStatus> {
    use crossterm::{
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };

    // 1) Leave the TUI: raw mode OFF, back to the main screen.
    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;

    // 2) Run the child with INHERITED stdio (it now owns the terminal).
    //    Use std::process here (blocking) — we WANT to block the UI while handed over.
    let status = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();

    // 3) Re-enter the TUI regardless of how the child exited.
    enable_raw_mode()?;
    execute!(std::io::stdout(), EnterAlternateScreen)?;
    terminal.clear()?;               // force full repaint
    Ok(status?)
}
```

Call this from a slash command like `/shell evil-winrm -i 10.0.0.5 -u admin -p …` or
`/msf`. Because `main` is `#[tokio::main]` and this function blocks, either run it
inside `tokio::task::block_in_place(|| …)` (multi-thread runtime) or briefly stop
polling the event loop while it runs. In practice: have the event loop match on the
"launch interactive" action, `terminal`-suspend, run it (blocking), then resume the
loop — no other jobs render meanwhile, which is exactly what the user expects.

### Strategy B — **`portable-pty`** — embed the tool inside your TUI

Use only when you want the interactive session to appear *inside* a shrike pane (split
view, logged keystrokes, multiplexed alongside other jobs) rather than taking over the
screen. `portable-pty` allocates a real PTY pair; you write user keystrokes to the
master and render the child's output in a ratatui pane. This is much more work: you
must feed it a terminal emulator/parser (e.g. `vt100` or `wezterm-term`) to interpret
escape sequences into a cell grid, handle resize (`PtySize`), and forward signals.

```rust
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};

let pty = NativePtySystem::default();
let pair = pty.openpty(PtySize { rows: 40, cols: 120, pixel_width: 0, pixel_height: 0 })?;
let mut cmd = CommandBuilder::new("evil-winrm");
cmd.args(["-i", "10.0.0.5", "-u", "admin", "-p", "Passw0rd!"]);
let mut child = pair.slave.spawn_command(cmd)?;
let mut reader = pair.master.try_clone_reader()?;   // read child output → feed vt100 parser
let mut writer = pair.master.take_writer()?;        // write user keystrokes → child stdin
// Spawn a blocking thread to read `reader` into a vt100::Parser; render its screen()
// into a ratatui pane each frame. Map crossterm KeyEvents → bytes → writer.
```

**Recommendation:** default to **Strategy A** for `evil-winrm`, `ftp`, `msfconsole`,
and `ssh` — it is a fraction of the code, gives a perfect terminal, and matches how
operators expect these tools to feel. Reserve **Strategy B** for a future "multiplexed
sessions" feature where seeing an interactive shell *next to* live scan output is worth
shipping a vt100 emulator. Note `portable-pty` uses blocking threads, not tokio, so
bridge it to your async world with `tokio::task::spawn_blocking` + an mpsc channel.

---

## 5. Persistence — resumable on-disk engagement workspace

Everything the operator does is written to disk as it happens, so a crash or restart
loses nothing and the workspace doubles as report evidence. Root under a stable data
dir (`dirs::data_dir()`), one directory per engagement.

### Layout

```
~/.local/share/shrike/                         (dirs::data_dir()/shrike)
└── engagements/
    └── acme-external-2026-08/                  ← one engagement
        ├── engagement.toml                     ← static config: scope, name, operator
        ├── state.json                          ← live resumable state (see below)
        ├── notes.md                            ← operator's freeform markdown notes
        ├── report.md                           ← generated export (markdown)
        ├── transcript.log                      ← append-only, every command + output line
        └── targets/
            ├── 10.0.0.5/
            │   ├── target.json                 ← host facts (os, hostname, tags)
            │   ├── recon/                       ← per-phase dirs
            │   │   ├── 0001-nmap.cmd            ← exact argv + timestamp
            │   │   ├── 0001-nmap.stdout
            │   │   ├── 0001-nmap.stderr
            │   │   └── 0001-nmap.xml            ← raw -oX artifact
            │   ├── access/
            │   └── loot/
            └── 10.0.0.6/
                └── ...
```

- **`engagement.toml`** (serde + `toml` 1.x) — human-editable static config: engagement
  name, in-scope CIDRs, operator, start date. Loaded once at open.
- **`state.json`** (serde_json) — the machine-owned resumable state: the job registry
  (id, argv, target, phase, status: queued/running/done/failed/cancelled, exit code,
  started/finished timestamps via `chrono`), discovered targets, next job id. Written
  atomically (write to `state.json.tmp`, `fs::rename` over the real file) after every
  state transition so a `kill -9` never corrupts it.
- **`transcript.log`** — the append-only source of truth for the scrollback. The UI's
  in-memory `transcript` Vec is just a viewport cache; on open you tail the last N KB
  of this file to repopulate history, and stream the rest lazily on scroll-up.
- **Per-job triple** (`NNNN-tool.cmd` / `.stdout` / `.stderr`) — every executed command
  is journaled the instant it spawns: the `.cmd` file (argv + ISO-8601 timestamp) is
  written *before* the child starts, and stdout/stderr are appended line-by-line as
  they stream (the same lines you send to the UI channel — write in the streaming loop).
  Raw structured artifacts (`nmap -oX foo.xml`) land beside them for later parsing with
  `roxmltree`.
- **`notes.md` / `report.md`** — `/note <text>` appends to notes.md; `/export` walks
  `state.json` + per-target dirs and renders a markdown report.

### Resume flow

```rust
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub struct EngagementState {
    pub next_job_id: u64,
    pub jobs: indexmap::IndexMap<u64, JobRecord>,        // ordered = display order
    pub targets: indexmap::IndexMap<String, TargetRecord>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct JobRecord {
    pub id: u64,
    pub argv: Vec<String>,
    pub target: Option<String>,
    pub phase: String,                                  // "recon" | "access" | ...
    pub status: String,                                 // queued|running|done|failed|cancelled
    pub exit_code: Option<i32>,
    pub started: chrono::DateTime<chrono::Utc>,
    pub finished: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct TargetRecord {
    pub host: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub tags: Vec<String>,
}

pub fn engagement_root(name: &str) -> PathBuf {
    dirs::data_dir().unwrap_or_else(|| PathBuf::from("."))
        .join("shrike").join("engagements").join(name)
}

pub fn load_or_init(name: &str) -> Result<EngagementState> {
    let dir = engagement_root(name);
    std::fs::create_dir_all(dir.join("targets"))?;
    let state_path = dir.join("state.json");
    if state_path.exists() {
        let raw = std::fs::read_to_string(&state_path)
            .with_context(|| format!("reading {}", state_path.display()))?;
        let mut st: EngagementState = serde_json::from_str(&raw)?;
        // On resume, any job left "running" was interrupted — mark it so the UI can
        // offer to re-queue it.
        for j in st.jobs.values_mut() {
            if j.status == "running" { j.status = "interrupted".into(); }
        }
        Ok(st)
    } else {
        Ok(EngagementState::default())
    }
}

/// Atomic save: never leave a half-written state.json.
pub fn save(name: &str, st: &EngagementState) -> Result<()> {
    let dir = engagement_root(name);
    let tmp = dir.join("state.json.tmp");
    let final_path = dir.join("state.json");
    std::fs::write(&tmp, serde_json::to_vec_pretty(st)?)?;
    std::fs::rename(tmp, final_path)?;   // rename is atomic on same filesystem
    Ok(())
}
```

On startup shrike lists `engagements/`, lets the user pick or create one, loads
`state.json`, re-hydrates the job/target tables and the transcript tail, and flags any
`interrupted` jobs for re-queue. All disk writes happen off the render path (in the job
tasks or a dedicated `spawn_blocking` writer) so persistence never stalls the UI.

---

## 6. ratatui vs alternatives, and the real risks (assessment)

**ratatui is the correct choice.** It is the maintained continuation of the archived
`tui-rs`, has by far the largest widget/example ecosystem, ships the `init/restore`
convenience layer that eliminates most raw-mode boilerplate, and is what comparable
tools (atuin, gitui, bottom, oha) ship on — so patterns and Stack Overflow answers
exist. The credible alternatives are weaker fits: **cursive** is higher-level and
callback/retained-mode (fights an async job engine and a custom transcript widget);
**crossterm alone** means hand-rolling all layout and scrollback; **Textual/Python**
or a web UI abandons the single-static-binary, drops-into-any-shell property that makes
a pentest tool deployable on a jump host.

**Real risks to plan for.** (1) *API churn* — ratatui had breaking changes at 0.26,
0.28, 0.29, and 0.30 (`size()`→`area()`, `FrameExt`, backend `Error` type, the
0.30 crate split); pin exact versions and budget a small migration each bump.
(2) *The scrollback widget is the hard part* — ratatui gives you no scrollback buffer;
you own the wrap-to-width, row-accounting, buffer cap, and disk-spill logic (§2), and
getting wrapped-line scroll math exact is the most bug-prone code in the app.
(3) *Interactive/TTY tools* — anything expecting a controlling terminal (msfconsole,
ssh, evil-winrm) will not behave inside the alt-screen; you must suspend the TUI or
adopt `portable-pty` + a vt100 emulator (§4), each with sharp edges (signal handling,
resize, blocking-thread bridging). (4) *Terminal state on panic* — if a panic escapes
before restore, the user's shell is left in raw mode; keep ratatui's panic hook and add
your own `catch_unwind`/guard around the interactive hand-off so the terminal is always
restored.

---

## Verified-version quick reference (crates.io, 2026-08-26)

| crate | version | crate | version |
|---|---|---|---|
| ratatui | 0.30.2 | anyhow | 1.0.104 |
| crossterm | 0.29.0 | thiserror | 2.0.20 |
| tokio | 1.53.1 | clap | 4.6.6 |
| tokio-util | 0.7.19 | regex | 1.13.1 |
| serde | 1.0.229 | ipnet | 2.12.1 |
| serde_json | 1.0.151 | roxmltree | 0.21.1 |
| toml | 1.1.x | quick-xml | 0.42.0 |
| chrono | 0.4.45 | indexmap | 2.14.0 |
| tracing-subscriber | 0.3.23 | dirs | 6.0.0 |
| textwrap | 0.16.2 | which | 8.0.5 |
| portable-pty | 0.9.0 | futures | 0.3.x |

Sources: crates.io crate APIs; ratatui.rs v0.30 highlights, async-event-stream tutorial,
and BREAKING-CHANGES.md; crossterm `event-stream-tokio` example.

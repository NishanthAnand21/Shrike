# SESSIONS.md — Interactive Tool Handoff & Reverse-Shell Listener

Research + compilable reference implementation for two capabilities in the `shrike`
ratatui TUI framework.

## Verified crate versions (as of 2026-08)

```toml
[dependencies]
ratatui       = "0.29"                     # provides ratatui::init() / ratatui::restore()
crossterm     = { version = "0.28", features = ["event-stream"] }
tokio         = { version = "1", features = ["full"] }   # net, io-util, macros, rt-multi-thread, sync, signal
tokio-util    = "0.7"                        # CancellationToken
futures       = "0.3"                        # StreamExt for EventStream.next()
```

Key API facts confirmed against docs.rs / crossterm master:

- **ratatui 0.29** re-exports `ratatui::init() -> DefaultTerminal` and `ratatui::restore()`.
  `init()` = `enable_raw_mode()` + `EnterAlternateScreen` + installs a panic hook that
  restores the terminal, then builds a `Terminal<CrosstermBackend<Stdout>>` (aliased
  `DefaultTerminal`). `restore()` = `disable_raw_mode()` + `LeaveAlternateScreen`.
  (`ratatui::run()` only exists in 0.30+, so we do the suspend/restore by hand.)
- **crossterm 0.28**: `EventStream` requires the `event-stream` feature. It implements
  `futures::Stream<Item = io::Result<Event>>`. Poll it with `StreamExt::next().await`.
  Critical: **only one reader may consume terminal input at a time.** While a child
  process (or the raw-mode socket bridge) owns stdin, the `EventStream` must NOT be
  polled, or the two readers race and steal each other's bytes. The clean fix is to
  drop / stop awaiting the `EventStream` for the duration of the handoff and recreate
  it afterward.
- `crossterm::terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen,
  LeaveAlternateScreen}`, `crossterm::cursor::{Hide, Show}`,
  `crossterm::execute!` — all stable in 0.28.

---

## Shared terminal state helpers

Put these in a `term` module. Everything routes through here so suspend/restore is
symmetric and there is exactly one place that knows the enter/leave sequence.

```rust
use std::io::{self, Stdout, Write};
use crossterm::{
    cursor::{Hide, Show},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Tear the TUI down to a normal cooked terminal so a child process can own the TTY.
/// EXACT reverse order of enter: show cursor -> leave alt screen -> disable raw mode.
pub fn suspend_tui(tui: &mut Tui) -> io::Result<()> {
    // Flush any pending frame first.
    tui.flush()?;
    let mut out = io::stdout();
    execute!(out, Show, LeaveAlternateScreen)?; // cursor visible, back to primary screen
    disable_raw_mode()?;                         // line buffering + echo back on
    out.flush()?;
    Ok(())
}

/// Re-enter the TUI after the child exits. Mirror of suspend, plus a full redraw.
pub fn resume_tui(tui: &mut Tui) -> io::Result<()> {
    let mut out = io::stdout();
    enable_raw_mode()?;
    execute!(out, EnterAlternateScreen, Hide)?;
    out.flush()?;
    // Discard ratatui's cached buffer so the next draw repaints every cell.
    tui.clear()?;                 // clears the known-buffer + screen
    Ok(())
}
```

`tui.clear()` is what prevents corruption: ratatui diffs against its internal buffer,
so after an external program has scribbled on the screen you must invalidate that
buffer or only "changed" cells repaint. `clear()` forces a full redraw on the next
`terminal.draw(...)`.

---

# 1. Interactive tool handoff — `/shell <cmd>`

Runs an interactive TTY child (evil-winrm, ssh, ftp, mssqlclient, msfconsole) with the
real terminal handed straight to it. We **inherit** stdin/stdout/stderr so the child
gets a genuine controlling terminal — no PTY emulation needed, because we are running
on the operator's real TTY.

### The blocking-vs-async question

Yes — you block the event loop for the whole child lifetime, and that is correct.
There is nothing useful for the TUI to do while another full-screen program owns the
screen, and you MUST NOT let `EventStream` poll stdin concurrently. Two safe patterns:

- **Simplest / recommended:** use `std::process::Command` and `.status()` (a blocking
  wait) inside `tokio::task::block_in_place` so you don't stall the whole runtime's
  worker. The async event loop is naturally paused because your handler is `.await`ing
  this call and you are not polling the `EventStream` meanwhile.
- **Alternative:** `tokio::process::Command` + `.status().await`. Also fine; just be
  sure the `EventStream` future is not being polled in the same `select!` arm.

The structural rule: the command dispatcher owns the terminal for the duration. In the
main loop, `select!` over `EventStream` and job-channel; when a `/shell` command is
parsed, break out of the `select!`, run the handoff to completion, then loop again and
build a *fresh* `EventStream`.

### `run_interactive`

```rust
use std::io;
use std::process::{Command, ExitStatus, Stdio};

/// Parse `cmd` (a shell-style string) and run it with the real terminal inherited.
/// Caller MUST have already suspended the TUI and stopped polling EventStream.
pub fn run_interactive(cmd: &str) -> io::Result<ExitStatus> {
    // Split into program + args. For full shell semantics (pipes, quoting) hand the
    // whole string to `sh -c`; for a simple arg vector, split on whitespace.
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::inherit())   // child reads the real keyboard
        .stdout(Stdio::inherit())  // child writes the real screen
        .stderr(Stdio::inherit())
        .spawn()?;
    // Blocking wait — child fully owns the TTY until it exits.
    child.wait()
}
```

### Wiring it into the async loop

```rust
use tokio::task;

/// Called from the command dispatcher when the operator types `/shell <cmd>`.
/// `tui` is the live DefaultTerminal. Returns after the child exits and the TUI
/// has been fully restored. `event_stream` is dropped by the caller before this
/// runs and recreated after (see main loop below).
async fn handle_shell(tui: &mut Tui, cmd: &str) -> io::Result<()> {
    suspend_tui(tui)?;                    // leave alt screen, cooked mode, show cursor

    // Run the (blocking) child without freezing the whole tokio runtime.
    let cmd = cmd.to_string();
    let status = task::block_in_place(|| run_interactive(&cmd))?;

    resume_tui(tui)?;                     // back to raw + alt screen + full redraw

    // Surface the exit status in the TUI log (pseudo).
    // app.log(format!("[shell] `{cmd}` exited with {status}"));
    let _ = status;
    Ok(())
}
```

### Main loop shape (why EventStream is recreated)

```rust
use crossterm::event::{Event, EventStream, KeyCode};
use futures::StreamExt;

async fn run_app(tui: &mut Tui /*, app, job_rx ... */) -> io::Result<()> {
    'outer: loop {
        let mut events = EventStream::new();   // fresh reader each time we own the TTY

        loop {
            tui.draw(|f| { /* ui(f, app) */ })?;

            tokio::select! {
                maybe_ev = events.next() => {
                    let Some(Ok(ev)) = maybe_ev else { continue };
                    if let Event::Key(k) = ev {
                        // ... command palette produces e.g. Command::Shell(cmd)
                        if let Some(cmd) = /* parse_shell(&k) */ None::<String> {
                            // 1. STOP polling this EventStream: drop it by leaving the
                            //    inner loop. This is the crossterm gotcha — the stream
                            //    must not read stdin while the child owns it.
                            drop(events);
                            // 2. Hand off.
                            handle_shell(tui, &cmd).await?;
                            // 3. Restart outer loop -> new EventStream.
                            continue 'outer;
                        }
                        if k.code == KeyCode::Char('q') { return Ok(()); }
                    }
                }
                // job_msg = job_rx.recv() => { /* update app state */ }
            }
        }
    }
}
```

Notes / gotchas:

- **Don't** keep the `EventStream` alive and just "ignore" it — a live `select!` arm
  still polls it and consumes keystrokes meant for the child. Dropping it (leaving the
  inner loop) is the reliable way to release stdin.
- `block_in_place` requires the multi-threaded runtime (`rt-multi-thread`, included in
  `features=["full"]`). On a current-thread runtime use `tokio::process::Command` +
  `.status().await` instead.
- Ratatui's `init()` panic hook already restores the terminal on panic; if you build
  the terminal manually keep an equivalent hook so a child-spawn panic can't leave the
  TTY in raw mode.
- SIGWINCH/resize during the child is handled by the child; on `resume_tui` the
  `tui.clear()` + next `draw` re-fits to the current size automatically.

---

# 2. Reverse-shell listener — `/listen <port>`

A managed TCP listener catching a reverse shell. Design mirrors a job system: a
background tokio task per listener, output streamed to the UI over an `mpsc` channel,
operator input written back to the socket, and an on-demand raw-mode "interactive
bridge" (`nc -lvnp`-style) that hands the real terminal to one session until the
operator presses a detach key (Ctrl-]).

## 2.1 Session model & registry

```rust
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

pub type SessionId = u64;

/// A message from a listener/session task to the UI (same spirit as JobEvent).
#[derive(Debug)]
pub enum SessionEvent {
    Listening { id: SessionId, port: u16 },
    Connected { id: SessionId, peer: SocketAddr },
    Output    { id: SessionId, data: Vec<u8> },   // raw bytes; UI lossily renders
    Closed    { id: SessionId, reason: String },
    ListenError { id: SessionId, error: String },
}

/// Live handle the UI keeps for each caught shell.
pub struct Session {
    pub id: SessionId,
    pub peer: SocketAddr,
    /// Send operator-typed commands into the socket (non-interactive mode).
    pub to_socket: mpsc::UnboundedSender<Vec<u8>>,
    /// Scrollback the UI paints.
    pub scrollback: Vec<u8>,
    /// Owned during an interactive bridge so no one else reads/writes the socket.
    pub stream: Arc<Mutex<Option<TcpStream>>>,
    pub cancel: CancellationToken,
}

#[derive(Default)]
pub struct SessionRegistry {
    pub sessions: HashMap<SessionId, Session>,
    next_id: SessionId,
}

impl SessionRegistry {
    pub fn alloc_id(&mut self) -> SessionId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}
```

## 2.2 Listener accept loop as a background task

Binds `0.0.0.0:<port>`, accepts connections, and for each spawns a reader task that
streams socket bytes to the UI and a writer path fed by an mpsc. A
`CancellationToken` cleanly stops the whole listener (operator `/kill <id>` or app
shutdown).

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawn the listener. Returns immediately; work happens in the background task.
/// `ui_tx` is the shared channel the main loop drains (like job events).
pub fn spawn_listener(
    listen_id: SessionId,
    port: u16,
    ui_tx: mpsc::UnboundedSender<SessionEvent>,
    cancel: CancellationToken,
    // A way to register a freshly-accepted session with the shared registry:
    registry: Arc<Mutex<SessionRegistry>>,
) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(("0.0.0.0", port)).await {
            Ok(l) => l,
            Err(e) => {
                let _ = ui_tx.send(SessionEvent::ListenError {
                    id: listen_id, error: e.to_string(),
                });
                return;
            }
        };
        let _ = ui_tx.send(SessionEvent::Listening { id: listen_id, port });

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,        // /kill or shutdown
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = ui_tx.send(SessionEvent::ListenError {
                                id: listen_id, error: e.to_string(),
                            });
                            continue;
                        }
                    };
                    handle_new_shell(stream, peer, &ui_tx, &registry).await;
                    // Keep listening for additional callbacks (multi-session).
                }
            }
        }
    });
}

/// Register one accepted shell and start its reader+writer pumps.
async fn handle_new_shell(
    stream: TcpStream,
    peer: SocketAddr,
    ui_tx: &mpsc::UnboundedSender<SessionEvent>,
    registry: &Arc<Mutex<SessionRegistry>>,
) {
    let _ = stream.set_nodelay(true);

    let (id, cancel, to_socket_rx) = {
        let mut reg = registry.lock().await;
        let id = reg.alloc_id();
        let cancel = CancellationToken::new();
        let (to_tx, to_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let shared = Arc::new(Mutex::new(Some(stream)));   // filled below
        reg.sessions.insert(id, Session {
            id, peer,
            to_socket: to_tx,
            scrollback: Vec::new(),
            stream: shared.clone(),
            cancel: cancel.clone(),
        });
        (id, cancel, to_rx)
    };

    let _ = ui_tx.send(SessionEvent::Connected { id, peer });

    // Pull the stream back out of the registry's Option to split it for the pumps.
    // While the pumps run, `stream` slot is None; on detach we put a stream back for
    // the interactive bridge (see 2.4). For simplicity here we split immediately.
    let stream = {
        let reg = registry.lock().await;
        reg.sessions.get(&id).unwrap().stream.clone()
    };

    spawn_pumps(id, stream, to_socket_rx, ui_tx.clone(), cancel);
}
```

## 2.3 Reader + writer pumps (non-interactive streaming)

Socket -> UI (via `SessionEvent::Output`) and mpsc -> socket (operator commands).
This is the "managed" mode: the shell runs in the background and the operator can fire
one-off commands and watch scrollback without leaving the TUI.

```rust
fn spawn_pumps(
    id: SessionId,
    stream: Arc<Mutex<Option<TcpStream>>>,
    mut to_socket_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ui_tx: mpsc::UnboundedSender<SessionEvent>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        // Take ownership of the stream and split it into read/write halves.
        let taken = { stream.lock().await.take() };
        let Some(sock) = taken else {
            let _ = ui_tx.send(SessionEvent::Closed { id, reason: "no stream".into() });
            return;
        };
        let (mut rd, mut wr) = tokio::io::split(sock);
        let mut buf = [0u8; 8192];

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    let _ = ui_tx.send(SessionEvent::Closed { id, reason: "cancelled".into() });
                    return;
                }
                // Socket -> UI
                n = rd.read(&mut buf) => match n {
                    Ok(0) => {
                        let _ = ui_tx.send(SessionEvent::Closed { id, reason: "peer closed".into() });
                        return;
                    }
                    Ok(n) => {
                        let _ = ui_tx.send(SessionEvent::Output { id, data: buf[..n].to_vec() });
                    }
                    Err(e) => {
                        let _ = ui_tx.send(SessionEvent::Closed { id, reason: e.to_string() });
                        return;
                    }
                },
                // Operator command -> socket
                cmd = to_socket_rx.recv() => match cmd {
                    Some(bytes) => {
                        if wr.write_all(&bytes).await.is_err() {
                            let _ = ui_tx.send(SessionEvent::Closed { id, reason: "write failed".into() });
                            return;
                        }
                        let _ = wr.flush().await;
                    }
                    None => { /* sender dropped; keep reading socket */ }
                },
            }
        }
    });
}
```

The UI drains `SessionEvent`s in the same `select!` as everything else and appends
`Output` bytes to `session.scrollback`. Operator sends a command with
`session.to_socket.send(format!("{cmd}\n").into_bytes())`.

## 2.4 Interactive bridge (raw-mode `nc`-style handoff)

Operator runs `/interact <id>`: suspend the TUI, take exclusive ownership of that
session's socket, and copy stdin<->socket in raw mode until a detach key (Ctrl-],
byte `0x1d`, like telnet). Then restore the TUI and hand the socket back to the pumps.

Because we need to detect the detach byte in the stdin stream, we can't use
`copy_bidirectional` for the stdin->socket direction (it has no escape hatch). We run a
manual `select!` loop: `copy_bidirectional` is fine when you don't need an escape key,
but here we scan stdin bytes.

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DETACH_BYTE: u8 = 0x1d; // Ctrl-]

/// Bridge the real terminal to `sock` in raw mode until the operator hits Ctrl-].
/// Precondition: TUI already suspended (suspend_tui) AND the EventStream dropped, so
/// nothing else is reading stdin. crossterm raw mode is enabled here explicitly.
async fn interactive_bridge(sock: TcpStream) -> io::Result<TcpStream> {
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    enable_raw_mode()?;                       // byte-at-a-time stdin, no echo

    let (mut rd, mut wr) = tokio::io::split(sock);
    // tokio async stdin/stdout. stdin() uses a blocking pool internally but is fine
    // for interactive rates; reads deliver bytes as typed because we're in raw mode.
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let mut sbuf = [0u8; 8192];   // socket -> screen
    let mut kbuf = [0u8; 1024];   // keyboard -> socket

    let result = loop {
        tokio::select! {
            // Remote output -> local screen
            n = rd.read(&mut sbuf) => match n {
                Ok(0) => break Ok(()),                    // peer closed
                Ok(n) => { stdout.write_all(&sbuf[..n]).await?; stdout.flush().await?; }
                Err(e) => break Err(e),
            },
            // Local keystrokes -> remote, scanning for the detach byte
            n = stdin.read(&mut kbuf) => match n {
                Ok(0) => break Ok(()),                    // stdin EOF
                Ok(n) => {
                    if let Some(pos) = kbuf[..n].iter().position(|&b| b == DETACH_BYTE) {
                        // Forward everything before the detach byte, then bail.
                        if pos > 0 { wr.write_all(&kbuf[..pos]).await?; wr.flush().await?; }
                        break Ok(());
                    }
                    wr.write_all(&kbuf[..n]).await?;
                    wr.flush().await?;
                }
                Err(e) => break Err(e),
            },
        }
    };

    disable_raw_mode()?;                      // caller's resume_tui re-enables it
    // Reunite the halves into the original stream to hand back to the pumps.
    let sock = rd.unsplit(wr);
    result.map(|_| sock)
}
```

### `copy_bidirectional` alternative

If you don't need a detach key (e.g. you detach by killing the session from another
control channel), the bridge body collapses to:

```rust
// Requires raw mode already enabled and the socket owned exclusively.
let mut stdin  = tokio::io::stdin();
let mut stdout = tokio::io::stdout();
// Wrap the pair so copy_bidirectional sees one duplex object:
let mut local = tokio::io::join(stdin, stdout);   // tokio::io::join(reader, writer)
tokio::io::copy_bidirectional(&mut local, &mut sock).await?;
```

We prefer the manual loop because operators expect a telnet-style escape (Ctrl-]) to
get back to the TUI without dropping the shell.

## 2.5 Driving the bridge from the dispatcher

```rust
async fn handle_interact(
    tui: &mut Tui,
    registry: &Arc<Mutex<SessionRegistry>>,
    id: SessionId,
) -> io::Result<()> {
    // 1. Reclaim the socket from the pumps. Signal the pump to release: simplest is to
    //    have the pump store the stream back into the Arc<Mutex<Option<..>>> on a
    //    "detach requested" flag, or (cleaner) design so /interact cancels the pump,
    //    which drops its half and lets us re-own. Here we assume the socket is parked
    //    in the registry slot.
    let sock = {
        let reg = registry.lock().await;
        let Some(s) = reg.sessions.get(&id) else { return Ok(()); };
        s.stream.lock().await.take()
    };
    let Some(sock) = sock else {
        // app.log("session busy or gone");
        return Ok(());
    };

    // 2. Suspend TUI. Caller has ALREADY dropped the EventStream (see main loop).
    suspend_tui(tui)?;

    // 3. Bridge until Ctrl-] or peer close.
    let restored = interactive_bridge(sock).await;

    // 4. Restore TUI.
    resume_tui(tui)?;

    // 5. Hand the socket back so background streaming resumes (if peer still up).
    if let Ok(sock) = restored {
        let reg = registry.lock().await;
        if let Some(s) = reg.sessions.get(&id) {
            *s.stream.lock().await = Some(sock);
            // re-spawn pumps for this session here if your design tears them down
        }
    }
    Ok(())
}
```

## 2.6 Concurrency & multi-session notes

- **Registry** is `Arc<Mutex<SessionRegistry>>` shared between the accept loop, pumps,
  and the UI. Keyed by `SessionId` so any number of concurrent shells coexist; the UI
  shows a session list and `/interact <id>` / `/kill <id>` target one.
- **One reader rule (again):** the interactive bridge and the background pump must not
  both hold the socket. The `Arc<Mutex<Option<TcpStream>>>` slot enforces "exactly one
  owner": pump `take()`s it to run; `/interact` requires taking it, so you must first
  stop the pump (cancel its token or use a dedicated detach signal) before the bridge
  can own it. Pick one ownership protocol and stick to it — mixing leads to interleaved
  reads.
- **CancellationToken** per listener AND optionally per session. `/kill <id>` cancels
  the session token (pump exits, socket dropped -> peer sees close). App shutdown
  cancels all listener tokens.
- **Backpressure:** `Output` uses an unbounded channel for simplicity; a fast-spewing
  shell can grow memory. For production, cap `scrollback` length in the UI and/or use a
  bounded channel with `try_send` + drop-oldest.
- **Same crossterm gotcha as `/shell`:** before calling `handle_interact`, the main
  loop must drop the `EventStream` (leave the inner select loop) so the raw stdin read
  in `interactive_bridge` is the only consumer. Recreate `EventStream` on return.

---

## Summary of the two invariants that prevent corruption

1. **Symmetric terminal state.** Every enter has a matching leave in reverse order
   (`suspend_tui` / `resume_tui`), and `resume_tui` calls `tui.clear()` to force a full
   repaint of ratatui's diff buffer.
2. **Single stdin consumer.** crossterm's `EventStream` must be dropped (not merely
   paused) whenever a child process or the raw socket bridge owns the terminal; a fresh
   `EventStream` is created after control returns.

## Sources

- ratatui `init`/`restore`: https://docs.rs/ratatui/latest/ratatui/fn.restore.html , https://docs.rs/ratatui/latest/ratatui/fn.init.html
- crossterm EventStream: https://docs.rs/crossterm/latest/crossterm/event/struct.EventStream.html , https://github.com/crossterm-rs/crossterm/blob/master/examples/event-stream-tokio.rs
- Ratatui async event stream tutorial: https://ratatui.rs/tutorials/counter-async-app/async-event-stream/
- tokio `copy_bidirectional` / `split` / `join`: https://docs.rs/tokio/latest/tokio/io/fn.copy_bidirectional.html

//! Managed reverse-shell listeners and caught sessions.
//!
//! Design (research/SESSIONS.md, with one simplification): each caught shell gets a
//! background "pump" task that OWNS its socket for the task's whole life. Streaming
//! mode and interactive-bridge mode are two select-loops inside that one task, chosen
//! by a control message — so the socket is never handed between tasks and there is no
//! ownership race. The UI talks to a session only through channels.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::sync::CancellationToken;

pub type SessionId = u64;

const DETACH_BYTE: u8 = 0x1d; // Ctrl-]

/// Events from listener/session tasks to the UI (drained in the main select loop).
#[derive(Debug)]
pub enum SessionEvent {
    Listening { id: SessionId, port: u16 },
    ListenError { id: SessionId, error: String },
    Connected { id: SessionId, peer: SocketAddr },
    Output { id: SessionId, text: String },
    Closed { id: SessionId, reason: String },
}

/// Control messages to a session pump.
enum Ctrl {
    /// Enter raw-mode interactive bridge; signal `done` when the operator detaches.
    Interact(oneshot::Sender<()>),
}

/// UI-side handle for one caught shell.
pub struct SessionHandle {
    pub id: SessionId,
    pub peer: SocketAddr,
    pub connected: String,
    pub alive: bool,
    to_socket: mpsc::UnboundedSender<Vec<u8>>,
    ctrl: mpsc::UnboundedSender<Ctrl>,
    cancel: CancellationToken,
}

impl SessionHandle {
    /// Fire a one-off command into the shell (appends a newline).
    pub fn send_cmd(&self, cmd: &str) -> bool {
        let mut bytes = cmd.as_bytes().to_vec();
        bytes.push(b'\n');
        self.to_socket.send(bytes).is_ok()
    }
    pub fn kill(&self) {
        self.cancel.cancel();
    }
}

/// UI-side handle for one listener.
pub struct ListenerHandle {
    pub id: SessionId,
    pub port: u16,
    pub cancel: CancellationToken,
}

#[derive(Default)]
pub struct Registry {
    pub sessions: HashMap<SessionId, SessionHandle>,
    pub listeners: HashMap<SessionId, ListenerHandle>,
    next_id: SessionId,
}

impl Registry {
    fn alloc(&mut self) -> SessionId {
        let id = self.next_id + 1;
        self.next_id = id;
        id
    }
    pub fn alive_sessions(&self) -> usize {
        self.sessions.values().filter(|s| s.alive).count()
    }
}

/// Start a listener on 0.0.0.0:port. Returns the listener id (also usable with /kill).
pub async fn listen(
    reg: Arc<Mutex<Registry>>,
    ui_tx: mpsc::UnboundedSender<SessionEvent>,
    port: u16,
) -> SessionId {
    let (lid, cancel) = {
        let mut r = reg.lock().await;
        let id = r.alloc();
        let cancel = CancellationToken::new();
        r.listeners.insert(
            id,
            ListenerHandle {
                id,
                port,
                cancel: cancel.clone(),
            },
        );
        (id, cancel)
    };

    let reg2 = reg.clone();
    tokio::spawn(async move {
        let listener = match TcpListener::bind(("0.0.0.0", port)).await {
            Ok(l) => l,
            Err(e) => {
                let _ = ui_tx.send(SessionEvent::ListenError {
                    id: lid,
                    error: e.to_string(),
                });
                reg2.lock().await.listeners.remove(&lid);
                return;
            }
        };
        let _ = ui_tx.send(SessionEvent::Listening { id: lid, port });
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let _ = stream.set_nodelay(true);
                        spawn_session(reg2.clone(), ui_tx.clone(), stream, peer).await;
                    }
                    Err(e) => {
                        let _ = ui_tx.send(SessionEvent::ListenError { id: lid, error: e.to_string() });
                    }
                }
            }
        }
        reg2.lock().await.listeners.remove(&lid);
    });
    lid
}

async fn spawn_session(
    reg: Arc<Mutex<Registry>>,
    ui_tx: mpsc::UnboundedSender<SessionEvent>,
    stream: TcpStream,
    peer: SocketAddr,
) {
    let (to_tx, to_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<Ctrl>();
    let cancel = CancellationToken::new();
    let id = {
        let mut r = reg.lock().await;
        let id = r.alloc();
        r.sessions.insert(
            id,
            SessionHandle {
                id,
                peer,
                connected: crate::model::state::now_iso(),
                alive: true,
                to_socket: to_tx,
                ctrl: ctrl_tx,
                cancel: cancel.clone(),
            },
        );
        id
    };
    let _ = ui_tx.send(SessionEvent::Connected { id, peer });
    pump(id, stream, to_rx, ctrl_rx, ui_tx, cancel);
}

/// The single owner of one session's socket. Streams by default; bridges on request.
fn pump(
    id: SessionId,
    stream: TcpStream,
    mut to_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut ctrl_rx: mpsc::UnboundedReceiver<Ctrl>,
    ui_tx: mpsc::UnboundedSender<SessionEvent>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut buf = [0u8; 8192];
        let reason = loop {
            tokio::select! {
                _ = cancel.cancelled() => break "killed".to_string(),
                n = rd.read(&mut buf) => match n {
                    Ok(0) => break "peer closed".to_string(),
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                        let _ = ui_tx.send(SessionEvent::Output { id, text });
                    }
                    Err(e) => break e.to_string(),
                },
                cmd = to_rx.recv() => if let Some(bytes) = cmd {
                    if wr.write_all(&bytes).await.is_err() { break "write failed".into(); }
                    let _ = wr.flush().await;
                },
                ctrl = ctrl_rx.recv() => if let Some(Ctrl::Interact(done)) = ctrl {
                    // Bridge stdin<->socket in raw mode until Ctrl-] or peer close.
                    let closed = bridge(&mut rd, &mut wr, &cancel).await;
                    let _ = done.send(());
                    if closed { break "peer closed".into(); }
                },
            }
        };
        let _ = ui_tx.send(SessionEvent::Closed { id, reason });
    });
}

/// Raw-mode passthrough between the real terminal and the socket halves.
/// Returns true if the peer closed (session is dead), false on operator detach.
async fn bridge<R, W>(rd: &mut R, wr: &mut W, cancel: &CancellationToken) -> bool
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    let _ = enable_raw_mode();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut sbuf = [0u8; 8192];
    let mut kbuf = [0u8; 1024];
    let peer_closed = loop {
        tokio::select! {
            _ = cancel.cancelled() => break true,
            n = rd.read(&mut sbuf) => match n {
                Ok(0) => break true,
                Ok(n) => {
                    let _ = stdout.write_all(&sbuf[..n]).await;
                    let _ = stdout.flush().await;
                }
                Err(_) => break true,
            },
            n = stdin.read(&mut kbuf) => match n {
                Ok(0) => break false,
                Ok(n) => {
                    if let Some(pos) = kbuf[..n].iter().position(|&b| b == DETACH_BYTE) {
                        if pos > 0 { let _ = wr.write_all(&kbuf[..pos]).await; let _ = wr.flush().await; }
                        break false;
                    }
                    let _ = wr.write_all(&kbuf[..n]).await;
                    let _ = wr.flush().await;
                }
                Err(_) => break false,
            },
        }
    };
    let _ = disable_raw_mode();
    peer_closed
}

/// Request the interactive bridge for a session; returns a receiver that fires when
/// the operator detaches (or the peer closes). Returns None if the session is gone.
pub async fn request_interact(
    reg: &Arc<Mutex<Registry>>,
    id: SessionId,
) -> Option<oneshot::Receiver<()>> {
    let r = reg.lock().await;
    let s = r.sessions.get(&id)?;
    let (done_tx, done_rx) = oneshot::channel();
    if s.ctrl.send(Ctrl::Interact(done_tx)).is_err() {
        return None;
    }
    Some(done_rx)
}

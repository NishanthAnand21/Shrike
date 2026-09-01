//! A tiny read-only web dashboard. Serves the engagement (reusing the HTML report
//! renderer) over HTTP on localhost so the operator can watch it in a browser.
//! No new crates — a minimal tokio HTTP/1.1 responder. Read-only and local.

use crate::model::state::Engagement;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Shared snapshot the server renders. The app refreshes it as state changes.
pub type Snapshot = Arc<std::sync::Mutex<String>>;

/// Render the current engagement to an HTML page for the dashboard.
pub fn render_snapshot(eng: &Engagement) -> String {
    crate::notes::html::render(eng)
}

/// Start the dashboard server. Returns immediately; serves until `cancel`.
/// `on_msg` receives human status lines to surface in the UI.
pub fn serve(
    port: u16,
    snapshot: Snapshot,
    cancel: CancellationToken,
    status: tokio::sync::mpsc::UnboundedSender<String>,
) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => l,
            Err(e) => {
                let _ = status.send(format!("web dashboard failed: {e}"));
                return;
            }
        };
        let _ = status.send(format!("web dashboard → http://127.0.0.1:{port}"));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                accepted = listener.accept() => {
                    if let Ok((mut sock, _)) = accepted {
                        let snap = snapshot.clone();
                        tokio::spawn(async move {
                            let mut buf = [0u8; 2048];
                            let _ = sock.read(&mut buf).await; // consume the request line/headers
                            let req = String::from_utf8_lossy(&buf);
                            let path = req.split_whitespace().nth(1).unwrap_or("/");
                            let body = if path.starts_with("/health") {
                                "ok".to_string()
                            } else {
                                snap.lock().map(|p| p.clone()).unwrap_or_default()
                            };
                            let ctype = if path.starts_with("/health") { "text/plain" } else { "text/html; charset=utf-8" };
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nRefresh: 5\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                            let _ = sock.flush().await;
                        });
                    }
                }
            }
        }
    });
}

//! Interactive web GUI. Serves the engagement (the HTML report) plus a command
//! bar that POSTs back to the running engine over a channel. Localhost-only and
//! token-gated so only this operator can drive it. A minimal hand-rolled HTTP
//! server on tokio — no new deps.

use crate::model::state::Engagement;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub type Snapshot = Arc<std::sync::Mutex<String>>;

/// Render the engagement report body for the dashboard.
pub fn render_snapshot(eng: &Engagement) -> String {
    crate::notes::html::render(eng)
}

/// Wrap the report with an interactive command bar (token-gated).
fn wrap_interactive(report_body: &str, token: &str) -> String {
    // The report is a full HTML doc; we inject a fixed command bar + script.
    let bar = format!(
        r#"<div id="shrike-bar" style="position:fixed;top:0;left:0;right:0;z-index:9999;background:#0b0d12;border-bottom:1px solid #56b6c2;padding:8px 14px;display:flex;gap:8px;align-items:center;font-family:ui-monospace,Menlo,monospace">
<span style="color:#56b6c2;font-weight:700">shrike ❯</span>
<input id="shrike-cmd" placeholder="type a command (e.g. /suggest, /run nmap-full, /next) and press Enter" style="flex:1;background:#161922;border:1px solid #232838;color:#c8cdd7;padding:6px 10px;border-radius:6px;font-family:inherit"/>
<span id="shrike-msg" style="color:#7a8090;font-size:12px"></span>
</div>
<div style="height:44px"></div>
<script>
const TOKEN={token:?};
const inp=document.getElementById('shrike-cmd');
const msg=document.getElementById('shrike-msg');
inp.addEventListener('keydown',async e=>{{
  if(e.key!=='Enter')return;
  const cmd=inp.value; if(!cmd.trim())return;
  inp.value=''; msg.textContent='running…';
  try{{
    const r=await fetch('/cmd',{{method:'POST',headers:{{'X-Shrike-Token':TOKEN}},body:cmd}});
    msg.textContent=r.ok?'sent ✓ (refreshing)':'error '+r.status;
    setTimeout(()=>location.reload(),900);
  }}catch(err){{msg.textContent='error: '+err}}
}});
</script>"#,
        token = token
    );
    // Insert the bar right after <body>.
    if let Some(i) = report_body.find("<body>") {
        let (a, b) = report_body.split_at(i + "<body>".len());
        format!("{a}{bar}{b}")
    } else {
        format!("{bar}{report_body}")
    }
}

fn header_val(req: &str, name: &str) -> Option<String> {
    let name_l = name.to_ascii_lowercase();
    for line in req.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().to_ascii_lowercase() == name_l {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Start the interactive dashboard. `cmd_tx` receives commands typed in the browser.
#[allow(clippy::too_many_arguments)]
pub fn serve(
    port: u16,
    token: String,
    snapshot: Snapshot,
    cmd_tx: mpsc::UnboundedSender<String>,
    cancel: CancellationToken,
    status: mpsc::UnboundedSender<String>,
) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => l,
            Err(e) => {
                let _ = status.send(format!("web GUI failed: {e}"));
                return;
            }
        };
        let _ = status.send(format!(
            "web GUI → http://127.0.0.1:{port}/  (token {token})"
        ));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                accepted = listener.accept() => {
                    if let Ok((mut sock, _)) = accepted {
                        let snap = snapshot.clone();
                        let tok = token.clone();
                        let ctx = cmd_tx.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 16384];
                            let n = sock.read(&mut buf).await.unwrap_or(0);
                            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                            let line = req.lines().next().unwrap_or("");
                            let mut parts = line.split_whitespace();
                            let method = parts.next().unwrap_or("");
                            let path = parts.next().unwrap_or("/");

                            let (status_line, ctype, body) = if method == "POST" && path.starts_with("/cmd") {
                                let ok = header_val(&req, "X-Shrike-Token").as_deref() == Some(tok.as_str());
                                if ok {
                                    let cmd = req.rsplit("\r\n\r\n").next().unwrap_or("").trim().to_string();
                                    if !cmd.is_empty() {
                                        let _ = ctx.send(cmd);
                                    }
                                    ("200 OK", "text/plain", "ok".to_string())
                                } else {
                                    ("403 Forbidden", "text/plain", "bad token".to_string())
                                }
                            } else if path.starts_with("/health") {
                                ("200 OK", "text/plain", "ok".to_string())
                            } else {
                                let report = snap.lock().map(|p| p.clone()).unwrap_or_default();
                                ("200 OK", "text/html; charset=utf-8", wrap_interactive(&report, &tok))
                            };
                            let refresh = if ctype.starts_with("text/html") { "Refresh: 6\r\n" } else { "" };
                            let resp = format!(
                                "HTTP/1.1 {status_line}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n{refresh}Connection: close\r\n\r\n{body}",
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

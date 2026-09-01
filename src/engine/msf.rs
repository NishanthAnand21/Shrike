//! Minimal Metasploit RPC (msfrpcd) client. MSF RPC is MessagePack-RPC over HTTP:
//! POST /api/ with a msgpack array [method, token?, args...]; the reply is a
//! msgpack map. We hand-roll the HTTP POST over tokio and use rmpv for the values.
//!
//! Start the daemon with:  msfrpcd -U <user> -P <pass> -p 55552 -S   (or -a 127.0.0.1)
//! This lets shrike drive a real Metasploit instance rather than reimplementing it.

use anyhow::{anyhow, bail, Result};
use rmpv::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct MsfClient {
    pub host: String,
    pub port: u16,
    pub token: String,
}

fn s(v: &str) -> Value {
    Value::String(v.to_string().into())
}

/// Look up a string field in a msgpack map reply.
fn map_get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    if let Value::Map(entries) = v {
        for (k, val) in entries {
            if k.as_str() == Some(key) {
                return Some(val);
            }
        }
    }
    None
}

fn as_string(v: &Value) -> String {
    match v {
        Value::String(us) => us.as_str().unwrap_or("").to_string(),
        Value::Binary(b) => String::from_utf8_lossy(b).into_owned(),
        other => other.to_string(),
    }
}

/// One MessagePack-RPC call to msfrpcd. Returns the decoded reply value.
async fn call(host: &str, port: u16, args: Vec<Value>) -> Result<Value> {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Array(args))?;

    let req = format!(
        "POST /api/ HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: binary/message-pack\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    let mut sock = TcpStream::connect((host, port)).await?;
    sock.write_all(req.as_bytes()).await?;
    sock.write_all(&body).await?;
    sock.flush().await?;

    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await?;

    // Split HTTP headers from the msgpack body.
    let sep = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("no HTTP body in msfrpcd reply"))?;
    let payload = &buf[sep + 4..];
    let mut rd = payload;
    let val = rmpv::decode::read_value(&mut rd)?;

    // msfrpcd signals errors with an "error" key.
    if let Some(err) = map_get(&val, "error") {
        if err.as_bool() == Some(true) {
            let msg = map_get(&val, "error_message")
                .map(as_string)
                .unwrap_or_else(|| "MSF error".into());
            bail!("{msg}");
        }
    }
    Ok(val)
}

impl MsfClient {
    /// auth.login -> token.
    pub async fn login(host: &str, port: u16, user: &str, pass: &str) -> Result<MsfClient> {
        let reply = call(host, port, vec![s("auth.login"), s(user), s(pass)]).await?;
        match map_get(&reply, "result").map(as_string).as_deref() {
            Some("success") => {
                let token = map_get(&reply, "token")
                    .map(as_string)
                    .ok_or_else(|| anyhow!("no token"))?;
                Ok(MsfClient {
                    host: host.to_string(),
                    port,
                    token,
                })
            }
            _ => bail!("authentication failed"),
        }
    }

    pub async fn version(&self) -> Result<String> {
        let r = call(
            &self.host,
            self.port,
            vec![s("core.version"), s(&self.token)],
        )
        .await?;
        Ok(format!(
            "Metasploit {} (ruby {})",
            map_get(&r, "version").map(as_string).unwrap_or_default(),
            map_get(&r, "ruby").map(as_string).unwrap_or_default()
        ))
    }

    /// console.create -> console id.
    pub async fn console_create(&self) -> Result<String> {
        let r = call(
            &self.host,
            self.port,
            vec![s("console.create"), s(&self.token)],
        )
        .await?;
        map_get(&r, "id")
            .map(as_string)
            .ok_or_else(|| anyhow!("no console id"))
    }

    /// console.write: send a command (newline appended).
    pub async fn console_write(&self, cid: &str, data: &str) -> Result<()> {
        let line = format!("{data}\n");
        call(
            &self.host,
            self.port,
            vec![s("console.write"), s(&self.token), s(cid), s(&line)],
        )
        .await?;
        Ok(())
    }

    /// console.read -> (output, busy).
    pub async fn console_read(&self, cid: &str) -> Result<(String, bool)> {
        let r = call(
            &self.host,
            self.port,
            vec![s("console.read"), s(&self.token), s(cid)],
        )
        .await?;
        let data = map_get(&r, "data").map(as_string).unwrap_or_default();
        let busy = map_get(&r, "busy")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Ok((data, busy))
    }

    /// session.list -> a human summary line per active session.
    pub async fn sessions(&self) -> Result<Vec<String>> {
        let r = call(
            &self.host,
            self.port,
            vec![s("session.list"), s(&self.token)],
        )
        .await?;
        let mut out = vec![];
        if let Value::Map(entries) = &r {
            for (id, info) in entries {
                let t = map_get(info, "type").map(as_string).unwrap_or_default();
                let tgt = map_get(info, "tunnel_peer")
                    .map(as_string)
                    .unwrap_or_default();
                let via = map_get(info, "via_exploit")
                    .map(as_string)
                    .unwrap_or_default();
                out.push(format!(
                    "session {} [{}] {} via {}",
                    as_string(id),
                    t,
                    tgt,
                    via
                ));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn msgpack_roundtrip() {
        // Ensure our request encoding is valid msgpack that decodes back.
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &Value::Array(vec![s("auth.login"), s("u"), s("p")]),
        )
        .unwrap();
        let mut rd = &body[..];
        let back = rmpv::decode::read_value(&mut rd).unwrap();
        assert_eq!(back.as_array().unwrap().len(), 3);
        assert_eq!(back.as_array().unwrap()[0].as_str(), Some("auth.login"));
    }
}

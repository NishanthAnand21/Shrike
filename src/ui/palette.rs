//! The slash-command palette: parses operator input into actions.

#[derive(Debug, Clone)]
pub enum Action {
    /// Run a catalog tool by id against the current target (or global).
    RunTool(String),
    /// Run a raw shell command as a job in the given phase.
    RunRaw(String),
    /// Import an nmap XML file.
    Import(String),
    /// Add a target (IP/CIDR/hostfile).
    AddTarget(String),
    /// Select the current host context by IP.
    Focus(String),
    /// Add a credential:  user:pass  or  domain/user:pass
    AddCred(String),
    /// Harvest creds/intel from a text blob or file.
    Harvest(String),
    /// Set a variable: proxy, iface, domain, dc, wordlist=...
    Set(String, String),
    /// Show suggestions for the current context.
    Suggest,
    /// Cancel a running job by id (or all).
    Cancel(Option<u64>),
    /// Export notes.md now.
    Export,
    /// Star the last command's record.
    Star,
    /// Cycle the phase filter.
    Phase(Option<String>),
    Help,
    Quit,
    /// Generate a payload: id [lhost] [lport] [+transform]
    Payload(String),
    /// Build an msfvenom command: id [lhost] [lport]
    Msf(String),
    /// List payloads (optional filter).
    Payloads(String),
    /// Not understood.
    Unknown(String),
}

/// Parse a line of operator input.
pub fn parse(line: &str) -> Action {
    let line = line.trim();
    if line.is_empty() {
        return Action::Suggest;
    }
    if !line.starts_with('/') {
        // Bare input that looks like an IP focuses it; otherwise a raw command.
        if line.parse::<std::net::Ipv4Addr>().is_ok() {
            return Action::Focus(line.to_string());
        }
        return Action::RunRaw(line.to_string());
    }
    let mut it = line[1..].splitn(2, char::is_whitespace);
    let cmd = it.next().unwrap_or("").to_ascii_lowercase();
    let rest = it.next().unwrap_or("").trim().to_string();
    match cmd.as_str() {
        "run" | "r" => RunTool(rest),
        "raw" | "sh" | "!" => RunRaw(rest),
        "import" => Import(rest),
        "target" | "add" => AddTarget(rest),
        "focus" | "host" | "use" => Focus(rest),
        "cred" | "creds" => AddCred(rest),
        "harvest" | "loot" => Harvest(rest),
        "set" => {
            let (k, v) = rest.split_once(|c| c == ' ' || c == '=').unwrap_or((rest.as_str(), ""));
            Set(k.trim().to_string(), v.trim().to_string())
        }
        "suggest" | "next" | "s" => Suggest,
        "cancel" | "stop" | "kill" => Cancel(rest.parse().ok()),
        "export" | "notes" => Export,
        "star" => Star,
        "phase" | "p" => Phase(if rest.is_empty() { None } else { Some(rest) }),
        "help" | "h" | "?" => Help,
        "payload" | "gen" | "rev" => Payload(rest),
        "msf" | "msfvenom" => Msf(rest),
        "payloads" | "listpayloads" => Payloads(rest),
        "quit" | "q" | "exit" => Quit,
        other => Unknown(other.to_string()),
    }
}
use Action::*;

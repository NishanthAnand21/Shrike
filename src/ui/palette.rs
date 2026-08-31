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
    /// Show state-aware attack-chain guidance.
    Guide,
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
    /// Toggle the dashboard side panel.
    TogglePanel,
    /// Auto-run all applicable installed tools for a phase (or the next phase) across scope.
    Auto(String),
    /// Add a finding: [sev] title @location
    AddFinding(String),
    /// Show command history.
    History,
    /// Re-run a previous command by record id.
    Rerun(String),
    /// Export the HTML report.
    Html,
    /// Switch the active view.
    ViewCmd(String),
    /// Suspend the TUI and run an interactive TTY command.
    Shell(String),
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
            let (k, v) = rest.split_once([' ', '=']).unwrap_or((rest.as_str(), ""));
            Set(k.trim().to_string(), v.trim().to_string())
        }
        "suggest" | "s" => Suggest,
        "next" | "chain" | "n" => Guide,
        "cancel" | "stop" | "kill" => Cancel(rest.parse().ok()),
        "export" | "notes" => Export,
        "star" => Star,
        "phase" | "p" => Phase(if rest.is_empty() { None } else { Some(rest) }),
        "help" | "h" | "?" => Help,
        "panel" | "dash" => TogglePanel,
        "auto" | "campaign" | "a" => Auto(rest),
        "finding" | "vuln" | "f" => AddFinding(rest),
        "history" | "hist" => History,
        "rerun" | "replay" => Rerun(rest),
        "html" | "report" => Html,
        "view" | "v" | "tab" => ViewCmd(rest),
        "shell" | "connect" | "interactive" => Shell(rest),
        "payload" | "gen" | "rev" => Payload(rest),
        "msf" | "msfvenom" => Msf(rest),
        "payloads" | "listpayloads" => Payloads(rest),
        "quit" | "q" | "exit" => Quit,
        other => Unknown(other.to_string()),
    }
}
use Action::*;

/// A slash-command, for the autocomplete popup and help.
pub struct Cmd {
    pub name: &'static str,
    pub args: &'static str,
    pub desc: &'static str,
    pub aliases: &'static [&'static str],
}

/// The command registry shown in the autocomplete menu.
pub static COMMANDS: &[Cmd] = &[
    Cmd {
        name: "suggest",
        args: "",
        desc: "recompute next-step suggestions",
        aliases: &["next", "s"],
    },
    Cmd {
        name: "run",
        args: "<tool-id>",
        desc: "run a catalog tool",
        aliases: &["r"],
    },
    Cmd {
        name: "raw",
        args: "<command>",
        desc: "run an arbitrary shell command",
        aliases: &["sh", "!"],
    },
    Cmd {
        name: "target",
        args: "<ip|cidr|file>",
        desc: "add targets to scope",
        aliases: &["add"],
    },
    Cmd {
        name: "import",
        args: "<nmap.xml>",
        desc: "ingest an nmap -oX scan",
        aliases: &[],
    },
    Cmd {
        name: "focus",
        args: "<ip>",
        desc: "set the current host context",
        aliases: &["host", "use"],
    },
    Cmd {
        name: "cred",
        args: "[dom/]user:secret",
        desc: "add a credential (hash or password)",
        aliases: &["creds"],
    },
    Cmd {
        name: "harvest",
        args: "<file|text>",
        desc: "scrape creds & intel from output",
        aliases: &["loot"],
    },
    Cmd {
        name: "payload",
        args: "<id> [lhost] [lport] [+xform]",
        desc: "generate a shell payload",
        aliases: &["gen", "rev"],
    },
    Cmd {
        name: "msf",
        args: "<id> [lhost] [lport]",
        desc: "build an msfvenom command + handler",
        aliases: &["msfvenom"],
    },
    Cmd {
        name: "payloads",
        args: "[filter]",
        desc: "list available payloads",
        aliases: &[],
    },
    Cmd {
        name: "set",
        args: "<key> <value>",
        desc: "set proxy/iface/domain/dc/lhost/lport",
        aliases: &[],
    },
    Cmd {
        name: "phase",
        args: "[name]",
        desc: "filter suggestions to a phase",
        aliases: &["p"],
    },
    Cmd {
        name: "panel",
        args: "",
        desc: "toggle the dashboard side panel",
        aliases: &["dash"],
    },
    Cmd {
        name: "cancel",
        args: "[job-id]",
        desc: "cancel a running job (or all)",
        aliases: &["stop", "kill"],
    },
    Cmd {
        name: "export",
        args: "",
        desc: "write notes.md now",
        aliases: &["notes"],
    },
    Cmd {
        name: "star",
        args: "",
        desc: "star the last command",
        aliases: &[],
    },
    Cmd {
        name: "help",
        args: "",
        desc: "show help",
        aliases: &["h", "?"],
    },
    Cmd {
        name: "quit",
        args: "",
        desc: "save and exit",
        aliases: &["q", "exit"],
    },
];

/// Completions matching the current input (which must start with '/').
/// Returns (name, args, desc) for each match.
pub fn completions(input: &str) -> Vec<&'static Cmd> {
    if !input.starts_with('/') {
        return vec![];
    }
    // Only while typing the command word itself (no space yet).
    let word = &input[1..];
    if word.contains(char::is_whitespace) {
        return vec![];
    }
    let w = word.to_ascii_lowercase();
    COMMANDS
        .iter()
        .filter(|c| c.name.starts_with(&w) || c.aliases.iter().any(|a| a.starts_with(&w)))
        .collect()
}

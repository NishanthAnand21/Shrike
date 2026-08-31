//! Tool-id → MITRE ATT&CK technique tag (research/ATTACK_MAP.md Part 1.2).

/// ATT&CK technique id for a catalog tool id, if notable.
pub fn tag_for_tool(tool: &str) -> Option<&'static str> {
    Some(match tool {
        "kerberoast" | "targetedkerberoast" => "T1558.003",
        "asreproast" => "T1558.004",
        "secretsdump" => "T1003.006",
        "nxc-lsassy" => "T1003.001",
        "nxc-sam" => "T1003.002",
        "responder" => "T1557.001",
        "ntlmrelayx" | "mitm6" => "T1557",
        "coercer" | "petitpotam" | "printerbug" => "T1187",
        "certipy-find" | "certipy-req" | "certipy-auth" | "certipy-shadow" => "T1649",
        "dacledit" | "owneredit" | "rbcd" | "addcomputer" | "bloodyad" => "T1098",
        "pywhisker" => "T1556",
        "evil-winrm" | "nxc-winrm" => "T1021.006",
        "psexec" | "smbmap" => "T1021.002",
        "wmiexec" => "T1021.003",
        "hashcat-ntlm" | "hashcat-tgs" | "hashcat-asrep" | "hashcat-netntlmv2" | "john" => {
            "T1110.002"
        }
        "nxc-spray" | "kerbrute-spray" => "T1110.003",
        "nuclei" | "sqlmap" | "searchsploit" | "dalfox" => "T1190",
        "ligolo-proxy" | "chisel-server" | "socat-relay" => "T1572",
        "sshuttle" => "T1090.001",
        "linpeas" | "winpeas" | "pspy" => "T1068",
        "ftp-anon" => "T1552.001",
        "getst" => "T1550.003",
        "nxc-smb-null" | "nxc-smb-auth" | "nxc-smb-guest" | "smbclient-list" => "T1135",
        _ => return None,
    })
}

/// Human-readable technique name for the ids we tag.
pub fn name_for(id: &str) -> &'static str {
    match id {
        "T1046" => "Network Service Discovery",
        "T1595.002" => "Vulnerability Scanning",
        "T1190" => "Exploit Public-Facing Application",
        "T1083" => "File and Directory Discovery",
        "T1135" => "Network Share Discovery",
        "T1087.002" => "Domain Account Discovery",
        "T1592.002" => "Gather Host Information: Software",
        "T1558.003" => "Kerberoasting",
        "T1558.004" => "AS-REP Roasting",
        "T1003.001" => "LSASS Memory",
        "T1003.002" => "Security Account Manager",
        "T1003.006" => "DCSync",
        "T1550.002" => "Pass the Hash",
        "T1550.003" => "Pass the Ticket",
        "T1557" => "Adversary-in-the-Middle",
        "T1557.001" => "LLMNR/NBT-NS Poisoning + Relay",
        "T1187" => "Forced Authentication",
        "T1649" => "Steal or Forge Authentication Certificates",
        "T1098" => "Account Manipulation",
        "T1556" => "Modify Authentication Process",
        "T1021.001" => "Remote Services: RDP",
        "T1021.002" => "Remote Services: SMB Admin Shares",
        "T1021.003" => "Remote Services: DCOM",
        "T1021.006" => "Remote Services: WinRM",
        "T1078" => "Valid Accounts",
        "T1110.002" => "Password Cracking",
        "T1110.003" => "Password Spraying",
        "T1110.004" => "Credential Stuffing",
        "T1068" => "Exploitation for Privilege Escalation",
        "T1082" => "System Information Discovery",
        "T1572" => "Protocol Tunneling",
        "T1090.001" => "Internal Proxy",
        "T1552.001" => "Credentials In Files",
        _ => "",
    }
}

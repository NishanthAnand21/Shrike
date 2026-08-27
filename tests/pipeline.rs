// End-to-end checks on the non-UI core, driven through the library-ish modules.
// We invoke the binary's modules by shelling out to the built binary for --plan,
// and unit-test the pure logic here by re-declaring the crate path.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shrike")
}

#[test]
fn plan_classifies_pivot_segment() {
    let dir = std::env::temp_dir().join(format!("shrike-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let xml = dir.join("s.xml");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&xml, SAMPLE_XML).unwrap();

    let out = Command::new(bin())
        .args([
            "--name",
            "t",
            "--workspace",
            dir.to_str().unwrap(),
            "--import",
            xml.to_str().unwrap(),
            "--targets",
            "172.16.5.9",
            "--plan",
        ])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("192.168.1.0/24"),
        "missing scanned segment:\n{s}"
    );
    assert!(s.contains("DIRECT"), "scanned segment should be direct");
    assert!(s.contains("172.16.5.0/24"), "missing pivot segment");
    assert!(
        s.contains("PIVOT REQUIRED"),
        "unscanned segment should need a pivot"
    );
    assert!(s.contains("oscp.exam"), "domain not extracted:\n{s}");
    let _ = std::fs::remove_dir_all(&dir);
}

const SAMPLE_XML: &str = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="192.168.1.50" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/>
<script id="rdp-ntlm-info" output="DNS_Domain_Name: oscp.exam&#10;DNS_Computer_Name: WS1.oscp.exam"/></port>
</ports>
<trace><hop ipaddr="10.0.0.1"/><hop ipaddr="192.168.1.50"/></trace>
</host>
</nmaprun>"#;

#[test]
fn tools_with_outfile_render_when_provided() {
    // Guards the bug where {outfile} was never supplied, so every nmap/ffuf/etc.
    // tool failed to launch with "needs: outfile".
    use std::collections::HashSet;
    // Re-declare the minimal surface we need from the catalog via the binary is not
    // possible here (integration test), so assert the template contract instead:
    // every template placeholder a tool references must be one the app can fill.
    // The app fills these (see Ctx::from_engagement + run_tool):
    let fillable: HashSet<&str> = [
        "ip",
        "target",
        "port",
        "url",
        "scheme",
        "domain",
        "netbios",
        "dc_ip",
        "basedn",
        "user",
        "pass",
        "nthash",
        "secret",
        "upn",
        "iface",
        "subnet",
        "hostname",
        "wordlist",
        "userlist",
        "passlist",
        "vhostlist",
        "apilist",
        "outfile",
        "outdir",
        "hashfile",
        "dumpfile",
        "relaylist",
        "query",
        "shell",
        "path",
        "lhost",
        "lport",
    ]
    .into_iter()
    .collect();
    // Parse the catalog source for {placeholder} tokens and ensure each is fillable.
    let src = include_str!("../src/catalog/tools.rs");
    let mut unknown = vec![];
    // Only consider lines that are template string literals, not doc comments/prose.
    for line in src.lines() {
        let l = line.trim_start();
        if l.starts_with("//") || !l.contains('"') {
            continue;
        }
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'{' {
                if let Some(end) = line[i + 1..].find('}') {
                    let name = &line[i + 1..i + 1 + end];
                    if !name.is_empty()
                        && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                        && !fillable.contains(name)
                    {
                        unknown.push(name.to_string());
                    }
                    i += end + 2;
                    continue;
                }
            }
            i += 1;
        }
    }
    assert!(
        unknown.is_empty(),
        "catalog references unfillable placeholders: {unknown:?}"
    );
}

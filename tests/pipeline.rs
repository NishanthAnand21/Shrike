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

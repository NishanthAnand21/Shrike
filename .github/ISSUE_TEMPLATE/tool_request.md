---
name: Tool / payload request
about: Ask for a new tool or payload in the catalog
labels: enhancement
---

**Tool / payload**
Name and the binary it wraps (must be an existing, installable tool).

**Phase**
discovery / web-enum / smb-enum / ad-enum / cred-access / cracking / pivot / privesc / …

**Command template**
The exact command line, with `{ip} {port} {url} {domain} {dc_ip} {user} {pass}` slots.

**When it applies**
Which open ports / services / credentials should gate it being suggested.

**Output**
Does it have a structured-output flag (`-oX`, `-oJ`, `--json`)? What does it yield
(users / hashes / shares / shell / …)?

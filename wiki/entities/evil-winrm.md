---
title: "evil-winrm — WinRM shell for offensive use"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, ruby, winrm, lateral-movement, remote-execution]
---

# evil-winrm

**evil-winrm** is the de-facto offensive **WinRM client** — a Ruby tool that
gives you an interactive PowerShell shell over WinRM (5985/5986) with attacker
conveniences built in: **Pass-the-Hash**, **Pass-the-Ticket (Kerberos)**, upload/
download, in-memory script and .NET assembly loading, and AMSI-bypass helpers.
It's the standard "I have creds for a box with WinRM open, get me a shell" tool,
and the reference client for the WinRM row in [[remote-execution]]. Extremely
common on HTB (the classic `evil-winrm -i box -u user -p pass` foothold).

## Core usage

```bash
# Password auth
evil-winrm -i 10.0.0.20 -u user -p 'Password1'

# Pass-the-Hash (NTLM) — no password needed
evil-winrm -i 10.0.0.20 -u administrator -H <nthash>

# Pass-the-Ticket (Kerberos) — set the ccache and use the realm flag
export KRB5CCNAME=user.ccache
evil-winrm -i host.corp.local -r corp.local          # -r = realm

# SSL/HTTPS listener (5986)
evil-winrm -i 10.0.0.20 -u user -p pass -S

# Stage local scripts / executables into the session
evil-winrm -i 10.0.0.20 -u user -p pass -s /opt/scripts/ -e /opt/exes/
```

In-session commands: `upload local remote`, `download remote local`,
`menu` (lists loaded helpers), `Invoke-Binary /opt/exes/rubeus.exe args`
(run a .NET assembly from memory), `Bypass-4MSI` ([[amsi]] bypass),
`Dll-Loader`, `services`.

## Where it fits / gotchas

- **Needs WinRM enabled + a listener** on the target (5985 http / 5986 https)
  and the user in **Remote Management Users** or local admin. Often open on
  servers, dev boxes, and anything SCCM-touched ([[sccm-abuse]]).
- **The double-hop bites here.** A WinRM logon is a network logon, so reaching a
  *second* host as the same user fails — evil-winrm's `-r` (Kerberos realm) lets
  you carry a ticket for the hop; otherwise see [[kerberos-double-hop]].
- **PtH/PtT** make it a natural pair with [[secretsdump]] / [[mimikatz]] output
  and [[pass-the-hash-and-ticket]] — dump a hash, `-H` straight into a shell.
- Runs from the **Linux operator host over the tunnel**
  ([[pivoting-and-tunneling]]); the target only sees WinRM traffic + PowerShell,
  not the tool.

## OPSEC / detection

- WinRM shells generate **4104** (PowerShell ScriptBlock) and WinRM/Operational
  logs; `Invoke-Binary`/`Bypass-4MSI` touch [[amsi]]/[[etw]] and are
  higher-signal — prefer them only when needed. See [[defense-evasion-ad]].
- A 5985 session from a non-admin workstation to servers, plus a burst of
  ScriptBlock logging, is the classic evil-winrm signature.
- Alternatives with different noise: PSRemoting native (`Enter-PSSession`),
  and the SMB/WMI exec transports in [[remote-execution]].

## Related

- [[remote-execution]] (transport decision table), [[kerberos-double-hop]],
  [[pass-the-hash-and-ticket]], [[amsi]], [[netexec]] (`nxc winrm`),
  [[pivoting-and-tunneling]].

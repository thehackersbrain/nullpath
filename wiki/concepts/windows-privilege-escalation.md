---
title: "Windows Local Privilege Escalation"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, privesc, local, methodology, red-team]
---

# Windows Local Privilege Escalation

**Turning a low-priv foothold into LOCAL SERVICE / local admin / SYSTEM on the
box you're already on.** In an AD engagement this is the *bridge* between
"interactive shell as `jdoe`" and everything the rest of this wiki assumes:
local admin is what lets you [[credential-dumping|dump LSASS/SAM]], run
[[ntlm-relay-coercion|coercion]] triggers, write [[gpo-abuse|GPOs]], and move
laterally ([[remote-execution]]) into the Tier 0 boxes. A lot of "the domain" attacks are
really *local* privesc first.

This page is the hub. Each technique gets its own page; this is the methodology
and the map.

## The model: what "higher" actually means

Local privesc is not one trick — it's "reach a *more privileged execution
context* than the token you hold right now." The targets, in increasing order
of value:

| Target | What it buys you in an AD engagement |
|---|---|
| **High integrity** (above UAC) | run admin-only tooling, write to protected keys, bypass the UAC wall |
| **Local admin** (`Administrators`) | LSASS/SAM dump, install services/drivers, coercion, GPO write, lateral movement |
| **LOCAL SERVICE / NETWORK SERVICE** | some apps run under these with *more* rights than the user (service token, named pipes, file handles) |
| **SYSTEM** | the most privileged local context; offline NTDS/SAM access, credential cache access, driver install |

Most real privesc is "user → local admin." The rest are variants of the same
goal reached by a different door.

## The methodology: enumerate before you exploit

**Run the automated enumeration first, every time.** Manual checks miss things;
the tooling is free and fast. The standard one-liners:

- **[[winpeas]]** — the default; one binary, comprehensive, `-q` for quick.
  ```powershell
  # drop it, run it, read the output
  winpeas.exe -q          # quick pass (minutes)
  winpeas.exe -all        # full pass (everything)
  ```
- **Seatbelt** (`sbtn.exe`) / **WinPEAS** / **PrivescCheck** — the same idea,
  different coverage. Run at least two; they flag different things.
- **PowerUp** (`Start-PrivEscAudit`) — the PowerShell audit inside
  [[powerupack]].

The tool output is a *menu*, not an answer. Read the flagged lines, understand
*why* each is exploitable, then pick the cleanest one. Common flags to
recognise:

- `Found potential privesc vector: Unquoted service path`
- `Found potential privesc vector: Service running with user permissions`
- `Found potential privesc vector: AlwaysInstallElevated is set`
- `Potential UAC Bypass: fodhelper`
- `SeImpersonatePrivilege present` (→ [[potato-family]] / [[named-pipe-hijacking]])
- `Found writable service binaries`

## The technique map (one page each)

| Class | Technique | Page |
|---|---|---|
| UAC wall | white-listed binary hijack, `ComputerDefaults`, signed-binary bypass | [[uac-bypass]] |
| Token model | token steal, `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, printer bug | [[token-privilege-escalation]] |
| Kernel | Coerced Pipe Impersonation (Rotten/God/Juicy/ODD/BOOM Potato) | [[potato-family]] |
| Service config | unquoted path, weak service ACL, binary replace, AlwaysInstallElevated | [[service-privesc]] |
| Task config | writable scheduled task, task binary replace | [[scheduled-task-abuse]] |
| File load | DLL search-order hijack, DLL sideloading, PATHEXT/PATH | [[dll-hijacking-sideloading]], [[environment-variable-attack]] |
| IPC | named pipe hijack (impersonate from the pipe) | [[named-pipe-hijacking]] |
| Local persistence | run keys, services, WMI, startup — to *keep* the win | [[windows-local-persistence]] |

Pick by **least noise + most durable result**. A quiet service-path write that
hands you admin on next logon often beats a flashy potato that gets flagged by
the EDR.

## The AD bridge: why local admin is the real prize

Local admin on a *member* box is a stepping stone, not the destination:

- **Credential theft** — local admin can dump [[lsass]] / [[sam-database]]
  (the on-host store map is [[credential-dumping]]). The hashes you get are
  usually *domain* hashes (the user's domain logon) → straight into
  [[pass-the-hash-and-ticket]] / [[overpass-the-hash]].
- **Coercion + relay** — local admin (or the service token) runs the
  [[printer-bug]] / PetitPotam coercion that feeds [[ntlm-relay-coercion]] and
  the [[ad-cs-esc-attacks|ESC8/ESC11]] chains.
- **GPO + object writes** — local admin on a box that's *in* a writable-GPO
  linked OU, or that can reach a writable AD object, extends
  [[gpo-abuse]] / [[acl-abuse]].
- **Lateral movement** — local admin is the entry ticket to
  [[remote-execution]] (psexec/wmiexec/smbexec) and RBCD.
- **LAPS** — local admin on a box often means read access to the
  [[laps]] password for that machine → admin on *another* Tier-0 box.

So the local-privesc step is what converts a *user* foothold into the *machine*
context the AD attack chain runs from. See [[ad-tier-model]] for why that
machine context is so valuable.

## Red-team notes (OPSEC)

- **Enumerate quiet, exploit quieter.** WinPEAS/Seatbelt are loud-ish (many
  registry/file reads, some process creation). Run them *after* you've got a
  stable foothold and before you start moving, not during the first 60 seconds.
- **Prefer file/registry writes that look normal** (a service path fix, a
  task update) over in-memory token tricks when the EDR is young, because the
  former leave a *plausible admin* footprint you can explain.
- **Clean up the tool.** Delete the privesc binary (or run it over a
  tunnel and wipe it) — a `winpeas.exe` left in `%temp%` is a forensics gift.
- **Chain to creds, then move.** The point of local admin is the *hashes*, not
  the admin itself. Dump, pivot, and consider whether to persist
  ([[windows-local-persistence]]) or stay clean.

## Detection

- **Enumeration tooling** — WinPEAS/Seatbelt process names + the *burst* of
  registry/file/service queries in a short window (Sysmon 11/13/17 + 10
  correlation).
- **The technique-specific artifacts** — each page above lists its own tells
  (new service, changed task, new DLL, token-with-privilege anomaly, etc.).
- **The meta-tell** — a non-admin logon producing an admin-context process
  (`services.exe` child, `schtasks` as admin, a high-integrity process spawned
  by a medium-integrity parent). That parent→child integrity jump is the
  single most reliable local-privesc signal.

## Links

- [[uac-bypass]] — climbing over the UAC wall
- [[token-privilege-escalation]] — the token/impersonation model
- [[potato-family]] — kernel local root
- [[service-privesc]] — service misconfig privesc
- [[scheduled-task-abuse]] — task misconfig privesc
- [[dll-hijacking-sideloading]] — binary-load privesc
- [[environment-variable-attack]] — PATH/PATHEXT privesc
- [[named-pipe-hijacking]] — IPC impersonation privesc
- [[windows-local-persistence]] — keeping the win
- [[winpeas]] — the enumeration tool
- [[credential-dumping]] — what local admin is *for*
- [[redteam-ad-methodology]] — where this sits in the engagement arc

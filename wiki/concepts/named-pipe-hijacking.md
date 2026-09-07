---
title: "Named Pipe Hijacking"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, privesc, named-pipe, ipc, impersonation]
---

# Named Pipe Hijacking

**Owning the *server* end of a named pipe that a *privileged* process connects
to, then impersonating that process's identity.** A named pipe is Windows IPC:
a **server** creates it, **clients** connect, and the server can call
`ImpersonateNamedPipeClient` to *become* the connected client for a call. If
the client on the other end is `SYSTEM` (or an admin) and you hold
`SeImpersonatePrivilege`, you just stole a privileged token.

This is the *primitive* that the [[printer-bug]] and the
[[potato-family|Potato family]] are built on — they're the *coercion* steps
that get a SYSTEM process to connect to *your* pipe. This page is the pipe
itself.

## The mechanics

1. **Create the pipe** (you're the server) with a name the target will open, or
   take over the name the target *expects*.
2. **Get a privileged client to connect** to it (this is the hard part — see
   coercion below).
3. **`ImpersonateNamedPipeClient`** on the connected handle — your thread now
   carries the client's identity as an impersonation token.
4. **Check the level** — `GetTokenInformation` must show
   `SecurityImpersonation` or higher (not just `SecurityIdentification`).
5. **`CreateProcessWithTokenW` / `DuplicateTokenEx` + `CreateProcessAsUser`** —
   launch your payload **with the client's token as primary**. You now run as
   the client (SYSTEM).

The whole thing hinges on two facts:
- you have **`SeImpersonatePrivilege`** (often in the `Users` token, or granted
  by the [[printer-bug]]), and
- a **privileged process is the one connecting** to your pipe.

## Getting the privileged client to connect (coercion)

You don't usually get to pick the client — you have to **force a SYSTEM
process to dial your pipe**. The known coercions:

- **The [[printer-bug]]** — coerce `spoolsv.exe` (SYSTEM) to create & open a
  pipe you then connect to. The classic, pre-2022 path.
- **The [[potato-family|Coerced Pipe Impersonation family]]** — on modern
  builds, coerce a SYSTEM process (via EFS / a WinSock-using service / a TCP
  connection that triggers the HTTP/WinSock stack) to connect to your pipe.
  Rotten/God/Juicy/ODD/BOOM Potato are the named variants.
- **TrustedInstaller / msiexec pipe** (`\\.\pipe\MSIServer`) — the
  `TrustedInstaller` service opens a named pipe; a low-priv user who can
  connect/impersonate on it can reach the TrustedInstaller context (used in
  some MSI-related privesc).
- **VSS (Volume Shadow Copy)** — `Vssvc` (SYSTEM) and the VSS writer
  communicate over a named pipe; the classic "VSS pipe" impersonation target.

The pattern is always: **identify the SYSTEM process that talks over a named
pipe → make it connect to the pipe you control → impersonate.**

## Tooling

- **`Coercer`** (0xrawsec) — the modern one-shot: coercion + named pipe +
  token steal, Go binary, the default for the Potato-style path.
- **`PrintSpoofer`** (cgc-club) — the printer-bug-specific pipe coercion.
- **impacket** (`impacket-printspooler`, and the EFS coercion scripts) — the
  Python coercion RPCs.
- Manual (C / a small Python script) — the quietest; create the pipe, coerce,
  impersonate, no tool name on disk.

## Red-team notes (OPSEC)

- **The pipe name is the fingerprint** — a SYSTEM process connecting to a pipe
  in `%temp%` named after *you* is the tell. Use a short-lived, boring name and
  delete it on success.
- **You need the privilege pair** — if your token lacks
  `SeImpersonatePrivilege`, the whole thing fails silently. Check `whoami /all`
  *first*; if it's not there, the [[printer-bug]] is what grants it (that's why
  the two are always paired).
- **Impersonation level matters** — `SecurityIdentification` (level 0) lets you
  *read* the token but not *use* it. You need `SecurityImpersonation` (2) or
  `SecurityDelegation` (3). The coercion variant that lands you at level 0 is a
  near-miss — re-coerce.
- **One-and-done** — the dance (create pipe → coerce → impersonate → spawn)
  should be a single tight sequence. Long-lived pipes and repeated coercion
  attempts are exactly what the EDR correlation looks for.

## Detection

- **Sysmon 17** — a named pipe created by a non-system process, then a
  **SYSTEM** process connecting to it (the coercion signature).
- **ETW `Microsoft-Windows-Kernel-Audit` / process-create** — a new
  high-integrity process whose parent is a short-lived pipe server.
- **The token jump** — a process appearing with the SYSTEM token and *no*
  corresponding 4624 logon (it was impersonated, not logged on).
- **`ImpersonateNamedPipeClient` + `CreateProcessWithToken` in one window** —
  the API pair the EDR callback flags.

## Links

- [[token-privilege-escalation]] — the token model this impersonates into
- [[printer-bug]] — the canonical SYSTEM-pipe coercion (CVE-2021-34527)
- [[potato-family]] — the modern Coerced Pipe Impersonation family
- [[ntlm-relay-coercion]] — the broader coercion family (EFS/PetitPotam)
- [[windows-privilege-escalation]] — the hub

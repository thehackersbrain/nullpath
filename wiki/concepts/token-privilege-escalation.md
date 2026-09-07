---
title: "Token Privilege Escalation (token steal + impersonation)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, privesc, token, impersonation, local]
---

# Token Privilege Escalation

**Running with a *different, more privileged* token than the one your process
was launched with.** Every Windows process carries a **security token** — the
object that encodes *who* it is (SID, groups), *what it may do* (privileges),
and *how trusted* it is (integrity level). Privesc at the token layer means
getting your code to execute under a token that's more privileged than yours:
steal one from a higher process, or impersonate a client that authenticated to
a pipe you own.

This is the *model* behind [[named-pipe-hijacking]], the
[[printer-bug|printer bug]], and the [[potato-family|Potato]] family. Those are
the *doors*; this page is the *lock* they turn.

## The token model

- A **primary token** belongs to a process; it's the identity of every thread
  in it.
- An **impersonation token** is attached to a *thread* after it has
  `Impersonate*`d a client (RPC, named pipe). It's the client's identity,
  usable only while that thread impersonates.
- What matters for privesc is the set of **privileges** in a token. The two
  that gate named-pipe impersonation:

| Privilege | Lets you |
|---|---|
| `SeImpersonatePrivilege` | act as a client that authenticated to you (RPC / named pipe) |
| `SeAssignPrimaryTokenPrivilege` | assign an arbitrary token as the *primary* token of a process you create |
| `SeCreateTokenPrivilege` | create a token from scratch (rare, very strong) |
| `SeTcbPrivilege` | act as the OS itself (SYSTEM-level) |

`SeImpersonatePrivilege` + `SeAssignPrimaryTokenPrivilege` together are the
classic pair: impersonate a client over a pipe, then launch a process carrying
that client's token.

## Technique 1 — token steal (duplicate a higher token)

When a process is already running as a more privileged user (a service under
`SYSTEM`, an admin's app), you can **copy its primary token** and spawn a new
process with it.

```
# Cobalt Strike: steal the token of pid <pid>, open a new shell as it
steal token <pid>

# Mimikatz: duplicate the token of the process and exec under it
mimikatz# token::steal <pid>
```

You get a **new context carrying the target's identity** — the original
process is untouched. This is the cleanest "I see a SYSTEM service, I want
SYSTEM" move. The tell: a new process whose token matches another unrelated
process, with no logon event for it.

## Technique 2 — named pipe impersonation (the privilege pair)

You **own a named pipe** and you hold the two privileges above. The shape:

1. Spawn a **dummy** child process (any process) — it will connect to your
   pipe.
2. Create the **named pipe**; the dummy connects to it.
3. `ImpersonateNamedPipeClient` on the pipe handle — you now hold the
   dummy's (or, in the coercion variants, a *privileged* client's)
   impersonation token.
4. Check the impersonation level is `SecurityImpersonation` or higher.
5. `CreateProcessWithTokenW` / `DuplicateTokenEx` + `CreateProcessAsUser` —
   launch `cmd.exe`/your payload **with the impersonated token as primary**.

The trick in every real use is *who* connects to the pipe. If it's your own
dummy, you just re-token to yourself. If a **privileged process** (the spooler,
a coerced SYSTEM service) is the one connecting, you steal *its* identity.
That's [[named-pipe-hijacking]] and the [[potato-family|Potato]] family.

## Technique 3 — the printer bug (getting the SYSTEM pipe)

The [[printer-bug]] (CVE-2021-34527) is the canonical *source* of a
privileged pipe: the Print Spooler (`spoolsv.exe`) runs as **SYSTEM with
`SeImpersonatePrivilege`**. The `SetPrintProcessor` RPC can be coerced so the
spooler **creates and opens a named pipe** in a temp dir. Any authenticated
user who triggered the RPC can open that pipe; the spooler (SYSTEM) is the
client on the other end — so you **impersonate to SYSTEM** without holding the
privilege pair yourself.

```
# PrintSpoofer (cgc-club) — the one-shot: coerce spooler, open the pipe,
# impersonate, drop a SYSTEM shell
PrintSpoofer.exe

# impacket (Python) — the coercion RPC
impacket-printspooler

# Coercer (0xrawsec) — printer bug + named pipe + token in one Go binary
coercer
```

The patched box (CVE-2021-34527 fix) removes the unauthenticated/low-priv
`SetPrintProcessor` path — but the *model* (coerce a SYSTEM process to connect
to your pipe, then impersonate) survives as the
[[potato-family|Coerced Pipe Impersonation]] family.

## Red-team notes (OPSEC)

- **Steal tokens, don't just dump** — a `steal token` gives you a *live*
  privileged context; a LSASS dump gives you *hashes*. Use the token for what
  it's good for (read the secrets, run the coercion), then drop it.
- **The dummy process is your footprint** — the named-pipe dance spawns a
  short-lived child and a pipe. EDRs watch for "process creates named pipe +
  impersonates + spawns high-integrity child". Keep the dummy boring
  (`cmd.exe /c wait`) and short.
- **Printer bug is loud on patched boxes** — if CVE-2021-34527 is patched,
  the classic PrintSpoofer path fails; pivot to the Potato family or a
  different coercion (EFS — see [[ntlm-relay-coercion]]).
- **Integrity, not just identity** — a stolen SYSTEM token is high integrity
  *and* the SYSTEM SID. Confirm both (`whoami /all`) before assuming you won.

## Detection

- **Token duplication** — a new process whose primary token matches an
  unrelated existing process, with **no corresponding 4624 logon** for it.
- **The named-pipe impersonation shape** — pipe create → connect →
  `ImpersonateNamedPipeClient` → `CreateProcessWithToken` in one short window
  (ETW + Sysmon 17/1 correlation).
- **Privilege anomaly** — a token that *gains* `SeImpersonatePrivilege` /
  `SeAssignPrimaryTokenPrivilege` without a logon that grants them.
- **Spooler pipe creation** — `spoolsv.exe` creating a named pipe in `%temp%`
  (the printer-bug tell; Sysmon 17/11).

## Links

- [[named-pipe-hijacking]] — the pipe you own and the client you steal
- [[printer-bug]] — the SYSTEM pipe source (CVE-2021-34527)
- [[potato-family]] — the modern Coerced Pipe Impersonation family
- [[uac-bypass]] — the rung below (integrity without a new identity)
- [[windows-privilege-escalation]] — the hub
- [[credential-dumping]] — the token is often used to reach these

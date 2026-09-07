---
title: "The Potato Family (Coerced Pipe Impersonation)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, privesc, potato, kernel, coercion, system]
---

# The Potato Family

**Local → SYSTEM for *any* user, on modern Windows, via *Coerced Pipe
Impersonation*.** The "Potato" family (Rotten / God / Juicy / ODD / BOOM
Potato) is the current default for local root. It exists because of two facts
that combined to break the old model:

1. Since Windows 10 1607, the **`Users` group holds
   `SeImpersonatePrivilege` + `SeAssignPrimaryTokenPrivilege`** by default. So
   a *normal* local user can already impersonate over a named pipe — no admin
   needed.
2. You can **coerce a SYSTEM process to connect to a pipe you own** — so the
   client you impersonate is *SYSTEM*.

`SeImpersonatePrivilege` + a SYSTEM client on your pipe = **any local user →
SYSTEM**. The "Potato" name comes from the 2020 "Coerced Pipe Impersonation in
Windows" write-up (Rotten Potato). The named variants differ only in **which
SYSTEM process they coerce** and **which build it works on** — the underlying
[[named-pipe-hijacking|named-pipe impersonation]] primitive is the same.

## The mechanics (the shape every variant shares)

1. **Create a named pipe** (you're the server).
2. **Coerce a SYSTEM process to connect** to it. This is the hard,
   build-specific step — each Potato targets a different SYSTEM service:
   - **Rotten / God / Juicy Potato** — coerce a SYSTEM process that uses the
     **WinSock / HTTP stack** (a `TCP` connection to a listening service
     triggers the stack, which opens your pipe).
   - **ODD Pot** (2021) — coerce the **EFS (Encrypting File System)**
     subsystem: create a file, trigger EFS to decrypt it, and the EFS path
     (a SYSTEM service) connects to your pipe.
   - **BOOM Pot** (2022) — a **TCP-based** coercion variant for the builds
     where the earlier ones regressed.
3. **`ImpersonateNamedPipeClient`** — your thread now carries SYSTEM.
4. **`CreateProcessWithTokenW`** — spawn your shell **as SYSTEM**.

The whole attack is *local* (no network, no admin) and lands you at the top of
the local box. It's the modern successor to the
[[printer-bug|printer bug]] (CVE-2021-34527): when the spooler coercion got
patched, the Coerced Pipe family took over as the generic local-to-SYSTEM path.

## Why "any user" (the privilege pair)

This is the part that makes it different from most privesc: you **don't need
to be admin first**. On a stock modern Windows box, a plain `Users` member
already has the two privileges the attack needs. So the chain is simply:

```
any local user  →  (has SeImpersonatePrivilege + SeAssignPrimaryTokenPrivilege)
                →  coerce SYSTEM process to my pipe
                →  impersonate → SYSTEM
```

Confirm the pair is present before you invest: `whoami /all | findstr /i
"impersonate assignprimary"`. If it's not (some hardened boxes strip it), the
[[printer-bug]] or a token-steal path is your alternative.

## Tooling

- **`Coercer`** (0xrawsec) — the modern one-shot; tries multiple coercion
  methods across builds, Go binary. The default for this family.
- **RottenPotato.py / GodPotato / juicyPotato** (ohpe) — the original Python
  variants (WinSock/HTTP coercion).
- **ODDPot.py** (beehive) — the EFS-coercion variant.
- Manual (a small C/Python script) — the quietest; no tool name on disk.

## Red-team notes (OPSEC)

- **It's local and it's quiet-ish** — no network, no new service. The footprint
  is the **pipe + the SYSTEM connection + the token jump**, all in a short
  window. EDRs specifically correlate that shape, so keep it a single tight
  sequence.
- **Build matters** — the coercion target changes across Windows builds; a
  Potato that works on one may silently no-op on another. `Coercer` tries
  several; if you go manual, pick the variant matched to the box's build.
- **You already might have the pair** — check `whoami /all` *before* reaching
  for the Potato. If `Users` holds the privileges (the default), you're one
  coercion away from SYSTEM with no admin at all.
- **SYSTEM is your local ceiling** — once you're SYSTEM, the box is yours
  ([[credential-dumping]], driver install, offline NTDS/SAM). Use it to grab
  the domain-relevant secrets, then decide on
  [[windows-local-persistence|persistence]].

## Detection

- **Sysmon 17** — a named pipe created by a **non-system** process, then a
  **SYSTEM** process connecting to it (the coercion signature, variant-agnostic).
- **The token jump with no logon** — a SYSTEM process appearing with **no
  corresponding 4624** (it was impersonated, not logged on).
- **The coercion-specific tell** — an **EFS decrypt** (ODD Pot) or a **TCP
  connect to a local service** (Rotten/God/Juicy/BOOM) immediately preceding the
  pipe connection.
- **`ImpersonateNamedPipeClient` + `CreateProcessWithToken`** in one window,
  from a low-priv parent (the EDR callback pair).
- **A low-priv user holding the privilege pair** — the *precondition* itself is
  a hardening review item (some defenders strip `Users` of the pair to break
  this family).

## Links

- [[named-pipe-hijacking]] — the pipe primitive this family drives
- [[token-privilege-escalation]] — the token model + the privilege pair
- [[printer-bug]] — the pre-2022 spooler coercion this family succeeded
- [[ntlm-relay-coercion]] — the broader coercion family (EFS/PetitPotam)
- [[windows-privilege-escalation]] — the hub

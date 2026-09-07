---
title: "The Kerberos Double-Hop Problem (and how to beat it)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [kerberos, lateral-movement, winrm, credssp, delegation, gotcha]
---

# The Kerberos Double-Hop Problem

The **double-hop** is the single most common "why doesn't this work" wall in AD
lateral movement, and it is a *feature*, not a bug. You WinRM/PSRemote into
**HostA** with a user's creds; from HostA you try to reach **HostB** (a share, a
DC LDAP query, another remote session) *as that same user* — and it fails with
`Access Denied` / `KDC cannot be found` / an anonymous logon, even though the
user plainly has rights on HostB. You just hit the double-hop.

## Why it happens (the mechanism)

When you authenticate to HostA over a **network logon** (WinRM, PSRemoting,
`runas /netonly`-style), HostA receives your identity but **not your
credentials or a delegatable TGT**. Kerberos, by design, does **not** forward
your TGT to HostA unless delegation is explicitly configured. So HostA has a
**service ticket to itself for you**, but nothing it can present to HostB *on
your behalf*. The "second hop" has no Kerberos material to use → it falls back
to the machine account or anonymous → denied.

- **First hop** (you → HostA): fine, you have a TGS for HostA.
- **Second hop** (HostA → HostB *as you*): no forwarded TGT, no cached
  password on HostA → nothing to authenticate with.

Interactive/RDP logons **don't** have this problem: an interactive logon caches
the credential on the target, so the second hop can re-auth. WinRM's network
logon is the classic trigger. Note `psexec`/`wmiexec` shells hit the same wall
for the same reason.

## How to beat it (ranked, hands-on)

### 1. CredSSP — the blunt, works-anywhere option

CredSSP delegates the **actual password** to HostA, so HostA can re-auth to
HostB freely. It's the easiest fix and the reason it exists.

```powershell
# From your box (must enable on both client and server side)
Enable-WSManCredSSP -Role Client -DelegateComputer hosta.corp.local
# on HostA: Enable-WSManCredSSP -Role Server
Enter-PSSession hosta -Authentication CredSSP -Credential corp\user
```
```bash
# evil-winrm exposes CredSSP-free workarounds; for CredSSP use PowerShell native
```
**Cost:** CredSSP hands your **plaintext password to HostA's LSASS** — if HostA
is compromised/monitored, you just donated a credential. It also needs config on
both ends (often not pre-enabled). See [[remote-execution]] (CredSSP row) — this
is exactly the "password in memory" tradeoff.

### 2. Inject a TGT into the remote session (Pass-the-Ticket, no config)

The cleanest operator move: don't rely on delegation at all — **carry a usable
TGT to the second hop yourself**. If you have the user's hash/key or a TGT, do
overpass-the-hash *from within* HostA (or inject the ticket into that logon
session).

```bash
# evil-winrm can pass a Kerberos ticket for the whole session:
export KRB5CCNAME=user.ccache
evil-winrm -i hosta -r corp.local        # -r = realm, uses your ccache for the hop
```
```powershell
# On HostA (Rubeus): request a fresh forwardable TGT into THIS logon session,
# then the second hop has real Kerberos material.
Rubeus.exe asktgt /user:user /rc4:<nthash> /domain:corp.local /ptt
# now: dir \\hostb\share  /  Get-ADUser ... works
```
This is [[overpass-the-hash]] / [[pass-the-hash-and-ticket]] applied to the
double-hop: you supply the missing TGT instead of asking Kerberos to forward it.
Needs the user's key/hash or an existing ticket ([[ticket-and-credential-opsec]]).

### 3. Fix it at the identity layer (delegation) — if you control it

If the account/host is *configured* for delegation, the TGT **is** forwarded and
the double-hop evaporates:

- **Unconstrained delegation** on HostA → HostA gets your forwardable TGT
  automatically ([[unconstrained-delegation]]).
- **Constrained delegation (S4U)** / **RBCD** → HostA can request a ticket to
  HostB *as you* via S4U2Proxy ([[s4u2self-s4u2proxy]],
  [[resource-based-constrained-delegation]]). If you have write over HostA's
  object you can *add* RBCD to engineer your way past the hop — that's an attack
  primitive, not just a fix.

### 4. Stash a credential on HostA (fallback)

- `$cred = Get-Credential; Invoke-Command -ComputerName hostb -Credential $cred`
  — pass an explicit `PSCredential` for the second hop (you re-supply the
  password inside the session; effectively manual CredSSP).
- Or just get an **interactive** logon (RDP) instead of a network one, which
  sidesteps the whole thing.

## Decision heuristic

- **You have the user's password/hash/ticket** → PtT/OPtH injection (#2). No
  config, no plaintext donation, cleanest.
- **You only have a live WinRM session and no key material** → CredSSP (#1) or
  explicit `-Credential` (#4), accepting the plaintext-to-HostA cost.
- **You control HostA's AD object** → weaponize delegation (#3) — now it's a
  privesc, not just a workaround.

## Red-team notes (OPSEC)

- **CredSSP is the noisy/risky one**: plaintext in HostA's LSASS ([[lsass]]) is
  both a capture risk *for you* and a detectable config change (WSMan CredSSP
  GPO/registry). Prefer ticket injection where you have the material.
- **Ticket injection keeps you Kerberos-clean** — the second hop looks like a
  normal 4768/4769 for the user, not an NTLM fallback (4776) or an anonymous
  denial that lights up failure telemetry.
- Recognize the failure *fast*: `Access Denied` on a resource the user *should*
  reach, right after a WinRM/psexec entry, is the double-hop 95% of the time —
  don't burn an hour on ACLs.

## Related

- Transports and where the hop bites: [[remote-execution]].
- Supplying the missing ticket: [[overpass-the-hash]],
  [[pass-the-hash-and-ticket]], [[ticket-and-credential-opsec]], [[ccache]].
- Delegation-based fixes/abuses: [[kerberos-delegation]],
  [[unconstrained-delegation]], [[resource-based-constrained-delegation]],
  [[s4u2self-s4u2proxy]].

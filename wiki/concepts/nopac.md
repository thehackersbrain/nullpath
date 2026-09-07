---
title: "noPac / sAMAccountName spoofing (CVE-2021-42278 + CVE-2021-42287)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [kerberos, active-directory, privilege-escalation, cve, s4u, pac]
---

# noPac / sAMAccountName spoofing

**noPac** (a.k.a. **sAMAccountName spoofing** / **sam-the-admin**) chains two
2021 bugs into a **single-step domain takeover from any authenticated user**:
create a computer account, rename it to impersonate a DC, and use **S4U2self**
to obtain a service ticket **as the DC** — then DCSync. It needs only valid
domain creds and (by default) `MachineAccountQuota > 0`, which is why it was one
of the most impactful AD findings of its era and still lands on unpatched or
lab/CTF domains.

## The two CVEs

- **CVE-2021-42278 (name validation).** AD failed to enforce that **machine
  account `sAMAccountName`s end in `$`** — so you can rename a computer account
  to a name that *looks like a user/DC* (e.g. `DC01`, no trailing `$`).
- **CVE-2021-42287 (S4U2self fallback).** When the KDC can't find the account
  named in a ticket request (`sname`/client), it **retries with a `$`
  appended**. So a TGT issued for `DC01` (your renamed machine) is, on lookup,
  resolved to the **real `DC01$`** — and S4U2self hands you a ticket as the DC.

Neither alone is game-over; **chained**, they let a non-privileged user mint a
service ticket impersonating a Domain Controller.

## The chain

1. **Add a computer** (needs `MachineAccountQuota > 0`, default 10 — or control
   of an existing computer object): `addcomputer.py` / Powermad
   `New-MachineAccount` → `FAKE$` with a known password.
2. **Rename** `FAKE$`'s `sAMAccountName` to a **DC's name without the `$`**
   (`DC01`) — CVE-2021-42278.
3. **Request a TGT** for `DC01`.
4. **Rename the computer back** (to `FAKE$`), so `DC01` no longer resolves as a
   distinct object.
5. **S4U2self** with that TGT for a service on yourself (e.g. `ldap`/`cifs`).
   Because the client name (`DC01`) now resolves to the **real DC** via the `$`
   fallback (CVE-2021-42287), the KDC issues a **service ticket as `DC01$`**.
6. That ticket impersonates the DC → **DCSync** the domain → Domain Admin.

## Command

```bash
# noPac.py / sam_the_admin — does the whole chain and can auto-DCSync:
noPac.py corp.local/user:'Password1' -dc-ip 10.0.0.10 -dc-host DC01 \
  --impersonate administrator -dump          # -dump = secretsdump the DC

# or step-wise to get a shell as the DC:
noPac.py corp.local/user:'Password1' -dc-ip 10.0.0.10 -dc-host DC01 \
  --impersonate administrator -shell
```

Run from the Linux operator host over the tunnel ([[pivoting-and-tunneling]]).

## Prerequisites (what to check first)

- **Valid domain creds** (any user).
- **`MachineAccountQuota > 0`** — check with `nxc ldap dc01 -u u -p p -M maq` or
  `Get-DomainObject -Identity 'DC=...' -Properties ms-DS-MachineAccountQuota`.
  If MAQ = 0, you need write over an existing computer object instead (the same
  edge that enables [[resource-based-constrained-delegation|RBCD]]).
- **Unpatched DCs** (missing the Nov 2021 update). Patched DCs enforce the
  `$`/SID checks and reject the rename-based confusion.

## Red-team notes (OPSEC)

- **Loud but fast.** It creates a computer (4741), renames `sAMAccountName`
  twice (5136/4781), and DCSyncs — a lot of high-fidelity events in a short
  window. Use it as a decisive move, clean up the machine account after, and
  don't leave the DC-named object lying around.
- **Prefer it where patching is behind** (it's a 2021 bug) — on a mature domain
  assume it's patched and pivot to [[resource-based-constrained-delegation|RBCD]]
  / [[shadow-credentials]] off the same MAQ/write primitive instead.
- The renamed-to-DC computer object is the smoking gun — **delete the machine
  account** you added on the way out.

## Detection

- **4741** (computer account created) by a non-admin, followed quickly by
  **5136 / 4781** changing that object's `sAMAccountName` — especially to a name
  matching a DC.
- A **machine account whose `sAMAccountName` lacks `$`** or matches a DC name
  (config/hunt query).
- **4769** for a service ticket whose client resolves to a DC from an unexpected
  host, then **4662** DCSync replication ([[dcsync]] detection).
- Mitigation: **patch CVE-2021-42278/42287**, set **`MachineAccountQuota = 0`**,
  and audit machine-account creation/renames.

## Links

- [[s4u2self-s4u2proxy]] — the S4U2self step the fallback bug abuses
- [[kerberos-pac]] — the ticket/PAC the DC impersonation carries
- [[dcsync]] — the end-goal once you hold a DC-impersonating ticket
- [[resource-based-constrained-delegation]] — the sibling MAQ/computer-write primitive (the patched-domain alternative)
- [[domain-controller]] — what you're impersonating and why it's game-over
- [[golden-silver-tickets]] — the follow-on persistence once you own krbtgt

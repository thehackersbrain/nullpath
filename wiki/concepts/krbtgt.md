---
title: KRBTGT Account
type: concept
created: 2026-06-12
updated: 2026-09-06
tags: [kerberos, active-directory, krbtgt, golden-ticket, dcsync]
---

# KRBTGT Account

The built-in AD account whose secret (NTLM hash / AES keys) is used by the
KDC to **encrypt and sign every Ticket Granting Ticket (TGT)** — see
[[kerberos-authentication]]. Whoever holds this secret can mint a TGT for
*any* user with *any* group membership, domain-wide. It is the single most
valuable secret in the domain.

## How the KDC actually uses it

- The KDC holds `krbtgt`'s **keys in memory** (RC4/NT, AES128, AES256). Every
  TGT's **encPart** (the session key) is encrypted with `krbtgt`'s key, and the
  TGT/PAC is **signed** so the target service (and the DC) can validate it
  without the KDC. See [[kerberos-pac]] for the signed blob and
  [[kerberos-encryption-types]] for the enctype choices.
- Because validation is **offline** (the target service just checks the
  signature against the `krbtgt` key it has), a forged-but-validly-signed TGT
  is indistinguishable from a real one. That's the whole
  [[golden-silver-tickets|Golden Ticket]] primitive.
- The account is a normal domain user (`krbtgt`), so its secret is in
  **NTDS.dit** ([[ntds-dit]], [[lsass]]) — obtainable by [[dcsync]]
  (`-just-dc-user krbtgt`) or a DC dump.

## The three keys and the Diamond Ticket

`krbtgt` carries **RC4**, **AES128**, and **AES256** keys. This matters for
forgery:

- **Golden Ticket** — usually built with AES256 (or RC4 for speed). See
  [[golden-silver-tickets]].
- **[[diamond-ticket]]** — built with **AES128** specifically to survive a
  single `krbtgt` rotation (see below). The choice of enctype is a detection
  signal and a durability lever. See [[kerberos-encryption-types]].

## Recovery: double password rotation

The standard remediation after a suspected `krbtgt` compromise (Golden
Ticket or DCSync) is to **rotate the `krbtgt` password twice**, waiting
~10 hours between rotations. AD retains the **current + previous** password,
so a single rotation isn't enough — a Golden Ticket signed with the
*old* key stays valid through the first rotation. The **Diamond Ticket**
exploits exactly this window. This appears as the headline mitigation in
both [[golden-silver-tickets]] and [[dcsync]].

```powershell
# Rotate twice, ~10h apart
Set-DomainObjectPassword -Identity krbtgt -AccountPassword (ConvertTo-SecureString 'New1' -AsPlainText -Force); Start-Sleep 36000
Set-DomainObjectPassword -Identity krbtgt -AccountPassword (ConvertTo-SecureString 'New2' -AsPlainText -Force)
```

## Why it matters

- **Golden Ticket** ([[golden-silver-tickets]]) / **Diamond Ticket**
  ([[diamond-ticket]]) are entirely about obtaining this secret (typically via
  [[dcsync]] or a dump of `ntds.dit`) and using it to forge arbitrary TGTs
  offline.
- A compromised `krbtgt` secret is treated as a **full domain compromise** —
  forged tickets remain valid until the secret is invalidated (double
  rotation).
- `krbtgt` + a weak/legacy trust into a second forest is the classic
  "second-forest" pivot — see [[ad-trust-attacks]].

## Detection

- **4662 / DCSync on `krbtgt`** — a principal requesting
  `GetChanges`/`GetChangesAll` for the `krbtgt` user object is a near-certain
  Golden-Ticket precursor (see [[dcsync]]).
- **4768 TGT with anomalous enctype** — an AES128 (`0x11`) or RC4 (`0x17`) TGT
  for a privileged account on an AES256 domain (see [[diamond-ticket]],
  [[kerberos-encryption-types]]).
- **4768 for a TGT with an impossibly long/odd lifetime** — forged-ticket
  tell.
- **LSASS/NTDS access on a DC** — the offline-dump route to the secret
  ([[lsass]], [[ntds-dit]]).

## Mitigations

- **Rotate twice** on any suspected compromise (above).
- **Restrict who can DCSync** (`GetChanges`/`GetChangesAll`) — the main
  remote path to `krbtgt`. See [[dcsync]], [[ad-tiering-and-hardening]].
- **Alert on `krbtgt` TGTs** with unusual enctype/lifetime.
- **Protect the DC's LSASS/NTDS** (Credential Guard, DSRM) — see
  [[ad-persistence]].

## Related

- [[dcsync]] — the most common way to obtain the `krbtgt` secret remotely
  without touching a DC's disk.
- [[golden-silver-tickets]] — the forgery this secret enables.
- [[diamond-ticket]] — the rotation-surviving AES128 variant.
- [[kerberos-pac]] — the signed blob the `krbtgt` key protects.
- [[kerberos-encryption-types]] — the enctype choices behind forgery.
- [[ad-trust-attacks]] — cross-forest pivot from a compromised `krbtgt`.
- [[dcshadow]], [[skeleton-key]] — the persistence techniques that survive a `krbtgt` rotation.
- [[adsecurity-org]] — Sean Metcalf's krbtgt / Golden-Ticket research (source)
- [[kerberos-authentication]] — the TGT/TGS flow this account underpins.

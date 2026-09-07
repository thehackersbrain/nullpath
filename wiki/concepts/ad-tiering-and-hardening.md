---
title: AD Tiering & Hardening Baseline
type: concept
created: 2026-06-12
updated: 2026-06-13
tags: [active-directory, hardening, mitigations]
---

# AD Tiering & Hardening Baseline

A set of architectural mitigations that recur across nearly every AD attack
page in this wiki. None of these stop a single technique outright — they
limit blast radius and make credential theft less likely to escalate to
domain compromise.

## The controls

- **Tiered Administration Model** (Tier 0/1/2 — see [[ad-tier-model]]) —
  Domain Admin credentials
  never touch lower-trust workstations, breaking the chain that turns a
  workstation compromise into a [[dcsync]] or [[golden-silver-tickets]]
  scenario. Cited in [[dcsync]], [[pass-the-hash-and-ticket]],
  [[golden-silver-tickets]], [[kerberos-delegation-abuse]].
- **Privileged Access Workstations (PAWs)** — dedicated hardened machines
  for admin tasks, part of the tiering model. See [[pass-the-hash-and-ticket]].
- **Protected Users security group** — members are restricted to AES-only
  Kerberos, get short (4h) TGT lifetimes, can't be delegated, and avoid
  credential caching. Recurs in [[kerberoasting]], [[as-rep-roasting]],
  [[dcsync]], [[pass-the-hash-and-ticket]], [[kerberos-delegation-abuse]].
- **Group Managed Service Accounts ([[gmsa]])** — 120-char auto-rotated
  passwords, removes offline cracking as a viable path. See
  [[kerberoasting]], [[as-rep-roasting]], [[golden-silver-tickets]],
  [[kerberos-delegation-abuse]].
- **Credential Guard** (VBS-isolated LSASS) — even SYSTEM-level attackers
  can't read hashes/tickets from memory. See [[pass-the-hash-and-ticket]],
  [[ntlm]].
- **LAPS** (Local Administrator Password Solution) — unique random local
  admin password per host, breaks lateral movement via shared local admin
  creds. See [[pass-the-hash-and-ticket]].
- **Enforce AES / disable RC4 (and DES)** — removes the cheap-to-crack
  encryption type that most offline-cracking attacks rely on. See
  [[kerberoasting]], [[as-rep-roasting]], [[golden-silver-tickets]],
  [[pass-the-hash-and-ticket]], [[ntlm]].
- **Honey accounts / honey SPNs / honeytokens** — decoy objects with no
  legitimate use; any interaction with them is a high-fidelity alert.
  Recurs in [[kerberoasting]], [[as-rep-roasting]], [[dcsync]],
  [[pass-the-hash-and-ticket]], [[kerberos-delegation-abuse]].
- **`krbtgt` password rotation (x2)** — incident-response action specific
  to suspected [[krbtgt]] secret compromise. See [[golden-silver-tickets]],
  [[dcsync]].
- **Machine Account Quota = 0** — prevents non-admins from creating computer
  accounts, closing off the default RBCD abuse path. See
  [[kerberos-delegation-abuse]], [[rbcd-via-ntlm-relay]], [[sccm-abuse]].
- **Extended Protection for Authentication (EPA) + HTTPS-only** — binds NTLM
  auth to the TLS channel, blocking relay of captured authentication to web
  endpoints. See [[ad-cs-esc-attacks]] (ESC8/ESC11), [[ntlm-relay-coercion]],
  [[sccm-abuse]].

## Takeaway

Almost every technique in this wiki is mitigated by some combination of:
*don't let weak/crackable secrets exist* (gMSA, AES, password policy) +
*don't let a low-tier compromise reach high-tier credentials* (tiering,
PAWs, Protected Users, Credential Guard, LAPS) + *detect anomalous use of
legitimate protocols* (honeytokens, 4768/4769 correlation, RC4 downgrade
monitoring).

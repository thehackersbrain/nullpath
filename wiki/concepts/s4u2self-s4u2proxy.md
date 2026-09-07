---
title: S4U2Self / S4U2Proxy (Service-for-User)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [kerberos, active-directory, delegation, protocol]
---

# S4U2Self / S4U2Proxy (Service-for-User)

The **Service-for-User (S4U)** extension (RFC 4178 §10) is how *constrained*
and *resource-based* delegation work at the protocol level. It lets a service
obtain a ticket *for a user* without knowing the user's password. It is the
mechanism underneath [[kerberos-delegation-abuse]]'s constrained and RBCD
abuse, and the reason a coerced user can hand an attacker their identity.

## S4U2Self (RFC 4178 §10.3)

A service that holds **constrained delegation** rights
(`msDS-AllowedToDelegateTo`) — or is the *target* of **RBCD**
(`msDS-AllowedToActOnBehalfOfOtherIdentity`, see below) — can ask the KDC for
a **service ticket for the user, addressed to itself**. The KDC issues a TGS
whose client is the user and whose server is the service, *without* the
user's password. The service then accesses a resource *as the user*. This is
legitimate: a print spooler fetching a user's document, a web app reading the
user's mailbox, etc.

**Abuse:** if you can coerce a victim's TGT to a machine/service you control
that has S4U2Self rights over you (RBCD), you request a TGS *for the victim*
to that service and act as the victim. This is the core of **RBCD** — see
[[kerberos-delegation-abuse]] and [[rbcd-via-ntlm-relay]].

## S4U2Proxy (RFC 4178 §10.4)

A service with constrained delegation can, after S4U2Self, request a
**service ticket for the user to a *different* service** on the user's behalf
— i.e. "act as the user over there." The allowed target services are exactly
the ones in `msDS-AllowedToDelegateTo`.

**Abuse:** if a machine has constrained delegation to a high-value SPN (a
DC's `cifs/`, a SQL server, `RestrictedKrbHost`), coercing a victim to
authenticate to that machine lets you request the victim's ticket to that SPN
and use the victim's privileges there.

## RBCD (resource-based constrained delegation)

Instead of the *source* service listing allowed targets, the *target resource*
lists who may delegate to it, via `msDS-AllowedToActOnBehalfOfOtherIdentity`.
This is a **GenericWrite** attribute — so the classic [[acl-abuse]] play is:
get GenericWrite on a computer object you can coerce a user to
(PetitPotam, SMB auto-logon), write your attacker machine's SID into
`msDS-AllowedToActOnBehalfOfOtherIdentity`, coerce the victim to authenticate
to your machine, and S4U2Self a TGS for the victim to your machine → you are
the victim there. Full walkthrough: [[kerberos-delegation-abuse]].

## Why the victim's TGT is the prize

In S4U flows the victim's **TGT is presented to / embedded in** the service
you control. Capturing or replaying it (or the resulting TGS) is what makes
[[pass-the-hash-and-ticket|Pass the Ticket]] and unconstrained delegation capture work — see
[[kerberos-delegation-abuse]] for the unconstrained case (where *any* service
the machine fronts hands over the full TGT).

## Commands

```powershell
# Constrained delegation (source side) — set allowed targets
Set-DomainComputer attackerpriest -Set @{'msds-allowedtodelegateto'='cifs/dc01.corp.local'}

# RBCD (target side) — let my machine act on behalf of others
$attackerSid = (Get-DomainComputer attackerbox -Properties objectsid).objectsid
$SD = New-ADServiceAccountResourceDelegationSD -Sid $attackerSid
Set-DomainComputer targetbox -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SD}

# S4U2Self / S4U2Proxy with Rubeus (as the coerced-to machine)
Rubeus.exe s4u /self /user:victim /service:cifs/attackerbox.corp.local /rc4
Rubeus.exe s4u /proxy /user:victim /service:cifs/target.corp.local /rc4
```

```bash
# Impacket — RBCD + S4U2Self (GetUserSPNs / ticks) — see kerberos-delegation-abuse
```

## Detection

- **Event 4769** with the **S4U** extension (`x500UniqueIdentifier` /
  `PA-PAC-REQUESTS` flags) — a service requesting a ticket *for* a user is
  the tell; watch for S4U2Self to unusual service SPNs.
- **Event 4768/4769** for the *victim* from a machine IP the victim doesn't
  normally use.
- 4769 for `cifs/<attacker-machine>` (an attacker-controlled SPN) — RBCD
  in progress.
- Audit writes to `msDS-AllowedToDelegateTo` and
  `msDS-AllowedToActOnBehalfOfOtherIdentity` (5136).

## Mitigations

- Constrain delegation tightly; prefer **Restricted** delegation
  (`RestrictedKrbHost/<spn>`) and [[gmsa]] service accounts.
- Audit `msDS-AllowedToDelegateTo` / `msDS-AllowedToActOnBehalfOfOtherIdentity`
  for unexpected entries; alert on 5136 changes to them.
- [[ad-tiering-and-hardening]] — keep Tier-0 machines out of delegation paths.

## Links

- [[kerberos-delegation]] — the UDE/CDE/RBCD hub page (what each form is)
- [[kerberos-delegation-abuse]] — the raw source summary
- [[kerberos-authentication]] — the TGS-REQ stage S4U drives
- [[acl-abuse]] — RBCD is a GenericWrite abuse of `msDS-AllowedToActOnBehalfOfOtherIdentity`
- [[rbcd-via-ntlm-relay]] — credential-less RBCD via mitm6/WPAD relay
- [[pass-the-hash-and-ticket]] — the captured TGT/TGS (PtT) the S4U flow exposes
- [[ntlm-relay-coercion]] — how the victim is coerced to present their TGT
- [[bronze-bit]] — CVE-2020-17049: flip the S4U2self forwardable bit to defeat Protected Users / "sensitive" flags
- [[nopac]] — CVE-2021-42287: S4U2self on a DC-renamed machine account → a ticket as the DC
- [[sapphire-ticket]] — uses S4U2self to pull a real privileged PAC into a forged TGT

## References

- [RFC 4178 — Kerberos Protocol Extensions (S4U)](https://datatracker.ietf.org/doc/html/rfc4178)
- [MS-SFU / MS-ADTS (constrained & RBCD)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts)
- [ired.team: Delegation abuse](https://www.ired.team/active-directory-kerberos-abuse/kerberos-delegation-abuse)

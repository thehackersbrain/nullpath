---
title: Diamond Ticket
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [kerberos, active-directory, ticket-forgery, privilege-escalation]
---

# Diamond Ticket

A variant of the [[golden-silver-tickets|Golden Ticket]] that forges the TGT
using the **AES128** key of `krbtgt` instead of the usual AES256. It is a
*downgrade* forgery (see [[kerberos-encryption-types]]) and is valuable for
two reasons:

1. **Rotation resistance.** After a `krbtgt` password rotation, AD retains
   the *previous* password for ~10 hours (the KDC validates against current
   + previous keys). A TGT signed with the **old AES128** key can stay valid
   across a rotation window where an AES256-built Golden Ticket's validity
   assumptions are re-examined. Combined with the fact that many domains
   still have the AES128 key present, a Diamond Ticket is more durable than
   a standard Golden Ticket.
2. **Detection avoidance.** Most "forged ticket" detections key off unusual
   **lifetime** or RC4 (`0x17`) usage. AES128 (`0x11`) is a legitimate, common
   enctype, so a Diamond Ticket blended into a domain that also uses AES128
   is quieter than an RC4 Golden Ticket.

## Prerequisites

- The `krbtgt` **AES128** key — from [[dcsync]] (`secretsdump.py` /
  `lsadump::dcsync` shows `aes128-cts-hmac-sha1-96`), or an `ntds.dit` dump.
- The domain SID and the target user SID.

## Commands

```powershell
# Rubeus — build a TGT signed with the AES128 key
Rubeus.exe asktgt /user:Administrator /domain:corp.local /rc4:<nt> /aes128:<32-hex> /aes256:<64-hex> /sids:S-1-5-21-...:512 /ptt
# (the /aes128 key is what the PAC/TGT is actually signed with in a Diamond build)
```

```
# Mimikatz
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /aes128:<32-hex> /ptt
```

**Verify:** `Rubeus.exe triage` shows the TGT; `whoami /all` lists
`corp.local\administrator` plus the `512` (Domain Admins) group SID if you
stuffed `/sids`.

## Why "Diamond"

SpecterOps named it for the downgrade path: you take a *higher*-security
domain (AES256) and mint a ticket using the *lower* (AES128) key that is
still honored — a downgrade that persists. See the [[ad-cs-esc-attacks]]-style
"weaker path still valid" theme.

## Detection

- **Event 4768** with a TGT encrypted `aes128-cts-hmac-sha1-96` (`0x11`) on a
  domain that policy-forces AES256 — an AES128 TGT is anomalous.
- A TGT whose lifetime exceeds the domain max, *signed with AES128* — pairs
  the classic Golden Ticket tell with the Diamond downgrade.
- Correlate with the `krbtgt` rotation window: an AES128 TGT that keeps working
  *after* a rotation is a strong Diamond Ticket indicator.

## Mitigations

- Rotate `krbtgt` **twice** (see [[krbtgt]]) — invalidates old-key tickets.
- Enforce **AES256-only** for `krbtgt` / domain-wide where possible
  ([[kerberos-encryption-types]]), removing the AES128 key the attack relies on.
- Alert on AES128 TGTs (`0x11`) for privileged accounts.

## Links

- [[golden-silver-tickets]] — the base Golden/Silver forgery this extends
- [[sapphire-ticket]] — the stealthier sibling: same "modify a real TGT" idea, but injects a **real** privileged PAC via S4U2self
- [[krbtgt]] — the account whose AES128 key is the primitive
- [[kerberos-encryption-types]] — the RC4/AES128/AES256 downgrade context
- [[dcsync]] — how you obtain the `krbtgt` AES128 key
- [[kerberos-pac]] — the PAC the forged TGT must carry valid group SIDs

## References

- [SpecterOps: The Diamond Ticket](https://posts.specterops.io/the-diamond-ticket-e38455777635)
- [Rubeus (GhostPack) — asktgt](https://github.com/GhostPack/Rubeus)
- [ired.team: Kerberos ticket forging](https://www.ired.team/active-directory-kerberos-abuse/kerberos-attacks)

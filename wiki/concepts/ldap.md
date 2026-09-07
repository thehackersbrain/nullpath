---
title: LDAP / LDAPS (directory protocol)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [protocol, ldap, active-directory, relay, enumeration]
---

# LDAP / LDAPS

**LDAP** is the protocol that talks to the Active Directory **directory
service** — the database of every user, group, computer, GPO, and trust in the
domain. Where [[kerberos-authentication]] grants *access* and [[smb]] moves
you *between boxes*, LDAP is how you **read and write the directory itself**:
enumerate the forest, check ACLs, and — critically for the relay family — the
**target you relay to** to plant attributes ([[resource-based-constrained-delegation]]),
create computer accounts, or join a machine. LDAPS (LDAP over TLS) is the
encrypted variant and the relay target of choice when SMB signing is enforced.
See [[rbcd-via-ntlm-relay]] for the credential-less LDAP relay path.

## What you do with LDAP

- **Enumerate** — read the directory tree: users, groups, computers, OUs,
  GPOs, trusts, and object attributes (ACLs, SPNs, `userAccountControl`).
  This is the raw data behind [[bloodhound]] and the PowerView
  `Get-Domain*` functions.
- **Write** — modify objects: set attributes (the RBCD
  `msDS-AllowedToActOnBehalfOfOtherIdentity` write), take ownership
  (`owneredit.py`), rewrite ACLs (`dacledit.py`), create computer accounts
  (`addcomputer.py`), and set delegation. These writes are what turn a relay
  or an ACL edge into privilege escalation ([[acl-abuse]]).
- **Bind** — authenticate to the directory (simple/LDAP bind, or a Kerberos
  bind). A bind is itself a credential check — and a relayable NTLM auth.

## LDAP signing & channel binding — the relay controls

Just as SMB signing gates SMB relays ([[smb]]), two AD settings gate **LDAP
relays**:

- **LDAP signing** — every LDAP bind is MAC-protected with the session key, so
  a captured NTLM bind can't be replayed to a second LDAP server. Enforced
  signing blocks the classic "relay NTLM to LDAP" move.
- **Channel Binding (CBC/TC-IPSec, "LDAP channel binding token")** — binds the
  LDAP session to the TLS channel (LDAPS), so a replayed bind over a new
  channel is rejected. Even with signing, an attacker can relay to LDAPS if
  channel binding is off — hence the `mitm6` → **LDAPS** RBCD path.

The relay family works by **coercing** a victim to NTLM-auth to the attacker,
then **relaying** that NTLM to an LDAP/LDAPS endpoint where the victim's
rights let it write an attribute. Signing + channel binding on is the
control that breaks this. See [[ntlm-relay-coercion]], [[mitm6-ipv6-relay]],
and [[ad-tiering-and-hardening]].

## Common enumeration (the PowerView / Impacket reads)

```powershell
# PowerView (reads the directory via LDAP)
Get-DomainUser -Properties samaccountname,useraccountcontrol
Get-DomainComputer -Properties dnsHostName
Get-DomainObjectAcl -Identity <target> -ResolvedRights    # ACL enumeration
Get-DomainTrust / Get-ForestTrust                          # trust enumeration
```
```bash
# Impacket
ldapsearch.py -usersfile users.txt -dc <dc> DOMAIN/user:pass   # raw directory reads
samrdump.py <target>                                            # SAM lookup
lookupsid.py <target>                                            # SID resolution
```

## The relay target (why LDAP is where RBCD lands)

When an attacker relays a coerced NTLM to **LDAP/LDAPS**, the coerced account's
**directory write rights** decide what sticks:

- **Write `msDS-AllowedToActOnBehalfOfOtherIdentity`** on a computer → RBCD
  ([[resource-based-constrained-delegation]]). Often possible by any domain
  user on *computer* objects.
- **Create a computer account** (Machine Account Quota > 0) → the RBCD
  "add my computer" step.
- **Write an ACL / take ownership** → [[acl-abuse]].
- **Set delegation attributes** → [[kerberos-delegation-abuse|delegation]].

So "relay to LDAP" isn't one attack — it's "get a principal's NTLM to the
directory and let *its rights* do the writing." See [[rbcd-via-ntlm-relay]]
for the no-creds variant and [[ntlmrelayx]] for the relay engine.

## Detection

- **Unusual LDAP bind patterns** — a principal binding to LDAP from an
  unexpected host/time, especially to **LDAPS** (389/636) from a non-DC.
- **5136 directory changes** — attribute writes (RBCD, ACL, ownership) from a
  non-admin principal; the durable tell of a successful LDAP relay.
- **4741 computer account created** — the RBCD `addcomputer` step.
- **Anonymous / null LDAP reads** (unauthenticated directory enumeration).
- **Bursts of object reads** from one source (BloodHound-style enumeration).

## Mitigations

- **Enforce LDAP signing + channel binding** (domain-wide) — the primary relay
  control ([[ad-tiering-and-hardening]]).
- **Require LDAPS** and pin the channel-binding token.
- **Restrict directory write rights** — limit who can set RBCD/delegation
  attributes, create computer accounts (Machine Account Quota = 0), and write
  ACLs ([[acl-abuse]]).
- **Alert on 5136** attribute changes from non-admin principals and on
  computer-account creation.
- **Tiering** — the structural fix: Tier-0 objects should only be writable by
  Tier-0 principals.

## Links

- [[resource-based-constrained-delegation]] — the attribute an LDAP relay writes
- [[rbcd-via-ntlm-relay]] — the credential-less mitm6 → LDAPS RBCD path
- [[ntlm-relay-coercion]], [[mitm6-ipv6-relay]] — the coercion + relay mechanics
- [[ntlmrelayx]] — the relay engine that targets LDAP/LDAPS
- [[acl-abuse]] — the ACL/ownership writes an LDAP relay can perform
- [[kerberos-delegation-abuse]] — the delegation attributes an LDAP relay can set
- [[bloodhound]] — the graph built from LDAP reads
- [[smb]] — the sibling protocol (and the other relay target)
- [[ad-tiering-and-hardening]] — the signing/channel-binding/write-right controls

## References

- [Microsoft: LDAP protocol](https://learn.microsoft.com/en-us/windows/win32/api/lapstruc/)
- [ired.team: LDAP](https://www.ired.team/windows-offensive-security/ldap)
- [dirkjanm: worst of both worlds (RBCD via LDAPS)](https://dirkjanm.io/)

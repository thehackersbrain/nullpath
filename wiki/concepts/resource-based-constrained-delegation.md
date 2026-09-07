---
title: Resource-Based Constrained Delegation (RBCD)
type: concept
created: 2026-09-06
updated: 2026-09-07
tags: [active-directory, kerberos, delegation, rbcd, s4u2self, privilege-escalation]
---

# Resource-Based Constrained Delegation (RBCD)

**RBCD** is the abuse of the `msDS-AllowedToActOnBehalfOfOtherIdentity`
attribute **on a machine (computer) object**. Unlike constrained delegation
(`msDS-AllowedToDelegateTo`, which you set on the *service*), RBCD is set on
the **target resource** — and crucially it can be written from the **target
forest/domain**, so a machine account can grant *itself* the right to act on
behalf of *any* user. Combined with the S4U protocol it lets you impersonate
any user on that machine — and, credential-less via
[[mitm6-ipv6-relay|mitm6]], it's one of the highest-leverage AD privesc
primitives in this wiki. See [[kerberos-delegation-abuse]] for the delegation
family and [[s4u2self-s4u2proxy]] for the S4U mechanics underneath.

## The attribute and the edge

- `msDS-AllowedToActOnBehalfOfOtherIdentity` on **computer object X** says:
  "machine X may act on behalf of *any* of these principals."
- **GenericWrite** on that attribute (or on the computer object) is the
  object-control edge — a classic [[acl-abuse]] play. BloodHound models the
  `GenericWrite → computer → msDS-AllowedToActOnBehalfOfOtherIdentity` edge.
- Because the attribute is writable by the **computer itself** (SELF) by
  default in many environments, an attacker who is **local admin on the target
  machine** (or holds its machine account creds) can set the attribute
  directly — no domain-wide write needed.

## The abuse (S4U)

Once you control machine X's `msDS-AllowedToActOnBehalfOfOtherIdentity`:

1. **Set the attribute** to your attacker principal (or `*`):
   ```powershell
   Set-DomainObject -Identity <computer>$ -Set @{
     'msDS-AllowedToActOnBehalfOfOtherIdentity'='S-1-5-21-<you>' }
   ```
2. **S4U2Self** — as machine X, request a service ticket for the victim user
   to the service on X (the KDC issues a TGS because X is "allowed to act on
   behalf of" that user):
   ```powershell
   Rubeus.exe s4u /user:<computer>$ /user@domain:<computer>$ /impersonateuser:<victim> \
     /service:cifs /service@domain:cifs@<forest> /rc4:<machine-nt> /domain:corp.local
   ```
3. **S4U2Proxy** — exchange the S4U2Self TGS for a TGT/TGS as the **victim
   user** on X (a "sloshy" / on-behalf-of ticket). You're now the victim on X.

This is the S4U2Self → S4U2Proxy flow in [[s4u2self-s4u2proxy]]. The payoff is
**impersonation of any user on the machine** — typically the machine's local
admin, a service account, or (if X is a DC) a domain account → DCSync.

## Credential-less RBCD (the mitm6 / "worst of both worlds")

The most powerful form: you don't even need the machine's NT hash.
[[dirkjanm]]'s **"worst of both worlds"** chain uses
[[mitm6-ipv6-relay|mitm6]] to:

1. **Coerce** the victim machine to make an NTLM auth to your mitm6 (WPAD
   redirect) — see [[ntlm-relay-coercion]].
2. **Relay** that NTLM to LDAPS to **write RBCD** on the machine
   (`msDS-AllowedToActOnBehalfOfOtherIdentity`) — the machine authenticating
   to itself is allowed to set the attribute.
3. Then run the S4U2Self/S4U2Proxy flow above **without any captured hash** —
   the relayed NTLM *is* the machine's auth.

Full walkthrough: [[rbcd-via-ntlm-relay]]. This is the "no creds, just a
network position" version and a recurring top finding. RBCD aimed at a DC
(impersonate a DA on the DC → DCSync) is [[path-rbcd-to-domain-admin]].

## Why it matters

- **Low-priv → high-priv** with a single attribute write + S4U — no GPO, no
  group membership, no ticket forgery.
- **Cross-forest / cross-domain** capable (the attribute is on the target
  machine, writable from the target's own context).
- **Credential-less** when chained with mitm6 — the network position *is* the
  credential.
- It's the modern replacement for "I'm local admin here, now what?" — local
  admin on a machine with an RBCD edge = impersonate anything on it.

## Red-team notes (OPSEC)

- **Check `MachineAccountQuota` first.** If `MAQ > 0` you can add a computer
  account to own the SPN the attack needs (`addcomputer.py`); if `MAQ = 0`
  (the common hardening) you need an already-controlled computer or a
  credential-less relay path (below).
- **Write the one attribute, then clear it.** The 5136 on
  `msDS-AllowedToActOnBehalfOfOtherIdentity` is high-fidelity and rare — set
  it, run S4U, and revert it in the same window.
- **Prefer the credential-less chain** (mitm6 → LDAPS RBCD write) when you
  hold only a network position — no captured hash, see [[rbcd-via-ntlm-relay]].
- **Run remotely.** `rbcd.py -action write` and `getST.py -impersonate` from
  Linux over the tunnel; `Rubeus.exe s4u` on-host. Match the requested TGS
  enctype to the domain to avoid the RC4 tell ([[kerberos-encryption-types]]).
- **Aim narrowly:** impersonate the specific user you need on the specific box
  (local admin, or a DA on a DC → DCSync), not a broad sweep.

## Detection

- **4738 / 5136** — a write to `msDS-AllowedToActOnBehalfOfOtherIdentity` on a
  computer object (the RBCD tell). Alert on any such attribute change.
- **4769 S4U2Self** — a TGS-REQ with the **S4U2Self extension** (the
  `canon-name`/`s4u2self` flag) for a machine service — see
  [[s4u2self-s4u2proxy]] detection.
- **4769 S4U2Proxy** — a TGS-REQ carrying the victim as the **impersonated**
  principal (`s4u2proxy`).
- **mitm6 tells** — an unexplained NTLM auth from a machine to a new IP
  (WPAD), or an LDAPS write from the machine to itself — see
  [[mitm6-ipv6-relay]], [[ntlm-relay-coercion]].

## Mitigations

- **Restrict who can write `msDS-AllowedToActOnBehalfOfOtherIdentity`** — remove
  GenericWrite / SELF-write on `msDS-AllowedToActOnBehalfOfOtherIdentity`;
  keep it on the **service** side (constrained) where you intend it. See
  [[acl-abuse]], [[ad-tiering-and-hardening]].
- **Alert on RBCD attribute writes** (5136) — they're rare and almost always
  an attack.
- **Limit S4U** — disable the S4U2Self/S4U2Proxy capability where not needed
  (`/S4U` in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`).
- **Break the mitm6 relay** — IPv6, WPAD, SMB signing — see
  [[mitm6-ipv6-relay]], [[ntlm-relay-coercion]].
- **GMsA / short-lived machine keys** — a captured machine key is
  short-lived — see [[gmsa]].

## Links

- [[s4u2self-s4u2proxy]] — the S4U protocol RBCD drives
- [[kerberos-delegation]] — the UDE/CDE/RBCD hub page
- [[kerberos-delegation-abuse]] — the delegation family (unconstrained /
  constrained / RBCD)
- [[dirkjanm-blog]] — the credential-less "worst of both worlds" RBCD research (source)
- [[rbcd-via-ntlm-relay]] — the credential-less mitm6 RBCD chain
- [[mitm6-ipv6-relay]] — the IPv6 MITM/relay that makes RBCD credential-less
- [[evilwpad]] — the rogue-WPAD tool that relays captured NTLM to LDAP for RBCD
- [[ntlm-relay-coercion]] — the coercion + relay RBCD relies on
- [[acl-abuse]] — the GenericWrite / object-control edge
- [[bloodhound]] — how you find the RBCD edge
- [[rubeus]] — the S4U tooling (`s4u`)
- [[ad-tiering-and-hardening]] — the structural mitigation

## References

- [Microsoft: msDS-AllowedToActOnBehalfOfOtherIdentity](https://learn.microsoft.com/en-us/previous-versions/windows/server/ff687055(v=ws.10))
- [ired.team: RBCD](https://www.ired.team/active-directory-kerberos-abuse/resource-based-constrained-delegation-rbcd)
- [dirkjanm: RBCD / mitm6](https://dirkjanm.io/)
- [kerberos-delegation-abuse (this wiki)](kerberos-delegation-abuse)

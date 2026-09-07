---
title: Kerberos Relay (KrbRelay)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [kerberos, ntlm-relay, active-directory, relay]
---

# Kerberos Relay (KrbRelay)

**Kerberos relay** is the Kerberos analog of [[ntlm-relay-coercion|NTLM
relay]]: an attacker in the middle reuses a captured **Kerberos**
authentication (an AP-REQ / TGS, or the victim's ticket) against a target
service that accepts Kerberos but doesn't properly **pin its own SPN** or
validate the ticket's intended service. Where NTLM relay needs the service to
speak NTLM (and not require signing/CBA), Kerberos relay needs the service to
accept Kerberos *and* not verify that the ticket was actually requested for
*it*.

## When it applies

- The target service authenticates via **Kerberos** (not NTLM) — e.g. a
  service that has disabled NTLM but still accepts Kerberos.
- The service **doesn't pin its SPN** (doesn't call
  `KerberosValidateClient`-style checks / doesn't require the ticket's server
  name to match its own) — so a ticket minted for a *different* SPN is
  accepted.
- The attacker can **capture** the victim's Kerberos auth to the attacker's
  (or a controlled) SPN — via coercion ([[ntlm-relay-coercion]]), a
  [[kerberos-delegation-abuse|delegation]] position, or a
  [[mitm6-ipv6-relay|mitm6]] position.

This is rarer than NTLM relay in the wild (most relay targets — SMB, AD CS
web enrollment, LDAPS — are NTLM), but it matters on NTLM-hardened networks
and in **S4U / unconstrained delegation** capture, where the victim's **TGT**
is the thing being relayed/replayed (see [[pass-the-hash-and-ticket|PtT]]).

## Contrast with the delegation-capture case

In **unconstrained delegation**, the victim's TGT is *embedded* in the TGS the
attacker's machine receives — the attacker doesn't "relay" an NTLM, they
**capture the TGT** and replay it (that's [[pass-the-hash-and-ticket|PtT]] /
delegation capture, not KrbRelay per se). KrbRelay proper is about reusing a
captured Kerberos *auth* against a non-SPN-pinned Kerberos service.

## Tooling / commands

```bash
# KrbRelay (the tool) — relay a captured Kerberos auth to a target service
# (positioning + capture is the same as ntlm-relay-coercion / mitm6)
krbrelay ...   # point the captured ticket/auth at the target's SPN

# The classic "capture then replay" of the victim TGT (unconstrained
# delegation) is really PtT:
Rubeus.exe ptt /ticket:<base64-victim-tgt>
```

```powershell
# Capture side: coerce the victim to authenticate to your SPN (S4U2Self /
# unconstrained), grab the TGT, then replay it to the target service
Rubeus.exe asktgt /user:victim /rc4   # or capture via delegation position
Rubeus.exe ptt /ticket:<captured>
```

## Detection

- A **4769** (TGS requested) for a SPN the victim wouldn't normally request,
  from an unusual source.
- A service accepting a ticket whose **server name doesn't match its own SPN**
  (SPN-pin failure) — the tell a KrbRelay succeeded.
- **4768/4769** for the victim from the attacker's machine IP.
- Downstream: 4624/4662 from the victim's identity on a host/service the
  victim didn't directly touch.

## Mitigations

- **Pin SPNs** — services should validate that the presented ticket's server
  name matches their own SPN (`KerberosValidateClient`, or the equivalent in
  the language runtime).
- **Prefer NTLM signing + CBA/LDAPS** on the relay-able targets (see
  [[ntlm-relay-coercion]]) so the NTLM path is closed too.
- **Constrain delegation** / avoid unconstrained (see
  [[kerberos-delegation-abuse]]) so the victim TGT isn't handed over in the
  first place.
- [[ad-tiering-and-hardening]] — limit what a replayed identity can reach.

## Links

- [[ntlm-relay-coercion]] — the NTLM relay + coercion hub (the more common cousin)
- [[mitm6-ipv6-relay]] — how the auth is captured in the first place
- [[kerberos-delegation-abuse]] — unconstrained delegation TGT capture (the adjacent case)
- [[pass-the-hash-and-ticket|PtT]] — replaying the captured ticket
- [[kerberos-authentication]] — the AP-REQ/TGS-REP stage the relay reuses
- [[s4u2self-s4u2proxy]] — the S4U flows that expose the victim ticket

## References

- [ired.team: Kerberos relay](https://www.ired.team/active-directory-kerberos-abuse/kerberos-attacks)
- [MS-KILE / Kerberos service-side validation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kerb)
- [InternalAllTheThings: Relay](https://swisskyrepo.github.io/InternalAllTheThings/)

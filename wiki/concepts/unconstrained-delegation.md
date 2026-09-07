---
title: "Unconstrained Delegation (abuse mechanics)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, kerberos, delegation, privilege-escalation]
---

# Unconstrained Delegation

**The service holds *your* TGT, and the service is DC-trusting.** A service
account (or computer) with **`UAS_DELEGATION`** set — **unconstrained
delegation** (the `TrustedForDelegation` flag) — is allowed to **forward the
caller's service tickets**, and crucially to request a **TGT for itself** and
then a **service ticket to *any* service** (including `krbtgt`/`host` on a
DC) using that TGT. The attacker's goal is to **capture the TGT for the
delegating service's SPN** (a TGS for the service that's really a
forwardable TGT), then use it to get a **TGS to the DC** — and from the DC
**UnPAC the DC's machine NT hash** → **DCSync** → DA.

This is the highest-value member of the three delegation flavors
([[kerberos-delegation]]); constrained (s4U2self) and RCBD are scoped,
unconstrained is *any* service.

## The abuse (how the TGT is actually captured)

1. **Get the service's TGT** — request a service ticket for the
   delegating service's SPN. The classic capture: **[[mitm6-ipv6-relay]]**
   (coerce the DC to auth to you, relay its TGT to a service with unconstrained
   delegation), or **[[resource-based-constrained-delegation]]** to force a
   S4U2self/forwarded ticket, or simply **log on to the service** as the
   service account.
2. **Use the captured TGT** — it's now *your* TGT for the service's
   identity:
   ```
   Rubeus.exe getTGT /tgtdeleg:<BASE64_TGT> /nowrap
   ```
3. **Request a TGS to the DC** (`host/<DC>.<domain>` or `krbtgt/<domain>`):
   the DC issues a service ticket whose **PAC** contains the **DC machine
   account's credentials**.
4. **UnPAC** the DC's NT hash from the PAC → **[[dcsync]]** /
   [[golden-silver-tickets]]:
   ```
   Rubeus.exe unPAC /ticket:<TGS>
   impacket-secretsdump -hashes :<DC_NT> '<DOMAIN>/<DC>$@<DC_IP>'
   ```

The end-to-end variant that starts from *no creds* (the DC coerced via
[[mitm6-ipv6-relay]]) is the canonical chain — see
[[path-unconstrained-delegation-to-domain-admin]] and
[[path-mitm6-rbcd-to-local-admin]].

## Red-team notes (OPSEC)

- **The delegation is a *network-position* condition** — you need the TGT
  capture (mitm6/RBCD), not a shell on the service. Plan the network seat
  first (same segment / DHCPv6 / RBCD write).
- **The UnPAC is the quiet step** — the TGS-to-DC (4769 to a DC SPN from a
  *workstation* identity) is the tell; the UnPAC itself is local.
- **`TrustedForDelegation` is rare and high-value** — it's almost always a
  *service* account that's under-protected; enumerate it
  ([[bloodhound]] / `get-DomainUser -UnconstrainedDelegation`) before you
  spend the TGT-capture effort.
- **A machine account with UDE is the same play** — a *computer* object can
  be trusted-for-delegation; capturing the machine's TGT is the same
  [[mitm6-ipv6-relay]] coercion target.

## Detection

- **4769 with the forwarded flag** (the R0/canonical tell) — a TGS for a
  delegating service **from a workstation** is the classic UDE-to-DC tell
  ([[kerberos-event-ids]]).
- **4769 to `krbtgt`/`host/<DC>`** from a non-DC source — the DC-TGS step.
- The **TGT capture** is upstream ([[mitm6-ipv6-relay]] / RBCD detection).
- `TrustedForDelegation` set on an account that doesn't need it (baseline
  drift).

## Mitigations

- **Restrict `TrustedForDelegation`** to the few service accounts that truly
  need it; prefer **[[kerberos-delegation|constrained/RBCD]]** where the
  target set is known.
- **Encrypt Kerberos** (AES) + **RC4 off** — a forwarded TGT for an RC4-only
  account is easier to capture/crack ([[kerberos-encryption-types]]).
- Alert on **forwarded-flag 4769 to DC SPNs from workstations**.

## Links

- [[kerberos-delegation]] — the three-flavor overview (UDE is the top tier)
- [[path-unconstrained-delegation-to-domain-admin]] — the end-to-end chain
- [[mitm6-ipv6-relay]] — the no-creds TGT-capture that feeds it
- [[resource-based-constrained-delegation]] — the scoped sibling
- [[pkinit-unpac-the-hash]] — the UnPAC step (cert-based, same idea)
- [[dcsync]] — the endgame the DC hash buys
- [[bloodhound]] — enumerate `TrustedForDelegation`

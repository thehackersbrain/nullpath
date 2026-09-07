---
title: Kerberos Authentication (AD)
type: concept
created: 2026-06-12
updated: 2026-06-13
tags: [kerberos, active-directory, protocol]
---

# Kerberos Authentication (AD)

The default authentication protocol in Active Directory. Almost every AD
attack technique in this wiki abuses some part of this flow.

## Core flow

1. **AS-REQ / AS-REP** — client authenticates to the Key Distribution Center
   (KDC, runs on the Domain Controller) and receives a **Ticket Granting
   Ticket (TGT)**. The TGT is encrypted with the secret of the **`krbtgt`**
   account — see [[krbtgt]].
2. **TGS-REQ / TGS-REP** — client presents its TGT to request a **Service
   Ticket (TGS)** for a specific service, identified by a **Service
   Principal Name (SPN)**. The TGS is encrypted with the *target service
   account's* secret.
3. **AP-REQ** — client presents the TGS directly to the target service,
   which decrypts it with its own secret to authenticate the user.

## Where attacks hook in

| Stage | Attack | Page |
| --- | --- | --- |
| AS-REQ (no pre-auth) | AS-REP Roasting — crack the AS-REP, encrypted with the *user's* hash | [[as-rep-roasting]] |
| TGS-REQ (any SPN) | Kerberoasting — crack the TGS, encrypted with the *service account's* hash | [[kerberoasting]] |
| Forge TGT | Golden Ticket — forge a TGT using the stolen `krbtgt` secret | [[golden-silver-tickets]] |
| Forge TGS | Silver Ticket — forge a TGS using a stolen service account secret | [[golden-silver-tickets]] |
| Steal & replay tickets | Pass-the-Ticket | [[pass-the-hash-and-ticket]] |
| Delegation (TGT embedded in TGS, S4U2Self/S4U2Proxy) | Unconstrained/Constrained/RBCD delegation abuse | [[kerberos-delegation-abuse]] |
| AS-REQ (PKINIT, certificate instead of password) | AD CS template/CA misconfigurations let an attacker obtain a cert and request a TGT as another principal | [[ad-cs-esc-attacks]] |
| AS-REQ (PKINIT) + TGS-REQ (S4U2Self/U2U) | UnPAC the hash — recover an account's NT hash from PAC_CREDENTIAL_INFO once you hold its private key | [[pkinit-unpac-the-hash]] |
| Write `msDS-KeyCredentialLink` | Shadow Credentials — plant your own PKINIT certificate on a target account | [[shadow-credentials]] |

## Common detection signals across these attacks

- **Encryption downgrade to RC4 (etype `0x17`)** — nearly every cracking
  attack benefits from RC4 over AES, so RC4 usage in a domain that supports
  AES is a strong signal. Appears in [[kerberoasting]],
  [[as-rep-roasting]], [[golden-silver-tickets]], [[pass-the-hash-and-ticket]].
- **Event ID 4768** (TGT requested) and **4769** (TGS requested) are the two
  core Kerberos audit events used across detections. A TGS request (4769)
  with no matching TGT request (4768) is a recurring "forged/stolen ticket"
  signal — see [[golden-silver-tickets]] and [[pass-the-hash-and-ticket]].
- **Honey accounts / honey SPNs / honeytokens** — recurring cheap
  high-fidelity detection pattern across nearly every technique here.

## Common mitigations across these attacks

- [[gmsa]] (Group Managed Service Accounts) — neutralizes offline cracking
  of service account secrets (Kerberoasting, Silver Ticket).
- **Protected Users group** — restricts to AES, shortens TGT lifetime,
  blocks delegation/caching. Referenced in [[kerberoasting]],
  [[as-rep-roasting]], [[pass-the-hash-and-ticket]],
  [[kerberos-delegation-abuse]].
- [[ad-tiering-and-hardening]] — the overarching architectural mitigation
  (tiered admin model, PAWs, Credential Guard, LAPS) that limits the blast
  radius once any single credential is compromised.
- **`krbtgt` password rotation (x2)** — the standard recovery action after
  a suspected Golden Ticket / DCSync, see [[krbtgt]].
- [[tgt-tgs]] — the two tickets (TGT/TGS) and which attacks hit which.
- [[kerberos-delegation]] — the UDE/CDE/RBCD family (S4U on top of TGS-REQ)
- [[as-rep-roasting]] — the AS-REQ-stage cracking (preauth disabled)

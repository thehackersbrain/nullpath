---
title: "Kerberos Event IDs (4768/4769/4770/4771 + attack tells)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, kerberos, detection, logging]
---

# Kerberos Event IDs

The DC-side events every Kerberos attack in this wiki lands in, and the
field-level tells that distinguish *which* attack. This is the detection
cross-reference: each technique page in the wiki cites its own event; this
page is the shared table.

## The core events (Kerberos Key Distribution Center, on DCs)

| ID | Event | What it tells you |
|---|---|---|
| **4768** | **TGT issued** | Pre-Auth Type: **0** = no preauth (the account is an [[as-rep-roasting]] target), **1** = encrypted timestamp (normal), **16** = PKINIT (cert logon — [[pkinit-unpac-the-hash]], [[golden-certificate]]). Ticket Encryption Type: **0x17 RC4** vs 0x12/0x18 AES. |
| **4769** | **Service ticket (TGS) issued** | Ticket Encryption Type **0x17 RC4** = [[kerberoasting]] / RC4-downgrade tell. **Forwarded flag** (the "R0" / canonical-name tell) = delegation ([[kerberos-delegation]]). TGS to `krbtgt`/DC SPNs from a workstation = UDE-to-DC ([[path-unconstrained-delegation-to-domain-admin]]). |
| **4770** | TGT request **failed** | Brute/spray noise; Kerbrute user-oracle failures. |
| **4771** | Service ticket request **failed** | Kerberoast brute follow-on, relay attempts, bad SPN requests. |
| **4772** | Service ticket **renewed** | Long-lived TGS renewals; ticket-lifetime extension behavior. |

## The NTLM / logon side

| ID | Event | Tell |
|---|---|---|
| **4776** | **NTLM authentication** to the DC | Any NTLM domain logon — the baseline for [[ntlm-relay-coercion]] bursts (4776 from an unusual source after a [[printer-bug]] coercion). |
| **4648** | Logon with **explicit credentials** | `runas /netonly`, WMI/exec with explicit creds — the [[overpass-the-hash]] and exec-transport surface. |
| **4624** (Type 3) | Network logon | **Key Length 0** = NTLM (hash) auth, not Kerberos — the PtH tell ([[pass-the-hash-and-ticket]]). |
| **4625** | Failed logon | Spray/brute fan-out; correlate with [[netexec]]/[[kerbrute]] sources. |

## Attack → tell map

| Attack | Primary tell |
|---|---|
| [[kerberoasting]] | 4769 **RC4 (0x17)** for SPN accounts, bursted, from one source; often *without* a recent 4768 for that user |
| [[as-rep-roasting]] | 4768 **Pre-Auth Type 0** (no preauth) |
| [[golden-silver-tickets]] (Golden) | 4768 **without any auth** (offline-forged TGT — no 4768 at all, then 4769s), unusual TGT lifetime, RC4 |
| [[golden-silver-tickets]] (Silver) | 4769 **without a preceding 4768** for that user/service |
| [[diamond-ticket]] | 4768 **RC4** with a *post-rotation* ticket-age mismatch (ticket older than krbtgt age) |
| [[kerberos-delegation]] (UDE) | 4769 **forwarded flag** + TGS to DC SPN from a workstation |
| [[overpass-the-hash]] | 4768 **RC4** for an account that normally uses AES |
| [[pass-the-hash-and-ticket]] (PtH) | 4624 Type 3 **Key Length 0** (NTLM), not Kerberos |
| [[pass-the-key]] | Kerberos TGT reuse — 4769s with a TGT age/issuer mismatch, no fresh 4768 |
| [[pkinit-unpac-the-hash]] / [[golden-certificate]] | 4768 **Pre-Auth Type 16 (PKINIT)** for an account that never uses certs |
| [[dcsync]] | not a KDC event — it's **4662/5136 replication** on the DC ([[dcsync]]) |
| [[ntlm-relay-coercion]] | **4776/4624-NTLM** burst to an unusual host after coercion ([[printer-bug]], [[mitm6-ipv6-relay]]) |

## Red-team notes (OPSEC)

- **The KDC logs what you do, not what you know** — a golden ticket is
  invisible *at the KDC* except by absence (4769s with no 4768); that's why
  the "no 4768" correlation rule is the detector, and why forging the TGT on
  the KDC side (a real 4768) is quieter.
- **RC4 is the fingerprint** — most attacks are visible as an **0x17** where
  the domain's baseline is AES; check the domain's [[kerberos-encryption-types]]
  posture before choosing an enctype.
- **Bursts are the pattern** — a kerberoast of 30 SPNs in 60 seconds from one
  client is the alert, not any single 4769.

## Links

- [[kerberos-authentication]] — the protocol these events trace
- [[ad-tiering-and-hardening]] — the baseline that makes the deltas visible
- [[tgt-tgs]] — the tickets the events describe
- [[kerberos-encryption-types]] — the RC4/AES field values

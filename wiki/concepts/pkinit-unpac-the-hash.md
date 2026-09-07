---
title: PKINIT and UnPAC the Hash
type: concept
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, kerberos, credential-access, pkinit, adcs]
---

# PKINIT and UnPAC the Hash

PKINIT is Kerberos's certificate-based pre-authentication mechanism — an
alternative to the normal password-derived-key pre-auth. It's the protocol
glue that connects [[ad-cs-esc-attacks|certificate-based AD attacks]] back
to the Kerberos/NTLM world covered in [[kerberos-authentication]].

## How it differs from normal pre-auth

Normal pre-auth: client encrypts a timestamp with a key derived from its
password; KDC decrypts with the same derived key (symmetric).

PKINIT: client signs/encrypts a timestamp with its **private key**
(certificate-based, asymmetric). The KDC verifies against the certificate
and, if valid, issues a TGT.

Requires: AD CS with a CA, and at least one DC on Windows Server 2016+.

## PAC_CREDENTIAL_INFO — the bridge to NTLM

When a TGT is issued via PKINIT, the KDC embeds a `PAC_CREDENTIAL_INFO`
structure in the ticket containing the account's NTLM (LM/NT) hashes — this
exists so a cert-authenticated user can still fall back to NTLM against
servers without Kerberos support.

## UnPAC the Hash

`PAC_CREDENTIAL_INFO` is encrypted and not readable from the TGT directly.
Recovering it requires a TGS-REQ using **S4U2Self + User-to-User (U2U)**
(the user requests a service ticket to itself); the resulting session key
decrypts `PAC_CREDENTIAL_INFO`, yielding the NT hash.

```
gettgtpkinit.py -cert-pfx CERT -pfx-pass PASS DOMAIN/USER ccache   # get TGT via PKINIT
getnthash.py -key SESSION_KEY DOMAIN/USER                          # UnPAC the hash
```
(Rubeus `/getcredentials` and Certipy `auth` do the equivalent on Windows.)

## Why this matters

Anything that gives an attacker a private key for an account — not just a
password — now converts to a full NT hash:

- [[shadow-credentials]] — mint your own key via `msDS-KeyCredentialLink`
  write.
- [[ad-cs-esc-attacks]] — obtain a certificate for another principal via
  template/CA misconfiguration.
- "Golden Certificate" — forge certs with a stolen CA private key.

All three converge on the same UnPAC-the-hash step to get a usable NT hash,
which then feeds into [[pass-the-hash-and-ticket]],
[[golden-silver-tickets]], and [[kerberos-delegation-abuse]].

## Detection

- Certificate-based 4768 pre-auth for accounts that don't normally do
  smart-card/cert logon.
- S4U2Self requests from non-service/non-computer accounts.
- `msDS-KeyCredentialLink` writes (precursor to [[shadow-credentials]]).

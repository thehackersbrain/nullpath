---
title: Pass the Cert (PKINIT)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, pkinit, pki, ad-cs, pass-the-cert, privilege-escalation]
---

# Pass the Cert (PKINIT)

**Pass the Cert** is the certificate analogue of Pass the Hash / Pass the
Ticket: instead of a hash or a ticket, the credential you replay is a **client
authentication certificate** (private key + cert). You present it via
**PKINIT** (Kerberos Pre-Authentication using Public Key Infrastructure) and
the KDC issues you a **real TGT** for the account the cert is bound to — no
password needed. It's the payoff primitive for a large share of this wiki's
AD CS and shadow-credential research: once an attack hands you a *valid
client-auth cert*, Pass the Cert turns it into a login. See
[[pkinit-unpac-the-hash]] for PKINIT mechanics and
[[ad-cs-esc-attacks]] for how the certs are obtained.

## How PKINIT works (the pre-auth you're replacing)

In normal Kerberos the AS-REQ's pre-authentication is a timestamp encrypted
with the user's key (see [[kerberos-authentication]]). **PKINIT** replaces
that with a **public-key exchange**: the client proves possession of the
**private key** of a cert whose subject maps to a domain account (via UPN or
SAMAccountName in the cert's Subject Alternative Name). The KDC validates the
cert chain (to a trusted CA / ADCS) and, on success, issues the TGT. So the
**cert private key is the password** — hold it, log in.

## How you get the cert (the upstream attacks)

Pass the Cert is the *last step*; the interesting work is getting a usable
client-auth cert:

- **AD CS ESC attacks** — [[ad-cs-esc-attacks]] (ESC1/ESC3/ESC8/etc.) let you
  request a **client-authentication** cert bound to a target (often
  Administrator or a Tier-0 account). [[cve-2024-49019|EKUwu]] and
  [[cve-2022-26923|ESC12]] are the headline variants.
- **Shadow Credentials** — [[shadow-credentials]] lets you **plant** a
  cert/key-trust (`msDS-KeyCredentialLink`) on any account you have
  GenericWrite on, then authenticate as it via PKINIT. [[whisker]] is the
  tooling.
- **Capture** — a stolen `.pfx` (cert + private key) from a host, a GMSA, or a
  service that uses cert-based logon.

## The abuse

```bash
# PKINIT login with a client-auth cert + private key (.pfx)
kinit -cert -keytab <user> <user>.pfx        # or Rubeus / RBCD tooling
# or via a keytab built from the cert:
certipy cert -pfx admin.pfx ...             # export the key
kinit admin@CORP -kt admin.keytab
klist                                      # TGT for admin (via PKINIT)
```
Once the TGT is in hand, it's a normal Kerberos session — DCSync, lateral,
domain dominance. See [[pkinit-unpac-the-hash]].

### The UnPAC bonus

PKINIT TGTs carry a **PAC** with the account's **NT hash** in
`PAC_CREDENTIAL_INFO` — so a PKINIT login can **recover the NT hash** of the
account (see [[pkinit-unpac-the-hash]], [[kerberos-pac]]). That means Pass the
Cert can *downgrade* into Pass the Hash for the same account — a persistence
boon.

## Why it matters

- **Cert = password** — a valid client-auth cert is a full login credential,
  independent of the password (survives password resets).
- **The AD CS / shadow-credential payoff** — most of those attacks end at
  "you have a cert"; Pass the Cert is how that becomes "you're in."
- **PKINIT → NT hash** — the UnPAC step turns a cert into a reusable NT hash
  (persistence + lateral).
- **Quiet** — a PKINIT TGT is a real KDC-minted ticket (4768 with PKINIT
  pre-auth type), not a forged one.

## Detection

- **4768 with PKINIT pre-auth** — a TGT requested via certificate (pre-auth
  type `PKINIT`), especially for privileged accounts from unusual hosts.
- **AD CS issuance** — a client-auth cert issued to a privileged UPN
  ([[ad-cs-esc-attacks]] tells).
- **`msDS-KeyCredentialLink` writes** — shadow-credential planting
  ([[shadow-credentials]]).
- **PAC_CREDENTIAL_INFO access** — the UnPAC read.

## Mitigations

- **Restrict client-auth cert issuance** — templates, EKUs, CA scopes
  ([[ad-cs-esc-attacks]]).
- **Limit `msDS-KeyCredentialLink` writes** — [[shadow-credentials]]
  mitigation.
- **Prefer/require specific PKINIT** or disable PKINIT where not needed;
  monitor for PKINIT pre-auth on privileged accounts.
- **Rotate/revoke** the cert (and key) if captured — the cert is the secret.
- **GMsA / short-lived keys** for service certs — see [[gmsa]].

## Links

- [[pkinit-unpac-the-hash]] — PKINIT mechanics + the UnPAC NT-hash recovery
- [[ad-cs-esc-attacks]] — how the client-auth certs are obtained
- [[shadow-credentials]] — planting the cert/key-trust
- [[kerberos-pac]] — the PAC_CREDENTIAL_INFO the UnPAC reads
- [[kerberos-authentication]] — the AS-REQ stage PKINIT replaces
- [[whisker]], [[certipy]] — the cert tooling
- [[gmsa]] — the rotating-cert/key mitigation

## References

- [Microsoft: PKINIT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kerb/)
- [ired.team: PKINIT / UnPAC](https://www.ired.team/active-directory-kerberos-abuse/)
- [ad-cs-esc-attacks (this wiki)](ad-cs-esc-attacks)
- [shadow-credentials (this wiki)](shadow-credentials)

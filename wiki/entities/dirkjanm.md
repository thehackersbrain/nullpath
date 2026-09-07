---
title: dirkjanm (Dirkjan Ochtman)
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [researcher, active-directory, ad-cs, ntlm-relay]
---

# dirkjanm (Dirkjan Ochtman)

**Dirkjan Ochtman** (`dirkjanm`) is a leading independent AD / AD CS
offensive-security researcher. His blog **dirkjanm.io** is a primary source
for NTLM-relay, RBCD, and AD CS technique development. He is the author of
[[mitm6]] and the origin of the **"worst of both worlds"** credential-less
RBCD write-ups that this wiki's [[rbcd-via-ntlm-relay]] and
[[mitm6-ipv6-relay]] pages are built on.

## Key contributions referenced in this wiki

- **mitm6** — the IPv6 NTLM relay / MITM tool ([[mitm6]]).
- **Credential-less RBCD** — the WPAD → LDAPS relay RBCD chain
  ([[rbcd-via-ntlm-relay]], [[mitm6-ipv6-relay]]).
- **NTLM relay + AD CS** — numerous relay-to-AD-CS / RBCD / delegation
  write-ups underpinning [[ntlm-relay-coercion]] and
  [[ad-cs-esc-attacks]].
- **Kerberos / delegation** research feeding [[s4u2self-s4u2proxy]] and
  [[kerberos-delegation-abuse]].

## Why he matters for this wiki

- He is the **technique source** for the credential-less relay/RBCD attack
  paths — the most "network-position + no creds" plays in the AD space.
- His write-ups are the canonical references for the mitm6/LDAPS RBCD flow.

## Links

- [[mitm6]] — his tool
- [[mitm6-ipv6-relay]] — the technique
- [[rbcd-via-ntlm-relay]] — the credential-less RBCD chain
- [[ntlm-relay-coercion]] — the relay + coercion hub
- [[ad-cs-esc-attacks]] — the AD CS research he contributes to
- [[kerberos-delegation-abuse]] — the delegation research

## References

- [dirkjanm.io](https://dirkjanm.io/)
- [mitm6 (GitHub)](https://github.com/dirkjanm/mitm6)
- [dirkjanm: RBCD / mitm6 posts](https://dirkjanm.io/)

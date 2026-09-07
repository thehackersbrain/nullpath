---
title: "Trust-key abuse & inter-realm TGT forging (trust tickets)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [kerberos, trusts, forest, ticket-forgery, privilege-escalation]
---

# Trust-key abuse & inter-realm TGT forging

When you authenticate across a trust, your home KDC hands you an **inter-realm
referral TGT** encrypted with the **trust key** shared between the two domains
(the password of the `<TRUSTED_DOMAIN>$` inter-domain trust account — see
[[ad-trusts]]). The target domain's KDC decrypts it with the same key and issues
service tickets. So if you **hold the trust key**, you can **forge that
inter-realm TGT yourself** — a "trust ticket" — and inject whatever SIDs the
target will honor. This is the primary way a child-domain compromise becomes a
**forest-wide Enterprise Admin**, and a route across forest trusts where SID
filtering permits.

## Two escalation primitives (child → forest root)

Because **intra-forest trusts don't filter SIDs** ([[ad-trusts]]), a child-domain
DA reaches the forest root two ways:

**A. krbtgt + SID history (the classic).** You have the child domain's `krbtgt`
key ([[dcsync]]). Forge an intra-forest referral TGT that stuffs the
**Enterprise Admins** SID of the *root* domain (`S-1-5-21-<root>-519`) into the
PAC's ExtraSids. The root KDC honors it (no filtering within the forest) → EA.
This is [[sid-history]] injection applied across the trust.

**B. The trust key directly.** DCSync the inter-domain trust account
(`<PARENT_DOMAIN>$`) to get the trust key, forge the inter-realm TGT with it, add
the 519 ExtraSid. Same outcome, different secret.

```bash
# Get the trust key (the trust account's hash) — it's just an account in the child:
secretsdump.py 'child.corp.local/DA:Pass@childdc' -just-dc-user 'corp.local\CHILD$'
#   or mimikatz on the DC:  lsadump::trust /patch   /   lsadump::dcsync /user:corp\CHILD$

# Forge the inter-realm trust ticket (mimikatz): child TGT that claims root EA
kerberos::golden /user:Administrator /domain:child.corp.local \
  /sid:<child-domain-sid> /sids:<root-domain-sid>-519 \
  /rc4:<trust-key-rc4> /service:krbtgt /target:corp.local /ticket:trust.kirbi

# Ask a TGS in the ROOT domain using that referral ticket, then use it:
Rubeus.exe asktgs /ticket:trust.kirbi /service:CIFS/rootdc.corp.local /dc:rootdc.corp.local /ptt

# Impacket automates the whole child->parent chain end to end:
raiseChild.py 'child.corp.local/DA:Pass'          # -> dumps root krbtgt, gives EA
```

`ticketer.py` with `-extra-sid <root>-519` builds the same forged ticket
programmatically; `raiseChild.py` is the one-shot.

## Cross-forest (external / forest trusts)

Across a **forest boundary** the trust key still lets you forge an inter-realm
TGT, **but SID filtering strips foreign privileged SIDs** (519/512 of the *other*
forest) from the PAC — so you can't just stuff Enterprise Admins. What still
works:

- SIDs that **belong to the trusted forest's own domains** are honored — useful
  where the target grants rights to your forest's principals.
- If the trust is **`TREAT_AS_EXTERNAL`** or filtering is otherwise weakened
  (CVE-2020-0665), previously-filtered SIDs slip through — that's the whole point
  of [[ad-trust-attacks]].
- Otherwise pivot via [[foreign-security-principals]], cross-forest delegation
  coercion, or [[cross-forest-adcs]] rather than raw SID injection.

## Red-team notes (OPSEC)

- **Rotate-resistant, like a golden ticket.** The trust key changes only on a
  ~30-day trust password rotation (and the DC keeps the previous key), so a trust
  ticket is durable — a quiet re-entry into the forest root.
- **519 from the wrong domain is the tell.** A forged inter-realm TGT carries an
  ExtraSid (`...-519`) whose domain differs from the account's — anomalous in the
  PAC. Keep lifetimes normal and don't over-stuff SIDs.
- **`raiseChild.py` is fast but loud** (it DCSyncs the root krbtgt); for a
  targeted, quieter move, forge the specific ticket you need and pull only what
  you came for.
- Prefer forging the referral ticket over re-DCSyncing each time — one trust-key
  grab, reusable forgeries.

## Detection

- **4769** for a `krbtgt` service in one domain immediately used to request TGSs
  in another; inter-realm TGS anomalies.
- Forged-ticket tells (as in [[golden-silver-tickets]]): lifetime > policy max,
  ExtraSids referencing a different domain's 519/512.
- DCSync of a **trust account** (`*$`) or the `krbtgt` (MS-DRSR replication from a
  non-DC) — high-fidelity ([[dcsync]] detection).
- `raiseChild.py`'s signature: child-DA auth → root krbtgt replication → forged EA.

## Links

- [[ad-trusts]] — trust types/keys this abuses (the fundamentals)
- [[sid-history]] — the ExtraSid injection mechanism forests honor intra-forest
- [[golden-silver-tickets]] — the base forgery; a trust ticket is its inter-realm form
- [[krbtgt]] — the child key used in primitive A
- [[dcsync]] — how you obtain the trust key / krbtgt
- [[ad-trust-attacks]] — when cross-forest SID filtering can be beaten
- [[kerberos-pac]] — the PAC/ExtraSids the forged ticket carries

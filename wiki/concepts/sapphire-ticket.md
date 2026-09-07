---
title: "Sapphire Ticket (real privileged PAC via S4U2self)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [kerberos, active-directory, ticket-forgery, privilege-escalation, opsec]
---

# Sapphire Ticket

The **Sapphire Ticket** is the stealthiest of the `krbtgt`-key forgeries. Like a
**Diamond Ticket** it modifies a **real** TGT rather than fabricating one from
scratch — but instead of *hand-crafting* the PAC's group SIDs (which is where
forged tickets look wrong), it inserts a **genuine, complete PAC belonging to a
powerful user**, obtained legitimately via **S4U2self**. The forged ticket
therefore carries a real, correctly-structured, fully-populated PAC — defeating
the PAC-anomaly detections that catch Golden/Diamond forgeries.

> Note: this wiki's [[diamond-ticket]] page currently frames Diamond as an
> AES128 *downgrade*; the accurate distinction is **Golden = forge a TGT from
> nothing; Diamond = decrypt/modify a real TGT's PAC; Sapphire = Diamond, but
> the injected PAC is a real one pulled via S4U2self.** (Diamond page flagged for
> correction.)

## The idea

1. You hold the `krbtgt` key ([[dcsync]]) — same prerequisite as
   [[golden-silver-tickets|Golden]]/[[diamond-ticket|Diamond]].
2. Use **S4U2self** ([[s4u2self-s4u2proxy]]) to request a service ticket *to
   yourself* **as an impersonated privileged user** (e.g. a Domain Admin). That
   ticket contains that user's **real PAC** — real group memberships, real
   signature structure.
3. Extract that legitimate PAC and embed it into a TGT you re-encrypt with the
   `krbtgt` key. The result authenticates as the privileged user with a PAC that
   is indistinguishable from one the DC itself issued.

## Command (Impacket ticketer)

```bash
# ticketer.py builds a Sapphire ticket when given -impersonate (pulls the target's
# real PAC via S4U2self) plus the krbtgt key and domain SID:
ticketer.py -request -impersonate Administrator \
  -domain corp.local -user lowprivuser -password 'LowPrivPass' \
  -nthash <krbtgt-nthash> -domain-sid S-1-5-21-... \
  Administrator

export KRB5CCNAME=Administrator.ccache
nxc smb dc01 --use-kcache          # use it ([[pass-the-hash-and-ticket]])
```

`-request -impersonate` is what separates a Sapphire build (fetch the real PAC)
from a plain offline forge.

## Red-team notes (OPSEC)

- **This is the forgery to reach for against PAC-validation defenses.** Golden
  and Diamond can be caught by PAC structure/lifetime anomalies; a Sapphire
  ticket's PAC is genuine, so those checks pass. If the environment does PAC
  validation or forged-ticket hunting, prefer Sapphire.
- **The S4U2self request is the residual tell** — building the ticket requires an
  S4U2self exchange for the impersonated user (4769), so it's not *zero* signal;
  keep the impersonated target plausible and lifetimes normal.
- Still requires `krbtgt` — it's a post-DA persistence/impersonation primitive,
  not a privesc. Rotate `krbtgt` twice to invalidate ([[krbtgt]]).

## Detection

- **S4U2self** for a privileged user followed by that user's TGT appearing from
  an unexpected host — the build step.
- Standard forged-ticket correlation is weaker here (the PAC is real), so lean on
  **behavioral** signals: a DA TGT in use from a non-Tier-0 host, impossible
  logon locations, and `krbtgt`-replication history ([[dcsync]] detection).
- The only durable fix is the same as Golden: **rotate `krbtgt` twice**
  ([[krbtgt]]).

## Links

- [[diamond-ticket]] — the "modify a real ticket" sibling (Sapphire embeds a real PAC)
- [[golden-silver-tickets]] — the base forgery; Sapphire is the stealthiest variant
- [[s4u2self-s4u2proxy]] — the S4U2self step that fetches the real privileged PAC
- [[kerberos-pac]] — why a genuine PAC beats anomaly detection
- [[krbtgt]] / [[dcsync]] — the key it needs and how it's obtained

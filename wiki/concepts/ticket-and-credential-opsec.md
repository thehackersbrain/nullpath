---
title: "Ticket & Credential Handling (engagement hygiene)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [red-team, active-directory, kerberos, opsec, tradecraft]
---

# Ticket & Credential Handling

The operational hygiene around the identity material you collect on an AD
engagement — tickets, hashes, keys — during the [[redteam-ad-methodology]]
flow. Sloppy handling both burns OPSEC and creates real risk with client
secrets in scope.

## Kerberos tickets in memory vs on disk

- **Windows** — inject with Pass-the-Ticket (`Rubeus.exe ptt /ticket:...`,
  `mimikatz kerberos::ptt`) so the TGT/TGS lives in the LSA, not on disk.
  `klist` to inspect, `klist purge` to clear before you leave.
- **Linux** — tickets live in a **ccache** file pointed to by `KRB5CCNAME`
  ([[ccache]]). Keep it in your loot dir, export it for the DC's context, and
  delete when done. This is what you carry over the tunnel in
  [[c2-and-pivoting-ad]].

```bash
export KRB5CCNAME=/loot/admin.ccache
klist                     # inspect
kdestroy                  # clear
# convert between Windows .kirbi and Linux .ccache
ticketConverter.py admin.kirbi admin.ccache
```

## Lifetimes & renewal

A TGT has a default **10h lifetime / 7d renewal window**. A ticket that keeps
working past that window is itself a detection signal (and the tell for a
forged [[golden-silver-tickets|Golden Ticket]] / [[diamond-ticket]]). Operate
inside normal lifetimes; renew rather than re-request where you can, to keep
4768/4769 volume down ([[opsec-ad-tradecraft]]).

## Credential material hygiene

- **Scope check first.** Only pull what the engagement authorises; a
  full [[dcsync]] of the domain grabs *every* account's secret — often
  broader than needed. Prefer `-just-dc-user` for the specific target.
- **Storage** — keep hashes/keys/tickets in a single engagement loot store,
  encrypted at rest; never in shell history or a shared host.
- **Redaction** — real hostnames, client account names, and cracked passwords
  get redacted in notes and this wiki (the house rule: no stolen data). Record
  the *technique and misconfig*, not the client's secret.
- **Cleanup** — purge injected tickets, remove staged tooling, and note any
  artefact you couldn't remove so it goes in the report.

## Reporting hook

Each secret obtained maps to a finding: *what right/misconfig exposed it*
(link the technique page), *what it unlocked*, and *the remediation*
([[ad-tiering-and-hardening]], krbtgt rotation via [[krbtgt]], enctype
hardening via [[kerberos-encryption-types]]).

## See also

- [[ccache]] — the Linux ticket cache format
- [[ticket-manipulation]] — the full kirbi↔ccache / PtT / triage command cheat-sheet
- [[ad-error-decoder]] — decode the Kerberos errors these commands throw
- [[redteam-ad-methodology]] — where this sits in the flow
- [[c2-and-pivoting-ad]] — moving tickets over the tunnel
- [[pass-the-hash-and-ticket]] — the reuse primitives you're handling
- [[golden-silver-tickets]] — forged tickets and their lifetime tells

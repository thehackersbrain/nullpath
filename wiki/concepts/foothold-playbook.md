---
title: "Foothold playbook (you hold X → do Y next)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [tradecraft, methodology, playbook, field-notes, red-team]
---

# Foothold playbook

The condensed decision runbook: **based on what you currently hold, what's the
next move** — ranked, with the one-liner and the page. It compresses
[[redteam-ad-methodology]] / [[situational-awareness]] / [[ad-enumeration]] and
the 20+ path notes into a single glance for when you're mid-box and asking "OK,
what now?" Golden rule throughout: **enumerate before you exploit**, and let
[[bloodhound]] pick the edge.

## You have: nothing (network position, no creds)

1. **Poison + relay** — [[llmnr-nbt-ns-poisoning]] / [[mitm6-ipv6-relay]] with
   [[responder]] → capture/relay NTLM ([[ntlm-relay-coercion]]).
2. **Coerce** — PetitPotam/PrinterBug → relay to LDAP/AD CS ([[ntlm-relay-coercion]], [[esc8]]).
3. **Unauth enum** — null/guest SMB, RID brute, `enum4linux-ng`, anon LDAP ([[ad-enumeration]]).
4. **Roast without creds** — [[timeroasting]] (computer accounts), AS-REP roast on found users ([[as-rep-roasting]] `-no-pass`).
5. **Spray** a common password against a built user list ([[password-spraying]]).

## You have: a username list (no password)

- `kerbrute userenum` to validate; **AS-REP roast** the preauth-disabled ones;
  then **spray** (lockout-aware) — [[password-spraying]].

## You have: one low-priv cred (password or NT hash)

1. **Validate + lockout policy** — `nxc smb dc -u u -p p --pass-pol`; where are you
   `(Pwn3d!)`? ([[ad-enumeration]]).
2. **Map it** — [[bloodhound]]/[[rusthound]] `-c DCOnly` first; find shortest path.
3. **Roast** — [[kerberoasting]] + [[as-rep-roasting]] in one pass (`nxc ldap --kerberoasting --asreproast`).
4. **AD CS** — `certipy find -vulnerable` ([[ad-cs-esc-attacks]]).
5. **What can I write?** — `bloodyAD ... get writable` ([[bloodyad]], [[acl-abuse]]) →
   RBCD / shadow creds / targeted roast / add-dcsync.
6. **Cheap creds** — GPP cpassword, share spidering, `get-desc-users`, **gMSA read**
   ([[gmsadumper]]), **LAPS read** ([[laps]]).
7. **MAQ + delegation** — `-M maq`; unconstrained/constrained/RBCD hosts
   ([[kerberos-delegation]]); if MAQ>0, [[nopac]] on unpatched DCs.

## You have: an NT hash

- **PtH** everywhere (`nxc -H`); **Overpass-the-hash** → a real TGT
  ([[overpass-the-hash]]); if it's a DCSync-capable principal, **[[dcsync]]**;
  if local admin, `secretsdump`. See [[pass-the-hash-and-ticket]].

## You have: a ticket (TGT/TGS)

- **PtT** (`export KRB5CCNAME=... ; nxc --use-kcache`), **S4U** if the account
  delegates ([[s4u2self-s4u2proxy]]). Plumbing: [[ticket-manipulation]].

## You have: local admin on a host

1. **Dump secrets** — `--sam`/`--lsa`/`--lsass`/`--dpapi` ([[credential-dumping]],
   [[lsass]], [[dpapi]]); **steal a session's ticket** (`--loggedon-users` → a privileged user present).
2. **DPAPI** — browser cookies (MFA-bypass) + saved creds ([[dpapi]]).
3. **SCCM** — NAA creds if it's a client ([[sccm-abuse]]).
4. **RBCD / shadow creds** on hosts you can write ([[resource-based-constrained-delegation]], [[shadow-credentials]]).

## You have: a foothold but it's low-priv on the box

- Local privesc first ([[windows-privilege-escalation]], [[potato-family]] via
  `SeImpersonate`) → local admin → the row above.

## You have: Domain Admin / DCSync rights

1. **DCSync `krbtgt`** + a few targets ([[dcsync]]).
2. **Golden/Diamond/Sapphire** for persistence ([[golden-silver-tickets]],
   [[diamond-ticket]], [[sapphire-ticket]]); **DPAPI backup key** for offline
   mass-decrypt ([[dpapi]]).
3. **Trusts** — child→parent EA, cross-forest ([[trust-key-abuse]], [[ad-trusts]]).
4. Persistence only if in scope ([[ad-persistence]]).

## When it's not working

- Push back toward **enumeration**, not more payloads.
- The **exact error** is the hint — decode it ([[ad-error-decoder]]).
- Run tools **from Linux over the tunnel**, by **hostname**, clock **synced**
  ([[pivoting-and-tunneling]]).

## Links

- [[redteam-ad-methodology]] — the full phased version of this
- [[ad-enumeration]] / [[situational-awareness]] — the recon this branches on
- [[ad-error-decoder]] — when a step errors; [[ticket-manipulation]] — ticket plumbing
- [[bloodhound]] — the graph that ranks the next edge

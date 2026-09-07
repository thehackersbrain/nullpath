---
title: "Printer Bug (CVE-2021-34527) — Print Spooler coercion"
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [windows, coercion, ntlm-relay, cve, print-spooler, lateral-movement]
---

# Printer Bug (CVE-2021-34527) — Print Spooler coercion

The **Printer Bug** is a coercion vector: a (often low-priv or machine)
account on a network can trick a **victim's Windows Print Spooler service**
into **authenticating to the attacker**, yielding the **victim's machine
account NTLM** to relay. It's the spooler-side cousin of **PetitPotam**
(EFSRPC) — together they're the two main "coerce a host to auth to me"
techniques feeding [[ntlm-relay-coercion]].

## The bug

- A caller with access to the spooler's RPC interface
  (`SpoolSS` on **port 135**) can call
  **`AddPrinterDependencyEx`** (and related) with a **crafted `PRINTER_INFO_2`
  whose `pDrivers`/driver path points at a UNC path**
  (`\\ATTACKER\share\driver.cab` or a driver folder).
- The **Print Spooler service** (running as **`LocalSystem`** on the victim)
  resolves that UNC path → the **victim's machine account** (`VICTIM$`)
  **authenticates to the attacker's SMB share** to pull the "driver."
- That authentication is **NTLM** (the machine account → your SMB server),
  which you **relay** — typically to **LDAP** (to write RBCD / create a
  computer account) or **SMB**. See [[ntlm-relay-coercion]] and
  [[rbcd-via-ntlm-relay]].

## Why it's a *coercion* vector

The attacker **doesn't need any of the victim's credentials** — they just
need to be able to **call the spooler's RPC** (often any domain user /
computer account that can reach port 135). The *victim's own service* does
the authenticating. So the chain is:

```
attacker (any acct that can reach victim:135)
  --AddPrinterDependencyEx(pDrivers=\\ATTACKER\share\... )-->
victim's Print Spooler (LocalSystem)
  --resolves UNC--> authenticates VICTIM$ to ATTACKER (SMB 445)
  --attacker relays VICTIM$ NTLM--> LDAP: write RBCD / create computer acct
  --victim$ is now "compromised"--> DCSync / domain (see rbcd-via-ntlm-relay)
```

**Variants:**
- **PrinterBug** — the original, RPC `SpoolSS` on **135**.
- **PrinterBug445** — the **named-pipe / port-445** variant (uses the spooler's
  named pipe instead of the 135 RPC endpoint), used when 135 is filtered.
- Contrast with **PetitPotam** (`EFSRpc`/`ECKeyEx` on 135) — same *effect*
  (coerce a machine-account NTLM), different RPC interface. Some hosts have
  one patched and the other not, so you try both.

## Detection

- **Spooler talking to a non-printer host** — the victim's machine account
  making an **outbound SMB** connection to an unusual host (your share).
- **`7045`/service** isn't the tell here (no service is installed on the
  victim); the tell is the **spooler's network connection** + a
  **`VICTIM$` Type-3 NTLM (Key Length 0)** to your host.
- On the **attacker side**, the relay then produces the usual
  [[rbcd-via-ntlm-relay]] / RBCD tells (a new computer account, a write to
  `msDS-AllowedToActOnBehalfOfOtherIdentity`).
- **RPC 135** from a non-admin / computer account to another host's spooler is
  itself suspicious.

## Mitigations

- **Patch** (Jan 2021 updates) — the fix restricts which calls can set a UNC
  driver path. The patch is version-specific (it changed across KBs), so
  "patched" is less clean than it looks.
- **Disable the Print Spooler** on servers/DCs that don't print
  (`PrintSpooler` service).
- **Restrict RPC 135 / 445** between non-printing systems (network policy).
- **SMB signing / NTLM restrictions** on the attacker's side of the relay
  (this affects the *relay*, not the coercion).
- Monitor **machine-account NTLM** to unexpected hosts.

## Tooling

- **Impacket** — `PrinterBug.py` (coerce via spooler RPC) and
  `PrinterBug445.py` (the 445 variant). Pair with `ntlmrelayx.py` to relay the
  captured `VICTIM$` to LDAP for RBCD. See [[impacket]] and
  [[ntlmrelayx]].

## Links

- [[ntlm-relay-coercion]] — the coercion + relay hub this feeds
- [[rbcd-via-ntlm-relay]] — the credential-less RBCD chain the coerced NTLM enables
- [[ntlmrelayx]] — the relay that captures/replays the machine NTLM
- [[ntlm]] — the machine-account NTLM that gets coerced
- [[service-account]] — the victim is usually a machine account
- [[krbrelay]] — the Kerberos-side coercion (contrast)
- [[mitm6-ipv6-relay]] — the IPv6 coercion alternative
- [[impacket]] — `PrinterBug.py` / `PrinterBug445.py`
- [[smb]] — the channel the coerced machine account authenticates over

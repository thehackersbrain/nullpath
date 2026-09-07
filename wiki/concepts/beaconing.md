---
title: "Beaconing (C2 traffic and its detection)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [c2, beaconing, detection, network, post-exploitation]
---

# Beaconing

**The C2's *heartbeat* — a compromised host that *periodically* checks in
with its command server.** The beacon is the **definitive** tell of a
compromised host that's *still* under attacker control (as opposed to a
one-shot dropper that does its thing and exits). **Detecting the beacon**
is the network-side answer to "is this host *still* compromised, and is
the attacker *still* in it?" — it's the [[reverse-engineering-workflow]]
step 3 (the network capture) made into a *detection*.

## Why the beacon is the tell (not the C2 traffic)

- **The C2 *traffic* is one-directional and one-off** — a dropper that
  *downloads* a payload and *exits* has C2 traffic, but it's **over** (the
  host is compromised, but the attacker *left*). The traffic is a
  *past* event.
- **The *beacon* is recurring and ongoing** — a compromised host that's
  *still* under control **checks in on a schedule** (every N seconds /
  minutes / hours). The beacon is a **present, continuous** event — the
  host is *still* talking to the attacker *right now*. That *recurrence*
  (the *periodicity*) is the beacon's signature, and it's what separates
  "the host was hit" from "the host is *still* held."

## The beacon's shape (what to look for)

- **The *periodicity*** — the beacon fires at a **fixed interval** (a
  `sleep(N)` in the C2 loop). The tell is the **regularity** (a
  connection every *exactly* 60 s, ± a small jitter). A *human* doesn't
  connect at a fixed interval; a *beacon* does.
- **The *jitter*** — a real beacon adds **jitter** (a random ±10–20% to
  the interval) to avoid a *perfect* period (which is a tell in itself).
  The tell is the **jittered-but-bounded** period (a connection every
  *50–70 s*, not *exactly* 60 s, not *random*).
- **The *small, consistent payload*** — the beacon's **check-in** is a
  *tiny* packet (a few hundred bytes: an agent ID, a timestamp, a
  "what's my next command?"). The tell is the **small, consistent
  request** (not a download, not an upload — a *heartbeat*).
- **The *response is the command*** — the C2 *responds* with the next
  command (a "run this," a "dump this," a "sleep"). The tell is the
  **request→command** pattern (a small request, a *meaningful* response —
  not a *data* response).

## The beacon *protocol* (the modern C2s)

- **The *encrypted* channel** — the beacon is **encrypted** (TLS, or a
  custom cipher) so the *payload* isn't readable; the *timing* (the
  period, the jitter) is **not** encrypted (it's in the *packet
  inter-arrival*). The tell is the **timing**, not the *content*.
- **The *channel*** — the beacon rides a **normal-looking channel**
  (HTTPS to a real CDN, a DNS query, an SMB share) to avoid a *content*
  tell. The tell is the **channel's *behavior*** (a HTTPS connection to a
  CDN *every 60 s from a server that's never browsed a CDN*).
- **The *mTLS* / the *certificate*** — some beacons use **mTLS** (a
  client cert) or a **specific cert** (the C2's cert). The tell is the
  **unusual cert** (a self-signed, a short-lived, a *revoked-but-still-
  used* cert on a *server* host).

## The *detection* (the network-side answer)

### The *time-based* beacon detection (the classic)
- **The *periodicity* analysis** — a **time-series** of the host's
  outbound connections; a **fixed period** (± jitter) to a *single*
  destination is a beacon. Tools: a **NetFlow**/**Zeek** time-series, a
  **Sigma** rule on the *connection interval*.
- **The *entropy* of the interval** — a *random* interval has high
  entropy; a *fixed* (jittered) interval has **low entropy** (it's
  *predictable*). The tell is the **low-entropy, bounded** interval.

### The *behavior-based* beacon detection (the higher-fidelity one)
- **The *small-request / command-response* pattern** — a connection that
  sends a *tiny* request and gets a *meaningful* (not-data) response,
  *repeatedly*, is a beacon (a *data* transfer is a *large* response; a
  *beacon* is a *small* request + a *command* response). The tell is the
  **request/response *shape***, not just the timing.
- **The *host-type* mismatch** — a **server** host (a domain controller,
  a file server) that beacons to a **CDN**/a **SaaS**/a **residential
  IP** is a *behavioral* mismatch (servers don't normally browse CDNs).
  The tell is the **host-type → destination-type** mismatch.
- **The *lateral + beacon* correlation** — a host that beacons *and*
  does **lateral movement** (a SMB to a *new* host, a WMI remote
  exec) is a beacon *with intent* (the beacon is the *control*, the
  lateral is the *action*). The tell is the **beacon + lateral**
  correlation (the beacon *triggers* the lateral).

### The *C2-specific* detection (the tool-aware one)
- **The *known-C2* signature** — a **known C2 framework** (Cobalt Strike,
  Sliver, Mythic) has a **known beacon signature** (a *specific* TLS
  fingerprint, a *specific* request path, a *specific* cert pattern).
  The tell is the **C2-framework signature** (a JA3/JA4 that matches a
  known C2, a request path that matches a known C2's default).
- **The *JA3/JA4* beacon** — the **TLS fingerprint** (the JA3/JA4) of a
  beacon is *consistent* (the same C2, the same fingerprint, *every*
  check-in). The tell is the **consistent JA3 on a *server* host** (a
  server with a *client-app* TLS fingerprint, repeating).

## The *evasion* (the C2's answer)

- **The *jitter* + the *random channel*** — a beacon with **high jitter**
  (±50%) and a **random channel** (a *different* CDN/destination *each*
  check-in) defeats the *periodicity* and the *consistent-destination*
  tells. The cost: the **C2 has to rotate** (a *new* destination *each*
  time), which is a *logistical* tell (a *new* infra per check-in).
- **The *covert channel*** — the beacon rides a **legitimate, high-entropy
  channel** (a *real* SaaS, a *real* CDN with *real* traffic) so the
  *timing* is hidden in the *noise*. The cost: the **C2 has to look like
  the *legit* app** (a *real* SaaS request pattern), which is a *protocol*
  tell (a *SaaS* request that's *too regular*).
- **The *long sleep* + the *on-demand*** — the beacon **sleeps a long
  time** (an hour, a day) and only wakes **on a trigger** (a *specific*
  file, a *specific* time). The tell is the **long, irregular** period
  (which *looks* random — but the *trigger* is a *behavioral* tell, not a
  *timing* tell).

## Red-team notes (OPSEC)

- **The *jitter* is non-negotiable** — a *perfect* period (exactly 60 s)
  is the *easiest* beacon to detect; **always jitter** (±10–20%). The
  jitter is the *single* cheapest anti-detection (it defeats the
  *periodicity* tell for free).
- **The *channel* has to look *normal*** — a beacon to a **bare IP** or a
  **no-TLS** endpoint is a *content* tell; a beacon to a **CDN over TLS**
  (with a *valid* cert) is a *timing-only* tell (much harder). The
  channel choice is the *biggest* single evasion (more than the cipher).
- **The *host-type* is the tell you can't hide** — a **server** host
  beaming to a **CDN** is a *behavioral* mismatch that *no* cipher/jitter
  hides (the *host* is a server, the *destination* is a CDN, the
  *pattern* is periodic). The evasion is the **channel** (make the *CDN*
  look *normal for a server* — a *server* that *legitimately* talks to a
  CDN), not the *timing*.
- **The *lateral* is the *intent*** — a beacon *alone* is "the host is
  held"; a beacon **+ lateral** is "the attacker is *moving*." The
  *lateral* is the *high-fidelity* tell (the beacon is *necessary but not
  sufficient* — the *lateral* is the *action* that means *something* is
  happening *right now*).

## Detection (the summary)

- **The *periodicity*** — a fixed (jittered) period to a *single*
  destination (the *timing* tell).
- **The *small-request / command-response* shape** — a *tiny* request + a
  *command* response, *repeatedly* (the *protocol* tell).
- **The *host-type → destination-type* mismatch** — a *server* host to a
  *CDN*/*SaaS*/*residential* (the *behavioral* tell).
- **The *consistent JA3/JA4* on a *server*** — a *client-app* TLS
  fingerprint, *repeating*, on a *server* host (the *C2-specific* tell).
- **The *beacon + lateral* correlation** — the beacon *triggers* a
  *lateral* (the *intent* tell — the highest-fidelity one).

## Links

- [[reverse-engineering-workflow]] — the step-3 (network capture) that
  *finds* the beacon
- [[defense-evasion-ad]] — the C2/evasion hub this belongs to
- [[etw]] — the *host* event layer the beacon's *lateral* trips (the
  *network* beacon + the *host* lateral = the full tell)
- [[c2-and-pivoting-ad]] — the C2/pivoting hub (the beacon is the C2's
  *heartbeat*; the pivot is the C2's *reach*)
- [[process-injection]] — the *host* action the beacon often *triggers*
  (a beacon → an injection → a dump)

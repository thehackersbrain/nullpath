# TODO — theory → practical conversion

Working checklist for making the wiki **practical-rich, not theory-rich** (see
the *Practical-first* rule + the *Practical-density check* in `CLAUDE.md`). A
page passes when it has a real **`## Commands`** (copy-pasteable one-liners),
**`## Red-team notes (OPSEC)`**, and **`## Detection`** block, leads with what to
*run*, and carries the field tips/gotchas — not prose-only exposition.

## How to use this file
1. Pick a page from the **Review queue** below.
2. Read it; if it's prose-heavy or missing a Commands block, enrich it (real
   filters/flags/one-liners by context; trim exposition that doesn't change what
   the operator does).
3. Move it to **Done**, wire any new cross-links, and add a `log.md` line.
4. Legend: `[x]` done · `[~]` verified already-practical (no action) · `[ ]` to review.

## Exempt (don't need a Commands block)
- **Entity pages for people/orgs** (`dirkjanm`, `specterops`, `ly4k`,
  `berserkarch`, `cyber-craft-labs`, `hideandsec`, …) — bios/pointers.
- **`sources/`** pages — source summaries. **`notes/path-*`** — already
  chain-of-commands by nature.
- **Tool entities** DO need usage commands (most already have them).

---

## Done (enriched this session)
- [x] `ldap` — raw `ldapsearch` attacker-filter grab-bag (UAC bit-AND rule)
- [x] `service-principal-name` — setspn/PowerView/GetUserSPNs + fake-SPN roast
- [x] `ntlm` — was prose-only; added capture/crack/PtH/NTLMv1-downgrade block
- [x] `smb` — added the share-enum one-liners (nxc/smbclient/smbmap/secretsdump)

## Verified already-practical (read this session — no action)
- [~] `kerberoasting` · `as-rep-roasting` · `kerberos-preauth` · `tgt-tgs`
- [~] `kerberos-encryption-types` · `kerberos-pac` · `kerberos-authentication` (hub, rewritten)
- [~] `ccache` · `ticket-and-credential-opsec` · `s4u2self-s4u2proxy` · `kerberos-delegation`
- [~] `acl-abuse` · `gmsa` · `remote-execution` · `situational-awareness`
- [~] all pages created this session are command-first by design (ad-enumeration,
  password-spraying, kerberos-double-hop, pivoting-and-tunneling, dpapi,
  mssql-abuse, modern-c2-frameworks, ad-trusts, trust-key-abuse,
  foreign-security-principals, cross-forest-adcs, esc16, sapphire-ticket,
  bronze-bit, timeroasting, nopac, targeted-roasting, ms14-068,
  kerberos-armoring-fast, ad-error-decoder, foothold-playbook, ticket-manipulation)

---

## Review queue (check → enrich if command-light)

### Priority 1 — fundamentals / structure (most likely prose-heavy)
- [ ] `ad-structure`
- [ ] `domain-controller`
- [ ] `sam-database`
- [ ] `ntds-dit`
- [ ] `lsass`
- [ ] `service-account`
- [ ] `krbtgt`
- [ ] `ad-tier-model`
- [ ] `kerberos-event-ids`

### Priority 1 — PKI / AD CS architecture
- [ ] `pki-and-ad-cs-architecture`
- [ ] `certificate-templates`
- [ ] `certificate-mapping`
- [ ] `ntauthcertificates`

### Priority 2 — RE / malware & C2 (conceptual, tend to explain)
- [ ] `reverse-engineering-workflow`
- [ ] `pe-executable`
- [ ] `shellcode`
- [ ] `api-hashing`
- [ ] `process-injection`
- [ ] `windows-syscalls`
- [ ] `anti-debugging`
- [ ] `anti-analysis`
- [ ] `packer-unpacking`
- [ ] `amsi`
- [ ] `etw`
- [ ] `beaconing`

### Priority 2 — ADFS
- [ ] `adfs`
- [ ] `adfs-device-auth`
- [ ] `adfs-mfa-bypass`

### Priority 3 — detection / hardening / methodology (may be prose by nature)
- [ ] `ad-tiering-and-hardening`
- [ ] `defense-evasion-ad`
- [ ] `opsec-ad-tradecraft`
- [ ] `honeytokens`
- [ ] `bloodhound-opsec`
- [ ] `redteam-ad-methodology`
- [ ] `c2-and-pivoting-ad`

### Priority 3 — spot-check (likely already practical; confirm the Commands block)
- [ ] cred family: `pass-the-hash-and-ticket` · `pass-the-key` · `overpass-the-hash`
      · `pass-the-cert` · `pkinit-unpac-the-hash` · `shadow-credentials` · `dcsync`
      · `golden-silver-tickets` · `sid-history`
- [ ] delegation: `unconstrained-delegation` · `resource-based-constrained-delegation`
- [ ] coercion/relay: `ntlm-relay-coercion` · `printer-bug` · `mitm6-ipv6-relay`
      · `wpad` · `llmnr-nbt-ns-poisoning` · `krbrelay`
- [ ] local privesc: `windows-privilege-escalation` · `uac-bypass`
      · `token-privilege-escalation` · `service-privesc` · `scheduled-task-abuse`
      · `named-pipe-hijacking` · `dll-hijacking-sideloading`
      · `environment-variable-attack` · `potato-family`
- [ ] persistence: `ad-persistence` · `dcshadow` · `skeleton-key` · `windows-local-persistence`
- [ ] AD CS ESC pages: `esc1`–`esc15` · `golden-certificate` (have certipy cmds; confirm density)
- [ ] deployment: `sccm-abuse` · `wds-mdt-discovery`

### Tool entities — confirm each has usage commands
- [ ] sweep `wiki/entities/*` tool pages (rubeus, mimikatz, impacket, certipy,
      certify, hashcat, john-the-ripper, kerbrute, responder, ntlmrelayx, mitm6,
      whisker, winpeas, procdump, secretsdump, adrecon, gpohound, pxethief,
      wdsfilecrawler, sharp-gpo-abuse, powerupack, sysmon, sigma, ghidra, x64dbg,
      upx, cobalt-strike, meterpreter, netexec, rusthound, gmsadumper, bloodyad,
      evil-winrm) — flag any without a commands/usage block.

---

## Also open (from earlier this session)
- [ ] **Run `npm run build`** to verify the ~40 pages added/edited this session
      (Bash was classifier-blocked; build not run).
- [ ] Optional polish: promote inline tool mentions to entities — `ligolo-ng`,
      `chisel`, `coercer`, `DonPAPI`, `SharpDPAPI`, `PowerUpSQL`, `MSSQLPwner`.

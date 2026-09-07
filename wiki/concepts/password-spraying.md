---
title: "Password Spraying (low-and-slow domain credential guessing)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [credential-access, initial-access, kerberos, ntlm, opsec, lockout]
---

# Password Spraying

**Password spraying** is the inverse of brute force: instead of many passwords
against one account (which trips lockout fast), you try **one password against
every account**, then wait, then try the next password. It's the single most
common way a red team turns *no creds* into a **first domain foothold** —
before [[kerberoasting]] or [[as-rep-roasting]] are even reachable (both need
an authenticated context or a valid username list). The whole game is respecting
the **account-lockout policy** so you never lock anyone out — a locked account is
a phone call to the helpdesk and a burned engagement.

## Prerequisites

1. **A username list.** Sprays are only as good as the list. Build it from:
   - OSINT (LinkedIn → `first.last`, `flast`, `f.last` permutations; tools like
     `linkedin2username`).
   - **Null/authenticated LDAP** if you already have *any* creds:
     `nxc smb dc01 -u '' -p '' --users` or `nxc ldap dc01 -u user -p pass --users`.
   - RID cycling on a null SMB session: `nxc smb dc01 -u '' -p '' --rid-brute`.
   - `kerbrute userenum` against a wordlist (see below) — validates which
     usernames exist **without a single logon attempt** (pre-auth probing only).
2. **The lockout policy.** This is the number you must respect. Pull it *before*
   spraying if you have any creds:
   ```bash
   nxc smb dc01 -u user -p pass --pass-pol
   ```
   Read three fields: **lockout threshold** (bad attempts before lock),
   **lockout window / observation window** (minutes bad-count is tracked over),
   and **reset/duration**. Rule of thumb: stay at **threshold − 1 or − 2**
   attempts per account per window, and let the observation window fully elapse
   between rounds. If threshold is `0` (disabled) you can be more aggressive —
   but confirm, don't assume.

## The two spray channels

| Channel | Tool | Failure event | Notes |
|---|---|---|---|
| **Kerberos pre-auth** | `kerbrute passwordspray` | **4771** (pre-auth failed) on the DC | No account gets a *logon*; fastest, and does **not** always increment badPwdCount the same way — but modern DCs do count Kerberos pre-auth failures toward lockout, so **still respect the policy**. Preferred: single UDP/TCP 88 to the DC, quiet-ish. |
| **NTLM / SMB / LDAP** | `nxc smb`/`ldap`, `Invoke-DomainPasswordSpray` | **4625** (logon failure), **4776** (NTLM) | Classic; louder, one 4625 per attempt. `nxc` `--continue-on-success` to keep going. |

```bash
# Kerberos spray (preferred – low-and-slow, hits the DC on 88)
kerbrute passwordspray -d corp.local --dc 10.0.0.10 users.txt 'Autumn2025!'

# NetExec SMB spray, one password across the list
nxc smb 10.0.0.10 -u users.txt -p 'Autumn2025!' --continue-on-success

# Spray a SINGLE known password you cracked/guessed against many hosts/users
nxc smb 10.0.0.0/24 -u users.txt -p 'Welcome1' --continue-on-success
```

Run all of this from the **Linux operator host over the tunnel** — see
[[pivoting-and-tunneling]] and [[c2-and-pivoting-ad]]. Enumeration commands to
build the list live in [[ad-enumeration]].

## Picking passwords (the actual craft)

Spraying works because of **human password patterns**, not raw entropy:

- **Season + year + symbol**: `Autumn2025!`, `Winter2026!`, `Spring2025$`.
- **Company name + year**: `Contoso2025`, `Contoso!`.
- **`Welcome1` / `Password1` / `Changeme123`** — default/reset passwords; new
  hires and reset accounts sit on these.
- **Month/local sports team + digits.** Localize to the target's region.
- Once you crack **one**, feed its *pattern* back in — orgs share password
  culture. Model masks in [[hashcat]] from what you've seen.

**One password, whole list, then STOP and WAIT.** Do not queue three passwords
back-to-back "to save time" — that's how you burn threshold on everyone at once.

## Red-team notes (OPSEC)

- **The lockout policy is the constraint, not the noise.** A single locked-out
  privileged account can blow the whole op. Compute your budget:
  `attempts_per_window = threshold − 2`, and set the tool's throttle so a full
  observation window passes between rounds (`--jitter`, or just script a
  `sleep`). When in doubt, **one attempt per account per lockout window** is the
  safe floor.
- **Watch for the honeytoken account.** A never-logged-on account with an
  enticing name (`svc_backup`, `admin_da`) that locks or alerts on *any* attempt
  is a [[honeytokens]] trap — cross-check names against real logon activity /
  `pwdLastSet` before including them.
- **Kerberos spray blends better** than SMB (4771 vs a wall of 4625/4776), and a
  single operator hitting only the DC on 88 looks less like a scan than SMB
  auth to every host. But a burst of 4771 across many users in a short window is
  itself a signature — space it out.
- **Distribute the source** where you can — many blue teams alert on N failures
  from *one* source IP. Spraying through the beacon's SOCKS ([[pivoting-and-tunneling]])
  puts the source *inside* the network, which is both quieter (internal, expected)
  and requires the defender to correlate by *account* not *IP*.
- **Success = a valid cred, not a shell.** Validate quietly
  (`nxc smb dc01 -u found -p pass` → `[+]`), then pivot to authenticated enum
  ([[ad-enumeration]]) and roasting — don't immediately spray that cred for
  admin across every host (that *is* a scan).

## Detection

- **4625** (logon failure) / **4771** (Kerberos pre-auth failure): the tell is
  **many distinct target accounts, one bad password, from one source, in a tight
  window** — the mirror image of a normal user fat-fingering their own password
  repeatedly. Detections key on *cardinality of accounts per source per window*.
- **4740** (account lockout): if you see this, you've already failed the OPSEC
  test — someone got locked.
- **4776** (NTLM validation) bursts on the DC.
- Sudden `badPwdCount` bumps across many users at once; Azure AD/Entra
  sign-in logs show the same shape for cloud sprays (AADSTS50126).
- Defensive mitigations that break spraying: **smart lockout**, MFA on all
  auth surfaces, banned-password lists (kills `Season+Year`), and disabling
  legacy/NTLM auth.

## Related

- Feeds: [[ad-enumeration]] (build the user list), [[kerberoasting]] /
  [[as-rep-roasting]] (next once you hold *any* cred).
- Tooling: [[netexec]], [[kerbrute]], [[hashcat]].
- Delivery: [[pivoting-and-tunneling]], [[c2-and-pivoting-ad]].
- Traps: [[honeytokens]].

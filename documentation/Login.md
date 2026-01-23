# Battle-Hardened AI Login Guide

This guide explains how to create and manage operator/admin logins for the Battle-Hardened AI dashboard.

The server does **not** store plain-text passwords. Users and password hashes are stored in a JSON config file.

---

## Where users are stored

All dashboard users live in this file (under the runtime JSON directory resolved by AI/path_helper):

- [server/json/admin_users.json](server/json/admin_users.json) when running from a source clone
- `<InstallDir>/server/json/admin_users.json` when using the Windows installer/EXE (for example `C:/Program Files/Battle-Hardened AI/server/json/admin_users.json`)

Example structure:

```json
{
  "users": [
    {
      "username": "admin",
      "password_hash": "pbkdf2:sha256$260000$...$...",
      "role": "admin",
      "totp_secret": "",
      "mfa_enabled": false
    }
  ],
  "password_hash_algorithm": "pbkdf2:sha256"
}
```

- `username`: login name for the dashboard.
- `password_hash`: PBKDF2-SHA256 hash of the password (no plain text).
- `role`: typically `admin` for full access.
- `totp_secret` / `mfa_enabled`: control optional MFA (TOTP).

---

## Quick option: disable login (dev only)

If you set:

```json
"users": []
```

in [server/json/admin_users.json](server/json/admin_users.json) and restart the server:

- The dashboard **will not require a login**.
- This is useful only for local development and must **not** be used in production.

---

## Create a new user

1. Open [server/json/admin_users.json](server/json/admin_users.json).
2. Inside the `"users"` array, add a new object. Example:

```json
{
  "username": "alice",
  "password_hash": "<REPLACE_WITH_HASH>",
  "role": "admin",
  "totp_secret": "",
  "mfa_enabled": false
}
```

3. Generate a password hash for the password you want (see next section) and paste it into `password_hash`.
4. Save the file and restart `server.py`.

After restart, you can log in with:

- Username: `alice`
- Password: whatever you used to generate the hash.

---

## Generate a password hash (PBKDF2-SHA256)

The server expects `pbkdf2:sha256` hashes in the format:

```text
pbkdf2:sha256$<iterations>$<salt>$<hex_digest>
```

You can generate one using Python.

### 1. Choose your password

Example:

- Desired password: `MyNewStrongPass!123`

### 2. Run a one-off Python snippet

From any terminal where Python is installed, run:

```bash
python - << "EOF"
import hashlib, os

password = "MyNewStrongPass!123".encode("utf-8")  # <-- your password
salt = os.urandom(16).hex()                         # random 16-byte salt
iterations = 260000

dk = hashlib.pbkdf2_hmac("sha256", password, salt.encode("utf-8"), iterations)
print(f"pbkdf2:sha256${iterations}${salt}${dk.hex()}")
EOF
```

The script will print a single line, for example:

```text
pbkdf2:sha256$260000$7b9f1a2c3d4e5f67890123456789abcd$3e1c...<more hex>...
```

Copy that entire line.

### 3. Update the user entry

In [server/json/admin_users.json](server/json/admin_users.json), set:

```json
"password_hash": "pbkdf2:sha256$260000$7b9f1a2c3d4e5f67890123456789abcd$3e1c..."
```

for the user you’re configuring.

Save the file and restart the server.

You can now log in with:

- That username
- The plain password you used in the script (e.g. `MyNewStrongPass!123`).

---

## Changing an existing password

To change a password for an existing user (for example, `admin`):

1. Pick the new password.
2. Generate a new PBKDF2-SHA256 hash using the Python snippet above (with your new password).
3. Replace the `password_hash` value for that user in [server/json/admin_users.json](server/json/admin_users.json).
4. Save the file and restart `server.py`.

Old passwords will no longer work; only the new one will.

---

## Enabling MFA (optional)

MFA support is wired via `totp_secret` and `mfa_enabled` fields. To enable for a user:

1. Set `mfa_enabled` to `true`.
2. Set `totp_secret` to the TOTP secret you provision in your authenticator app.
3. Ensure the identity access config enforces MFA for admins if desired.

The login flow will then require both password and TOTP code.

---

## Safety notes

- Never commit real production passwords or secrets to version control.
- Treat [server/json/admin_users.json](server/json/admin_users.json) as sensitive configuration.
- For production, use strong, unique passwords and enable MFA where possible.

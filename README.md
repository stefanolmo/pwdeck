# PW Deck

Local **password manager** with the same dark look as [CNC Deck](https://github.com/stefanolmo/cncgrbl): no server, no cloud, no account.
Everything lives in **one encrypted file** (`.pwdeck`) that contains an **SQLite** database. Copy the file to back it up or to move
it to another computer.
Python 3.11+ · Qt6 (PySide6) · `cryptography`. Tested on Ubuntu 24.04.

<p align="center"><img src="docs/splash.png" alt="PW Deck - splash screen" width="640"></p>
<p align="center"><img src="docs/main.png" alt="PW Deck - main window" width="900"></p>

## Installation (Ubuntu)

```bash
./install.sh          # venv in ~/.local/share/pwdeck, "pwdeck" launcher, menu entry
pwdeck                # or: pwdeck ~/passwords.pwdeck
```

Without installing: `pip install -r requirements.txt && python3 -m pwdeck`.

## What it stores (Passbolt-style resources)

| Type | Fields |
|---|---|
| **Password** | name, username, password, one or more URLs, **TOTP** (optional, live code), description |
| **TOTP** | stand-alone one-time code (Base32 secret or `otpauth://` URI, SHA1/256/512, 6–10 digits, any period) |
| **Secure note** | free text |
| **Card** | holder, number, expiry, CVV, PIN, notes |
| **SSH key** | user, host, private key, public key, passphrase, notes |
| **Custom** | description + any number of custom fields |

Every item can also have: **custom fields** (optionally hidden), **folders** (nested), **tags**, **favorite**, an **expiry date**,
a 25-entry **history** of previous secrets, and goes to the **trash** before being deleted for good.

## Features

| | |
|---|---|
| Vault | single file, AES-256-GCM, scrypt key derivation, atomic writes (temp file + fsync + rename), a write after every change |
| Unlock | master password **+ optional keyfile** (second factor) **+ recovery key** (printed once at creation) |
| Generator | CSPRNG, length 8–128, character classes, no look-alikes, guaranteed one char per class, strength meter |
| Clipboard | auto-clear after N seconds (only if it still holds *your* value), asks clipboard managers (KDE/Klipper) not to record it |
| Auto-lock | after N idle minutes, and optionally on minimize; the key is dropped from the app on lock |
| Search | all words must match across name, username, URL, tags, folder, description (secure-note bodies are not searched) |
| Audit | weak, reused, old, expired passwords; optional online breach check (Have I Been Pwned *k-anonymity*: only 5 hash chars leave the PC, on explicit click) |
| Backup | verified copy, rotating **automatic backups** (keep last N), and an **Emergency kit** zip (vault + standalone recovery script + instructions) |
| Import | generic CSV with auto-detected columns (Passbolt, KeePass, Bitwarden, LastPass, Chrome, 1Password… — see below), Bitwarden JSON, PW Deck JSON; duplicates skipped |
| Export | CSV / JSON **in clear text** (mode 600, with a warning) — only for migrating away |
| Safety nets | detects when the file was changed by another program (sync client, other PC) before overwriting; instance lock; tamper detection |

Shortcuts: `Ctrl+N` new · `Ctrl+F` search · `Ctrl+U` copy username · `Ctrl+P` copy password · `Ctrl+T` copy TOTP · `Ctrl+E` edit · `Del` trash · `Ctrl+G` generator · `Ctrl+L` lock.

## Backup, and what to do if the PC dies

The vault file is **already encrypted**, so any copy is safe to store anywhere (USB stick, NAS, a cloud folder).

1. **Automatic**: Settings → *Automatic backups*: a verified copy is made when you unlock/lock (at most hourly), the newest N are kept.
   Default folder: `backups/` next to the vault. **Point it at another disk** — a backup on the same disk does not survive a disk failure.
2. **Manual**: *Backup → Save a verified copy…* (the copy is decrypted again and checked with SQLite `integrity_check`).
3. **Emergency kit**: *Backup → Emergency kit…* creates a zip with the vault, `pwdeck_recover.py` and instructions. Keep it with your documents.
   It contains **no** password and **no** recovery key.

Restoring on a new machine:

* with PW Deck: install it, *Open other…*, choose the file, enter the master password (+ keyfile). Nothing else to migrate.
* without PW Deck, only Python + `pip install cryptography`:
  ```bash
  python3 pwdeck_recover.py decrypt vault.pwdeck -o vault.sqlite          # a plain SQLite file, open it with any tool
  python3 pwdeck_recover.py csv     vault.pwdeck -o vault.csv --recovery  # using the recovery key
  ```

**You must keep, separately from the vault:** the master password (in your head / a sealed envelope), the **keyfile** if you use one
(losing it = losing the vault), and the **recovery key**. Without them nobody can open the file — there is no reset.

## File format and security notes

```
"PWDECK\0\1" | u32 header length | JSON header | AES-256-GCM(DEK, nonce, sqlite bytes, aad=magic)
header: scrypt params + salt, key slots {password, recovery} = AES-GCM-wrapped DEK, payload nonce
```

* The SQLite database is only ever in memory (`Connection.serialize()`) or encrypted; no plain temp file is written.
* A random 256-bit **data key** encrypts the content and is stored wrapped by a key derived from the password (scrypt N=2¹⁷, r=8: 128 MiB; "High": 256 MiB),
  and by the recovery key (HKDF). Changing the master password only rewrites the header.
* With a keyfile, the password is first combined as `HMAC-SHA256(SHA256(keyfile), password)`. The master password is NFKC-normalised.
* The whole file is authenticated: any modification is detected on open.
* **Not SQLCipher.** The file is not a SQLCipher database: it is an authenticated container around a normal SQLite image. The trade-offs: no extra native
  dependency, one authenticated blob, but the whole database is loaded in RAM and rewritten on each save (fine for thousands of entries, not for gigabytes).
* **Limits you should know about**: Python cannot reliably wipe secrets from memory, so while the vault is unlocked a process-memory dump
  can reveal them; a keylogger or malware running as your user defeats any local password manager; the clipboard is readable by other
  programs until it is cleared. The strength meter is a heuristic. This code has **not been independently audited**.
* If the vault is in a synced folder (Dropbox, Nextcloud…) do not edit it from two computers at the same time: the app will warn before overwriting
  a file that changed, but it does not merge.

## Import notes

CSV columns are matched by name (case-insensitive): `name/title`, `url/uri/login_uri`, `username/login/login_username`, `password/login_password`,
`notes/description`, `folder/group/grouping`, `totp/login_totp`, `type`, `favorite`, `tags`. The format has only been tested with synthetic files
modelled on KeePass/Bitwarden layouts, **not with real exports from every product**: check the result of your first import. KDBX (KeePass) and
encrypted exports are not supported — export unencrypted CSV/JSON, import, then delete the export.

## Development

```bash
pip install -e .[dev]
python -m pytest                                              # crypto, vault, TOTP (RFC 6238 vectors), generator, import/export, offscreen UI
QT_QPA_PLATFORM=offscreen python3 docs/make_screenshots.py    # regenerate the README images
```

The core (`crypto.py`, `vault.py`, `totp.py`, `generator.py`, `importers.py`) does not import Qt. `recover.py` is self-contained on purpose
and its compatibility with the main code is covered by a test.

## Ideas not implemented yet

Browser auto-fill extension (needs a local native-messaging bridge) · passphrase generator (needs a vetted word list) · KDBX import/export ·
attachments · multiple vaults at once · QR scan for TOTP · hardware keys (FIDO2 hmac-secret / YubiKey) as a second factor · merge of divergent vault copies.

#!/usr/bin/env python3
"""Standalone emergency tool for PW Deck vaults. Needs ONLY Python >= 3.11 and the `cryptography` package
(`pip install cryptography`); it does not import anything else from PW Deck, so you can copy this single file
next to a backup and use it on any machine, with no GUI.

    python3 pwdeck_recover.py info    vault.pwdeck
    python3 pwdeck_recover.py decrypt vault.pwdeck -o vault.sqlite        # plain SQLite file (open it with any tool!)
    python3 pwdeck_recover.py csv     vault.pwdeck -o vault.csv           # plain-text export
    options: --keyfile FILE   --recovery   (ask for the recovery key instead of the master password)

The outputs are UNENCRYPTED: delete them securely when done.
"""
import argparse
import base64
import csv
import getpass
import hashlib
import hmac
import json
import os
import sqlite3
import struct
import sys
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"PWDECK\x00\x01"


def parse(blob):
    if blob[:8] != MAGIC:
        sys.exit("not a PW Deck vault (bad magic)")
    (n,) = struct.unpack(">I", blob[8:12])
    return json.loads(blob[12:12 + n]), blob[12 + n:]


def unlock(header, password, keyfile, recovery):
    b64 = base64.b64decode
    if recovery:
        clean = "".join(c for c in recovery.upper() if c.isalnum())
        kek = HKDF(hashes.SHA256(), 32, salt=None, info=b"pwdeck-recovery-key-v1").derive(base64.b32decode(clean))
        slot, name = header["slots"]["recovery"], "recovery"
    else:
        pw = unicodedata.normalize("NFKC", password).encode()
        k = header["kdf"]
        if k.get("keyfile"):
            if keyfile is None:
                sys.exit("this vault needs a keyfile (--keyfile FILE)")
            pw = hmac.new(hashlib.sha256(keyfile).digest(), pw, hashlib.sha256).digest()
        n = 1 << k["log_n"]
        kek = hashlib.scrypt(pw, salt=b64(k["salt"]), n=n, r=k["r"], p=k["p"], maxmem=128 * n * k["r"] * 2 + (8 << 20), dklen=32)
        slot, name = header["slots"]["password"], "password"
    try:
        return AESGCM(kek).decrypt(b64(slot["nonce"]), b64(slot["ct"]), b"pwdeck-slot-" + name.encode())
    except InvalidTag:
        sys.exit("wrong password / keyfile / recovery key")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["info", "decrypt", "csv"])
    ap.add_argument("vault")
    ap.add_argument("-o", "--output")
    ap.add_argument("--keyfile")
    ap.add_argument("--recovery", action="store_true")
    a = ap.parse_args()
    blob = open(a.vault, "rb").read()
    header, ct = parse(blob)
    if a.command == "info":
        k = header["kdf"]
        print(f"PW Deck vault, format v{header['v']}, scrypt N=2^{k['log_n']} r={k['r']} p={k['p']}, "
              f"keyfile: {'yes' if k.get('keyfile') else 'no'}, recovery key: {'yes' if 'recovery' in header['slots'] else 'no'}, "
              f"size: {len(blob)} bytes")
        return
    if not a.output:
        sys.exit("-o OUTPUT is required")
    keyfile = open(a.keyfile, "rb").read() if a.keyfile else None
    secret = getpass.getpass("Recovery key: " if a.recovery else "Master password: ")
    dek = unlock(header, None if a.recovery else secret, keyfile, secret if a.recovery else None)
    try:
        plain = AESGCM(dek).decrypt(base64.b64decode(header["nonce"]), ct, MAGIC)
    except InvalidTag:
        sys.exit("the vault content is damaged (authentication failed)")
    if a.command == "decrypt":
        fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(plain)
        print(f"written {a.output} (plain SQLite)")
    else:
        db = sqlite3.connect(":memory:")
        db.deserialize(plain)
        fold = {r[0]: (r[1], r[2]) for r in db.execute("SELECT id,parent_id,name FROM folders")}

        def path(fid):
            parts = []
            while fid in fold:
                parts.append(fold[fid][1])
                fid = fold[fid][0]
            return "/".join(reversed(parts))

        fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["folder", "type", "name", "url", "username", "password", "totp", "description", "extra", "fields"])
            for r in db.execute("SELECT folder_id,type,name,uris,username,password,totp,description,extra,fields FROM items WHERE deleted IS NULL"):
                uris = json.loads(r[3])
                w.writerow([path(r[0]), r[1], r[2], uris[0] if uris else "", r[4], r[5], r[6], r[7], r[8], r[9]])
        print(f"written {a.output} (plain text CSV)")


if __name__ == "__main__":
    main()

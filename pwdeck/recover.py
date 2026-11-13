#!/usr/bin/env python3
"""Standalone emergency tool for PW Deck vaults. Needs ONLY Python >= 3.11 and the `cryptography` package (>= 46 for Argon2id)
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
        if k.get("alg") == "argon2id":
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
            kek = Argon2id(salt=b64(k["salt"]), length=32, iterations=k["t"], lanes=k["p"], memory_cost=k["m"]).derive(pw)
        else:
            n = 1 << k["log_n"]
            kek = hashlib.scrypt(pw, salt=b64(k["salt"]), n=n, r=k["r"], p=k["p"], maxmem=128 * n * k["r"] * 2 + (8 << 20), dklen=32)
        slot, name = header["slots"]["password"], "password"
    try:
        return AESGCM(kek).decrypt(b64(slot["nonce"]), b64(slot["ct"]), b"pwdeck-slot-" + name.encode())
    except InvalidTag:
        sys.exit("wrong password / keyfile / recovery key")


def unsealed_db(plain, dek):
    """Returns an in-memory SQLite whose secret columns are plain text (format v2 stores them sealed inside the database)."""
    db = sqlite3.connect(":memory:")
    db.deserialize(bytearray(plain))
    db.row_factory = sqlite3.Row
    if int(db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0]) < 2:
        return db
    fk = HKDF(hashes.SHA256(), 32, salt=None, info=b"pwdeck-field-key-v1").derive(dek)
    vid = db.execute("SELECT value FROM meta WHERE key='vault_id'").fetchone()[0]

    def op(iid, col, blob, sub=""):
        if not blob:
            return ""
        blob = bytes(blob)
        return AESGCM(fk).decrypt(blob[1:13], blob[13:], f"{vid}|{iid}|{col}|{sub}".encode()).decode()

    b64 = base64.b64decode
    for r in db.execute("SELECT id,password,description,totp,fields,extra FROM items").fetchall():
        i = r["id"]
        extra = {k: op(i, "extra", b64(v), k) for k, v in json.loads(r["extra"]).items() if v}
        fields = [{"label": f["label"], "hidden": f["hidden"], "value": op(i, "fields", b64(f["value"]), f"field:{n}") if f["value"] else ""}
                  for n, f in enumerate(json.loads(r["fields"]))]
        db.execute("UPDATE items SET password=?,description=?,totp=?,fields=?,extra=? WHERE id=?",
                   (op(i, "password", r["password"]), op(i, "description", r["description"]), op(i, "totp", r["totp"]),
                    json.dumps(fields), json.dumps(extra), i))
    for h in db.execute("SELECT id,item_id,snapshot FROM history").fetchall():
        blob = b64(h["snapshot"])
        db.execute("UPDATE history SET snapshot=? WHERE id=?",
                   (AESGCM(fk).decrypt(blob[1:13], blob[13:], f"{vid}|{h['item_id']}|history|".encode()).decode(), h["id"]))
    db.execute("UPDATE meta SET value='1' WHERE key='schema'")      # now it is a plain (v1 layout) database
    db.commit()
    db.execute("VACUUM")
    return db


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
        kd = f"Argon2id m={k['m']}KiB t={k['t']} p={k['p']}" if k.get("alg") == "argon2id" else f"scrypt N=2^{k['log_n']} r={k['r']} p={k['p']}"
        print(f"PW Deck vault, format v{header['v']}, {kd}, "
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
    db = unsealed_db(plain, dek)
    if a.command == "decrypt":
        fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(db.serialize())
        print(f"written {a.output} (plain SQLite)")
    else:
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
            for r in db.execute("SELECT folder_id,type,name,uris,username,password,totp,description,extra,fields FROM items WHERE deleted IS NULL").fetchall():
                uris = json.loads(r[3])
                w.writerow([path(r[0]), r[1], r[2], uris[0] if uris else "", r[4], r[5], r[6], r[7], r[8], r[9]])
        print(f"written {a.output} (plain text CSV)")


if __name__ == "__main__":
    main()

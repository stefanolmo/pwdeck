import os
import sqlite3
import subprocess
import sys
import time
import zipfile

import pytest

from pwdeck import crypto, generator, importers, totp
from pwdeck.backup import make_bundle
from pwdeck.vault import (CorruptVaultError, Item, NotAVaultError, Vault, VaultChangedError, VaultLockedError,
                          WrongPasswordError, auto_backup)


# ------------------------------------------------------------------ crypto / container
def test_roundtrip_and_no_plaintext_on_disk(vpath):
    v, rk = Vault.create(vpath, "pw", kdf="fast")
    v.add_item(Item(name="Bank", username="mario.rossi", password="S3cr3t-Marker-XYZ", uris=["https://bank.example"]))
    v.close()
    raw = open(vpath, "rb").read()
    for marker in (b"SQLite format", b"Bank", b"mario.rossi", b"S3cr3t-Marker-XYZ", b"bank.example"):
        assert marker not in raw
    v = Vault.open(vpath, "pw")
    it = v.items()[0]
    assert (it.name, it.password, it.uris) == ("Bank", "S3cr3t-Marker-XYZ", ["https://bank.example"])
    v.close()


def test_wrong_password_and_normalisation(vpath):
    v, _ = Vault.create(vpath, "caf\u00e8", kdf="fast")
    v.close()
    with pytest.raises(WrongPasswordError):
        Vault.open(vpath, "wrong")
    Vault.open(vpath, "cafè").close()            # NFD-typed password == NFC one


def test_recovery_key_and_password_change(vault, vpath):
    vault.add_item(Item(name="a"))
    rk = vault.recovery
    vault.change_password("new pass")
    vault.close()
    with pytest.raises(WrongPasswordError):
        Vault.open(vpath, "correct horse")
    Vault.open(vpath, "new pass").close()
    v = Vault.open(vpath, recovery_key=rk.lower())       # still valid after the password change, case-insensitive
    assert len(v.items()) == 1
    rk2 = v.new_recovery_key()
    v.close()
    with pytest.raises(WrongPasswordError):
        Vault.open(vpath, recovery_key=rk)
    Vault.open(vpath, recovery_key=rk2).close()


def test_keyfile(vpath):
    kf = os.urandom(64)
    v, _ = Vault.create(vpath, "pw", keyfile=kf, kdf="fast")
    assert v.uses_keyfile
    v.close()
    assert Vault.peek(vpath)["keyfile"] is True
    with pytest.raises(WrongPasswordError):
        Vault.open(vpath, "pw")
    with pytest.raises(WrongPasswordError):
        Vault.open(vpath, "pw", keyfile=os.urandom(64))
    Vault.open(vpath, "pw", keyfile=kf).close()


def test_tamper_and_garbage(vault, vpath):
    vault.close()
    blob = bytearray(open(vpath, "rb").read())
    blob[-5] ^= 1
    open(vpath, "wb").write(blob)
    with pytest.raises(CorruptVaultError):
        Vault.open(vpath, "correct horse")
    open(vpath, "wb").write(b"hello world, not a vault")
    with pytest.raises(NotAVaultError):
        Vault.open(vpath, "x")


def test_nonce_changes_every_save(vault, vpath):
    a = open(vpath, "rb").read()
    vault.save()
    assert open(vpath, "rb").read() != a


def test_external_change_detected(vault, vpath):
    vault.add_item(Item(name="x"))
    with open(vpath, "ab") as f:
        f.write(b"x")
    with pytest.raises(VaultChangedError):
        vault.add_item(Item(name="y"))
    vault.save(force=True)


def test_instance_lock(vault, vpath):
    with open(vpath + ".lock", "w") as f:
        f.write(str(os.getppid()))                     # a live process that is not us
    with pytest.raises(VaultLockedError):
        Vault.open(vpath, "correct horse")
    with open(vpath + ".lock", "w") as f:
        f.write("999999")                               # stale lock is ignored
    Vault.open(vpath, "correct horse", lock=True).close()


# ------------------------------------------------------------------ vault logic
def test_items_folders_tags_trash_history(vault):
    f = vault.add_folder("Work")
    sub = vault.add_folder("VPN", f)
    it = Item(name="srv", username="u", password="p1", folder_id=sub, tags=["prod", "ssh"], favorite=True)
    vault.add_item(it)
    assert vault.folder_path(sub) == "Work/VPN"
    assert vault.folder_ids_under(f) == {f, sub}
    it = vault.get_item(it.id)
    assert it.tags == ["prod", "ssh"] and it.favorite
    it.password = "p2"
    vault.update_item(it)
    h = vault.history(it.id)
    assert len(h) == 1 and h[0]["data"]["password"] == "p1"
    vault.trash_item(it.id)
    assert vault.items() == [] and len(vault.items(trash=True)) == 1
    vault.restore_item(it.id)
    assert len(vault.items()) == 1
    vault.delete_folder(sub)                              # item falls back to root, sub-folders move up
    assert vault.get_item(it.id).folder_id is None
    vault.purge_item(it.id)
    assert vault.history(it.id) == []
    with pytest.raises(Exception):
        vault.move_folder(f, f)


def test_batch_writes_once(vault, vpath):
    saves = []
    vault.on_saved = saves.append
    with vault.batch():
        for i in range(20):
            vault.add_item(Item(name=f"i{i}"))
    assert len(saves) == 1 and len(vault.items()) == 20


def test_copy_verify_and_bundle(vault, tmp_path):
    vault.add_item(Item(name="a"))
    p = vault.copy_to(str(tmp_path))
    assert vault.verify_file(p) == 1
    z = make_bundle(vault, str(tmp_path / "kit.zip"))
    assert sorted(zipfile.ZipFile(z).namelist()) == ["README.txt", "pwdeck_recover.py", "test.pwdeck"]


def test_auto_backup_rotation(vault, tmp_path):
    d = str(tmp_path / "bk")
    assert auto_backup(vault, d, keep=2, min_interval_s=0)
    assert auto_backup(vault, d, keep=2, min_interval_s=3600) is None
    for i in range(3):
        time.sleep(1.05)
        auto_backup(vault, d, keep=2, min_interval_s=0)
    assert len(os.listdir(d)) == 2


def test_standalone_recover_tool(vault, vpath, tmp_path):
    vault.add_item(Item(name="Mail", username="me", password="pw-123", uris=["https://m.example"]))
    tool = os.path.join(os.path.dirname(__file__), "..", "pwdeck", "recover.py")
    out = str(tmp_path / "out.sqlite")
    r = subprocess.run([sys.executable, "-c",
                        f"import getpass,sys; getpass.getpass=lambda p='': 'correct horse'; sys.argv=['x','decrypt',{vpath!r},'-o',{out!r}];"
                        f"import runpy; runpy.run_path({tool!r}, run_name='__main__')"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    row = sqlite3.connect(out).execute("SELECT name,password FROM items").fetchone()
    assert row == ("Mail", "pw-123")
    r = subprocess.run([sys.executable, "-c",
                        f"import getpass,sys; getpass.getpass=lambda p='': {vault.recovery!r}; sys.argv=['x','csv',{vpath!r},'-o',{str(tmp_path/'o.csv')!r},'--recovery'];"
                        f"import runpy; runpy.run_path({tool!r}, run_name='__main__')"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "pw-123" in open(tmp_path / "o.csv").read()


# ------------------------------------------------------------------ totp
def test_totp_rfc6238_vectors():
    t = totp.Totp(b"12345678901234567890", digits=8)
    assert t.code(59) == "94287082"
    assert t.code(1111111109) == "07081804"
    t256 = totp.Totp(b"12345678901234567890123456789012", digits=8, algorithm="SHA256")
    assert t256.code(59) == "46119246"


def test_totp_parse():
    t = totp.parse("otpauth://totp/ACME:me@x.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&digits=8&period=60&algorithm=SHA256")
    assert (t.digits, t.period, t.algorithm, t.issuer) == (8, 60, "SHA256", "ACME")
    assert totp.parse("jbsw y3dp ehpk 3pxp").secret == b"Hello!\xde\xad\xbe\xef"
    for bad in ("", "otpauth://hotp/x?secret=AAAA", "not base32 !!", "otpauth://totp/x"):
        with pytest.raises(ValueError):
            totp.parse(bad)


# ------------------------------------------------------------------ generator
def test_generator():
    o = generator.GenOptions(length=24)
    for _ in range(50):
        p = generator.generate(o)
        assert len(p) == 24 and any(c.isdigit() for c in p) and any(c.isupper() for c in p) and any(c.islower() for c in p) \
            and any(c in generator.SYMBOLS for c in p)
    p = generator.generate(generator.GenOptions(length=64, symbols=False, avoid_ambiguous=True))
    assert not set(p) & generator.AMBIGUOUS and p.isalnum()
    with pytest.raises(ValueError):
        generator.generate(generator.GenOptions(lower=False, upper=False, digits=False, symbols=False))


def test_strength_ordering():
    s = lambda p: generator.estimate(p)  # noqa: E731
    assert s("password")[1] == 0 and s("123456")[1] == 0
    assert s("abcdef")[1] <= 1 and s("aaaaaaaaaaaa")[1] <= 1
    assert s("Tr0ub4dor&3")[0] < s(generator.generate(generator.GenOptions(length=20)))[0]
    assert s(generator.generate(generator.GenOptions(length=24)))[1] == 4


# ------------------------------------------------------------------ import / export
def test_csv_import_keepass_like(vault):
    text = '"Group","Title","Username","Password","URL","Notes"\n"Work/Mail","Gmail","me","pw1","https://g.com","n"\n"","NoUser","","","",""\n'
    items = importers.parse_csv(text)
    assert importers.import_items(vault, items) == (2, 0)
    g = next(i for i in vault.items() if i.name == "Gmail")
    assert vault.folder_path(g.folder_id) == "Work/Mail" and g.uris == ["https://g.com"] and g.description == "n"
    assert importers.import_items(vault, importers.parse_csv(text)) == (0, 2)       # duplicates skipped


def test_csv_import_bitwarden_semicolon_and_errors(vault):
    text = "folder;favorite;type;name;notes;login_uri;login_username;login_password;login_totp\nF;1;login;X;;http://x;u;p;JBSWY3DPEHPK3PXP\n"
    (it,) = importers.parse_csv(text)
    assert it.favorite and it.totp == "JBSWY3DPEHPK3PXP" and it.extra["_folder"] == "F"
    with pytest.raises(ValueError):
        importers.parse_csv("a,b\n1,2\n")


def test_bitwarden_json_and_roundtrip(vault, tmp_path):
    bw = {"folders": [{"id": "f1", "name": "Fam"}], "items": [
        {"type": 1, "name": "Netflix", "folderId": "f1", "favorite": True, "login": {"username": "u", "password": "p", "uris": [{"uri": "https://n"}]},
         "fields": [{"name": "pin", "value": "1", "type": 1}]},
        {"type": 3, "name": "Visa", "card": {"cardholderName": "M R", "number": "4111", "code": "123", "expMonth": "1", "expYear": "2030"}},
        {"type": 2, "name": "Wifi", "notes": "ssid"}]}
    import json
    p = tmp_path / "bw.json"
    p.write_text(json.dumps(bw))
    items = importers.detect_and_parse(str(p))
    assert importers.import_items(vault, items) == (3, 0)
    card = next(i for i in vault.items() if i.type == "card")
    assert card.extra["number"] == "4111" and card.extra["expiry"] == "1/2030"
    # PW Deck JSON round trip into a second vault
    p2 = tmp_path / "x.json"
    importers.write_private(str(p2), importers.export_json(vault))
    assert oct(os.stat(p2).st_mode & 0o777) == "0o600"
    v2, _ = Vault.create(str(tmp_path / "v2.pwdeck"), "x", kdf="fast")
    assert importers.import_items(v2, importers.detect_and_parse(str(p2))) == (3, 0)
    n = next(i for i in v2.items() if i.name == "Netflix")
    assert n.fields == [{"label": "pin", "value": "1", "hidden": True}] and v2.folder_path(n.folder_id) == "Fam"
    v2.close()
    assert "Netflix" in importers.export_csv(vault)


def test_failed_close_keeps_vault_usable(vault, vpath, monkeypatch):
    vault.touch_used(vault.add_item(Item(name="a")))
    monkeypatch.setattr(vault, "save", lambda force=False: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        vault.close()
    assert len(vault.items()) == 1          # database still open, nothing lost
    monkeypatch.undo()
    vault.close()

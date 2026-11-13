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
    it = v.items(secrets=True)[0]
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
    g = next(i for i in vault.items(secrets=True) if i.name == "Gmail")
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
    card = next(i for i in vault.items(secrets=True) if i.type == "card")
    assert card.extra["number"] == "4111" and card.extra["expiry"] == "1/2030"
    # PW Deck JSON round trip into a second vault
    p2 = tmp_path / "x.json"
    importers.write_private(str(p2), importers.export_json(vault))
    assert oct(os.stat(p2).st_mode & 0o777) == "0o600"
    v2, _ = Vault.create(str(tmp_path / "v2.pwdeck"), "x", kdf="fast")
    assert importers.import_items(v2, importers.detect_and_parse(str(p2))) == (3, 0)
    n = next(i for i in v2.items(secrets=True) if i.name == "Netflix")
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


# ------------------------------------------------------------------ field sealing (format v2)
def _marker_vault(vault):
    return vault.add_item(Item(name="Bank", username="mario", password="PWD-marker-111", totp="JBSWY3DPEHPK3PXP",
                               description="DESC-marker-222", uris=["https://bank.example"],
                               extra={"cvv": "CVV-marker-333", "holder": "HOLD-marker-444"},
                               fields=[{"label": "pin", "value": "FLD-marker-555", "hidden": True}]))


def test_memory_image_has_no_plaintext_secrets(vault):
    _marker_vault(vault)
    image = bytes(vault.db.serialize())                    # exactly what sits in RAM while the vault is unlocked
    for secret in (b"PWD-marker-111", b"JBSWY3DPEHPK3PXP", b"DESC-marker-222", b"CVV-marker-333", b"HOLD-marker-444", b"FLD-marker-555"):
        assert secret not in image
    assert b"Bank" in image and b"mario" in image and b"bank.example" in image and b"pin" in image   # searchable metadata stays plain


def test_light_items_and_reveal(vault):
    iid = _marker_vault(vault)
    (it,) = vault.items()
    assert it.password == "" and it.totp == "" and it.description == "" and it.extra == {}
    assert it.has == {"password", "totp", "description", "cvv", "holder", "field:0"}
    assert it.fields == [{"label": "pin", "value": "", "hidden": True}]
    assert vault.reveal(iid, "password") == "PWD-marker-111" and vault.reveal(iid, "totp") == "JBSWY3DPEHPK3PXP"
    assert vault.reveal(iid, "description") == "DESC-marker-222" and vault.reveal(iid, "cvv") == "CVV-marker-333"
    assert vault.reveal(iid, "field:0") == "FLD-marker-555" and vault.reveal(iid, "pin") == ""
    full = vault.get_item(iid)
    assert full.password == "PWD-marker-111" and full.extra["holder"] == "HOLD-marker-444" and full.fields[0]["value"] == "FLD-marker-555"
    assert vault.has_duplicate(Item(name="Bank", username="mario", password="PWD-marker-111", uris=["https://bank.example"]))
    assert not vault.has_duplicate(Item(name="Bank", username="mario", password="other", uris=["https://bank.example"]))


def test_sealed_values_are_bound_to_their_row_and_column(vault):
    a = vault.add_item(Item(name="a", password="pw-a", description="d-a"))
    b = vault.add_item(Item(name="b", password="pw-b"))
    pa = vault.db.execute("SELECT password FROM items WHERE id=?", (a,)).fetchone()[0]
    vault.db.execute("UPDATE items SET password=? WHERE id=?", (pa, b))               # paste a's ciphertext into b
    with pytest.raises(CorruptVaultError):
        vault.reveal(b, "password")
    vault.db.execute("UPDATE items SET description=? WHERE id=?", (pa, a))            # same row, wrong column
    with pytest.raises(CorruptVaultError):
        vault.reveal(a, "description")


def test_verify_file_detects_a_damaged_sealed_field(vault, tmp_path):
    iid = vault.add_item(Item(name="a", password="pw-a"))
    assert vault.verify_file(vault.copy_to(str(tmp_path))) == 1
    blob = bytearray(vault.db.execute("SELECT password FROM items WHERE id=?", (iid,)).fetchone()[0])
    blob[-1] ^= 1
    vault.db.execute("UPDATE items SET password=? WHERE id=?", (bytes(blob), iid))
    with pytest.raises(CorruptVaultError):
        vault.copy_to(str(tmp_path / "bad.pwdeck"))


def _make_v1_vault(path, password):
    """A vault exactly as format v1 stored it (plain secret columns), built with the public crypto API."""
    import json
    from pwdeck import vault as vmod
    dek, header, rk = crypto.create_keys(password, None, "fast")
    db = sqlite3.connect(":memory:")
    db.executescript(vmod.SCHEMA)
    for k, v in (("schema", "1"), ("vault_id", "vid-1"), ("created", "0")):
        db.execute("INSERT INTO meta VALUES(?,?)", (k, v))
    db.execute("INSERT INTO items(id,type,name,username,password,uris,description,totp,fields,extra,favorite,created,modified,pw_changed)"
               " VALUES('i1','password','Old','me','V1-pass-marker','[\"https://x\"]','V1-desc','JBSWY3DPEHPK3PXP',?,?,1,1,1,1)",
               (json.dumps([{"label": "l", "value": "V1-field", "hidden": True}]), json.dumps({"cvv": "V1-cvv"})))
    db.execute("INSERT INTO history(item_id,ts,snapshot) VALUES('i1',1,?)", (json.dumps({"password": "V1-old-pass"}),))
    db.commit()
    crypto.atomic_write(path, crypto.encode(header, dek, db.serialize()))
    return rk


def test_v1_vault_is_migrated_and_backed_up(vpath):
    rk = _make_v1_vault(vpath, "pw")
    original = open(vpath, "rb").read()
    v = Vault.open(vpath, "pw")
    assert open(vpath + ".pre-v2.bak", "rb").read() == original             # untouched copy of the old file
    it = v.get_item("i1")
    assert (it.password, it.description, it.totp, it.extra, it.fields[0]["value"], it.favorite) == \
        ("V1-pass-marker", "V1-desc", "JBSWY3DPEHPK3PXP", {"cvv": "V1-cvv"}, "V1-field", True)
    assert v.history("i1")[0]["data"] == {"password": "V1-old-pass"}
    image = bytes(v.db.serialize())
    assert b"V1-pass-marker" not in image and b"V1-cvv" not in image and b"V1-old-pass" not in image   # VACUUM left no remnants
    v.close()
    v = Vault.open(vpath, recovery_key=rk)                                 # already v2 on disk: no second migration
    assert v.reveal("i1", "password") == "V1-pass-marker"
    v.close()


def test_recover_tool_unseals_v2(vault, vpath, tmp_path):
    _marker_vault(vault)
    tool = os.path.join(os.path.dirname(__file__), "..", "pwdeck", "recover.py")
    out = str(tmp_path / "o.sqlite")
    r = subprocess.run([sys.executable, "-c",
                        f"import getpass,sys; getpass.getpass=lambda p='': 'correct horse'; sys.argv=['x','decrypt',{vpath!r},'-o',{out!r}];"
                        f"import runpy; runpy.run_path({tool!r}, run_name='__main__')"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    row = sqlite3.connect(out).execute("SELECT password,description,totp,extra,fields FROM items").fetchone()
    assert row[:3] == ("PWD-marker-111", "DESC-marker-222", "JBSWY3DPEHPK3PXP")
    assert "CVV-marker-333" in row[3] and "FLD-marker-555" in row[4]


# ------------------------------------------------------------------ Argon2id / legacy scrypt
def test_new_vaults_use_argon2id_and_old_scrypt_vaults_still_open(tmp_path):
    p1, p2 = str(tmp_path / "a.pwdeck"), str(tmp_path / "s.pwdeck")
    a, rka = Vault.create(p1, "pw", kdf="fast")
    s, rks = Vault.create(p2, "pw", kdf="scrypt-fast")
    assert not a.kdf_is_legacy and "Argon2id" in a.kdf_info and s.kdf_is_legacy and "scrypt" in s.kdf_info
    a.add_item(Item(name="x", password="p"))
    s.add_item(Item(name="x", password="p"))
    a.close()
    s.close()
    assert "Argon2id" in Vault.peek(p1)["kdf"] and "scrypt" in Vault.peek(p2)["kdf"]
    for p, rk in ((p1, rka), (p2, rks)):
        v = Vault.open(p, "pw")
        assert v.items(secrets=True)[0].password == "p"
        v.close()
        with pytest.raises(WrongPasswordError):
            Vault.open(p, "nope")
        Vault.open(p, recovery_key=rk).close()


def test_upgrade_scrypt_vault_to_argon2id_keeps_recovery_and_content(tmp_path):
    p = str(tmp_path / "s.pwdeck")
    v, rk = Vault.create(p, "pw", kdf="scrypt-fast")
    v.add_item(Item(name="x", password="secret"))
    v.change_password("pw", None, "fast")                      # same password, new derivation
    assert not v.kdf_is_legacy
    v.close()
    v = Vault.open(p, "pw")
    assert v.reveal(v.items()[0].id, "password") == "secret" and "Argon2id" in v.kdf_info
    v.close()
    Vault.open(p, recovery_key=rk).close()


def test_hostile_kdf_parameters_are_rejected(tmp_path):
    p = str(tmp_path / "h.pwdeck")
    Vault.create(p, "pw", kdf="fast")[0].close()
    header, ct = crypto.parse(open(p, "rb").read())
    for patch in ({"m": 1 << 30}, {"t": 0}, {"p": 99}, {"m": 4}, {"alg": "md5"}):
        h = {**header, "kdf": {**header["kdf"], **patch}}
        with pytest.raises(CorruptVaultError):
            crypto.unlock(h, "pw")


def test_recover_tool_handles_scrypt_vaults_too(tmp_path):
    p = str(tmp_path / "s.pwdeck")
    v, _ = Vault.create(p, "pw", kdf="scrypt-fast")
    v.add_item(Item(name="Mail", password="pw-123"))
    v.close()
    tool = os.path.join(os.path.dirname(__file__), "..", "pwdeck", "recover.py")
    out = str(tmp_path / "o.sqlite")
    r = subprocess.run([sys.executable, "-c",
                        f"import getpass,sys; getpass.getpass=lambda p='': 'pw'; sys.argv=['x','decrypt',{p!r},'-o',{out!r}];"
                        f"import runpy; runpy.run_path({tool!r}, run_name='__main__')"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert sqlite3.connect(out).execute("SELECT password FROM items").fetchone() == ("pw-123",)
    info = subprocess.run([sys.executable, tool, "info", p], capture_output=True, text=True)
    assert "scrypt" in info.stdout

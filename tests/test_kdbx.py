import datetime as dt
import os
import subprocess
import sys

import pytest

pytest.importorskip("pykeepass")
from pykeepass import PyKeePass, create_database  # noqa: E402

from pwdeck import importers, kdbx  # noqa: E402
from pwdeck.vault import Item, Vault  # noqa: E402


@pytest.fixture
def rich(vault):
    f = vault.add_folder("Work")
    s = vault.add_folder("Servers", f)
    iid = vault.add_item(Item(name="GitHub", username="me", password="S3cret!", uris=["https://gh.example", "https://gh2.example", "https://gh3.example"],
                              totp="JBSWY3DPEHPK3PXP", description="line1\nline2", tags=["dev", "git"], favorite=True, folder_id=s,
                              expires=1893456000.0,
                              fields=[{"label": "recovery", "value": "AAAA-BBBB", "hidden": True}, {"label": "plain", "value": "visible", "hidden": False},
                                      {"label": "Password", "value": "clash", "hidden": False}]))
    vault.add_attachment(iid, "key.txt", b"ATTACHED-DATA" * 100)
    vault.add_item(Item(name="Visa", type="card", extra={"number": "4111", "cvv": "123", "holder": "M R", "expiry": "08/29"}))
    vault.add_item(Item(name="Root note", type="note", description="secret note"))
    vault.add_item(Item(name="Bastion", type="ssh", username="ops", extra={"private_key": "-----BEGIN-----", "passphrase": "pp"}))
    trashed = vault.add_item(Item(name="Trashed", password="x"))
    vault.trash_item(trashed)
    return vault


def test_export_is_a_valid_kdbx_that_keepass_tools_can_read(rich, tmp_path):
    p = str(tmp_path / "o.kdbx")
    assert kdbx.export_kdbx(rich, p, "kdbx-pw") == 4 and oct(os.stat(p).st_mode & 0o777) == "0o600"
    kp = PyKeePass(p, password="kdbx-pw")                                   # read back with the reference library
    e = next(x for x in kp.entries if x.title == "GitHub")
    assert (e.username, e.password, e.url, e.notes) == ("me", "S3cret!", "https://gh.example", "line1\nline2")
    assert e.group.path == ["Work", "Servers"] and set(e.tags) == {"dev", "git", "favorite"}
    assert e.otp.startswith("otpauth://totp/") and "secret=JBSWY3DPEHPK3PXP" in e.otp
    assert e.expires and e.expiry_time == dt.datetime.fromtimestamp(1893456000, dt.timezone.utc)
    props = e.custom_properties
    assert props["KP2A_URL"] == "https://gh2.example" and props["KP2A_URL_1"] == "https://gh3.example"
    assert props["recovery"] == "AAAA-BBBB" and e.is_custom_property_protected("recovery") and not e.is_custom_property_protected("plain")
    assert props["field: Password"] == "clash"                               # a custom field called "Password" must not clobber the real one
    assert [(a.filename, a.data) for a in e.attachments] == [("key.txt", b"ATTACHED-DATA" * 100)]
    assert not any(x.title == "Trashed" for x in kp.entries)                # the trash is not exported
    card = next(x for x in kp.entries if x.title == "Visa")
    assert card.custom_properties["pwdeck.cvv"] == "123" and card.is_custom_property_protected("pwdeck.cvv") and not card.is_custom_property_protected("pwdeck.holder")
    assert next(x for x in kp.entries if x.title == "Root note").group.path == []


def test_roundtrip_into_a_second_vault(rich, tmp_path):
    p = str(tmp_path / "o.kdbx")
    kdbx.export_kdbx(rich, p, "pw")
    items, warnings = kdbx.import_kdbx(p, "pw")
    assert warnings == [] and len(items) == 4
    v2, _ = Vault.create(str(tmp_path / "v2.pwdeck"), "x", kdf="fast")
    assert importers.import_items(v2, items) == (4, 0)
    g = next(i for i in v2.items(secrets=True) if i.name == "GitHub")
    assert (g.username, g.password, g.uris, g.description, g.favorite, g.tags) == \
        ("me", "S3cret!", ["https://gh.example", "https://gh2.example", "https://gh3.example"], "line1\nline2", True, ["dev", "git"])
    assert v2.folder_path(g.folder_id) == "Work/Servers" and g.expires == 1893456000.0 and "JBSWY3DPEHPK3PXP" in g.totp
    assert {f["label"]: (f["value"], f["hidden"]) for f in g.fields} == {"recovery": ("AAAA-BBBB", True), "plain": ("visible", False), "field: Password": ("clash", False)}
    (a,) = v2.attachments(g.id)
    assert v2.get_attachment(a["id"]) == ("key.txt", b"ATTACHED-DATA" * 100)
    card = next(i for i in v2.items(secrets=True) if i.type == "card")
    assert card.extra == {"number": "4111", "cvv": "123", "holder": "M R", "expiry": "08/29"}
    ssh = next(i for i in v2.items(secrets=True) if i.type == "ssh")
    assert ssh.extra == {"private_key": "-----BEGIN-----", "passphrase": "pp"} and ssh.username == "ops"
    assert importers.import_items(v2, kdbx.import_kdbx(p, "pw")[0]) == (0, 4)       # a second import adds nothing
    v2.close()


def test_credentials(rich, tmp_path):
    p = str(tmp_path / "o.kdbx")
    kf = tmp_path / "k.key"
    kf.write_bytes(os.urandom(64))
    kdbx.export_kdbx(rich, p, "pw", str(kf))
    with pytest.raises(ValueError, match="Wrong password"):
        kdbx.import_kdbx(p, "pw")                                            # keyfile missing
    with pytest.raises(ValueError, match="Wrong password"):
        kdbx.import_kdbx(p, "bad", str(kf))
    assert len(kdbx.import_kdbx(p, "pw", str(kf))[0]) == 4
    with pytest.raises(FileExistsError):
        kdbx.export_kdbx(rich, p, "pw")                                      # never overwrites
    junk = tmp_path / "junk.kdbx"
    junk.write_bytes(b"not a database at all")
    with pytest.raises(ValueError, match="Cannot read"):
        kdbx.import_kdbx(str(junk), "pw")


def test_import_of_a_keepassxc_style_database(tmp_path):
    p = str(tmp_path / "x.kdbx")
    kp = create_database(p, password="pw")
    g = kp.add_group(kp.root_group, "Banking")
    e = kp.add_entry(g, "Bank", "user", "pw1", url="https://bank.example", notes="n", tags="a;b")
    e.set_custom_property("TOTP Seed", "jbsw y3dp ehpk 3pxp")
    e.set_custom_property("TOTP Settings", "60;8")
    e.set_custom_property("KP2A_URL", "https://bank2.example")
    e.set_custom_property("Memo", "m", protect=True)
    e.expires = True
    e.expiry_time = dt.datetime(2031, 5, 5, 12, 0, tzinfo=dt.timezone.utc)
    otp = kp.add_entry(kp.root_group, "Authenticator only", "", "", otp="otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
    gone = kp.add_entry(kp.root_group, "Deleted", "u", "p")
    kp.trash_entry(gone)
    kp.save()
    items, warnings = kdbx.import_kdbx(p, "pw")
    assert [w for w in warnings if "Recycle Bin" in w] and len(items) == 2
    b = next(i for i in items if i.name == "Bank")
    assert b.uris == ["https://bank.example", "https://bank2.example"] and b.extra["_folder"] == "Banking" and b.tags == ["a", "b"]
    assert b.totp == "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=60&digits=8"
    assert b.fields == [{"label": "Memo", "value": "m", "hidden": True}]
    assert b.expires == dt.datetime(2031, 5, 5, 12, 0, tzinfo=dt.timezone.utc).timestamp()
    assert next(i for i in items if i.name == "Authenticator only").type == "totp"


def test_pykeepass_missing_is_reported_cleanly():
    code = ("import sys; sys.modules['pykeepass'] = None\n"
            "from pwdeck import kdbx\n"
            "assert not kdbx.available()\n"
            "try:\n    kdbx.import_kdbx('x.kdbx', 'pw')\nexcept kdbx.KdbxUnavailable as e:\n    print('OK', e)\n")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
    assert r.returncode == 0 and "pip install pykeepass" in r.stdout, r.stderr

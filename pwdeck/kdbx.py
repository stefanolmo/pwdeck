"""KeePass (KDBX 4) import and export, via the optional `pykeepass` package (`pip install pykeepass`).

Mapping (PW Deck -> KDBX): folders -> groups; name/username/password/first URL/description -> Title/UserName/Password/URL/Notes;
TOTP -> the `otp` field (otpauth:// URI, as KeePassXC does); further URLs -> `KP2A_URL`, `KP2A_URL_1`…; tags -> tags (+ `favorite`);
expiry -> expiry; custom fields -> custom properties (hidden ones are *protected*); card/SSH fields -> `pwdeck.<key>` properties and
`PWDECK_TYPE`; attachments -> binaries. Not exported: history, the trash. Imported from KeePass/KeePassXC: everything above plus
KeePassXC's older `TOTP Seed`/`TOTP Settings`; the Recycle Bin is skipped.

The exported file is a normal encrypted KDBX 4 database protected by a password you choose for it (not your master password) and
optionally a keyfile. Compatibility with KeePassXC / KeePass 2 is what pykeepass produces (tested here with pykeepass itself only).
"""
from __future__ import annotations

import datetime as dt
import os
from urllib.parse import quote

from .itemtypes import type_fields
from .vault import MAX_ATTACHMENT, Item, Vault

RESERVED = {"title", "username", "password", "url", "notes", "otp", "totp seed", "totp settings", "pwdeck_type"}
SECRET_EXTRA = {"number", "cvv", "pin", "private_key", "passphrase"}


class KdbxUnavailable(RuntimeError):
    """pykeepass is not installed."""


def available() -> bool:
    try:
        import pykeepass  # noqa: F401
        return True
    except ImportError:
        return False


def _pk():
    try:
        import pykeepass
        return pykeepass
    except ImportError as e:
        raise KdbxUnavailable("KDBX support needs the optional package pykeepass:  pip install pykeepass") from e


def _otp_uri(it: Item) -> str:
    t = it.totp.strip()
    if not t or t.lower().startswith("otpauth://"):
        return t
    label = f"{quote(it.name)}:{quote(it.username)}" if it.username else quote(it.name)
    return f"otpauth://totp/{label}?secret={''.join(t.split()).upper()}&issuer={quote(it.name)}"


def _safe_label(label: str, taken: set[str]) -> str:
    base = label.strip() or "Field"
    if base.lower() in RESERVED or base.lower().startswith(("kp2a_url", "pwdeck.")):
        base = f"field: {base}"
    name, n = base, 2
    while name.lower() in taken:
        name, n = f"{base} ({n})", n + 1
    taken.add(name.lower())
    return name


# ------------------------------------------------------------------------------------------------ export
def export_kdbx(vault: Vault, path: str, password: str, keyfile: str | None = None) -> int:
    """Writes `path` (must not exist). Returns the number of exported items. The trash is not exported."""
    pk = _pk()
    if os.path.exists(path):
        raise FileExistsError(path)
    kp = pk.create_database(path, password=password, keyfile=keyfile)
    groups: dict[str | None, object] = {None: kp.root_group}
    folders = {f["id"]: f for f in vault.folders()}

    def group_for(fid):
        if fid in groups:
            return groups[fid]
        f = folders[fid]
        groups[fid] = kp.add_group(group_for(f["parent_id"]) if f["parent_id"] in folders else kp.root_group, f["name"])
        return groups[fid]

    n = 0
    for it in vault.items(secrets=True):
        g = group_for(it.folder_id) if it.folder_id in folders else kp.root_group
        notes = it.description
        tags = list(it.tags) + (["favorite"] if it.favorite else [])
        e = kp.add_entry(g, it.name, it.username, it.password, url=it.uri or None, notes=notes or None, tags=tags or None,
                         otp=_otp_uri(it) or None)
        if it.expires:
            e.expires = True
            e.expiry_time = dt.datetime.fromtimestamp(it.expires, dt.timezone.utc)
        e.set_custom_property("PWDECK_TYPE", it.type)
        for i, u in enumerate(it.uris[1:]):
            e.set_custom_property("KP2A_URL" if i == 0 else f"KP2A_URL_{i}", u)
        for k, v in it.extra.items():
            if v:
                e.set_custom_property(f"pwdeck.{k}", v, protect=k in SECRET_EXTRA)
        taken: set[str] = set()
        for f in it.fields:
            e.set_custom_property(_safe_label(f.get("label", ""), taken), f.get("value", ""), protect=bool(f.get("hidden")))
        for a in vault.attachments(it.id):
            name, data = vault.get_attachment(a["id"])
            e.add_attachment(kp.add_binary(data), name)
        n += 1
    kp.save()
    os.chmod(path, 0o600)
    return n


# ------------------------------------------------------------------------------------------------ import
def import_kdbx(path: str, password: str | None, keyfile: str | None = None) -> tuple[list[Item], list[str]]:
    """Returns (items, warnings). Raises ValueError with a readable message for wrong credentials / unreadable files."""
    pk = _pk()
    try:
        kp = pk.PyKeePass(path, password=password or None, keyfile=keyfile)
    except pk.exceptions.CredentialsError as e:
        raise ValueError("Wrong password or keyfile.") from e
    except Exception as e:      # noqa: BLE001  pykeepass raises assorted errors for damaged / unsupported files
        raise ValueError(f"Cannot read this KDBX file: {e}") from e
    bin_group = kp.recyclebin_group
    items: list[Item] = []
    warnings: list[str] = []
    skipped_bin = 0
    for e in kp.entries:
        if bin_group is not None and e.group is not None and (e.group.uuid == bin_group.uuid or _inside(e.group, bin_group)):
            skipped_bin += 1
            continue
        props = e.custom_properties
        t = props.get("PWDECK_TYPE", "password")
        it = Item(type=t if t in ("password", "totp", "note", "card", "ssh", "custom") else "password")
        it.name = (e.title or e.url or "(no name)").strip()
        it.username, it.password, it.description = e.username or "", e.password or "", e.notes or ""
        it.uris = [e.url] if e.url else []
        extra_urls = sorted((k for k in props if k.upper().startswith("KP2A_URL")), key=lambda k: (len(k), k))
        it.uris += [props[k] for k in extra_urls if props[k]]
        it.totp = (e.otp or "").strip() or _legacy_totp(props)
        tags = [x for x in (e.tags or []) if x]
        it.favorite = "favorite" in tags
        it.tags = [x for x in tags if x != "favorite"]
        if e.expires and e.expiry_time:
            d = e.expiry_time if e.expiry_time.tzinfo else e.expiry_time.replace(tzinfo=dt.timezone.utc)
            it.expires = d.timestamp()
        for k, v in props.items():
            lk = k.lower()
            if lk in RESERVED or lk.startswith("kp2a_url"):
                continue
            if lk.startswith("pwdeck."):
                it.extra[k[7:]] = v or ""
            else:
                it.fields.append({"label": k, "value": v or "", "hidden": bool(e.is_custom_property_protected(k))})
        if it.type == "password" and it.totp and not it.password and not it.username and "PWDECK_TYPE" not in props:
            it.type = "totp"
        for a in e.attachments:
            data = a.data
            if len(data) > MAX_ATTACHMENT:
                warnings.append(f"{it.name}: attachment {a.filename} skipped (over {MAX_ATTACHMENT // (1 << 20)} MiB)")
            else:
                it.attachments_to_add.append((a.filename or "file", data))
        parts = [p.replace("/", "-") for p in (e.group.path if e.group is not None else []) if p]
        it.extra["_folder"] = "/".join(parts)
        items.append(it)
    if skipped_bin:
        warnings.append(f"{skipped_bin} entries in the Recycle Bin were not imported")
    return items, warnings


def _inside(group, ancestor) -> bool:
    g = group
    while g is not None:
        if g.uuid == ancestor.uuid:
            return True
        g = g.parentgroup
    return False


def _legacy_totp(props: dict) -> str:
    """KeePassXC <= 2.5 / KeeOtp style: 'TOTP Seed' (+ 'TOTP Settings' = "period;digits")."""
    seed = next((v for k, v in props.items() if k.lower() == "totp seed"), "")
    if not seed:
        return ""
    settings = next((v for k, v in props.items() if k.lower() == "totp settings"), "")
    try:
        period, digits = (int(x) for x in settings.split(";")[:2])
    except ValueError:
        return seed
    return f"otpauth://totp/x?secret={''.join(seed.split()).upper()}&period={period}&digits={digits}"

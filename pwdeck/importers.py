"""Import (generic CSV with auto-mapped columns — Passbolt/KeePass/Bitwarden/LastPass/Chrome…, Bitwarden JSON,
PW Deck JSON) and export (CSV, JSON). Exports are PLAIN TEXT: the caller must warn the user."""
from __future__ import annotations

import csv
import io
import json
import time

from .itemtypes import TYPES
from .vault import Item, Vault

_COLS = {
    "name": ("name", "title", "account", "site", "resource", "label"),
    "uri": ("url", "uri", "login_uri", "website", "web site", "address", "login url"),
    "username": ("username", "user", "login", "login_username", "user name", "email", "login name"),
    "password": ("password", "login_password", "pass", "pwd"),
    "description": ("description", "notes", "note", "extra", "comment", "comments"),
    "folder": ("folder", "group", "grouping", "path", "category", "collection"),
    "totp": ("totp", "login_totp", "otp", "otpauth", "one-time password", "2fa"),
    "type": ("type",),
    "favorite": ("favorite", "fav"),
    "tags": ("tags", "tag", "labels"),
}


def _map_headers(header: list[str]) -> dict[str, int]:
    low = [h.strip().lower().lstrip("﻿") for h in header]
    out: dict[str, int] = {}
    for key, names in _COLS.items():
        for n in names:
            if n in low:
                out[key] = low.index(n)
                break
    return out


def parse_csv(text: str) -> list[Item]:
    text = text.lstrip("﻿")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    if not rows:
        return []
    cols = _map_headers(rows[0])
    if "name" not in cols and "uri" not in cols:
        raise ValueError("no recognisable columns (need at least name/title or url)")
    items = []
    for r in rows[1:]:
        if not any(c.strip() for c in r):
            continue
        g = lambda k: r[cols[k]].strip() if k in cols and cols[k] < len(r) else ""   # noqa: E731
        t = g("type").lower()
        it = Item(type="note" if t in ("note", "securenote", "secure note") else "password")
        it.name = g("name") or g("uri") or "(no name)"
        it.uris = [g("uri")] if g("uri") else []
        it.username, it.password, it.description, it.totp = g("username"), g("password"), g("description"), g("totp")
        if it.totp and not it.password and not it.username:
            it.type = "totp"
        it.favorite = g("favorite").lower() in ("1", "true", "yes", "x")
        it.tags = [x.strip() for x in g("tags").replace(";", ",").split(",") if x.strip()]
        it.extra["_folder"] = g("folder")
        items.append(it)
    return items


def parse_bitwarden_json(text: str) -> list[Item]:
    d = json.loads(text)
    if d.get("encrypted"):
        raise ValueError("encrypted Bitwarden exports are not supported: export unencrypted JSON")
    folders = {f["id"]: f["name"] for f in d.get("folders", [])}
    out = []
    for x in d.get("items", []):
        kind = x.get("type")
        it = Item(type={1: "password", 2: "note", 3: "card", 4: "custom"}.get(kind, "custom"), name=x.get("name") or "(no name)")
        it.description = x.get("notes") or ""
        it.favorite = bool(x.get("favorite"))
        it.extra["_folder"] = folders.get(x.get("folderId"), "")
        if kind == 1:
            lg = x.get("login") or {}
            it.username, it.password, it.totp = lg.get("username") or "", lg.get("password") or "", lg.get("totp") or ""
            it.uris = [u["uri"] for u in lg.get("uris") or [] if u.get("uri")]
        elif kind == 3:
            c = x.get("card") or {}
            it.extra.update(holder=c.get("cardholderName") or "", number=c.get("number") or "", cvv=c.get("code") or "",
                            expiry=f"{c.get('expMonth') or ''}/{c.get('expYear') or ''}".strip("/"))
        elif kind == 4:
            idn = x.get("identity") or {}
            it.fields += [{"label": k, "value": str(v), "hidden": False} for k, v in idn.items() if v]
        for f in x.get("fields") or []:
            it.fields.append({"label": f.get("name") or "", "value": f.get("value") or "", "hidden": f.get("type") == 1})
        out.append(it)
    return out


def parse_pwdeck_json(text: str) -> list[Item]:
    d = json.loads(text)
    if d.get("format") != "pwdeck-export":
        raise ValueError("not a PW Deck JSON export")
    out = []
    for x in d["items"]:
        it = Item(type=x["type"], name=x["name"])
        for k in ("username", "password", "uris", "description", "totp", "fields", "extra", "tags", "favorite", "expires"):
            if k in x:
                setattr(it, k, x[k])
        it.extra["_folder"] = x.get("folder", "")
        out.append(it)
    return out


def detect_and_parse(path: str) -> list[Item]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        text = f.read()
    s = text.lstrip()
    if s.startswith("{"):
        d = json.loads(text)
        if d.get("format") == "pwdeck-export":
            return parse_pwdeck_json(text)
        if "items" in d:
            return parse_bitwarden_json(text)
        raise ValueError("unknown JSON format")
    return parse_csv(text)


def import_items(vault: Vault, items: list[Item], skip_duplicates: bool = True) -> tuple[int, int]:
    """Returns (imported, skipped). One single write for the whole import."""
    added = skipped = 0
    with vault.batch():
        for it in items:
            folder = it.extra.pop("_folder", "")
            it.folder_id = vault.ensure_folder_path(folder) if folder else None
            if skip_duplicates and vault.has_duplicate(it):
                skipped += 1
                continue
            vault.add_item(it)
            added += 1
    return added, skipped


# ---------------------------------------------------------------------------------------------- export
CSV_COLUMNS = ["folder", "type", "name", "url", "username", "password", "totp", "description", "tags", "favorite"]


def export_csv(vault: Vault) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for it in vault.items(secrets=True):
        desc = it.description
        for k, v in it.extra.items():                       # card/ssh specific values would be lost otherwise
            if v:
                desc += f"\n{k}: {v}"
        for f in it.fields:
            desc += f"\n{f.get('label')}: {f.get('value')}"
        w.writerow([vault.folder_path(it.folder_id), it.type, it.name, it.uri, it.username, it.password, it.totp,
                    desc.strip(), ",".join(it.tags), int(it.favorite)])
    return buf.getvalue()


def export_json(vault: Vault) -> str:
    items = []
    for it in vault.items(secrets=True):
        items.append({"type": it.type, "name": it.name, "folder": vault.folder_path(it.folder_id), "username": it.username,
                      "password": it.password, "uris": it.uris, "description": it.description, "totp": it.totp,
                      "fields": it.fields, "extra": it.extra, "tags": it.tags, "favorite": it.favorite,
                      "expires": it.expires, "created": it.created, "modified": it.modified})
    return json.dumps({"format": "pwdeck-export", "version": 1, "exported": time.time(), "items": items}, indent=2)


def write_private(path: str, text: str) -> None:
    """Plain-text exports are created with mode 0600."""
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        f.write(text)

"""The vault: an SQLite database kept in memory and stored on disk only as an encrypted container (see crypto.py)."""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import sqlite3
import time
import uuid
from dataclasses import dataclass, field

from . import crypto
from .crypto import (CorruptVaultError, NotAVaultError, VaultError, WrongPasswordError)  # noqa: F401  (re-exported)
from .itemtypes import COLUMN_KEYS

SCHEMA_VERSION = 2          # 2 = secret columns hold sealed (field-encrypted) values; 1 = plaintext columns (migrated on open)
SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE folders(id TEXT PRIMARY KEY, parent_id TEXT REFERENCES folders(id) ON DELETE SET NULL,
                     name TEXT NOT NULL, created REAL, modified REAL);
CREATE TABLE items(
  id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL,
  folder_id TEXT REFERENCES folders(id) ON DELETE SET NULL,
  username TEXT NOT NULL DEFAULT '', password TEXT NOT NULL DEFAULT '', uris TEXT NOT NULL DEFAULT '[]',
  description TEXT NOT NULL DEFAULT '', totp TEXT NOT NULL DEFAULT '',
  fields TEXT NOT NULL DEFAULT '[]', extra TEXT NOT NULL DEFAULT '{}',
  favorite INTEGER NOT NULL DEFAULT 0, created REAL, modified REAL, pw_changed REAL,
  expires REAL, deleted REAL, last_used REAL);
CREATE TABLE tags(item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE, tag TEXT NOT NULL,
                  PRIMARY KEY(item_id, tag));
CREATE TABLE history(id INTEGER PRIMARY KEY AUTOINCREMENT, item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                     ts REAL NOT NULL, snapshot TEXT NOT NULL);
CREATE INDEX idx_items_folder ON items(folder_id);
CREATE INDEX idx_items_deleted ON items(deleted);
"""
SECRET_KEYS = ("password", "totp", "number", "cvv", "pin", "private_key", "passphrase", "description")
SEALED_COLUMNS = ("password", "totp", "description")


class VaultChangedError(VaultError):
    """The file on disk was modified by someone else since we loaded/saved it (sync client, second machine…)."""


class VaultLockedError(VaultError):
    """Another running instance has the vault open."""


def new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Item:
    type: str = "password"
    name: str = ""
    id: str = field(default_factory=new_id)
    folder_id: str | None = None
    username: str = ""
    password: str = ""
    uris: list[str] = field(default_factory=list)
    description: str = ""
    totp: str = ""
    fields: list[dict] = field(default_factory=list)          # [{"label","value","hidden"}]
    extra: dict = field(default_factory=dict)                  # type specific keys (card number, ssh key…)
    tags: list[str] = field(default_factory=list)
    favorite: bool = False
    created: float = 0.0
    modified: float = 0.0
    pw_changed: float = 0.0
    expires: float | None = None
    deleted: float | None = None
    last_used: float | None = None
    # keys that hold a value: columns, `extra` keys and "field:<i>" for custom fields. Filled when loading, so the UI can
    # list what an item contains without decrypting it (light items have empty secret values).
    has: set = field(default_factory=set)

    def get(self, key: str):
        return getattr(self, key) if key in COLUMN_KEYS else self.extra.get(key, "")

    def set(self, key: str, value) -> None:
        if key in COLUMN_KEYS:
            setattr(self, key, value)
        else:
            self.extra[key] = value

    @property
    def uri(self) -> str:
        return self.uris[0] if self.uris else ""

    def secrets_snapshot(self) -> dict:
        d = {k: self.get(k) for k in SECRET_KEYS if self.get(k)}
        if self.fields:
            d["fields"] = self.fields
        return d


def _stat(path: str):
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


class Vault:
    """Use `Vault.create()` / `Vault.open()`. Every mutation is written to disk immediately (atomic replace)
    unless done inside `with vault.batch():`."""

    def __init__(self, path: str, db: sqlite3.Connection, dek: bytes, header: dict):
        self.path = os.path.abspath(path)
        self.db = db
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self._dek = dek
        self._fk = crypto.derive_field_key(dek)
        self._vid: str | None = None
        self.db.execute("PRAGMA secure_delete=ON")        # overwrite deleted/updated content inside the in-memory image
        self._header = header
        self.via_recovery = False       # True when unlocked with the recovery key: the old password is then unknown by definition
        self._batch = 0
        self._dirty = False
        self._stat = None
        self._lock_path = self.path + ".lock"
        self.on_saved = None            # optional callback(path)

    # ------------------------------------------------------------------ lifecycle
    @classmethod
    def create(cls, path: str, password: str, keyfile: bytes | None = None, kdf: str = crypto.DEFAULT_KDF,
               overwrite: bool = False) -> tuple["Vault", str]:
        if os.path.exists(path) and not overwrite:
            raise VaultError(f"{path} already exists")
        dek, header, recovery = crypto.create_keys(password, keyfile, kdf)
        db = sqlite3.connect(":memory:")
        db.executescript(SCHEMA)
        db.execute("INSERT INTO meta VALUES('schema', ?)", (str(SCHEMA_VERSION),))
        db.execute("INSERT INTO meta VALUES('vault_id', ?)", (new_id(),))
        db.execute("INSERT INTO meta VALUES('created', ?)", (str(time.time()),))
        db.commit()
        v = cls(path, db, dek, header)
        v._acquire_lock()
        v.save(force=True)
        return v, recovery

    @classmethod
    def open(cls, path: str, password: str | None = None, keyfile: bytes | None = None,
             recovery_key: str | None = None, lock: bool = True) -> "Vault":
        with open(path, "rb") as f:
            blob = f.read()
        st = _stat(path)
        header, ct = crypto.parse(blob)
        dek = crypto.unlock(header, password, keyfile, recovery_key)
        plain = crypto.decrypt_payload(header, ct, dek)
        db = sqlite3.connect(":memory:")
        try:
            db.deserialize(plain)
            ver = db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
        except sqlite3.DatabaseError as e:
            raise CorruptVaultError("the decrypted content is not a valid database") from e
        if ver is None or int(ver[0]) > SCHEMA_VERSION:
            raise VaultError("this vault was created by a newer version of PW Deck")
        v = cls(path, db, dek, header)
        v.via_recovery = bool(recovery_key)
        v._stat = st
        if lock:
            v._acquire_lock()
        if int(ver[0]) < SCHEMA_VERSION:
            try:
                v._migrate_v1()
            except Exception:
                v.close_quietly()
                raise
        return v

    @staticmethod
    def peek(path: str) -> dict:
        """Header information that needs no key (does the vault need a keyfile? is there a recovery slot?)."""
        with open(path, "rb") as f:
            header, _ = crypto.parse(f.read())
        return {"keyfile": bool(header["kdf"].get("keyfile")), "recovery": "recovery" in header["slots"],
                "kdf": crypto.kdf_description(header["kdf"])}

    def close_quietly(self) -> None:
        with contextlib.suppress(Exception):
            self.db.close()
        self._dek = self._fk = None
        self._release_lock()

    def close(self) -> None:
        if self._dek is None:
            return
        if self._dirty:
            self.save()                 # on failure the exception propagates and the vault stays open: nothing is lost
        self.db.close()
        self._dek = self._fk = None
        self._release_lock()

    # ------------------------------------------------------------------ instance lock (best effort)
    def _acquire_lock(self) -> None:
        try:
            if os.path.exists(self._lock_path):
                with open(self._lock_path) as f:
                    pid = int((f.read() or "0").strip() or 0)
                if pid and pid != os.getpid() and _pid_alive(pid):
                    raise VaultLockedError(f"the vault is already open in another PW Deck process (pid {pid})")
            with open(self._lock_path, "w") as f:
                f.write(str(os.getpid()))
        except (OSError, ValueError):
            pass

    def _release_lock(self) -> None:
        with contextlib.suppress(OSError):
            if os.path.exists(self._lock_path):
                with open(self._lock_path) as f:
                    if f.read().strip() == str(os.getpid()):
                        os.unlink(self._lock_path)

    # ------------------------------------------------------------------ persistence
    def save(self, force: bool = False) -> None:
        if not force and self._stat is not None and _stat(self.path) != self._stat:
            raise VaultChangedError("the vault file was changed on disk by another program since it was loaded")
        self.db.commit()
        blob = crypto.encode(self._header, self._dek, self.db.serialize())
        crypto.atomic_write(self.path, blob)
        self._stat = _stat(self.path)
        self._dirty = False
        if self.on_saved:
            self.on_saved(self.path)

    def _changed(self) -> None:
        self._dirty = True
        if self._batch == 0:
            self.save()

    @contextlib.contextmanager
    def batch(self):
        """Group many changes into a single write (imports)."""
        self._batch += 1
        try:
            yield
        finally:
            self._batch -= 1
            if self._batch == 0 and self._dirty:
                self.save()

    @property
    def dirty(self) -> bool:
        return self._dirty

    def copy_to(self, dest: str) -> str:
        """Writes a fresh, verified copy of the encrypted vault to `dest` (a file, or a directory)."""
        if os.path.isdir(dest):
            dest = os.path.join(dest, time.strftime(os.path.splitext(os.path.basename(self.path))[0] + "-%Y%m%d-%H%M%S.pwdeck"))
        crypto.atomic_write(dest, crypto.encode(self._header, self._dek, self.db.serialize()))
        self.verify_file(dest)
        return dest

    def verify_file(self, path: str) -> int:
        """Decrypts `path` with the key of this open vault and runs SQLite integrity_check. Returns the item count."""
        with open(path, "rb") as f:
            header, ct = crypto.parse(f.read())
        plain = crypto.decrypt_payload(header, ct, self._dek)
        db = sqlite3.connect(":memory:")
        try:
            db.deserialize(plain)
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise CorruptVaultError("integrity check failed")
            db.row_factory = sqlite3.Row
            for r in db.execute("SELECT * FROM items"):                  # every sealed value must authenticate
                self._load(r, [], full=True)
            for r in db.execute("SELECT item_id, snapshot FROM history"):
                crypto.unseal(self._fk, self._aad(r["item_id"], "history"), crypto.b64d(r["snapshot"]))
            return db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        finally:
            db.close()

    # ------------------------------------------------------------------ keys
    def change_password(self, new_password: str, keyfile: bytes | None = None, kdf: str = crypto.DEFAULT_KDF) -> None:
        self._header = crypto.rewrap_password(self._header, self._dek, new_password, keyfile, kdf)
        self._dirty = True
        self.save()
        self.via_recovery = False

    def new_recovery_key(self) -> str:
        self._header, key = crypto.new_recovery_slot(self._header, self._dek)
        self._dirty = True
        self.save()
        return key

    def verify_password(self, password: str, keyfile: bytes | None = None) -> bool:
        try:
            return crypto.unlock(self._header, password, keyfile) == self._dek
        except WrongPasswordError:
            return False

    @property
    def kdf_info(self) -> str:
        return crypto.kdf_description(self._header["kdf"])

    @property
    def kdf_is_legacy(self) -> bool:
        return self._header["kdf"].get("alg") != "argon2id"

    @property
    def uses_keyfile(self) -> bool:
        return bool(self._header["kdf"].get("keyfile"))

    @property
    def vault_id(self) -> str:
        if self._vid is None:
            self._vid = self.db.execute("SELECT value FROM meta WHERE key='vault_id'").fetchone()[0]
        return self._vid

    # ------------------------------------------------------------------ folders
    def add_folder(self, name: str, parent_id: str | None = None) -> str:
        fid, now = new_id(), time.time()
        self.db.execute("INSERT INTO folders VALUES(?,?,?,?,?)", (fid, parent_id, name.strip() or "Folder", now, now))
        self._changed()
        return fid

    def rename_folder(self, fid: str, name: str) -> None:
        self.db.execute("UPDATE folders SET name=?, modified=? WHERE id=?", (name.strip(), time.time(), fid))
        self._changed()

    def move_folder(self, fid: str, parent_id: str | None) -> None:
        p = parent_id
        while p:                                           # refuse cycles
            if p == fid:
                raise VaultError("cannot move a folder into itself")
            row = self.db.execute("SELECT parent_id FROM folders WHERE id=?", (p,)).fetchone()
            p = row[0] if row else None
        self.db.execute("UPDATE folders SET parent_id=?, modified=? WHERE id=?", (parent_id, time.time(), fid))
        self._changed()

    def delete_folder(self, fid: str) -> None:
        """Items inside go to the root, sub-folders move up one level."""
        parent = self.db.execute("SELECT parent_id FROM folders WHERE id=?", (fid,)).fetchone()
        self.db.execute("UPDATE folders SET parent_id=? WHERE parent_id=?", (parent[0] if parent else None, fid))
        self.db.execute("DELETE FROM folders WHERE id=?", (fid,))
        self._changed()

    def folders(self) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT id,parent_id,name FROM folders ORDER BY name COLLATE NOCASE")]

    def folder_path(self, fid: str | None) -> str:
        names, seen = [], set()
        while fid and fid not in seen:
            seen.add(fid)
            r = self.db.execute("SELECT parent_id,name FROM folders WHERE id=?", (fid,)).fetchone()
            if not r:
                break
            names.append(r["name"])
            fid = r["parent_id"]
        return "/".join(reversed(names))

    def ensure_folder_path(self, path: str) -> str | None:
        """Creates (or reuses) a nested folder from 'a/b/c'."""
        parent = None
        for part in [p.strip() for p in path.replace("\\", "/").split("/") if p.strip()]:
            row = self.db.execute("SELECT id FROM folders WHERE name=? AND parent_id IS ?", (part, parent)).fetchone()
            parent = row[0] if row else self.add_folder(part, parent)
        return parent

    def folder_ids_under(self, fid: str) -> set[str]:
        out, todo = set(), [fid]
        kids: dict[str, list[str]] = {}
        for f in self.folders():
            kids.setdefault(f["parent_id"], []).append(f["id"])
        while todo:
            x = todo.pop()
            if x not in out:
                out.add(x)
                todo.extend(kids.get(x, []))
        return out

    # ------------------------------------------------------------------ sealing helpers
    def _aad(self, iid: str, col: str, sub: str = "") -> bytes:
        return f"{self.vault_id}|{iid}|{col}|{sub}".encode()

    def _seal_str(self, iid: str, col: str, text: str, sub: str = "") -> bytes:
        return crypto.seal(self._fk, self._aad(iid, col, sub), text.encode("utf-8")) if text else b""

    def _open_str(self, iid: str, col: str, blob, sub: str = "") -> str:
        if not blob:
            return ""
        return crypto.unseal(self._fk, self._aad(iid, col, sub), bytes(blob)).decode("utf-8")

    def _seal_map(self, iid: str, m: dict) -> str:
        return json.dumps({k: crypto.b64e(self._seal_str(iid, "extra", str(v), k)) for k, v in m.items() if v})

    def _seal_fields(self, iid: str, fields: list[dict]) -> str:
        return json.dumps([{"label": f.get("label", ""), "hidden": bool(f.get("hidden")),
                            "value": crypto.b64e(self._seal_str(iid, "fields", f.get("value", ""), f"field:{i}"))}
                           for i, f in enumerate(fields)])

    def _load(self, r: sqlite3.Row, tags: list[str], full: bool) -> Item:
        iid = r["id"]
        extra_raw, fields_raw = json.loads(r["extra"]), json.loads(r["fields"])
        has = {c for c in SEALED_COLUMNS if r[c]}
        has |= {k for k, v in extra_raw.items() if v}
        has |= {f"field:{i}" for i, f in enumerate(fields_raw) if f.get("value")}
        it = Item(type=r["type"], name=r["name"], id=iid, folder_id=r["folder_id"], username=r["username"],
                  uris=json.loads(r["uris"]), tags=sorted(tags), favorite=bool(r["favorite"]), created=r["created"] or 0,
                  modified=r["modified"] or 0, pw_changed=r["pw_changed"] or 0, expires=r["expires"], deleted=r["deleted"],
                  last_used=r["last_used"], has=has)
        if full:
            it.password, it.totp = self._open_str(iid, "password", r["password"]), self._open_str(iid, "totp", r["totp"])
            it.description = self._open_str(iid, "description", r["description"])
            it.extra = {k: self._open_str(iid, "extra", crypto.b64d(v), k) for k, v in extra_raw.items() if v}
            it.fields = [{"label": f["label"], "hidden": f["hidden"],
                          "value": self._open_str(iid, "fields", crypto.b64d(f["value"]), f"field:{i}") if f.get("value") else ""}
                         for i, f in enumerate(fields_raw)]
        else:                                                   # light item: structure only, no secret values
            it.fields = [{"label": f["label"], "hidden": f["hidden"], "value": ""} for f in fields_raw]
        return it

    def _write_item(self, it: Item, insert: bool) -> None:
        iid = it.id
        vals = (it.type, it.name.strip() or "(no name)", it.folder_id, it.username, self._seal_str(iid, "password", it.password),
                json.dumps(it.uris), self._seal_str(iid, "description", it.description), self._seal_str(iid, "totp", it.totp),
                self._seal_fields(iid, it.fields), self._seal_map(iid, it.extra), int(it.favorite),
                it.modified, it.pw_changed, it.expires, it.deleted, it.last_used)
        if insert:
            self.db.execute("INSERT INTO items(type,name,folder_id,username,password,uris,description,totp,fields,extra,"
                            "favorite,modified,pw_changed,expires,deleted,last_used,id,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            vals + (iid, it.created))
        else:
            self.db.execute("UPDATE items SET type=?,name=?,folder_id=?,username=?,password=?,uris=?,description=?,totp=?,"
                            "fields=?,extra=?,favorite=?,modified=?,pw_changed=?,expires=?,deleted=?,last_used=? WHERE id=?",
                            vals + (iid,))
        self.db.execute("DELETE FROM tags WHERE item_id=?", (iid,))
        self.db.executemany("INSERT OR IGNORE INTO tags VALUES(?,?)", [(iid, t.strip()) for t in it.tags if t.strip()])

    def _migrate_v1(self) -> None:
        """v1 stored secrets as plain columns inside the (encrypted) container. Seal them, keep the old file as *.pre-v2.bak."""
        bak = self.path + ".pre-v2.bak"
        if not os.path.exists(bak):
            shutil.copy2(self.path, bak)
        db = self.db
        for r in db.execute("SELECT id,password,description,totp,fields,extra FROM items").fetchall():
            iid = r["id"]
            extra, fields = json.loads(r["extra"]), json.loads(r["fields"])
            db.execute("UPDATE items SET password=?, description=?, totp=?, fields=?, extra=? WHERE id=?",
                       (self._seal_str(iid, "password", r["password"] or ""), self._seal_str(iid, "description", r["description"] or ""),
                        self._seal_str(iid, "totp", r["totp"] or ""), self._seal_fields(iid, fields), self._seal_map(iid, extra), iid))
        for h in db.execute("SELECT id,item_id,snapshot FROM history").fetchall():
            db.execute("UPDATE history SET snapshot=? WHERE id=?",
                       (crypto.b64e(crypto.seal(self._fk, self._aad(h["item_id"], "history"), h["snapshot"].encode())), h["id"]))
        db.execute("UPDATE meta SET value=? WHERE key='schema'", (str(SCHEMA_VERSION),))
        db.commit()
        db.execute("VACUUM")                                    # drop the freed pages that still held the old plaintext
        self._dirty = True
        self.save(force=True)

    # ------------------------------------------------------------------ items
    def add_item(self, it: Item) -> str:
        now = time.time()
        it.created = it.created or now
        it.modified = now
        it.pw_changed = it.pw_changed or now
        self._write_item(it, True)
        self._changed()
        return it.id

    def update_item(self, it: Item) -> None:
        old = self.get_item(it.id)
        if old is None:
            raise VaultError("item not found")
        it.modified = time.time()
        if old.secrets_snapshot() != it.secrets_snapshot():
            snap = json.dumps(old.secrets_snapshot()).encode()
            self.db.execute("INSERT INTO history(item_id,ts,snapshot) VALUES(?,?,?)",
                            (it.id, old.modified, crypto.b64e(crypto.seal(self._fk, self._aad(it.id, "history"), snap))))
            self.db.execute("DELETE FROM history WHERE item_id=? AND id NOT IN "
                            "(SELECT id FROM history WHERE item_id=? ORDER BY id DESC LIMIT 25)", (it.id, it.id))
        if old.password != it.password:
            it.pw_changed = it.modified
        self._write_item(it, False)
        self._changed()

    def get_item(self, iid: str, full: bool = True) -> Item | None:
        """full=True decrypts every secret (editing, export); full=False returns a light item (see `Item.has`)."""
        r = self.db.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()
        return self._load(r, self._tags(iid), full) if r else None

    def reveal(self, iid: str, key: str) -> str:
        """Decrypts ONE secret value: a column (password/totp/description), an `extra` key, or 'field:<i>'."""
        r = self.db.execute("SELECT password,totp,description,extra,fields FROM items WHERE id=?", (iid,)).fetchone()
        if r is None:
            raise VaultError("item not found")
        if key in SEALED_COLUMNS:
            return self._open_str(iid, key, r[key])
        if key.startswith("field:"):
            i = int(key[6:])
            f = json.loads(r["fields"])[i]
            return self._open_str(iid, "fields", crypto.b64d(f["value"]), key) if f.get("value") else ""
        v = json.loads(r["extra"]).get(key)
        return self._open_str(iid, "extra", crypto.b64d(v), key) if v else ""

    def _tags(self, iid: str) -> list[str]:
        return [x[0] for x in self.db.execute("SELECT tag FROM tags WHERE item_id=?", (iid,))]

    def items(self, trash: bool = False, secrets: bool = False) -> list[Item]:
        """Light items by default (no secret values, `has` tells what exists). secrets=True decrypts everything."""
        tagmap: dict[str, list[str]] = {}
        for iid, tag in self.db.execute("SELECT item_id, tag FROM tags"):
            tagmap.setdefault(iid, []).append(tag)
        q = "SELECT * FROM items WHERE deleted IS NOT NULL" if trash else "SELECT * FROM items WHERE deleted IS NULL"
        return [self._load(r, tagmap.get(r["id"], []), secrets) for r in self.db.execute(q + " ORDER BY name COLLATE NOCASE")]

    def trash_item(self, iid: str) -> None:
        self.db.execute("UPDATE items SET deleted=? WHERE id=?", (time.time(), iid))
        self._changed()

    def restore_item(self, iid: str) -> None:
        self.db.execute("UPDATE items SET deleted=NULL WHERE id=?", (iid,))
        self._changed()

    def purge_item(self, iid: str) -> None:
        self.db.execute("DELETE FROM items WHERE id=?", (iid,))
        self._changed()

    def empty_trash(self) -> int:
        n = self.db.execute("DELETE FROM items WHERE deleted IS NOT NULL").rowcount
        self._changed()
        return n

    def set_favorite(self, iid: str, fav: bool) -> None:
        self.db.execute("UPDATE items SET favorite=? WHERE id=?", (int(fav), iid))
        self._changed()

    def move_item(self, iid: str, folder_id: str | None) -> None:
        self.db.execute("UPDATE items SET folder_id=?, modified=? WHERE id=?", (folder_id, time.time(), iid))
        self._changed()

    def touch_used(self, iid: str) -> None:
        self.db.execute("UPDATE items SET last_used=? WHERE id=?", (time.time(), iid))
        self._dirty = True                                # saved with the next real change / on close: no write per copy

    def history(self, iid: str) -> list[dict]:
        return [{"id": r["id"], "ts": r["ts"],
                 "data": json.loads(crypto.unseal(self._fk, self._aad(iid, "history"), crypto.b64d(r["snapshot"])))}
                for r in self.db.execute("SELECT * FROM history WHERE item_id=? ORDER BY id DESC", (iid,))]

    def all_tags(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT DISTINCT tag FROM tags ORDER BY tag COLLATE NOCASE")]

    def has_duplicate(self, it: Item) -> bool:
        for x in self.items():                                   # light items; only candidates get their password decrypted
            if x.type == it.type and x.name == it.name and x.username == it.username and x.uris == it.uris \
                    and (self.reveal(x.id, "password") if "password" in x.has else "") == it.password:
                return True
        return False

    def stats(self) -> dict:
        n = self.db.execute("SELECT COUNT(*) FROM items WHERE deleted IS NULL").fetchone()[0]
        t = self.db.execute("SELECT COUNT(*) FROM items WHERE deleted IS NOT NULL").fetchone()[0]
        return {"items": n, "trash": t, "folders": self.db.execute("SELECT COUNT(*) FROM folders").fetchone()[0]}


def purge_old_backups(directory: str, stem: str, keep: int) -> None:
    files = sorted(f for f in os.listdir(directory) if f.startswith(stem + "-") and f.endswith(".pwdeck"))
    for f in files[:-keep] if keep > 0 else []:
        with contextlib.suppress(OSError):
            os.unlink(os.path.join(directory, f))


def auto_backup(vault: Vault, directory: str, keep: int = 10, min_interval_s: float = 3600) -> str | None:
    """Rotating verified backups; skips if the newest one is younger than `min_interval_s`. Returns the new path."""
    os.makedirs(directory, exist_ok=True)
    stem = os.path.splitext(os.path.basename(vault.path))[0]
    existing = sorted(f for f in os.listdir(directory) if f.startswith(stem + "-") and f.endswith(".pwdeck"))
    if existing and time.time() - os.path.getmtime(os.path.join(directory, existing[-1])) < min_interval_s:
        return None
    dest = vault.copy_to(directory)
    purge_old_backups(directory, stem, keep)
    return dest


def default_backup_dir(vault_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(vault_path)), "backups")

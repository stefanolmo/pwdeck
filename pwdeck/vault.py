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
from .types import COLUMN_KEYS

SCHEMA_VERSION = 1
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


def _row_to_item(r: sqlite3.Row, tags: list[str]) -> Item:
    return Item(type=r["type"], name=r["name"], id=r["id"], folder_id=r["folder_id"], username=r["username"],
                password=r["password"], uris=json.loads(r["uris"]), description=r["description"], totp=r["totp"],
                fields=json.loads(r["fields"]), extra=json.loads(r["extra"]), tags=sorted(tags),
                favorite=bool(r["favorite"]), created=r["created"] or 0, modified=r["modified"] or 0,
                pw_changed=r["pw_changed"] or 0, expires=r["expires"], deleted=r["deleted"], last_used=r["last_used"])


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
        self._header = header
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
        v._stat = st
        if lock:
            v._acquire_lock()
        return v

    @staticmethod
    def peek(path: str) -> dict:
        """Header information that needs no key (does the vault need a keyfile? is there a recovery slot?)."""
        with open(path, "rb") as f:
            header, _ = crypto.parse(f.read())
        return {"keyfile": bool(header["kdf"].get("keyfile")), "recovery": "recovery" in header["slots"],
                "kdf": f"scrypt N=2^{header['kdf']['log_n']}"}

    def close(self) -> None:
        if self._dek is None:
            return
        if self._dirty:
            self.save()                 # on failure the exception propagates and the vault stays open: nothing is lost
        self.db.close()
        self._dek = None
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
            return db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        finally:
            db.close()

    # ------------------------------------------------------------------ keys
    def change_password(self, new_password: str, keyfile: bytes | None = None, kdf: str = crypto.DEFAULT_KDF) -> None:
        self._header = crypto.rewrap_password(self._header, self._dek, new_password, keyfile, kdf)
        self._dirty = True
        self.save()

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
    def uses_keyfile(self) -> bool:
        return bool(self._header["kdf"].get("keyfile"))

    @property
    def vault_id(self) -> str:
        return self.db.execute("SELECT value FROM meta WHERE key='vault_id'").fetchone()[0]

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

    # ------------------------------------------------------------------ items
    def _write_item(self, it: Item, insert: bool) -> None:
        vals = (it.type, it.name.strip() or "(no name)", it.folder_id, it.username, it.password, json.dumps(it.uris),
                it.description, it.totp, json.dumps(it.fields), json.dumps(it.extra), int(it.favorite),
                it.modified, it.pw_changed, it.expires, it.deleted, it.last_used)
        if insert:
            self.db.execute("INSERT INTO items(type,name,folder_id,username,password,uris,description,totp,fields,extra,"
                            "favorite,modified,pw_changed,expires,deleted,last_used,id,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            vals + (it.id, it.created))
        else:
            self.db.execute("UPDATE items SET type=?,name=?,folder_id=?,username=?,password=?,uris=?,description=?,totp=?,"
                            "fields=?,extra=?,favorite=?,modified=?,pw_changed=?,expires=?,deleted=?,last_used=? WHERE id=?",
                            vals + (it.id,))
        self.db.execute("DELETE FROM tags WHERE item_id=?", (it.id,))
        self.db.executemany("INSERT OR IGNORE INTO tags VALUES(?,?)",
                            [(it.id, t.strip()) for t in it.tags if t.strip()])

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
            self.db.execute("INSERT INTO history(item_id,ts,snapshot) VALUES(?,?,?)",
                            (it.id, old.modified, json.dumps(old.secrets_snapshot())))
            self.db.execute("DELETE FROM history WHERE item_id=? AND id NOT IN "
                            "(SELECT id FROM history WHERE item_id=? ORDER BY id DESC LIMIT 25)", (it.id, it.id))
        if old.password != it.password:
            it.pw_changed = it.modified
        self._write_item(it, False)
        self._changed()

    def get_item(self, iid: str) -> Item | None:
        r = self.db.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()
        return _row_to_item(r, self._tags(iid)) if r else None

    def _tags(self, iid: str) -> list[str]:
        return [x[0] for x in self.db.execute("SELECT tag FROM tags WHERE item_id=?", (iid,))]

    def items(self, trash: bool = False) -> list[Item]:
        tagmap: dict[str, list[str]] = {}
        for iid, tag in self.db.execute("SELECT item_id, tag FROM tags"):
            tagmap.setdefault(iid, []).append(tag)
        q = "SELECT * FROM items WHERE deleted IS NOT NULL" if trash else "SELECT * FROM items WHERE deleted IS NULL"
        return [_row_to_item(r, tagmap.get(r["id"], [])) for r in self.db.execute(q + " ORDER BY name COLLATE NOCASE")]

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
        return [{"id": r["id"], "ts": r["ts"], "data": json.loads(r["snapshot"])}
                for r in self.db.execute("SELECT * FROM history WHERE item_id=? ORDER BY id DESC", (iid,))]

    def all_tags(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT DISTINCT tag FROM tags ORDER BY tag COLLATE NOCASE")]

    def has_duplicate(self, it: Item) -> bool:
        return any(x.type == it.type and x.name == it.name and x.username == it.username and x.password == it.password
                   and x.uris == it.uris for x in self.items())

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

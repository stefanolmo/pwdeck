"""Container format of the vault file (`.pwdeck`) and key management.

File layout (all integers big-endian)::

    8 bytes   magic  b"PWDECK\\x00\\x01"
    4 bytes   N = length of the JSON header
    N bytes   JSON header (UTF-8): KDF parameters, key slots, payload nonce
    rest      AES-256-GCM(DEK, payload_nonce, <serialized SQLite database>, aad=magic)

* The database is a normal SQLite file, but it only ever exists in memory (`sqlite3.Connection.serialize`) or encrypted.
* DEK = random 256-bit data key. It is stored *wrapped* (AES-GCM) in one or more key slots:
    - ``password``: KEK = scrypt(NFKC(master password) [+ keyfile], salt)
    - ``recovery``: KEK = HKDF-SHA256(recovery key), the recovery key is a random 160-bit code shown once at creation
  so changing the master password only rewrites the header and the vault can be opened with either slot.
* A keyfile (optional) is mixed into the password: ``HMAC-SHA256(key=SHA256(keyfile), msg=password)``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"PWDECK\x00\x01"
KDF_PRESETS = {                       # name: (log2 N, r, p)  scrypt memory = 128 * N * r bytes
    "standard": (17, 8, 1),           # 128 MiB, ~0.3-0.6 s
    "high": (18, 8, 1),               # 256 MiB, ~1 s
    "fast": (14, 8, 1),               # 16 MiB — tests / very slow machines only
}
DEFAULT_KDF = "standard"
_MAX_LOG_N = 22


class VaultError(Exception):
    pass


class NotAVaultError(VaultError):
    pass


class WrongPasswordError(VaultError):
    pass


class CorruptVaultError(VaultError):
    pass


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def normalize_password(password: str) -> bytes:
    """NFKC so that the same password typed on another OS / keyboard layout produces the same bytes."""
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def keyfile_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _kek_from_password(password: str, kdf: dict, keyfile: bytes | None) -> bytes:
    pw = normalize_password(password)
    if kdf.get("keyfile"):
        if keyfile is None:
            raise WrongPasswordError("this vault requires a keyfile")
        pw = hmac.new(keyfile_digest(keyfile), pw, hashlib.sha256).digest()
    elif keyfile is not None:
        raise WrongPasswordError("this vault does not use a keyfile")
    log_n, r, p = kdf["log_n"], kdf["r"], kdf["p"]
    if not (10 <= log_n <= _MAX_LOG_N and 1 <= r <= 32 and 1 <= p <= 16):
        raise CorruptVaultError("implausible KDF parameters")
    n = 1 << log_n
    return hashlib.scrypt(pw, salt=b64d(kdf["salt"]), n=n, r=r, p=p, maxmem=128 * n * r * 2 + (8 << 20), dklen=32)


def new_recovery_key() -> str:
    """160 random bits as 8 groups of 4 base32 characters: ABCD-EFGH-…"""
    raw = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    return "-".join(raw[i:i + 4] for i in range(0, 32, 4))


def _kek_from_recovery(recovery_key: str) -> bytes:
    clean = "".join(ch for ch in recovery_key.upper() if ch.isalnum())
    if len(clean) != 32:
        raise WrongPasswordError("malformed recovery key")
    try:
        raw = base64.b32decode(clean)
    except Exception as e:
        raise WrongPasswordError("malformed recovery key") from e
    return HKDF(hashes.SHA256(), 32, salt=None, info=b"pwdeck-recovery-key-v1").derive(raw)


def _wrap(kek: bytes, dek: bytes, name: str) -> dict:
    nonce = secrets.token_bytes(12)
    return {"nonce": b64e(nonce), "ct": b64e(AESGCM(kek).encrypt(nonce, dek, b"pwdeck-slot-" + name.encode()))}


def _unwrap(kek: bytes, slot: dict, name: str) -> bytes:
    try:
        return AESGCM(kek).decrypt(b64d(slot["nonce"]), b64d(slot["ct"]), b"pwdeck-slot-" + name.encode())
    except InvalidTag as e:
        raise WrongPasswordError("wrong password, keyfile or recovery key") from e


def new_kdf(preset: str = DEFAULT_KDF, uses_keyfile: bool = False) -> dict:
    log_n, r, p = KDF_PRESETS[preset]
    return {"alg": "scrypt", "log_n": log_n, "r": r, "p": p, "salt": b64e(secrets.token_bytes(32)), "keyfile": uses_keyfile}


def create_keys(password: str, keyfile: bytes | None = None, preset: str = DEFAULT_KDF,
                with_recovery: bool = True) -> tuple[bytes, dict, str | None]:
    """Returns (dek, header_without_nonce, recovery_key)."""
    dek = secrets.token_bytes(32)
    kdf = new_kdf(preset, keyfile is not None)
    header = {"v": 1, "kdf": kdf, "slots": {"password": _wrap(_kek_from_password(password, kdf, keyfile), dek, "password")}}
    recovery = None
    if with_recovery:
        recovery = new_recovery_key()
        header["slots"]["recovery"] = _wrap(_kek_from_recovery(recovery), dek, "recovery")
    return dek, header, recovery


def unlock(header: dict, password: str | None = None, keyfile: bytes | None = None,
           recovery_key: str | None = None) -> bytes:
    """Returns the DEK or raises WrongPasswordError."""
    slots = header.get("slots", {})
    if recovery_key:
        if "recovery" not in slots:
            raise WrongPasswordError("this vault has no recovery key")
        return _unwrap(_kek_from_recovery(recovery_key), slots["recovery"], "recovery")
    if password is None:
        raise WrongPasswordError("password required")
    return _unwrap(_kek_from_password(password, header["kdf"], keyfile), slots["password"], "password")


def rewrap_password(header: dict, dek: bytes, new_password: str, keyfile: bytes | None, preset: str = DEFAULT_KDF) -> dict:
    h = json.loads(json.dumps(header))
    kdf = new_kdf(preset, keyfile is not None)
    h["kdf"] = kdf
    h["slots"]["password"] = _wrap(_kek_from_password(new_password, kdf, keyfile), dek, "password")
    return h


def new_recovery_slot(header: dict, dek: bytes) -> tuple[dict, str]:
    h = json.loads(json.dumps(header))
    key = new_recovery_key()
    h["slots"]["recovery"] = _wrap(_kek_from_recovery(key), dek, "recovery")
    return h, key


def encode(header: dict, dek: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    h = dict(header)
    h["nonce"] = b64e(nonce)
    hj = json.dumps(h, separators=(",", ":"), sort_keys=True).encode()
    return MAGIC + struct.pack(">I", len(hj)) + hj + AESGCM(dek).encrypt(nonce, plaintext, MAGIC)


def parse(blob: bytes) -> tuple[dict, bytes]:
    """Splits a vault file into (header, ciphertext) without any key."""
    if len(blob) < 12 or blob[:6] != MAGIC[:6]:
        raise NotAVaultError("not a PW Deck vault file")
    if blob[:8] != MAGIC:
        raise NotAVaultError("unsupported vault format version")
    (n,) = struct.unpack(">I", blob[8:12])
    if n > 1 << 20 or 12 + n > len(blob):
        raise CorruptVaultError("truncated or damaged header")
    try:
        header = json.loads(blob[12:12 + n])
        header["kdf"], header["slots"], header["nonce"]
    except Exception as e:
        raise CorruptVaultError("damaged header") from e
    return header, blob[12 + n:]


def decrypt_payload(header: dict, ciphertext: bytes, dek: bytes) -> bytes:
    try:
        return AESGCM(dek).decrypt(b64d(header["nonce"]), ciphertext, MAGIC)
    except InvalidTag as e:
        raise CorruptVaultError("the vault content is damaged or has been modified") from e


# ---------------------------------------------------------------------------------------------- field sealing
# Inside the SQLite image every secret value is ALSO encrypted on its own (AES-256-GCM, key = HKDF(DEK)), so the database
# that lives in memory while the vault is unlocked contains no plaintext secrets: a value is decrypted only when the user
# reveals / copies / edits it. The AAD binds each ciphertext to vault, item, column and sub-key (no swapping between rows).
FIELD_INFO = b"pwdeck-field-key-v1"
_SEALED_V1 = b"\x01"


def derive_field_key(dek: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=None, info=FIELD_INFO).derive(dek)


def seal(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return _SEALED_V1 + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, aad: bytes, blob: bytes) -> bytes:
    if len(blob) < 1 + 12 + 16 or blob[:1] != _SEALED_V1:
        raise CorruptVaultError("malformed sealed field")
    try:
        return AESGCM(key).decrypt(blob[1:13], blob[13:], aad)
    except InvalidTag as e:
        raise CorruptVaultError("a field of the vault is damaged or was tampered with") from e


def atomic_write(path: str, data: bytes) -> None:
    """Write to a temp file in the same directory, fsync, then rename over the target."""
    d = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(d, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    try:
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass

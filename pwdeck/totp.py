"""RFC 6238 TOTP (and RFC 4226 HOTP) with otpauth:// URI parsing. Standard library only."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


@dataclass
class Totp:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    issuer: str = ""
    label: str = ""

    def code(self, now: float | None = None) -> str:
        t = int((time.time() if now is None else now) // self.period)
        mac = hmac.new(self.secret, struct.pack(">Q", t), _ALGOS[self.algorithm]).digest()
        o = mac[-1] & 0x0F
        n = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** self.digits
        return str(n).zfill(self.digits)

    def remaining(self, now: float | None = None) -> float:
        now = time.time() if now is None else now
        return self.period - (now % self.period)


def _b32(s: str) -> bytes:
    s = "".join(s.split()).replace("-", "").upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s)


def parse(text: str) -> Totp:
    """Accepts an `otpauth://totp/...` URI or a bare base32 secret. Raises ValueError."""
    text = (text or "").strip()
    if not text:
        raise ValueError("empty")
    try:
        if text.lower().startswith("otpauth://"):
            u = urlparse(text)
            if u.netloc.lower() != "totp":
                raise ValueError("only TOTP is supported")
            q = {k.lower(): v[0] for k, v in parse_qs(u.query).items()}
            label = unquote(u.path.lstrip("/"))
            algo = q.get("algorithm", "SHA1").upper()
            if algo not in _ALGOS:
                raise ValueError("unsupported algorithm")
            digits, period = int(q.get("digits", 6)), int(q.get("period", 30))
            if not (4 <= digits <= 10 and 1 <= period <= 300):
                raise ValueError("bad digits/period")
            return Totp(_b32(q["secret"]), digits, period, algo, q.get("issuer", label.split(":")[0] if ":" in label else ""), label)
        return Totp(_b32(text))
    except (KeyError, base64.binascii.Error) as e:
        raise ValueError("invalid TOTP secret") from e

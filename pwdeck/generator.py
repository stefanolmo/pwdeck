"""Password generator (CSPRNG) and a heuristic strength estimator."""
from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import dataclass

AMBIGUOUS = set("Il1O0o|`'\"")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?~"
_COMMON = {"password", "123456", "12345678", "123456789", "qwerty", "abc123", "letmein", "welcome", "admin", "iloveyou",
           "monkey", "dragon", "master", "login", "passw0rd", "p@ssw0rd", "football", "baseball", "sunshine", "princess",
           "000000", "111111", "1234", "12345", "1q2w3e", "qwertyuiop", "password1", "changeme", "secret", "root", "test"}
_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


@dataclass
class GenOptions:
    length: int = 20
    lower: bool = True
    upper: bool = True
    digits: bool = True
    symbols: bool = True
    avoid_ambiguous: bool = False
    custom_symbols: str = SYMBOLS


def _pools(o: GenOptions) -> list[str]:
    pools = []
    for on, chars in ((o.lower, string.ascii_lowercase), (o.upper, string.ascii_uppercase),
                      (o.digits, string.digits), (o.symbols, o.custom_symbols)):
        if on:
            c = "".join(ch for ch in chars if not (o.avoid_ambiguous and ch in AMBIGUOUS))
            if c:
                pools.append(c)
    return pools


def generate(o: GenOptions | None = None) -> str:
    """At least one character from every enabled class, uniformly shuffled."""
    o = o or GenOptions()
    pools = _pools(o)
    if not pools:
        raise ValueError("enable at least one character class")
    if not 4 <= o.length <= 256 or o.length < len(pools):
        raise ValueError("length must be between 4 and 256")
    allc = "".join(pools)
    chars = [secrets.choice(p) for p in pools] + [secrets.choice(allc) for _ in range(o.length - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def estimate(password: str) -> tuple[float, int]:
    """(bits, score 0..4). A *heuristic*: charset-size entropy with penalties for repeats, runs, keyboard
    rows, dictionary words and low variety. It is an upper bound; for random generator output it is exact."""
    if not password:
        return 0.0, 0
    pw = password
    low = pw.lower()
    if low in _COMMON:
        return 5.0, 0
    pool = 0
    for pat, size in ((r"[a-z]", 26), (r"[A-Z]", 26), (r"[0-9]", 10), (r"[^a-zA-Z0-9]", 33)):
        if re.search(pat, pw):
            pool += size
    bits = len(pw) * math.log2(max(pool, 2))
    # low variety: few distinct characters
    distinct = len(set(pw))
    bits -= (len(pw) - distinct) * math.log2(max(pool, 2)) * 0.6
    # sequential / keyboard runs of >= 3
    runs = 0
    for i in range(len(low) - 2):
        a, b, c = low[i:i + 3]
        if ord(b) - ord(a) == ord(c) - ord(b) and abs(ord(b) - ord(a)) == 1:
            runs += 1
        elif any(a + b + c in row or (a + b + c)[::-1] in row for row in _ROWS):
            runs += 1
    bits -= runs * 5
    for w in _COMMON:
        if len(w) >= 5 and w in low:
            bits -= len(w) * 2.5
    if pw.isdigit():
        bits *= 0.8
    bits = max(bits, 0.0)
    score = 0 if bits < 28 else 1 if bits < 45 else 2 if bits < 65 else 3 if bits < 90 else 4
    return bits, score


LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"]

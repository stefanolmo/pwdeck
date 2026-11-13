"""Security audit: weak / reused / old / expired passwords, optional Have I Been Pwned check (k-anonymity)."""
from __future__ import annotations

import hashlib
import time
import urllib.request
from collections import defaultdict

from .generator import estimate
from .vault import Item

DAY = 86400.0


def analyze(items: list[Item], max_age_days: int = 365, weak_bits: float = 45.0, now: float | None = None) -> dict[str, list[tuple[Item, str]]]:
    now = now or time.time()
    out: dict[str, list[tuple[Item, str]]] = {"weak": [], "reused": [], "old": [], "expired": [], "no2fa": []}
    by_pw = defaultdict(list)
    for it in items:
        if it.password:
            by_pw[it.password].append(it)
            bits, _ = estimate(it.password)
            if bits < weak_bits:
                out["weak"].append((it, f"{int(bits)} bit"))
            if it.pw_changed and (now - it.pw_changed) / DAY > max_age_days:
                out["old"].append((it, f"{int((now - it.pw_changed) / DAY)} days old"))
        if it.expires and it.expires < now:
            out["expired"].append((it, time.strftime("expired %Y-%m-%d", time.localtime(it.expires))))
        if it.type == "password" and it.uris and not it.totp:
            out["no2fa"].append((it, "no TOTP stored"))
    for pw, group in by_pw.items():
        if len(group) > 1:
            for it in group:
                out["reused"].append((it, f"same as {len(group) - 1} other"))
    return out


def score(items: list[Item], report: dict) -> int:
    """0..100, only counts problems of the first four categories."""
    n = sum(1 for i in items if i.password)
    if not n:
        return 100
    bad = {i.id for k in ("weak", "reused", "old", "expired") for i, _ in report[k]}
    return round(100 * (1 - len(bad) / n))


def hibp_count(password: str, timeout: float = 8.0) -> int:
    """How many times the password appears in known breaches. Only the first 5 hex chars of the SHA-1 leave
    this machine (k-anonymity range API). Raises OSError on network problems."""
    h = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    req = urllib.request.Request("https://api.pwnedpasswords.com/range/" + h[:5], headers={"User-Agent": "pwdeck", "Add-Padding": "true"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode()
    for line in body.splitlines():
        suffix, _, n = line.partition(":")
        if suffix == h[5:]:
            return int(n)
    return 0

"""Reads another process's memory (we are its parent, same uid) and counts occurrences of byte patterns (ASCII and UTF-16LE,
because Qt keeps text as UTF-16)."""
import os
import re


def count(pid: int, patterns: dict[str, str]) -> dict[str, int]:
    pats = {}
    for name, text in patterns.items():
        pats[name] = [text.encode("ascii"), text.encode("utf-16-le")]
    out = {n: 0 for n in patterns}
    with open(f"/proc/{pid}/maps") as m, open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for line in m:
            mt = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
            lo, hi, perms = int(mt[1], 16), int(mt[2], 16), mt[3]
            if not perms.startswith("rw") or hi - lo > 1 << 31:
                continue
            try:
                mem.seek(lo)
                data = mem.read(hi - lo)
            except (OSError, ValueError, OverflowError):
                continue
            for n, ps in pats.items():
                out[n] += sum(data.count(p) for p in ps)
    return out

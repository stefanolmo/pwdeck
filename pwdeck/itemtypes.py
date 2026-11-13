"""Item types and their fields (the Passbolt "resource types", plus a few more). Drives the editor and the detail view."""
from __future__ import annotations

from dataclasses import dataclass

# kinds: line, secret (hidden by default), multi (multi-line text), secretmulti, uris, totp
@dataclass(frozen=True)
class Field:
    key: str
    label: str
    kind: str = "line"


COLUMN_KEYS = {"username", "password", "uris", "description", "totp"}     # stored in real columns, the rest in `extra`

TYPES: dict[str, tuple[str, list[Field]]] = {
    "password": ("Password", [Field("username", "Username"), Field("password", "Password", "secret"),
                              Field("uris", "URL", "uris"), Field("totp", "TOTP", "totp"),
                              Field("description", "Description", "multi")]),
    "totp": ("TOTP", [Field("username", "Account"), Field("uris", "URL", "uris"), Field("totp", "TOTP", "totp"),
                      Field("description", "Description", "multi")]),
    "note": ("Secure note", [Field("description", "Note", "secretmulti")]),
    "card": ("Card", [Field("holder", "Card holder"), Field("number", "Number", "secret"), Field("expiry", "Expiry (MM/YY)"),
                      Field("cvv", "CVV", "secret"), Field("pin", "PIN", "secret"), Field("description", "Notes", "multi")]),
    "ssh": ("SSH key", [Field("username", "User"), Field("uris", "Host", "uris"),
                        Field("private_key", "Private key", "secretmulti"), Field("public_key", "Public key", "multi"),
                        Field("passphrase", "Passphrase", "secret"), Field("description", "Notes", "multi")]),
    "custom": ("Custom", [Field("description", "Description", "multi")]),
}
TYPE_ORDER = list(TYPES)


def type_label(t: str) -> str:
    return TYPES.get(t, (t, []))[0]


def type_fields(t: str) -> list[Field]:
    return TYPES.get(t, ("", []))[1]

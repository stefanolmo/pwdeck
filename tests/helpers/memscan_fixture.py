"""Builds the vault used by the memory-scan tests, with recognisable markers. Env PWDECK_ROOT selects which code creates it."""
import base64
import os
import sys

TOTP = {0: base64.b32encode(b"MARKTOTP-0-marker!").decode().rstrip("="), 1: base64.b32encode(b"MARKTOTP-1-marker!").decode().rstrip("=")}
# (marker name) -> (text, kind)   kind: "secret" = only decrypted on user action, "display" = low-sensitivity, shown when the item is selected
MARKERS = {
    "A0.password": ("PWM-pass-0-aaaaaaaa", "secret"), "A0.totp": (TOTP[0], "secret"), "A0.hidden_field": ("PWM-cf-0-cccccccc", "secret"),
    "A0.description": ("PWM-desc-0-bbbbbbbb", "secret"), "A0.plain_field": ("PWM-plainfield-0-dddd", "display"),
    "A1.password": ("PWM-pass-1-eeeeeeee", "secret"), "A1.totp": (TOTP[1], "secret"), "A1.description": ("PWM-desc-1-ffffffff", "secret"),
    "A2.number": ("PWM-card-2-4111xxxx", "secret"), "A2.cvv": ("PWM-cvv-2-999", "secret"), "A2.holder": ("PWM-holder-2-gggg", "display"),
    "A3.private_key": ("PWM-ssh-3-privatekey", "secret"), "A3.passphrase": ("PWM-ssh-3-passphrase", "secret"),
}
M = {k: v[0] for k, v in MARKERS.items()}


def build(path, pw):
    sys.path.insert(0, os.environ["PWDECK_ROOT"])
    from pwdeck.vault import Item, Vault
    v, _ = Vault.create(path, pw, kdf="fast")
    v.add_item(Item(name="A0", username="u0", password=M["A0.password"], totp=M["A0.totp"], description=M["A0.description"], uris=["https://a0.example"],
                    fields=[{"label": "secret", "value": M["A0.hidden_field"], "hidden": True}, {"label": "plain", "value": M["A0.plain_field"], "hidden": False}]))
    v.add_item(Item(name="A1", username="u1", password=M["A1.password"], totp=M["A1.totp"], description=M["A1.description"]))
    v.add_item(Item(name="A2", type="card", extra={"number": M["A2.number"], "cvv": M["A2.cvv"], "holder": M["A2.holder"]}))
    v.add_item(Item(name="A3", type="ssh", username="ops", extra={"private_key": M["A3.private_key"], "passphrase": M["A3.passphrase"]}))
    v.close()


if __name__ == "__main__":
    build(sys.argv[1], sys.argv[2])

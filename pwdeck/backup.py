"""Emergency bundle: vault + standalone recovery script + instructions in one zip."""
from __future__ import annotations

import os
import time
import zipfile

from .vault import Vault

README = """PW DECK - EMERGENCY KIT
=======================
Created: {when}

Contents
  {vault}       your vault: an AES-256-GCM encrypted container holding an SQLite database
  pwdeck_recover.py  standalone tool, needs only Python 3.11+ and `pip install cryptography`

This kit contains NO password. To open the vault you need the master password (and the keyfile, if you
use one) or the recovery key you saved when you created the vault. Without them nobody can open it - not even us.

Option A - on a machine with PW Deck installed
  Copy {vault} anywhere, start PW Deck, "Open vault..." and enter the master password.

Option B - without PW Deck (command line)
  python3 pwdeck_recover.py info    {vault}
  python3 pwdeck_recover.py decrypt {vault} -o vault.sqlite     (add --recovery to use the recovery key, --keyfile FILE for a keyfile)
  python3 pwdeck_recover.py csv     {vault} -o vault.csv
  The outputs are NOT encrypted. Delete them when done.
"""


def make_bundle(vault: Vault, dest_zip: str) -> str:
    """Verified copy of the vault + recovery script + README, as a zip."""
    tmp = dest_zip + ".part.pwdeck"
    try:
        vault.copy_to(tmp)
        name = os.path.basename(vault.path)
        with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(tmp, name)
            z.write(os.path.join(os.path.dirname(__file__), "recover.py"), "pwdeck_recover.py")
            z.writestr("README.txt", README.format(vault=name, when=time.strftime("%Y-%m-%d %H:%M")))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return dest_zip

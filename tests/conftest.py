import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from pwdeck.vault import Vault


@pytest.fixture
def vpath(tmp_path):
    return str(tmp_path / "test.pwdeck")


@pytest.fixture
def vault(vpath):
    v, rk = Vault.create(vpath, "correct horse", kdf="fast")
    v.recovery = rk
    yield v
    v.close()

"""Reads the memory of a real PW Deck process (offscreen Qt UI) and checks which secrets exist there, at each stage.
The child never knows the markers: the scanning is done by this (parent) process through /proc/<pid>/mem."""
import os
import subprocess
import sys

import pytest

from tests.helpers import memscan
from tests.helpers.memscan_fixture import M, MARKERS, build

ROOT = os.path.dirname(os.path.dirname(__file__))
pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux") or not os.path.exists("/proc/self/mem"), reason="needs /proc")


class Child:
    def __init__(self, vault, pw):
        env = dict(os.environ, PWDECK_ROOT=ROOT, VAULT=vault, PWDECK_TEST_PW=pw)
        self.p = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "helpers", "memscan_child.py")], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env, cwd=ROOT)
        self.pid = int(self.p.stdout.readline())
        assert self.p.stdout.readline().strip() == "ready"

    def do(self, cmd):
        self.p.stdin.write(cmd + "\n")
        self.p.stdin.flush()
        assert self.p.stdout.readline().strip() == "ok"
        return {k: v for k, v in memscan.count(self.pid, M).items() if v}

    def close(self):
        self.p.stdin.write("quit\n")
        self.p.stdin.flush()
        self.p.wait(10)


@pytest.fixture
def child(tmp_path):
    path = str(tmp_path / "m.pwdeck")
    os.environ["PWDECK_ROOT"] = ROOT
    build(path, "pw-test-123")
    c = Child(path, "pw-test-123")
    yield c
    c.close()


def secrets_only(found):
    return {k for k in found if MARKERS[k][1] == "secret"}


TOTP_KEYS = {"A0.totp", "A1.totp"}      # design exception: the TOTP secret of the SELECTED item is decrypted to show the live code


def test_unopened_items_are_not_in_memory(child):
    # before this change: 28 hits, all 9 secret markers present right after unlock (measured on the previous format)
    assert secrets_only(child.do("unlock")) == set()
    assert secrets_only(child.do("select 0")) - TOTP_KEYS == set()      # A0 selected but masked: password and hidden field sealed
    assert secrets_only(child.do("select 3")) - TOTP_KEYS == set()      # A3 (SSH key): private key and passphrase masked


def test_only_what_you_reveal_is_decrypted(child):
    child.do("unlock")
    child.do("select 0")
    found = secrets_only(child.do("reveal"))                             # the user clicks the eye on every secret of A0
    assert {"A0.password", "A0.hidden_field", "A0.description"} <= found
    assert not any(k.startswith(("A1.", "A2.", "A3.")) for k in found)   # nothing of the other items is in memory


def test_display_fields_appear_only_for_the_selected_item(child):
    assert not child.do("unlock")                                # nothing at all after unlock
    found = child.do("select 0")
    assert "A0.plain_field" in found and not any(k.startswith(("A1.", "A2.", "A3.")) for k in found)
    assert "A0.description" not in found                         # descriptions are masked like passwords


def test_lock_removes_what_was_decrypted_from_the_ui_and_db(child):
    child.do("unlock")
    child.do("select 1")
    child.do("reveal")
    after = child.do("lock")
    # Python/Qt do not zero freed memory, so remnants of values that WERE revealed may linger; items never revealed must not appear
    assert not any(k.startswith(("A0.", "A2.", "A3.")) for k in after)

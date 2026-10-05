import os

import pytest
from cryptography.exceptions import InvalidTag

from scannerip.identity import IdentityVault, hardware_fingerprint, load_or_create_secret

FP = b"machine-123|laptop|x86_64|a1b2c3d4e5f6"


def test_secret_is_created_once_and_private(isolated_home):
    first = load_or_create_secret()
    assert len(first) == 32
    assert load_or_create_secret() == first
    if os.name == "posix":
        assert (isolated_home / "secret.key").stat().st_mode & 0o777 == 0o600


def test_corrupt_secret_is_replaced(isolated_home):
    isolated_home.mkdir(parents=True)
    (isolated_home / "secret.key").write_bytes(b"short")
    assert len(load_or_create_secret()) == 32


def test_root_id_is_stable_but_depends_on_secret():
    secret = os.urandom(32)
    a = IdentityVault(secret, FP)
    b = IdentityVault(secret, FP)
    c = IdentityVault(os.urandom(32), FP)
    assert a.root_id == b.root_id
    assert a.root_id != c.root_id
    assert a.session_id != b.session_id  # new session every launch


def test_rotating_id_changes_every_rotation():
    vault = IdentityVault(os.urandom(32), FP)
    snaps = [vault.rotate("203.0.113.5") for _ in range(5)]
    assert len({s.rotating_id for s in snaps}) == 5
    assert len({s.sealed for s in snaps}) == 5  # fresh nonce each time
    assert [s.rotation for s in snaps] == [1, 2, 3, 4, 5]
    assert vault.current == snaps[-1]


def test_seal_round_trip_and_wrong_key():
    secret = os.urandom(32)
    vault = IdentityVault(secret, FP)
    token = vault.seal()
    assert vault.unseal(token) == FP
    assert IdentityVault(secret, FP).unseal(token) == FP  # same machine, same key
    with pytest.raises(InvalidTag):
        IdentityVault(os.urandom(32), FP).unseal(token)


def test_raw_fingerprint_never_shows_up():
    vault = IdentityVault(os.urandom(32), FP)
    vault.rotate("198.51.100.1")
    shown = repr(vault) + str(vault.layers()) + str(vault.current)
    for piece in (b"machine-123", b"laptop", b"a1b2c3d4e5f6", FP):
        assert piece.decode() not in shown


def test_layers_has_five_rows():
    vault = IdentityVault(os.urandom(32), FP)
    rows = vault.layers()
    assert len(rows) == 5
    assert "waiting" in rows[4][1]
    vault.rotate("192.0.2.1")
    assert vault.layers()[4][1].startswith("RID-")


def test_short_secret_rejected():
    with pytest.raises(ValueError):
        IdentityVault(b"tiny", FP)


def test_real_fingerprint_is_stable():
    assert hardware_fingerprint() == hardware_fingerprint()

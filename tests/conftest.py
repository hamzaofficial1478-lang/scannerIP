import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Keep keys and scan logs out of the real home folder during tests."""
    home = tmp_path / "scannerip-home"
    monkeypatch.setenv("SCANNERIP_HOME", str(home))
    return home

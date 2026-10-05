import json

from scannerip.cli import main
from scannerip.samples import write_samples


def test_scan_command_reports_and_logs(tmp_path, capsys, isolated_home):
    paths = write_samples(tmp_path)
    picked = [str(p) for p in paths if p.name.startswith(("01_", "07_"))]
    assert main(["scan", *picked]) == 0
    out = capsys.readouterr().out
    assert "CLEAN" in out and "DANGEROUS" in out and "Logged as RID-" in out
    lines = (isolated_home / "scan_log.jsonl").read_text().splitlines()
    entries = [json.loads(line) for line in lines]
    assert [e["level"] for e in entries] == ["CLEAN", "DANGEROUS"]
    assert all(e["rotating_id"].startswith("RID-") for e in entries)


def test_scan_no_log_and_no_codes(tmp_path, capsys, isolated_home):
    from PIL import Image
    blank = tmp_path / "blank.png"
    Image.new("RGB", (50, 50), "white").save(blank)
    assert main(["scan", "--no-log", str(blank)]) == 1
    assert not (isolated_home / "scan_log.jsonl").exists()


def test_identity_command(capsys):
    assert main(["identity"]) == 0
    out = capsys.readouterr().out
    assert "Layer 0" in out and "ROOT-" in out and "SID-" in out and "RID-" in out


def test_shield_simulated(capsys):
    assert main(["shield", "--mode", "simulate", "--interval", "2", "--count", "1"]) == 0
    out = capsys.readouterr().out
    assert "SIMULATED MODE" in out and "RID-" in out


def test_inspect_refuses_simulated(capsys):
    assert main(["inspect", "https://example.com", "--mode", "simulate"]) == 2
    assert "real IP" in capsys.readouterr().err


def test_proxy_mode_needs_a_file(capsys):
    assert main(["shield", "--mode", "proxy"]) == 2
    assert "--proxies" in capsys.readouterr().err


def test_samples_command(tmp_path, capsys):
    assert main(["samples", str(tmp_path / "out")]) == 0
    assert len(list((tmp_path / "out").glob("*.png"))) >= 20

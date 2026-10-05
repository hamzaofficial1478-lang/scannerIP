"""Smoke test for the desktop app. Skipped when there's no display."""

import gc
import os
import threading
import time
import weakref

import pytest

tk = pytest.importorskip("tkinter")


@pytest.fixture
def app(tmp_path):
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    from scannerip.gui import App
    from scannerip.identity import IdentityVault
    from scannerip.rotator import SimulatedRotator
    from scannerip.scanlog import ScanLog

    application = App(root, SimulatedRotator(seed=7), interval=2,
                      vault=IdentityVault(os.urandom(32), b"gui-test"),
                      log=ScanLog(tmp_path / "log.jsonl"))
    yield application
    application.close()
    del application, root
    gc.collect()  # tear Tk down here, on the main thread


def pump(app, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.root.update()
        time.sleep(0.02)


def test_shield_updates_the_window(app):
    pump(app, 0.5)
    assert app.vault.rotation >= 1
    assert app.ip_label.cget("text") == app.shield.current.exit.ip
    assert len(app.shift_tree.get_children()) >= 1
    assert app.layer_values[4].cget("text").startswith("RID-")
    assert app.inspect_btn.instate(["disabled"])


def test_scanning_an_image_shows_the_report(app, tmp_path):
    from scannerip.samples import write_samples

    pump(app, 0.3)
    paths = {p.name: p for p in write_samples(tmp_path / "s")}
    codes = app.scan_file(str(paths["07_fake_app_download.png"]))
    pump(app, 0.1)
    assert len(codes) == 1
    assert "DANGEROUS" in app.badge.cget("text")
    assert "apk" in app.findings.get("1.0", "end")
    assert len(app.scan_tree.get_children()) == 1
    # simulated shield can't hide the real IP, so inspection stays off
    assert app.inspect_btn.instate(["disabled"])

    app.scan_file(str(paths["17_hidden_rtl_trick.png"]))
    assert "<U+202E>" in app.content.get("1.0", "end")


def test_close_is_clean(app):
    pump(app, 0.2)
    app.close()
    assert app.closed and not app.shield.running


def test_window_is_freed_on_the_main_thread(tmp_path):
    """Regression: if the window survives in a reference cycle, a later garbage
    collection on a background thread tears Tk down there and the whole
    program aborts with "Tcl_AsyncDelete: async handler deleted by the wrong
    thread". So closing must leave nothing but plain references behind."""
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    from scannerip.gui import App
    from scannerip.identity import IdentityVault
    from scannerip.rotator import SimulatedRotator
    from scannerip.samples import write_samples
    from scannerip.scanlog import ScanLog

    gc.collect()
    gc.disable()
    try:
        app = App(root, SimulatedRotator(), vault=IdentityVault(os.urandom(32), b"gui-test"),
                  log=ScanLog(tmp_path / "log.jsonl"))
        app.scan_file(str(write_samples(tmp_path / "s")[0]))
        app.shift_now()
        pump(app, 0.4)
        app.close()
        app_ref, root_ref = weakref.ref(app), weakref.ref(root)
        del app, root
        assert app_ref() is None and root_ref() is None, "window is stuck in a reference cycle"
        collector = threading.Thread(target=gc.collect)
        collector.start()
        collector.join()
    finally:
        gc.enable()

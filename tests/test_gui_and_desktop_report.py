"""Tests for granular percentage progress, detailed Desktop TXT report with end summary,
and classic PySide6 GUI ('Tara' button + bottom progress bar).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ss_core import engine8_reporter, orchestrator, utils
from ss_core.models import ScanContext
from tests.sim_lab import build_clean_baseline, make_jar


class TestGuiProgressAndDesktopTxtReport(unittest.TestCase):
    def test_monotonic_percentage_progress_full_and_filtered(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)

            # Test full run
            pcts: list[int] = []
            msgs: list[str] = []

            def _cb(pct: int, msg: str) -> None:
                pcts.append(pct)
                msgs.append(msg)

            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
            )
            orchestrator.run_all_engines(ctx, progress_pct_cb=_cb)
            self.assertTrue(pcts, "Expected progress callbacks")
            self.assertEqual(0, pcts[0])
            self.assertEqual(100, pcts[-1])
            self.assertEqual(pcts, sorted(pcts), f"Progress must be monotonic: {pcts}")
            self.assertGreater(len(set(pcts)), 6)

            # Test subset engines scaling cleanly to 100
            sub_pcts: list[int] = []
            ctx2 = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
            )
            orchestrator.run_all_engines(
                ctx2,
                selected_engines={"E1", "E5"},
                progress_pct_cb=lambda p, _m: sub_pcts.append(p),
            )
            self.assertEqual(0, sub_pcts[0])
            self.assertEqual(100, sub_pcts[-1])
            self.assertEqual(sub_pcts, sorted(sub_pcts))

    def test_detailed_desktop_txt_report_and_bottom_summary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            desktop = home / "Desktop"
            desktop.mkdir(parents=True, exist_ok=True)

            # Drop a clear cheat artifact so section 2 & 3 & bottom summary populate
            make_jar(
                home / ".minecraft/mods/wurst-client.jar",
                {
                    "fabric.mod.json": b'{"id":"wurst","name":"Wurst"}',
                    "net/wurstclient/KillAura.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x41\x00\x01",
                },
            )

            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
            )
            orchestrator.run_all_engines(ctx)
            txt_path, payload = engine8_reporter.write_desktop_txt_report(ctx, desktop_dir=desktop)

            self.assertTrue(txt_path.exists())
            self.assertEqual(desktop, txt_path.parent)
            self.assertTrue(txt_path.name.startswith("MC_SS_Raporu_"))
            self.assertTrue(txt_path.name.endswith(".txt"))

            txt = txt_path.read_text(encoding="utf-8")
            idx_sec1 = txt.find("1. ONCELIKLI BULGULAR OZETI (HILE / SUPHELI TESPITLER)")
            idx_sec2 = txt.find("2. DETAYLI ADLI BULGULAR VE KANITLAR (ONEM SIRASINA GORE)")
            idx_sec2a = txt.find("2A. KRITIK VE YUKSEK RISKLI BULGULAR")
            idx_sec3 = txt.find("3. SISTEM, RING-0 CEKIRDEK, DONANIM VE OYUN ORTAMI OZETI")
            idx_sec4 = txt.find("4. TARANAN BOLGELER VE MOTOR KAPSAMI")
            idx_end_sum = txt.find("KISA SONUC OZETI (TARAMA OZETI)")

            self.assertGreater(idx_sec1, 0)
            self.assertGreater(idx_sec2, idx_sec1)
            self.assertGreater(idx_sec2a, idx_sec2)
            self.assertGreater(idx_sec3, idx_sec2a)
            self.assertGreater(idx_sec4, idx_sec3)
            self.assertGreater(idx_end_sum, idx_sec4, "Concise summary must appear at the very end")

            self.assertIn("wurst-client.jar", txt)
            self.assertIn(str(txt_path), txt)
            self.assertIn(payload["report_sha256"], txt)

    def test_resolve_desktop_and_self_bin_exemption(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            tr_desk = home / "Masaüstü"
            tr_desk.mkdir()
            self.assertEqual(tr_desk, utils.resolve_desktop_dir(home))

            fake_bin = home / "MC-SS-Sentinel"
            fake_bin.write_text("elf", encoding="utf-8")
            prev = os.environ.get("SS_SENTINEL_SELF_BIN")
            os.environ["SS_SENTINEL_SELF_BIN"] = str(fake_bin)
            try:
                self.assertTrue(utils.is_self_tool_path(fake_bin))
            finally:
                if prev is None:
                    os.environ.pop("SS_SENTINEL_SELF_BIN", None)
                else:
                    os.environ["SS_SENTINEL_SELF_BIN"] = prev

    def test_consent_dialog_requires_scroll_to_bottom_and_black_theme(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
        import ss_gui

        app = QApplication.instance() or QApplication([])
        dlg = ss_gui.ConsentDialog()
        dlg.show()
        app.processEvents()

        self.assertFalse(dlg.windowIcon().isNull(), "App icon must load for ConsentDialog")
        self.assertIn("#000000", dlg.styleSheet())
        sb = dlg.contract_view.verticalScrollBar()
        self.assertGreater(sb.maximum(), 0, "Contract text should overflow and require scrolling")
        self.assertFalse(dlg.ok_button.isEnabled(), "Tamam button must be disabled before scrolling to bottom")

        # Partial scroll should NOT unlock Tamam
        sb.setValue(max(1, sb.maximum() // 2))
        app.processEvents()
        self.assertFalse(dlg.ok_button.isEnabled(), "Partial scroll must not enable Tamam")

        # Scroll all the way to bottom -> enables Tamam
        sb.setValue(sb.maximum())
        app.processEvents()
        self.assertTrue(dlg.ok_button.isEnabled(), "Scrolling to bottom must enable Tamam")
        dlg.close()

    def test_classic_gui_offscreen_scan_writes_desktop_txt(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtCore import QEventLoop, QTimer
        from PySide6.QtWidgets import QApplication
        import ss_gui

        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, _root, _proc = build_clean_baseline(base)
            desktop = home / "Desktop"
            desktop.mkdir(parents=True, exist_ok=True)

            win = ss_gui.SentinelMainWindow(home_dir=home, desktop_dir=desktop)
            self.assertFalse(win.windowIcon().isNull(), "App icon must load for SentinelMainWindow")
            self.assertIn("#000000", win.styleSheet())
            self.assertEqual("Tara", win.scan_button.text())
            self.assertEqual(0, win.progress_bar.value())
            self.assertTrue(win.dev_label.openExternalLinks())
            self.assertIn("CmdSuv", win.dev_label.text())
            self.assertIn("https://github.com/CmdSuv", win.dev_label.text())

            loop = QEventLoop()
            finished_ok: list[bool] = []

            def _after_start() -> None:
                assert win._worker is not None
                win._worker.scan_completed.connect(lambda _p, _pl: (finished_ok.append(True), loop.quit()))
                win._worker.scan_failed.connect(lambda _e: (finished_ok.append(False), loop.quit()))

            QTimer.singleShot(120000, loop.quit)
            try:
                win.scan_button.click()
                _after_start()
                loop.exec()
                app.processEvents()
            finally:
                if win._worker is not None and win._worker.isRunning():
                    win._worker.wait(10000)
                win.close()

            self.assertEqual([True], finished_ok, f"Status was: {win.status_label.text()}")
            self.assertEqual(100, win.progress_bar.value())
            self.assertTrue(win.scan_button.isEnabled())
            status_txt = win.status_label.text()
            self.assertIn("Tarama tamamlandı", status_txt)
            self.assertIn("masaüstüne kaydedildi", status_txt.lower())
            self.assertNotIn("Risk:", status_txt)
            self.assertNotIn("KRITIK", status_txt)
            txts = list(desktop.glob("MC_SS_Raporu_*.txt"))
            self.assertEqual(1, len(txts))

    def test_self_manifest_skips_exact_sha_only_not_tampered_script(self) -> None:
        from ss_core import _self_manifest, engine4_deep_files

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "evil_clone.py"
            p.write_text('CHEAT = "killaura vapev4"\n', encoding="utf-8")
            ctx = ScanContext(home_dir=Path(td), live_mode=False)
            engine4_deep_files._inspect_script_for_cheat_or_antiforensics(ctx, p, p.read_bytes())
            self.assertTrue(
                any(f.rule_id == "E4-SCRIPT-CHEAT-OR-ANTIFORENSIC" for f in ctx.findings)
            )
            # Only non-tampered SHA matches if present in manifest
            self.assertIsInstance(_self_manifest.SELF_PY_SHA256S, frozenset)


if __name__ == "__main__":
    unittest.main()

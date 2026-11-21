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

    def test_detailed_desktop_html_web_report_and_consistency(self) -> None:
        import json
        import re
        from ss_core.models import Confidence, Finding, Severity

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            desktop = home / "Desktop"
            desktop.mkdir(parents=True, exist_ok=True)

            # Drop a cheat JAR + XSS-shaped filename to verify HTML/JS safety & consistency
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
            # Inject an XSS-like finding path to prove HTML & script-JSON escaping hold
            ctx.add_finding(
                Finding(
                    rule_id="E4-FILE-CHEAT-NAME",
                    engine="Engine 4",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    category="Test XSS",
                    title="Test </script><img src=x onerror=alert(1)>",
                    description="XSS guard check",
                    path="/tmp/</script><script>alert(1)</script>.jar",
                    evidence=["</script><svg onload=alert(1)>"],
                )
            )
            html_path, payload = engine8_reporter.write_desktop_html_report(ctx, desktop_dir=desktop)
            self.assertTrue(html_path.exists())
            self.assertEqual(desktop, html_path.parent)
            self.assertTrue(html_path.name.startswith("MC_SS_Raporu_"))
            self.assertTrue(html_path.name.endswith(".html"))

            doc = html_path.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", doc)
            self.assertIn("Content-Security-Policy", doc)
            self.assertIn("default-src 'none'", doc)
            self.assertNotIn("<script src=", doc)
            self.assertNotIn("<link rel=\"stylesheet\" href=\"http", doc)
            # Raw unescaped XSS tags must NEVER appear anywhere in HTML
            self.assertNotIn("<img src=x onerror=alert(1)>", doc)
            self.assertNotIn("<script>alert(1)</script>", doc)
            self.assertNotIn("<svg onload=alert(1)>", doc)
            self.assertIn("wurst-client.jar", doc)
            self.assertIn(payload["report_sha256"], doc)
            self.assertIn(payload["assessment"]["verdict"], doc)
            self.assertIn("TXT İndir", doc)
            self.assertIn("JSON İndir", doc)
            self.assertIn("Yazdır / PDF", doc)

            # Embedded JSON & TXT download blobs must parse cleanly and match payload 1:1
            m_json = re.search(r'<script id="ss-json-blob" type="application/json">(.*?)</script>', doc, re.S)
            m_txt = re.search(r'<script id="ss-txt-blob" type="application/json">(.*?)</script>', doc, re.S)
            self.assertIsNotNone(m_json)
            self.assertIsNotNone(m_txt)
            assert m_json is not None and m_txt is not None
            embedded_json_wrap = json.loads(m_json.group(1))
            embedded_payload = json.loads(embedded_json_wrap["content"])
            embedded_txt_wrap = json.loads(m_txt.group(1))
            self.assertEqual(payload["report_sha256"], embedded_payload["report_sha256"])
            self.assertEqual(payload["assessment"]["risk_score"], embedded_payload["assessment"]["risk_score"])
            self.assertEqual(payload["assessment"]["verdict"], embedded_payload["assessment"]["verdict"])
            self.assertEqual(payload["assessment"]["domain_scores"], embedded_payload["assessment"]["domain_scores"])
            self.assertIn(payload["report_sha256"], embedded_txt_wrap["content"])

    def test_domain_classification_consistency_audit(self) -> None:
        from ss_core.models import Confidence, Finding, Severity

        def _f(rid: str, ev: list[str] | None = None) -> Finding:
            return Finding(
                rule_id=rid,
                engine=rid.split("-")[0],
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Audit",
                title="Audit",
                description="Audit",
                evidence=ev or [],
            )

        # Passive /dev/uinput permission must NOT land in cheat_evidence
        self.assertEqual("os_security", engine8_reporter._classify_domain(_f("E3-UINPUT-WRITABLE")))
        # System package update deleted binary in /usr stays os_security; home/tmp deleted binary is cheat_evidence
        self.assertEqual("os_security", engine8_reporter._classify_domain(_f("E2-PROC-DELETED-EXE", ["exe=/usr/bin/firefox (deleted)"])))
        self.assertEqual("cheat_evidence", engine8_reporter._classify_domain(_f("E2-PROC-DELETED-EXE", ["exe=/tmp/ghost (deleted)"])))
        # Real cheat & injection rules must land in cheat_evidence
        for rid in (
            "E1-HIST-CHEAT-CMD",
            "E1-ETC-LD-PRELOAD",
            "E2-PROC-MEMFD-EXE",
            "E2-PROC-TRACERPID",
            "E2-FD-CHEAT-PATH",
            "E4-FILE-CHEAT-NAME",
            "E4-RP-XRAY-TEXTURE",
            "E4-SHADER-XRAY",
            "E6-CLIPBOARD-HIT",
            "E6-JAVA-USERPREFS-CHEAT",
            "E9-AUDIT-INJECT-SYSCALL",
        ):
            self.assertEqual("cheat_evidence", engine8_reporter._classify_domain(_f(rid)), f"Misclassified {rid}")
        # Anti-forensic wiping & future timestomp must land in forensic_tampering
        for rid in (
            "E1-HIST-TRUNCATED",
            "E1-XBEL-DEVNULL",
            "E1-XBEL-WIPED",
            "E1-PKG-LOG-TAMPERED",
            "E4-TIME-FUTURE",
        ):
            self.assertEqual("forensic_tampering", engine8_reporter._classify_domain(_f(rid)), f"Misclassified {rid}")

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
            self.assertEqual("Taramayı Başlat", win.scan_button.text())
            self.assertEqual(0, win.progress_bar.value())
            self.assertIn("CmdSuv", win.dev_label.text())
            self.assertIn("https://github.com/CmdSuv", win.dev_label.text())
            self.assertEqual(9, len(win._chip_labels))
            opened: list[str] = []
            orig_open = ss_gui._open_external
            ss_gui._open_external = lambda target: opened.append(target) or True  # type: ignore[assignment]
            try:
                win.github_button.click()
                win.dev_label.linkActivated.emit("https://github.com/CmdSuv")
            finally:
                ss_gui._open_external = orig_open  # type: ignore[assignment]
            self.assertEqual(["https://github.com/CmdSuv"] * 2, opened)

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
            self.assertFalse(win.open_report_button.isHidden())
            self.assertIsNotNone(win._last_report_path)
            self.assertTrue(win._last_report_path.name.endswith(".html"))
            htmls = list(desktop.glob("MC_SS_Raporu_*.html"))
            self.assertEqual(1, len(htmls))
            self.assertIn("<!DOCTYPE html>", htmls[0].read_text(encoding="utf-8"))

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

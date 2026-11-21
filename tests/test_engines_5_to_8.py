"""Tests for Engines 5, 6, 7, and 8 (Minecraft, Desktop/SQLite/Wine, Network/USB, Correlation/Reports)."""

from __future__ import annotations

import codecs
import gzip
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from ss_core import (
    engine5_minecraft,
    engine6_desktop_traces,
    engine7_network_usb,
    engine8_reporter,
)
from ss_core.models import Confidence, Finding, ScanContext, Severity
from tests.sim_lab import build_clean_baseline, write_simulated_proc_entry


class TestEngine5Minecraft(unittest.TestCase):
    def test_clean_baseline_mc_no_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine5_minecraft.run(ctx)
            self.assertEqual([], [f.rule_id for f in ctx.findings])

    def test_options_configs_logs_cross_verify_and_hserr(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            mc = home / ".minecraft"
            (mc / "options.txt").write_text(
                "gamma:15.0\n"
                "key_key.meteor.clickgui:key.keyboard.right_shift\n"
                'resourcePacks:["vanilla","file/XRay-Ultimate-1.21.zip"]\n',
                encoding="utf-8",
            )
            (mc / "config/Wurst").mkdir(parents=True, exist_ok=True)
            (mc / "launcher_profiles.json").write_text(
                '{"profiles":{"p1":{"javaArgs":"-Xmx4G -javaagent:/tmp/loader.jar"}}}',
                encoding="utf-8",
            )
            (mc / "logs/latest.log").write_text(
                "[12:00:01] [main/INFO]: Loading 3 mods:\n"
                "\t- sodium 0.5.8\n"
                "\t- doomsday 1.2.0\n"
                "\t- extrahelper 1.0\n",
                encoding="utf-8",
            )
            gz_log = mc / "logs/2026-11-15-1.log.gz"
            gz_log.write_bytes(gzip.compress(b"[main/INFO]: Initializing net.ccbluex.liquidbounce\n"))
            (mc / "hs_err_pid5555.log").write_text(
                "Dynamic libraries:\n7f001000-7f002000 r-xp /tmp/libvape_hook.so\n",
                encoding="utf-8",
            )

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine5_minecraft.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E5-OPTIONS-FULLBRIGHT",
                "E5-OPTIONS-CHEAT-KEYBIND",
                "E5-OPTIONS-XRAY-PACK",
                "E5-CHEAT-CONFIG-ARTIFACT",
                "E5-LAUNCHER-JVM-AGENT",
                "E5-LOG-MISSING-CHEAT-MOD",
                "E5-LOG-CHEAT-TRACE",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")


class TestEngine6DesktopTraces(unittest.TestCase):
    def test_clean_baseline_desktop_no_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine6_desktop_traces.run(ctx)
            self.assertEqual([], [f.rule_id for f in ctx.findings])

    def test_xbel_klipper_trash_sqlite_freelist_carving_and_wine_rot13(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))

            # 1. recently-used.xbel deleted file
            (home / ".local/share/recently-used.xbel").write_text(
                '<?xml version="1.0"?>\n<xbel version="1.0">'
                '<bookmark href="file:///tmp/ghost_loader.jar" modified="2026-11-15T14:00:00Z"/>'
                "</xbel>",
                encoding="utf-8",
            )

            # 2. Klipper UTF-16BE clipboard
            klip = home / ".local/share/klipper/history2.lst"
            klip.parent.mkdir(parents=True, exist_ok=True)
            klip.write_bytes(b"\x00\x00\x00\x01" + "https://vape.gg/download".encode("utf-16be") + b"\x00\x00")

            # 3. Trash
            tinfo = home / ".local/share/Trash/info"
            tinfo.mkdir(parents=True, exist_ok=True)
            (tinfo / "meteor-client-0.5.8.jar.trashinfo").write_text(
                "[Trash Info]\nPath=/home/player/.minecraft/mods/meteor-client-0.5.8.jar\nDeletionDate=2026-11-15T16:50:00\n",
                encoding="utf-8",
            )

            # 4. Chrome SQLite: DELETE rows WITHOUT VACUUM so freelist carving catches deleted URL!
            chrome_db = home / ".config/google-chrome/Default/History"
            conn = sqlite3.connect(chrome_db)
            conn.execute("PRAGMA secure_delete = OFF")
            now_wk = int((time.time() + 11644473600) * 1_000_000)
            conn.execute(
                "INSERT INTO urls VALUES (999, 'https://doomsdayclient.com/download/dd.jar', 'Doomsday', 1, ?)",
                (now_wk,),
            )
            conn.commit()
            conn.execute("DELETE FROM urls")
            conn.commit()
            conn.close()

            # 5. Firefox places.sqlite active download
            ff_dir = home / ".var/app/org.mozilla.firefox/.mozilla/firefox/abc.default-release"
            ff_dir.mkdir(parents=True, exist_ok=True)
            ff_db = ff_dir / "places.sqlite"
            fconn = sqlite3.connect(ff_db)
            fconn.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_date INTEGER)")
            fconn.execute("CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, content TEXT, dateAdded INTEGER)")
            now_pr = int(time.time() * 1_000_000)
            for i in range(20):
                fconn.execute("INSERT INTO moz_places VALUES (?, ?, 'Site', ?)", (i + 1, f"https://example.org/{i}", now_pr))
            fconn.execute(
                "INSERT INTO moz_places VALUES (100, 'https://cdn.discordapp.com/attachments/1/2/vapev4.jar', 'dl', ?)",
                (now_pr,),
            )
            fconn.execute(
                "INSERT INTO moz_annos VALUES (1, 100, 'file:///home/player/Downloads/vapev4.jar', ?)",
                (now_pr,),
            )
            fconn.commit()
            fconn.close()

            # 6. Wine ROT13 UserAssist! ('Z:\\tmp\\VapeV4.exe' -> ROT13)
            wine_dir = home / ".wine"
            wine_dir.mkdir(parents=True, exist_ok=True)
            enc_name = codecs.encode(r"Z:\\tmp\\VapeV4.exe", "rot_13")
            (wine_dir / "user.reg").write_text(
                '[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\UserAssist\\\\{CEBFF5CD}\\\\Count]\n'
                f'"{enc_name}"=hex:00,00,00,00\n',
                encoding="utf-8",
            )

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine6_desktop_traces.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E6-XBEL-DELETED-ARTIFACT",
                "E6-CLIPBOARD-HIT",
                "E6-TRASH-SUSPICIOUS",
                "E6-BROWSER-HISTORY-WIPED",
                "E6-BROWSER-SQLITE-FREELIST-CARVE",
                "E6-BROWSER-CHEAT-URL",
                "E6-BROWSER-CHEAT-DOWNLOAD",
                "E6-WINE-USERASSIST-ROT13",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")


class TestEngine7NetworkUsb(unittest.TestCase):
    def test_clean_baseline_net_no_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine7_network_usb.run(ctx)
            self.assertEqual([], [f.rule_id for f in ctx.findings])

    def test_proxy_sockets_vpn_hosts_and_usb(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            write_simulated_proc_entry(
                proc,
                pid=4242,
                comm="java",
                cmdline=["java", "net.minecraft.client.main.Main"],
                fds={"10": "socket:[55555]", "11": "socket:[66666]"},
            )
            # 127.0.0.1 = 0100007F; 1080 = 0x0438; 1337 = 0x0539; 0A=LISTEN, 01=ESTABLISHED
            (proc / "net/tcp").write_text(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                "   0: 0100007F:0438 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 55555\n"
                "   1: 0100007F:0539 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 66666\n",
                encoding="utf-8",
            )
            (root / "sys/class/net/wg0").mkdir(parents=True, exist_ok=True)
            (root / "sys/class/net/wg0/operstate").write_text("unknown\n", encoding="utf-8")
            (root / "etc/hosts").write_text("127.0.0.1 api.vape.gg\n", encoding="utf-8")

            usb = root / "sys/bus/usb/devices/1-2"
            usb.mkdir(parents=True, exist_ok=True)
            (usb / "idVendor").write_text("09da\n", encoding="utf-8")
            (usb / "idProduct").write_text("c10a\n", encoding="utf-8")
            (usb / "manufacturer").write_text("A4TECH\n", encoding="utf-8")
            (usb / "product").write_text("Bloody V7\n", encoding="utf-8")
            (usb / "bDeviceClass").write_text("00\n", encoding="utf-8")

            usb_stick = root / "sys/bus/usb/devices/1-3"
            (usb_stick / "1-3:1.0").mkdir(parents=True, exist_ok=True)
            (usb_stick / "idVendor").write_text("0781\n", encoding="utf-8")
            (usb_stick / "idProduct").write_text("5581\n", encoding="utf-8")
            (usb_stick / "manufacturer").write_text("SanDisk\n", encoding="utf-8")
            (usb_stick / "product").write_text("Ultra USB 3.0\n", encoding="utf-8")
            (usb_stick / "bDeviceClass").write_text("00\n", encoding="utf-8")
            (usb_stick / "1-3:1.0/bInterfaceClass").write_text("08\n", encoding="utf-8")

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine7_network_usb.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E7-LOCAL-PROXY-ACTIVE",
                "E7-CHEAT-PORT-LISTEN",
                "E7-VPN-ACTIVE",
                "E7-HOSTS-SPOOF",
                "E7-USB-BLOODY-MOUSE",
                "E7-USB-STORAGE-CONNECTED",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")


class TestEngine8Reporter(unittest.TestCase):
    def test_correlation_scoring_and_xss_safe_html_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctx = ScanContext(home_dir=Path(td), live_mode=False)
            ctx.add_finding(
                Finding(
                    rule_id="E1-HIST-ZERO",
                    engine="E1",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Test",
                    title="History zero <script>alert(1)</script>",
                    description="Desc",
                    evidence=["<img src=x onerror=alert(1)>"],
                )
            )
            ctx.add_finding(
                Finding(
                    rule_id="E5-LOG-MISSING-LATEST",
                    engine="E5",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Test",
                    title="Missing latest.log",
                    description="Desc",
                )
            )
            engine8_reporter.correlate_findings(ctx)
            rids = {f.rule_id for f in ctx.findings}
            self.assertIn("E8-CORR-WIPE-CHAIN", rids)

            out_dir = Path(td) / "reports"
            paths = engine8_reporter.write_reports(ctx, out_dir)
            html_content = paths["html"].read_text(encoding="utf-8")
            txt_content = paths["txt"].read_text(encoding="utf-8")
            json_data = json.loads(paths["json"].read_text(encoding="utf-8"))

            self.assertNotIn("<script>alert(1)</script>", html_content)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_content)
            self.assertGreaterEqual(json_data["assessment"]["risk_score"], 68)
            self.assertIn("E8-CORR-WIPE-CHAIN", txt_content)
            self.assertEqual(len(json_data["report_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()

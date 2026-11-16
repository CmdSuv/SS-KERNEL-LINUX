"""Comprehensive red-team regression tests covering plugged bypasses across E1-E8."""

from __future__ import annotations

import codecs
import os
import sqlite3
import struct
import subprocess
import tempfile
import time
import unittest
import zipfile
import zlib
from pathlib import Path

import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ss_core import (
    engine1_integrity,
    engine2_live_proc,
    engine3_input_macro,
    engine4_deep_files,
    engine5_minecraft,
    engine6_desktop_traces,
    engine7_network_usb,
    engine8_reporter,
)
from ss_core.models import Confidence, Finding, ScanContext, Severity
from tests.sim_lab import build_clean_baseline, make_jar, write_simulated_proc_entry


def _make_png_with_chunk(extra_chunk: tuple[bytes, bytes] | None = None) -> bytes:
    def _chunk(ctype: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)
    raw = b"\x00\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff"
    idat = zlib.compress(raw)
    parts = [b"\x89PNG\r\n\x1a\n", _chunk(b"IHDR", ihdr), _chunk(b"IDAT", idat)]
    if extra_chunk is not None:
        parts.append(_chunk(extra_chunk[0], extra_chunk[1]))
    parts.append(_chunk(b"IEND", b""))
    return b"".join(parts)


class TestRedTeamBypasses(unittest.TestCase):
    def test_e1_antiforensic_rm_unlink_redirect_posix_shadow_and_logout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            (home / ".bash_history").write_text(
                "ls -la\n"
                "rm /home/player/.minecraft/mods/wurst.jar\n"
                "unlink /home/player/.minecraft/mods/meteor.jar\n"
                "> /home/player/.bash_history\n",
                encoding="utf-8",
            )
            (home / ".bashrc").write_text(
                'export PATH="$HOME/.local/bin:$PATH"\n'
                'ps() { command ps "$@" | grep -v autoclick; }\n',
                encoding="utf-8",
            )
            (home / ".bash_logout").write_text("set +o history\nhistory -c\n", encoding="utf-8")

            shadow_ps = home / ".local/bin/ps"
            shadow_ps.parent.mkdir(parents=True, exist_ok=True)
            shadow_ps.write_text("echo filtered\n", encoding="utf-8")
            os.chmod(shadow_ps, 0o755)

            shadow_pgrep = home / ".local/bin/pgrep"
            shadow_pgrep.write_bytes(b"")
            os.chmod(shadow_pgrep, 0o755)

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine1_integrity.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E1-HIST-ANTIFORENSIC-CMD",
                "E1-RC-ALIAS-HIJACK",
                "E1-RC-ANTIFORENSIC-HOOK",
                "E1-PATH-SHADOW-SCRIPT",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")

            hist_hits = [f for f in ctx.findings if f.rule_id == "E1-HIST-ANTIFORENSIC-CMD"]
            ev_joined = "\n".join(e for f in hist_hits for e in f.evidence)
            self.assertIn("rm /home/player/.minecraft/mods/wurst.jar", ev_joined)
            self.assertIn("unlink", ev_joined)
            self.assertIn("> /home/player/.bash_history", ev_joined)

            shadow_ev = "\n".join(e for f in ctx.findings if f.rule_id == "E1-PATH-SHADOW-SCRIPT" for e in f.evidence)
            self.assertIn("ps", shadow_ev)
            self.assertIn("pgrep", shadow_ev)

    def test_e2_reflective_elf_second_slot_libjvm_deleted_zip_and_perfdisable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            decoy = b"\x7fELF\x99" + (b"\x00" * 64)
            valid_elf = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8) + struct.pack("<H", 3) + (b"\x00" * 16)
            mem_blob = (decoy + valid_elf).ljust(4096, b"\x00")

            write_simulated_proc_entry(
                proc,
                pid=7777,
                comm="python3",
                cmdline=["python3", "-m", "helper", "-XX:+PerfDisableSharedMem"],
                exe_target="/usr/bin/python3",
                maps_lines=[
                    "00000000-00001000 rwxp 00000000 00:00 0",
                    "7f0000100000-7f0000200000 r-xp 00000000 08:01 123 /usr/lib/jvm/java-21/lib/server/libjvm.so",
                ],
                fds={
                    "7": "/home/player/payload.zip (deleted)",
                    "8": "/dev/shm/injector_stage (deleted)",
                },
                mem_bytes=mem_blob,
            )

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False, enable_memory_scan=True)
            engine2_live_proc.run(ctx)
            rids = {f.rule_id for f in ctx.findings if f.pid == 7777}
            for expected in (
                "E2-RAM-REFLECTIVE-ELF",
                "E2-FD-DELETED-FILE",
                "E2-JVM-PERF-DISABLE",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")
            self.assertIn(7777, ctx.telemetry.get("java_pids", []))

    def test_e3_xlib_xtest_subprocess_dotool_fastclick_and_event_uinput(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            docs = home / "Documents"
            docs.mkdir(parents=True, exist_ok=True)
            (docs / "mc_pvp_macro.py").write_text(
                "from Xlib.ext import xtest\n"
                "def pulse(dpy):\n"
                "    xtest.fake_input(dpy, 4, 1)\n",
                encoding="utf-8",
            )
            (docs / "sub_click.py").write_text(
                "import subprocess\n"
                "subprocess.run(['xdotool', 'click', '1'])\n",
                encoding="utf-8",
            )
            (home / "click_helper.sh").write_text(
                "#!/bin/bash\n"
                "echo 'click left' | dotool\n",
                encoding="utf-8",
            )
            (docs / "fast_loop.py").write_text(
                "import time\n"
                "def loop(mouse_click):\n"
                "    time.sleep(0.01)\n"
                "    return mouse_click\n",
                encoding="utf-8",
            )

            # Event-only virtual uinput sysfs device (no mouse/kbd handler)
            dev_input = proc / "bus/input"
            dev_input.mkdir(parents=True, exist_ok=True)
            (dev_input / "devices").write_text(
                'I: Bus=0003 Vendor=0000 Product=0000 Version=0000\n'
                'N: Name="Disguised Controller"\n'
                'P: Phys=\n'
                'S: Sysfs=/devices/virtual/input/input99\n'
                'H: Handlers=event19\n\n',
                encoding="utf-8",
            )

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine3_input_macro.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            self.assertIn("E3-VIRTUAL-UINPUT-SYSFS", rids, f"Missing E3-VIRTUAL-UINPUT-SYSFS in {rids}")
            script_findings = [f for f in ctx.findings if f.rule_id == "E3-MACRO-SCRIPT"]
            self.assertTrue(script_findings, f"Expected E3-MACRO-SCRIPT, got {rids}")
            ev_all = "\n".join(e for f in script_findings for e in f.evidence)
            for fname in ("mc_pvp_macro.py", "sub_click.py", "click_helper.sh", "fast_loop.py"):
                self.assertIn(fname, ev_all, f"{fname} missed by E3 script scan")

    def test_e4_template_xray_large_jar_versions_index1800_polyglot_script_and_no_fp(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)

            # Compile real Java bytecode classes in a single javac batch
            src_dir = base / "java_src"
            cls_dir = base / "java_cls"
            src_dir.mkdir()
            cls_dir.mkdir()

            srcs = {
                "net/cheat/KillAura.java": (
                    "package net.cheat;\n"
                    "public class KillAura {\n"
                    '    public static final String MOD = "WurstClient AutoClicker";\n'
                    "}\n"
                ),
                "fake/PkgKill.java": (
                    "package fake;\n"
                    "public class PkgKill {\n"
                    '    public static final String REF = "java/lang/KillAura";\n'
                    "}\n"
                ),
                "net/minecraft/client/Options.java": (
                    "package net.minecraft.client;\n"
                    "import java.util.ArrayList;\n"
                    "public class Options {\n"
                    '    public String debugKey = "showHitboxes";\n'
                    "    public ArrayList<String> keys = new ArrayList<>();\n"
                    "}\n"
                ),
                "me/jellysquid/mods/sodium/SodiumUnsafe.java": (
                    "package me.jellysquid.mods.sodium;\n"
                    "import sun.misc.Unsafe;\n"
                    "public class SodiumUnsafe {\n"
                    "    public static Class<?> c = Unsafe.class;\n"
                    "}\n"
                ),
            }
            java_files: list[str] = []
            for rel, code in srcs.items():
                p = src_dir / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(code, encoding="utf-8")
                java_files.append(str(p))
            subprocess.check_call(["javac", "-d", str(cls_dir), *java_files])

            killaura_cls = (cls_dir / "net/cheat/KillAura.class").read_bytes()
            fake_pkg_cls = (cls_dir / "fake/PkgKill.class").read_bytes()
            options_cls = (cls_dir / "net/minecraft/client/Options.class").read_bytes()
            sodium_cls = (cls_dir / "me/jellysquid/mods/sodium/SodiumUnsafe.class").read_bytes()

            mc = home / ".minecraft"

            # 1. X-Ray template cube_all.json model pack
            make_jar(
                mc / "resourcepacks/template_xray.zip",
                {
                    "pack.mcmeta": b'{"pack":{"pack_format":34,"description":"clean"}}',
                    "assets/minecraft/models/block/cube_all.json": b'{"parent":"block/cube_all","elements":[]}',
                },
            )

            # 2. >32MB (33 MiB) padded cheat JAR via ZIP_STORED
            big_jar = mc / "mods/padded_cleanname.jar"
            with zipfile.ZipFile(big_jar, "w", compression=zipfile.ZIP_STORED) as zf:
                zf.writestr("assets/pad.bin", b"\x00" * (33 * 1024 * 1024))
                zf.writestr("net/cheat/KillAura.class", killaura_cls)

            # 3. Trojanized >24h versions/ and libraries/ JARs
            ver_jar = mc / "versions/1.21.4/1.21.4.jar"
            make_jar(ver_jar, {"net/cheat/KillAura.class": killaura_cls})
            lib_jar = mc / "libraries/com/example/helper/1.0/helper-1.0.jar"
            make_jar(lib_jar, {"fake/PkgKill.class": fake_pkg_cls})
            old_ts = time.time() - 5 * 86400
            os.utime(ver_jar, (old_ts, old_ts))
            os.utime(lib_jar, (old_ts, old_ts))

            # 4. Cheat class beyond 1800 class entries
            entries_1850 = {f"p/Clean{i}.class": b"not_even_needed" for i in range(1850)}
            entries_1850["z/KillAura.class"] = killaura_cls
            make_jar(mc / "mods/many_classes.jar", entries_1850)

            # 5. PE + JAR polyglot in Downloads
            small_jar = base / "nested.jar"
            make_jar(small_jar, {"net/cheat/KillAura.class": killaura_cls})
            pe_stub = bytearray(512)
            pe_stub[0:2] = b"MZ"
            struct.pack_into("<I", pe_stub, 0x3C, 0x80)
            pe_stub[0x80:0x84] = b"PE\x00\x00"
            (home / "Downloads/tool.exe").write_bytes(bytes(pe_stub) + small_jar.read_bytes())

            # 6. PNG chunk-embedded valid ELF
            valid_elf = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8) + struct.pack("<H", 3) + (b"\x00" * 32)
            (home / "Downloads/avatar.png").write_bytes(_make_png_with_chunk((b"tEXt", b"Comment\x00" + valid_elf)))

            # 7. Script inside .minecraft/mods
            (mc / "mods/cleaner.sh").write_text("#!/bin/bash\nrm ~/.bash_history\n", encoding="utf-8")

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False, deep_home_scan=False)
            engine4_deep_files.run(ctx)

            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E4-RP-XRAY-EMPTY-MODEL",
                "E4-JAR-CLASS-CONSTANT-POOL",
                "E4-POLYGLOT-PAYLOAD",
                "E4-SCRIPT-CHEAT-OR-ANTIFORENSIC",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")

            flagged_paths = {f.path for f in ctx.findings if f.rule_id == "E4-JAR-CLASS-CONSTANT-POOL"}
            for p in (big_jar, ver_jar, lib_jar, mc / "mods/many_classes.jar"):
                self.assertTrue(
                    any(str(p) in (fp or "") for fp in flagged_paths),
                    f"Expected {p} in E4-JAR-CLASS-CONSTANT-POOL paths: {flagged_paths}",
                )

            poly_paths = {f.path for f in ctx.findings if f.rule_id == "E4-POLYGLOT-PAYLOAD"}
            self.assertIn(str(home / "Downloads/tool.exe"), poly_paths)
            self.assertIn(str(home / "Downloads/avatar.png"), poly_paths)

            # 8. Real FP regression check: clean Options.class (showHitboxes + ArrayList), sodium Unsafe, jtracy native
            fp_base = base / "fp_clean"
            h2, r2, p2 = build_clean_baseline(fp_base)
            mc2 = h2 / ".minecraft"
            make_jar(mc2 / "versions/26.3/26.3.jar", {"net/minecraft/client/Options.class": options_cls})
            make_jar(
                mc2 / "mods/sodium-fabric-0.6.jar",
                {
                    "fabric.mod.json": b'{"id":"sodium","name":"Sodium"}',
                    "me/jellysquid/mods/sodium/SodiumUnsafe.class": sodium_cls,
                },
            )
            make_jar(
                mc2 / "libraries/com/mojang/jtracy/1.0/jtracy-1.0.jar",
                {"linux/x86_64/libjtracy.so": valid_elf},
            )
            ctx_clean = ScanContext(home_dir=h2, root_prefix=r2, proc_root=p2, live_mode=False, deep_home_scan=False)
            engine4_deep_files.run(ctx_clean)
            high_or_crit = [f for f in ctx_clean.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
            self.assertEqual([], high_or_crit, f"Unexpected FP findings: {[(f.rule_id, f.evidence) for f in high_or_crit]}")

    def test_e5_lunar_optionslc_debug_killaura_chat_wiped_mods_and_prism_log(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            mc = home / ".minecraft"
            (mc / "options.txt").write_text(
                "key_key.debug.showHitboxes:key.keyboard.b\n"
                "key_key.debug.killaura:key.keyboard.r\n",
                encoding="utf-8",
            )
            (mc / "launcher_profiles.json").write_text(
                '{"profiles":{"p1":{"javaArgs":"-javaagent:/tmp/launcher_agent.jar"}}}\n',
                encoding="utf-8",
            )
            # Wipe disk mods directory completely while logs declare both cheat & non-cheat mods
            mods_dir = mc / "mods"
            if mods_dir.exists():
                for child in mods_dir.iterdir():
                    child.unlink()
                mods_dir.rmdir()
            (mc / "logs/latest.log").write_text(
                "[12:00:00] [Render thread/INFO]: [FabricLoader] Loading 2 mods:\n"
                "\t- sodium 0.6.0\n"
                "\t- wurst 7.40.0\n"
                "[12:00:01] [Render thread/INFO]: Loaded method <init> in net.cheat.KillAura\n",
                encoding="utf-8",
            )

            # Lunar offline/multiver optionsLC.txt
            lunar_ver = home / ".lunarclient/offline/multiver"
            lunar_ver.mkdir(parents=True, exist_ok=True)
            (lunar_ver / "optionsLC.txt").write_text("key_key.autoclicker:key.keyboard.v\n", encoding="utf-8")

            # Global PrismLauncher cfg + log
            prism = home / ".local/share/PrismLauncher"
            (prism / "logs").mkdir(parents=True, exist_ok=True)
            (prism / "prismlauncher.cfg").write_text("JvmArgs=-javaagent:/tmp/hidden_agent.jar\n", encoding="utf-8")
            (prism / "logs/PrismLauncher-0.log").write_text(
                "Launching with -javaagent:/dev/shm/stealth.jar\n", encoding="utf-8"
            )

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine5_minecraft.run(ctx)

            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E5-OPTIONS-CHEAT-KEYBIND",
                "E5-LOG-CHEAT-TRACE",
                "E5-LOG-MISSING-CHEAT-MOD",
                "E5-LOG-MODLIST-MISMATCH",
                "E5-LAUNCHER-JVM-AGENT",
                "E5-INSTANCE-JVM-AGENT",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")

            # Verify vanilla debug showHitboxes did NOT trigger options keybind finding
            kb_ev = "\n".join(e for f in ctx.findings if f.rule_id == "E5-OPTIONS-CHEAT-KEYBIND" for e in f.evidence)
            self.assertNotIn("showHitboxes", kb_ev)
            self.assertIn("key_key.debug.killaura", kb_ev)
            self.assertIn("key_key.autoclicker", kb_ev)

    def test_e6_history_flood_url_chains_orphan_trash_and_wine_rot13(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            hist = home / ".config/google-chrome/Default/History"
            hist.parent.mkdir(parents=True, exist_ok=True)
            if hist.exists():
                hist.unlink()
            conn = sqlite3.connect(str(hist))
            conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER)")
            conn.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, tab_url TEXT, target_path TEXT, start_time INTEGER)")
            conn.execute("CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT)")
            conn.execute("CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, term TEXT)")

            now_wk = int((time.time() + 11644473600) * 1_000_000)
            rows = [(i + 1, f"https://clean-site-{i}.example.com", "Clean Page", now_wk - i) for i in range(3500)]
            rows.append((9999, "https://vape.gg/download", "Vape Client", now_wk - 9999))
            conn.executemany("INSERT INTO urls VALUES (?, ?, ?, ?)", rows)
            conn.execute("INSERT INTO downloads VALUES (1, 'https://redirect.example.com', '/tmp/mod.jar', ?)", (now_wk,))
            conn.execute("INSERT INTO downloads_url_chains VALUES (1, 0, 'https://cdn.example.net/WurstClient.jar')")
            conn.commit()
            conn.close()

            # Orphan Trash/files artifact without .trashinfo
            trash_files = home / ".local/share/Trash/files"
            trash_files.mkdir(parents=True, exist_ok=True)
            (trash_files / "vape_loader.jar").write_bytes(b"PK\x03\x04")

            # Wine UserAssist ROT13 KillAura.exe
            wine_dir = home / ".wine"
            wine_dir.mkdir(parents=True, exist_ok=True)
            enc_killaura = codecs.encode(r"Z:\\tmp\\KillAura.exe", "rot_13")
            (wine_dir / "user.reg").write_text(
                '[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\UserAssist\\\\{CEBFF5CD}\\\\Count]\n'
                f'"{enc_killaura}"=hex:00,00,00,00\n',
                encoding="utf-8",
            )

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine6_desktop_traces.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E6-BROWSER-CHEAT-URL",
                "E6-BROWSER-CHEAT-DOWNLOAD",
                "E6-TRASH-SUSPICIOUS",
                "E6-WINE-USERASSIST-ROT13",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")

    def test_e7_hosts_piggyback_and_non_java_loopback_socks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            (root / "etc/hosts").write_text("127.0.0.1 localhost api.lunarclient.com\n", encoding="utf-8")

            write_simulated_proc_entry(
                proc,
                pid=8888,
                comm="python3",
                cmdline=["python3", "/tmp/tunnel.py"],
                exe_target="/usr/bin/python3",
                fds={"5": "socket:[77777]"},
            )
            # ESTABLISHED (01) loopback connection from python3 -> 127.0.0.1:1080 (0100007F:0438)
            (proc / "net/tcp").write_text(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                "   0: 0100007F:9A10 0100007F:0438 01 00000000:00000000 00:00000000 00000000 1000 0 77777\n",
                encoding="utf-8",
            )

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine7_network_usb.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            self.assertIn("E7-HOSTS-SPOOF", rids)
            self.assertIn("E7-LOCAL-PROXY-ACTIVE", rids)

    def test_e8_corr_jvm_inject_chain_with_launcher_agent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctx = ScanContext(home_dir=Path(td), live_mode=False)
            ctx.add_finding(
                Finding(
                    rule_id="E5-LAUNCHER-JVM-AGENT",
                    engine="Engine 5",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Launcher JVM Injection",
                    title="Launcher agent",
                    description="Agent arg",
                    evidence=["-javaagent:/tmp/a.jar"],
                )
            )
            ctx.add_finding(
                Finding(
                    rule_id="E4-JAR-CHEAT-METADATA",
                    engine="Engine 4",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Cheat JAR",
                    title="Cheat jar",
                    description="Metadata",
                    evidence=["Mod ID: wurst"],
                )
            )
            engine8_reporter.correlate_findings(ctx)
            rids = {f.rule_id for f in ctx.findings}
            self.assertIn("E8-CORR-JVM-INJECT-CHAIN", rids)


if __name__ == "__main__":
    unittest.main(verbosity=2)

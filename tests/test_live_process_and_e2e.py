"""Real live Linux process tests (Java -javaagent + /proc/<pid>/mem + deleted fd/mmap)
and full Clean vs. Multi-Layer Adversarial End-to-End tests.
"""

from __future__ import annotations

import codecs
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from ss_core import engine2_live_proc, engine8_reporter, orchestrator
from ss_core.models import ScanContext
from tests.sim_lab import (
    build_clean_baseline,
    compile_java_to_class_bytes,
    make_jar,
    make_paeth_filtered_png,
    write_simulated_proc_entry,
)


class TestLiveLinuxProcessesAndE2E(unittest.TestCase):
    def test_e2e_clean_baseline_scores_clean(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
            )
            orchestrator.run_all_engines(ctx)
            payload = engine8_reporter.build_report_payload(ctx)
            self.assertEqual(
                0,
                payload["assessment"]["risk_score"],
                f"Expected clean score 0, got findings: {payload['findings']}",
            )
            self.assertEqual("CLEAN", payload["assessment"]["verdict_level"])
            self.assertEqual([], ctx.errors)

    def test_e2e_full_adversarial_multilayer_attack(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)

            # E1: anti-forensic wipe + reboot
            (proc / "uptime").write_text("200.0 400.0\n", encoding="utf-8")
            (home / ".bash_history").write_text("shred -u vape.jar\n", encoding="utf-8")

            # E2: deleted mapped jar + RAM sig
            write_simulated_proc_entry(
                proc,
                pid=7777,
                comm="java",
                cmdline=["java", "-javaagent:/tmp/loader.jar", "net.minecraft.client.main.Main"],
                maps_lines=["7f00-7f01 r-xp 00000000 08:01 1 /tmp/vapev4.jar (deleted)"],
                fds={"4": "/dev/uinput", "5": "/tmp/vapev4.jar (deleted)"},
                mem_bytes=b"\x00" * 64 + b"vapev4 KillAura AutoClicker SelfDestruct" + b"\x00" * 64,
            )

            # E3: input-remapper + virtual uinput
            (proc / "bus/input/devices").write_text(
                'N: Name="ydotool virtual device"\nP: Phys=uinput\nH: Handlers=event5\n\n',
                encoding="utf-8",
            )
            ir = home / ".config/input-remapper-2/presets/mouse/pvp.json"
            ir.parent.mkdir(parents=True, exist_ok=True)
            ir.write_text('[{"output_symbol":"repeat(20, key(BTN_LEFT))"}]', encoding="utf-8")

            # E4: spoofed mod + X-Ray texture + timestomp
            build_j = base / "jbuild"
            build_j.mkdir()
            cls_rel, cls_bytes = compile_java_to_class_bytes(
                build_j,
                "me/vape",
                "KillAura",
                'package me.vape; public class KillAura { public static String X = "vapev4"; }',
            )
            bad_mod = home / ".minecraft/mods/sodium-extra.jar"
            make_jar(
                bad_mod,
                {
                    "fabric.mod.json": b'{"id":"evilclient","name":"EvilClient"}',
                    cls_rel: cls_bytes,
                },
            )
            make_jar(
                home / ".minecraft/resourcepacks/xray.zip",
                {
                    "pack.mcmeta": b'{"pack":{"pack_format":34,"description":"x"}}',
                    "assets/minecraft/textures/block/stone.png": make_paeth_filtered_png(16, 16, 100),
                },
            )

            # E5: deleted mod mismatch in latest.log + keybind
            (home / ".minecraft/options.txt").write_text(
                "gamma:12.0\nkey_key.meteor.clickgui:key.keyboard.r\n", encoding="utf-8"
            )
            (home / ".minecraft/logs/latest.log").write_text(
                "Loading 2 mods:\n\t- sodium 0.5.8\n\t- doomsday 1.0\n", encoding="utf-8"
            )

            # E6: Trash + recently-used deleted + Wine ROT13 + Browser
            tinfo = home / ".local/share/Trash/info"
            tinfo.mkdir(parents=True, exist_ok=True)
            (tinfo / "doomsday.jar.trashinfo").write_text(
                "[Trash Info]\nPath=/home/player/.minecraft/mods/doomsday.jar\nDeletionDate=2026-11-15T16:59:00\n",
                encoding="utf-8",
            )
            (home / ".local/share/recently-used.xbel").write_text(
                '<xbel version="1.0"><bookmark href="file:///tmp/doomsday.jar"/></xbel>',
                encoding="utf-8",
            )
            wine_dir = home / ".wine"
            wine_dir.mkdir(parents=True, exist_ok=True)
            (wine_dir / "user.reg").write_text(
                '[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\UserAssist\\\\{CE}\\\\Count]\n'
                f'"{codecs.encode("VapeV4.exe", "rot_13")}"=hex:01\n',
                encoding="utf-8",
            )

            # E7: hosts + VPN
            (root / "etc/hosts").write_text("127.0.0.1 vape.gg\n", encoding="utf-8")
            (root / "sys/class/net/tun0").mkdir(parents=True, exist_ok=True)
            (root / "sys/class/net/tun0/operstate").write_text("up\n", encoding="utf-8")

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            orchestrator.run_all_engines(ctx)
            paths = engine8_reporter.write_reports(ctx, base / "reports")
            payload = json.loads(paths["json"].read_text(encoding="utf-8"))

            self.assertEqual("CRITICAL", payload["assessment"]["verdict_level"])
            self.assertGreaterEqual(payload["assessment"]["risk_score"], 90)
            rids = {f["rule_id"] for f in payload["findings"]}
            for corr in (
                "E8-CORR-WIPE-CHAIN",
                "E8-CORR-STEALTH-MACRO",
                "E8-CORR-SPOOFED-ARTIFACT",
                "E8-CORR-GHOST-RAM",
            ):
                self.assertIn(corr, rids, f"Missing correlation {corr}")
            self.assertTrue(paths["html"].is_file() and paths["txt"].is_file())

    def test_real_live_deleted_fd_mmap_and_proc_mem_child(self) -> None:
        """Spawn a REAL Linux process holding a deleted /tmp/*.jar + mmap + RAM cheat strings."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            jar_path = Path(f"/tmp/ss_live_test_{os.getpid()}_{int(time.time())}.jar")
            make_jar(jar_path, {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"})
            # Ensure jar is >= 4096 bytes for mmap
            jar_path.write_bytes(jar_path.read_bytes() + b"A" * 4096)

            child_script = base / "child_sim.py"
            child_script.write_text(
                "import mmap, os, sys, time\n"
                f"p = {str(jar_path)!r}\n"
                "f = open(p, 'rb')\n"
                "mm = mmap.mmap(f.fileno(), 4096, access=mmap.ACCESS_READ)\n"
                "os.unlink(p)\n"
                "# Allocate marker strings directly in live process heap\n"
                "secret_a = ('doomsday' + 'client_live_marker').encode('utf-16le')\n"
                "secret_b = b'KillAura AutoClicker SelfDestruct Reach Velocity'\n"
                "print('READY', flush=True)\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )

            proc = subprocess.Popen(
                [sys.executable, str(child_script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                line = proc.stdout.readline().strip() if proc.stdout else ""
                self.assertEqual("READY", line)

                ctx = ScanContext(
                    home_dir=base,
                    live_mode=False,
                    enable_memory_scan=True,
                )
                engine2_live_proc.run(ctx)

                child_findings = [f for f in ctx.findings if f.pid == proc.pid]
                rids = {f.rule_id for f in child_findings}
                self.assertIn("E2-FD-DELETED-FILE", rids, f"Expected deleted FD on live child PID {proc.pid}, got {rids}")
                self.assertIn("E2-MAP-DELETED-BIN", rids, f"Expected deleted mmap on live child PID {proc.pid}, got {rids}")
                self.assertIn("E2-RAM-STRICT-SIG", rids, f"Expected RAM strict hit on live child PID {proc.pid}, got {rids}")
                self.assertIn("E2-RAM-MODULE-CLUSTER", rids, f"Expected RAM cluster hit on live child PID {proc.pid}, got {rids}")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                for st in (proc.stdout, proc.stderr):
                    if st is not None:
                        st.close()
                if jar_path.exists():
                    jar_path.unlink()

    def test_real_live_jvm_javaagent_jcmd_and_ram(self) -> None:
        """Spawn a REAL Linux OpenJDK JVM with -javaagent and scan via live jcmd + /proc/<pid>/mem."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_dir = base / "src"
            cls_dir = base / "cls"
            src_dir.mkdir()
            cls_dir.mkdir()

            agent_java = src_dir / "TestAgent.java"
            agent_java.write_text(
                "import java.lang.instrument.Instrumentation;\n"
                "public class TestAgent {\n"
                "    public static void premain(String args, Instrumentation inst) {}\n"
                "}\n",
                encoding="utf-8",
            )
            main_java = src_dir / "KillAuraHost.java"
            main_java.write_text(
                "public class KillAuraHost {\n"
                "    public static void main(String[] args) throws Exception {\n"
                "        String marker = new StringBuilder(\"vape\").append(\"v4_jvm_heap_test\").toString();\n"
                "        String cluster = \"KillAura AutoClicker SelfDestruct Reach Velocity\";\n"
                "        System.out.println(\"JVM_READY \" + marker.length() + cluster.length());\n"
                "        System.out.flush();\n"
                "        Thread.sleep(60000);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            subprocess.check_call(["javac", "-d", str(cls_dir), str(agent_java), str(main_java)])

            agent_jar = base / "agent.jar"
            make_jar(
                agent_jar,
                {
                    "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nPremain-Class: TestAgent\n",
                    "TestAgent.class": (cls_dir / "TestAgent.class").read_bytes(),
                },
            )

            proc = subprocess.Popen(
                [
                    "java",
                    f"-javaagent:{agent_jar}",
                    "-Xmx128m",
                    "-cp",
                    str(cls_dir),
                    "KillAuraHost",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                line = proc.stdout.readline().strip() if proc.stdout else ""
                self.assertTrue(line.startswith("JVM_READY"), f"Unexpected JVM stdout: {line}")

                ctx = ScanContext(
                    home_dir=base,
                    live_mode=True,
                    enable_memory_scan=True,
                    max_mem_scan_bytes_per_proc=128 * 1024 * 1024,
                )
                engine2_live_proc.run(ctx)

                jvm_findings = [f for f in ctx.findings if f.pid == proc.pid]
                rids = {f.rule_id for f in jvm_findings}
                self.assertIn("E2-JVM-AGENT-ARG", rids, f"Missing E2-JVM-AGENT-ARG on live JVM PID {proc.pid}: {rids}")
                self.assertIn("E2-PROC-CHEAT-NAME", rids, f"Missing E2-PROC-CHEAT-NAME on KillAuraHost JVM PID {proc.pid}: {rids}")
                self.assertTrue(
                    "E2-RAM-STRICT-SIG" in rids or "E2-RAM-MODULE-CLUSTER" in rids,
                    f"Expected RAM signature in live JVM /proc/{proc.pid}/mem, got {rids}",
                )
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                for st in (proc.stdout, proc.stderr):
                    if st is not None:
                        st.close()


if __name__ == "__main__":
    unittest.main()

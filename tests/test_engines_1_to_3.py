"""Tests for Engines 1, 2, and 3 (Integrity, Live /proc & RAM, Input/Macro)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ss_core import engine1_integrity, engine2_live_proc, engine3_input_macro
from ss_core.models import ScanContext
from tests.sim_lab import build_clean_baseline, write_simulated_proc_entry


class TestEngine1Integrity(unittest.TestCase):
    def test_clean_baseline_no_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine1_integrity.run(ctx)
            self.assertEqual([], [f.rule_id for f in ctx.findings])

    def test_anti_forensic_evasion_tricks_caught(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            # 1. Recent reboot
            (proc / "uptime").write_text("420.0 1000.0\n", encoding="utf-8")
            # 2. bash_history -> /dev/null
            bh = home / ".bash_history"
            bh.unlink()
            os.symlink("/dev/null", bh)
            # 3. zsh_history with shred + timestomp
            zh = home / ".zsh_history"
            zh.write_text("shred -u /tmp/vapev4.jar\nhistory -c\nsetfattr -x user.xdg.origin.url mod.jar\n")
            old_t = 1700000000.0
            os.utime(zh, (old_t, old_t))
            # 4. PATH shadow wrapper script for `ps`
            lbin = home / ".local/bin"
            lbin.mkdir(parents=True, exist_ok=True)
            fake_ps = lbin / "ps"
            fake_ps.write_text("#!/bin/sh\n/usr/bin/ps \"$@\" | grep -v vape\n", encoding="utf-8")
            os.chmod(fake_ps, 0o755)
            # 5. /etc/ld.so.preload + bashrc LD_PRELOAD & alias
            (root / "etc/ld.so.preload").write_text("/tmp/libhook.so\n", encoding="utf-8")
            (home / ".bashrc").write_text(
                "export LD_PRELOAD=/dev/shm/cheat.so\n"
                "export JAVA_TOOL_OPTIONS=-javaagent:/tmp/a.jar\n"
                "alias jcmd='echo disabled'\n",
                encoding="utf-8",
            )
            # 6. Multi-monitor
            (root / "sys/class/drm/card0-HDMI-1").mkdir(parents=True, exist_ok=True)
            (root / "sys/class/drm/card0-HDMI-1/status").write_text("connected\n", encoding="utf-8")

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine1_integrity.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E1-REBOOT-RECENT",
                "E1-HIST-DEVNULL",
                "E1-HIST-TIMESTOMP",
                "E1-HIST-ANTIFORENSIC-CMD",
                "E1-PATH-SHADOW-SCRIPT",
                "E1-ETC-LD-PRELOAD",
                "E1-RC-LDPRELOAD",
                "E1-RC-JAVA-TOOL-OPTS",
                "E1-RC-ALIAS-HIJACK",
                "E1-MULTI-MONITOR",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")


class TestEngine2LiveProc(unittest.TestCase):
    def test_clean_baseline_proc_no_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine2_live_proc.run(ctx)
            self.assertEqual([], [f.rule_id for f in ctx.findings])

    def test_simulated_proc_injection_ram_and_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))

            # Build fake RAM memory buffer (chunked boundary + UTF-16LE + cluster + reflective ELF)
            buf = bytearray(b"\x00" * 4096)
            # Strict UTF-16LE signature
            sig_u16 = "doomsdayclient".encode("utf-16le")
            buf[100 : 100 + len(sig_u16)] = sig_u16
            # Contextual cluster in 64KB window
            cluster = b" KillAura AutoClicker SelfDestruct Reach Velocity "
            buf[500 : 500 + len(cluster)] = cluster
            # Reflective ELF header
            elf_hdr = b"\x7fELF\x02\x01\x01" + (b"\x00" * 9) + b"\x03\x00" + (b"\x00" * 8)
            buf[1000 : 1000 + len(elf_hdr)] = elf_hdr

            write_simulated_proc_entry(
                proc,
                pid=9991,
                comm="kworker/u8:1",  # masquerade!
                cmdline=[
                    "java",
                    "-javaagent:/tmp/injector.jar",
                    "-XX:+DisableAttachMechanism",
                    "net.minecraft.client.main.Main",
                ],
                exe_target="/memfd:payload (deleted)",
                tracer_pid=1234,
                environ={"LD_PRELOAD": "/dev/shm/hook.so"},
                maps_lines=[
                    f"0000-1000 rw-p 00000000 00:00 0 ",
                    "7f00-7f01 r-xp 00000000 08:01 55 /tmp/evil_cheat.so (deleted)",
                    "8000-8001 r-xp 00000000 00:00 0 /memfd:jit_evil",
                ],
                fds={
                    "3": "/tmp/hidden.jar (deleted)",
                    "4": "/dev/uinput",
                },
                ns={
                    "mnt": "mnt:[4026539999]",  # isolated container namespace!
                    "pid": "pid:[4026531840]",
                    "net": "net:[4026531840]",
                    "user": "user:[4026531840]",
                },
                cgroup="0::/user.slice/libpod-12345.scope",
                mem_bytes=bytes(buf),
            )

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine2_live_proc.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E2-PROC-TRACERPID",
                "E2-PROC-MEMFD-EXE",
                "E2-PROC-MASQUERADE",
                "E2-PROC-LDPRELOAD",
                "E2-JVM-AGENT-ARG",
                "E2-JVM-DISABLE-ATTACH",
                "E2-PROC-ISOLATED-NS",
                "E2-MAP-DELETED-BIN",
                "E2-MAP-TMP-LIB",
                "E2-MAP-EXEC-MEMFD",
                "E2-FD-DELETED-FILE",
                "E2-FD-UINPUT-ACCESS",
                "E2-RAM-STRICT-SIG",
                "E2-RAM-MODULE-CLUSTER",
                "E2-RAM-REFLECTIVE-ELF",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")


class TestEngine3InputMacro(unittest.TestCase):
    def test_clean_baseline_input_no_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine3_input_macro.run(ctx)
            self.assertEqual([], [f.rule_id for f in ctx.findings])

    def test_macro_devices_presets_and_scripts_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            (proc / "bus/input/devices").write_text(
                'N: Name="ydotool virtual device"\n'
                'P: Phys=uinput\n'
                'H: Handlers=event9\n\n',
                encoding="utf-8",
            )
            (root / "tmp").mkdir(parents=True, exist_ok=True)
            (root / "tmp/.ydotool_socket").write_text("", encoding="utf-8")

            ir_dir = home / ".config/input-remapper-2/presets/Logitech"
            ir_dir.mkdir(parents=True, exist_ok=True)
            (ir_dir / "minecraft_pvp.json").write_text(
                '[{"input_combination":[{"type":1,"code":275}],"target_uinput":"mouse","output_symbol":"repeat(20, key(BTN_LEFT)).wait(25)"}]',
                encoding="utf-8",
            )
            (home / ".config/input-remapper-2/config.json").write_text(
                '{"autoload":{"Logitech":"minecraft_pvp"}}', encoding="utf-8"
            )

            sol_dir = home / ".config/solaar"
            sol_dir.mkdir(parents=True, exist_ok=True)
            (sol_dir / "rules.yaml").write_text("- Rule:\n  - MouseClick: [left, 15]\n", encoding="utf-8")

            (home / ".config/xclicker").mkdir(parents=True, exist_ok=True)
            (home / ".xbindkeysrc").write_text('"xdotool click --repeat 20 1"\n  b:8\n', encoding="utf-8")

            script = home / "Desktop/fast_click.py"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "import evdev, time\nfrom evdev import UInput\n# loop\nwhile True:\n    time.sleep(0.03)\n",
                encoding="utf-8",
            )

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine3_input_macro.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E3-VIRTUAL-UINPUT-DEVICE",
                "E3-YDOTOOL-SOCKET",
                "E3-INPUT-REMAPPER-MACRO",
                "E3-INPUT-REMAPPER-AUTOLOAD",
                "E3-SOLAAR-RULE",
                "E3-XCLICKER-CONFIG",
                "E3-HOTKEY-MACRO",
                "E3-MACRO-SCRIPT",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")


if __name__ == "__main__":
    unittest.main()

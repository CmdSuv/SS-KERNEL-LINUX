"""Adversarial regression tests for plugged bypasses and real-host false-positive guards."""

from __future__ import annotations

import io
import json
import os
import struct
import tempfile
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
from ss_core.utils import match_cheat_signatures
from tests.sim_lab import build_clean_baseline, write_simulated_proc_entry


def _make_adam7_rgba_png(width: int = 8, height: int = 8) -> bytes:
    """Create a genuine PNG-spec Adam7 interlaced RGBA image (top half alpha=0, bottom alpha=255)."""
    passes = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))
    raw = bytearray()
    for xs, ys, xstep, ystep in passes:
        pw = (width - xs + xstep - 1) // xstep if width > xs else 0
        ph = (height - ys + ystep - 1) // ystep if height > ys else 0
        if pw == 0 or ph == 0:
            continue
        for py in range(ph):
            raw.append(0)
            y = ys + py * ystep
            alpha = 0 if y < (height // 2) else 255
            for _ in range(pw):
                raw.extend((120, 120, 120, alpha))

    def _chunk(ctype: bytes, cdata: bytes) -> bytes:
        return struct.pack(">I", len(cdata)) + ctype + cdata + struct.pack(">I", zlib.crc32(ctype + cdata) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 1)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(bytes(raw))) + _chunk(b"IEND", b"")


def _make_indexed_4bit_png(width: int = 8, height: int = 8) -> bytes:
    """Create a 4-bit indexed PNG with PLTE + tRNS where half the pixels reference alpha=0."""
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        byte_val = 0x00 if y < (height // 2) else 0x11
        raw.extend([byte_val] * (width // 2))

    def _chunk(ctype: bytes, cdata: bytes) -> bytes:
        return struct.pack(">I", len(cdata)) + ctype + cdata + struct.pack(">I", zlib.crc32(ctype + cdata) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 4, 3, 0, 0, 0)
    plte = b"\x00\x00\x00\x88\x88\x88"
    trns = b"\x00\xff"
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"PLTE", plte)
        + _chunk(b"tRNS", trns)
        + _chunk(b"IDAT", zlib.compress(bytes(raw)))
        + _chunk(b"IEND", b"")
    )


def _make_minimal_class(this_name: str, utf8_literals: list[str], indy_count: int = 0) -> bytes:
    """Construct a valid minimal Java .class byte payload for testing Constant Pool parsing."""
    cp_entries: list[bytes] = []

    def _add_utf8(s: str) -> int:
        b = s.encode("utf-8")
        cp_entries.append(b"\x01" + struct.pack(">H", len(b)) + b)
        return len(cp_entries)

    def _add_class(name_idx: int) -> int:
        cp_entries.append(b"\x07" + struct.pack(">H", name_idx))
        return len(cp_entries)

    t_utf = _add_utf8(this_name)
    t_cls = _add_class(t_utf)
    s_utf = _add_utf8("java/lang/Object")
    s_cls = _add_class(s_utf)
    for lit in utf8_literals:
        _add_utf8(lit)
    for i in range(indy_count):
        # InvokeDynamic (tag 18): bootstrap_method_attr_index(2) + name_and_type_index(2)
        nat_utf = _add_utf8(f"m{i}")
        desc_utf = _add_utf8("()Ljava/lang/String;")
        cp_entries.append(b"\x0c" + struct.pack(">HH", nat_utf, desc_utf))
        nat_idx = len(cp_entries)
        cp_entries.append(b"\x12" + struct.pack(">HH", 0, nat_idx))

    buf = bytearray()
    buf.extend(b"\xca\xfe\xba\xbe")
    buf.extend(struct.pack(">HH", 0, 65))  # Java 21
    buf.extend(struct.pack(">H", len(cp_entries) + 1))
    for ent in cp_entries:
        buf.extend(ent)
    buf.extend(struct.pack(">HHH", 0x0021, t_cls, s_cls))
    buf.extend(struct.pack(">HHHH", 0, 0, 0, 0))
    return bytes(buf)


class TestBypassHardening(unittest.TestCase):
    def test_camelcase_cheat_signatures_and_word_boundaries(self) -> None:
        s1, h1, _ = match_cheat_signatures("me/ghost/KillAuraModule AutoClicker")
        self.assertIn("killaura", h1)
        self.assertIn("autoclicker", h1)

        s2, h2, _ = match_cheat_signatures("myKillAuraV4 key_key.debug.showHitboxes")
        self.assertIn("killaura", h2)
        self.assertIn("hitboxes", h2)

        # Clean English words must NOT false-positive
        s_clean, h_clean, l_clean = match_cheat_signatures("breach outreach skilled claimassistants")
        self.assertEqual((s_clean, h_clean, l_clean), ([], [], []))

    def test_ld_audit_perfdisable_gamedir_and_proxy_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            hidden_mc = Path(td) / "hidden_instance"
            (hidden_mc / "mods").mkdir(parents=True, exist_ok=True)
            (hidden_mc / "config").mkdir(parents=True, exist_ok=True)
            (hidden_mc / "options.txt").write_text("gamma:5.0\n", encoding="utf-8")

            # Add LD_AUDIT to .bashrc too
            (home / ".bashrc").write_text("export LD_AUDIT=/tmp/audit_hook.so\n", encoding="utf-8")

            write_simulated_proc_entry(
                proc,
                pid=7777,
                comm="java",
                cmdline=[
                    "java",
                    "-XX:+PerfDisableSharedMem",
                    "-DsocksProxyHost=127.0.0.1",
                    "--gameDir",
                    str(hidden_mc),
                    "net.minecraft.client.main.Main",
                ],
                environ={"LD_AUDIT": "/dev/shm/ghost_audit.so", "HOME": str(home)},
                maps_lines=[
                    "7f00-7f01 r-xp 00000000 00:00 0 /memfd:jit_evil",
                    "7f02-7f03 r--s 00000000 00:00 0 /memfd:shared-memory-region (deleted)",
                    "7f04-7f05 r-xp 00000000 00:00 0 /memfd:JITCode:QtQml (deleted)",
                ],
                fds={
                    "5": "/dev/shm/.com.valvesoftware.Steam.PyqUjp (deleted)",
                },
            )

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine1_integrity.run(ctx)
            engine2_live_proc.run(ctx)
            engine5_minecraft.run(ctx)
            engine7_network_usb.run(ctx)
            rids = {f.rule_id for f in ctx.findings}

            self.assertIn("E1-RC-LDAUDIT", rids)
            self.assertIn("E2-PROC-LDAUDIT", rids)
            self.assertIn("E2-JVM-PERF-DISABLE", rids)
            self.assertIn("E2-MAP-EXEC-MEMFD", rids)
            self.assertIn("E7-JVM-PROXY-FLAG", rids)
            self.assertIn("E5-OPTIONS-FULLBRIGHT", rids)  # Found via live --gameDir!
            # Benign Steam /dev/shm/*.Py* and QtQml/shared-memory-region (deleted) must NOT fire!
            self.assertNotIn("E2-FD-DELETED-FILE", rids)
            self.assertNotIn("E2-MAP-DELETED-BIN", rids)

    def test_ram_bounded_terms_no_browser_false_positive_and_detects_killaura(self) -> None:
        strict_hits: dict[str, list[str]] = {}
        cluster_hits: list[str] = []
        elf_hits: list[str] = []
        benign_buf = (
            b"https://legalclaimassistants.com/page\x00"
            b"ScheduleSelfDestruction.kClearUserDataUponProfileDestruction\x00"
        )
        engine2_live_proc._scan_region_bytes(benign_buf, 0x1000, "", strict_hits, cluster_hits, elf_hits)
        self.assertEqual(strict_hits, {})

        cheat_buf = b"com/ghost/modules/KillAura\x00triggerbot\x00SelfDestruct\x00"
        engine2_live_proc._scan_region_bytes(cheat_buf, 0x2000, "", strict_hits, cluster_hits, elf_hits)
        self.assertIn("killaura", strict_hits)
        self.assertIn("triggerbot", strict_hits)
        self.assertIn("selfdestruct", strict_hits)

    def test_disguised_virtual_uinput_sysfs_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            (proc / "bus/input/devices").write_text(
                'I: Bus=0003 Vendor=046d Product=c077 Version=0111\n'
                'N: Name="Logitech USB Optical Mouse"\n'
                'P: Phys=\n'
                'S: Sysfs=/devices/virtual/input/input99\n'
                'H: Handlers=mouse2 event19\n\n',
                encoding="utf-8",
            )
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine3_input_macro.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            self.assertIn("E3-VIRTUAL-UINPUT-SYSFS", rids)

    def test_adam7_and_4bit_indexed_xray_png_and_parent_air_model(self) -> None:
        res_adam7 = engine4_deep_files.analyze_png_transparency(_make_adam7_rgba_png())
        self.assertIsNotNone(res_adam7)
        self.assertAlmostEqual(res_adam7["transparent_ratio"], 0.5, places=2)

        res_idx4 = engine4_deep_files.analyze_png_transparency(_make_indexed_4bit_png())
        self.assertIsNotNone(res_idx4)
        self.assertAlmostEqual(res_idx4["transparent_ratio"], 0.5, places=2)

        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            pack = home / ".minecraft/resourcepacks/model_parent_xray.zip"
            pack.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(pack, "w") as zf:
                zf.writestr("assets/minecraft/models/block/stone.json", json.dumps({"parent": "minecraft:block/air"}))
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, deep_home_scan=False, live_mode=False)
            engine4_deep_files.run(ctx)
            self.assertIn("E4-RP-XRAY-EMPTY-MODEL", {f.rule_id for f in ctx.findings})

    def test_fabric_concat_recipe_classes_do_not_false_positive_obfuscation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            mods_dir = home / ".minecraft/mods"
            mods_dir.mkdir(parents=True, exist_ok=True)
            jar_path = mods_dir / "fabric-api-mock.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr("fabric.mod.json", json.dumps({"id": "fabric-api-base", "name": "Fabric API"}))
                for idx in range(5):
                    # Java 9+ StringConcatFactory stores \x01 and \x02 inside CONSTANT_Utf8 string literals!
                    cls = _make_minimal_class(
                        f"net/fabricmc/fabric/impl/ModClass{idx}",
                        ["Value=\x01 count=\x02", "Tag:\x01"],
                        indy_count=22,
                    )
                    zf.writestr(f"net/fabricmc/fabric/impl/ModClass{idx}.class", cls)
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, deep_home_scan=False, live_mode=False)
            engine4_deep_files.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            self.assertNotIn("E4-JAR-OBFUSCATION", rids)

    def test_pe_injector_and_antiforensic_script_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            dl = home / "Downloads"
            dl.mkdir(parents=True, exist_ok=True)
            (dl / "injector.dll").write_bytes(
                b"MZ\x90\x00" + b"\x00" * 120 + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
            )
            (dl / "cleanup.sh").write_text("#!/bin/bash\nhistory -c\nshred -u /tmp/cheat.jar\n", encoding="utf-8")

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, deep_home_scan=False, live_mode=False)
            engine4_deep_files.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            self.assertIn("E4-PE-CHEAT-OR-INJECTOR", rids)
            self.assertIn("E4-SCRIPT-CHEAT-OR-ANTIFORENSIC", rids)

    def test_vanilla_debug_keybinds_clean_and_gammautils_downgraded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            mc = home / ".minecraft"
            (mc / "options.txt").write_text(
                "gamma:1.0\nkey_key.debug.showHitboxes:key.keyboard.b\nlastServer:mc.example.org\n",
                encoding="utf-8",
            )
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine5_minecraft.run(ctx)
            self.assertEqual([], [f.rule_id for f in ctx.findings])

            # Now test standalone gammautils in options.txt -> MEDIUM, not CRITICAL
            (mc / "options.txt").write_text(
                "gamma:1.0\nkey_key.gammautils.toggle:key.keyboard.g\n", encoding="utf-8"
            )
            ctx2 = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine5_minecraft.run(ctx2)
            kb_findings = [f for f in ctx2.findings if f.rule_id == "E5-OPTIONS-CHEAT-KEYBIND"]
            self.assertEqual(len(kb_findings), 1)
            self.assertEqual(kb_findings[0].severity, Severity.MEDIUM)

    def test_e8_jvm_inject_chain_ignores_lunar_info_agent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            ctx_clean = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            ctx_clean.add_finding(
                Finding(
                    rule_id="E2-JVM-AGENT-ARG",
                    engine="Engine 2",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    category="JVM Agent",
                    title="Lunar Ichor",
                    description="Benign Lunar agent",
                )
            )
            ctx_clean.add_finding(
                Finding(
                    rule_id="E4-JAR-DANGEROUS-API",
                    engine="Engine 4",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    category="API",
                    title="Benign check",
                    description="Test",
                )
            )
            engine8_reporter.correlate_findings(ctx_clean)
            self.assertNotIn("E8-CORR-JVM-INJECT-CHAIN", {f.rule_id for f in ctx_clean.findings})

            ctx_evil = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            ctx_evil.add_finding(
                Finding(
                    rule_id="E2-PROC-LDAUDIT",
                    engine="Engine 2",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Injection",
                    title="LD_AUDIT",
                    description="Inject",
                )
            )
            ctx_evil.add_finding(
                Finding(
                    rule_id="E4-JAR-CLASS-CONSTANT-POOL",
                    engine="Engine 4",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Bytecode",
                    title="Cheat",
                    description="Inject",
                )
            )
            engine8_reporter.correlate_findings(ctx_evil)
            self.assertIn("E8-CORR-JVM-INJECT-CHAIN", {f.rule_id for f in ctx_evil.findings})


if __name__ == "__main__":
    unittest.main()

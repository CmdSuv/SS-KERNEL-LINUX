"""Tests for Engine 4: Real compiled .class Constant Pool, ELF, Polyglot, xattr, Timestomp, X-Ray PNG & Shaders."""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from ss_core import engine4_deep_files
from ss_core.models import ScanContext
from tests.sim_lab import (
    build_clean_baseline,
    compile_c_shared_so,
    compile_java_to_class_bytes,
    make_jar,
    make_minimal_png,
    make_paeth_filtered_png,
)


class TestEngine4DeepFiles(unittest.TestCase):
    def test_clean_baseline_no_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine4_deep_files.run(ctx)
            self.assertEqual([], [f.rule_id for f in ctx.findings])

    def test_real_compiled_java_class_spoofed_jar_jij_xattr_timestomp(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            build_tmp = base / "build_java"
            build_tmp.mkdir()

            # Compile a real Java class calling java.awt.Robot and containing KillAura constant pool strings
            java_src = (
                "package net.shadow;\n"
                "import java.awt.Robot;\n"
                "public class CombatHelper {\n"
                "    public static final String MODULE = \"KillAura\";\n"
                "    public static final String CLIENT = \"MeteorClient\";\n"
                "    public void click() throws Exception {\n"
                "        Robot r = new Robot();\n"
                "        r.mousePress(16);\n"
                "    }\n"
                "}\n"
            )
            cls_rel, cls_bytes = compile_java_to_class_bytes(
                build_tmp, "net/shadow", "CombatHelper", java_src
            )

            # Also compile a nested Jar-in-Jar class with Agent manifest
            jij_buf = io.BytesIO()
            with zipfile.ZipFile(jij_buf, "w") as nzf:
                nzf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\nPremain-Class: com.doomsdayclient.Agent\n")
                nzf.writestr(cls_rel, cls_bytes)

            # Package disguised as 'optifine-hd-u-i6.jar' in mods/
            spoof_jar = home / ".minecraft/mods/optifine-hd-u-i6.jar"
            make_jar(
                spoof_jar,
                {
                    "fabric.mod.json": json.dumps({"id": "shadowcombat", "name": "ShadowCombat"}).encode(),
                    "META-INF/jars/embedded_payload.jar": jij_buf.getvalue(),
                    cls_rel: cls_bytes,
                },
            )
            # Timestomp mtime 90 days into the past while ctime/btime remain NOW!
            old_ts = home / ".minecraft/mods/optifine-hd-u-i6.jar"
            past = os.stat(old_ts).st_mtime - (90 * 86400)
            os.utime(old_ts, (past, past))

            # Set xattr if filesystem supports it (btrfs/ext4/tmpfs user xattr)
            xattr_supported = False
            try:
                os.setxattr(spoof_jar, "user.xdg.origin.url", b"https://vape.gg/files/release.jar")
                xattr_supported = True
            except OSError:
                pass

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine4_deep_files.run(ctx)
            rids = {f.rule_id for f in ctx.findings}

            for expected in (
                "E4-JAR-SPOOFED-MOD-NAME",
                "E4-JAR-CLASS-CONSTANT-POOL",
                "E4-JAR-DANGEROUS-API",
                "E4-JAR-AGENT-MANIFEST",
                "E4-TIMESTOMP-ANOMALY",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")

            if xattr_supported:
                self.assertIn("E4-XATTR-CHEAT-URL", rids)

    def test_real_compiled_elf_extension_spoof_and_polyglot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            c_dir = base / "c_src"
            c_dir.mkdir()

            so_path = compile_c_shared_so(
                c_dir,
                "hook",
                '#include <stdio.h>\n'
                'void Agent_OnLoad(void *vm) { printf("vapev4 loaded"); }\n'
                'void XTestFakeButtonEvent(void) {}\n'
                'void Java_me_vape_Bridge_init(void) {}\n',
            )
            # Disguise compiled ELF as a .png inside Downloads!
            spoofed_elf = home / "Downloads/texture_preview.png"
            spoofed_elf.write_bytes(so_path.read_bytes())

            # Create a real PNG + appended ZIP polyglot in Downloads!
            valid_png = make_minimal_png(8, 8, (100, 100, 100, 255), 0)
            inner_zip_buf = io.BytesIO()
            with zipfile.ZipFile(inner_zip_buf, "w") as zf:
                zf.writestr("secret/KillAura.txt", b"vape.gg")
            poly = home / "Downloads/wallpaper_polyglot.png"
            poly.write_bytes(valid_png + inner_zip_buf.getvalue())

            # Symlink escaping mods/ to /tmp
            evil_target = root / "tmp/outside_mod.jar"
            evil_target.parent.mkdir(parents=True, exist_ok=True)
            make_jar(evil_target, {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"})
            os.symlink(evil_target, home / ".minecraft/mods/legit_link.jar")

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine4_deep_files.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E4-EXT-SPOOF",
                "E4-ELF-SUSPICIOUS",
                "E4-POLYGLOT-PAYLOAD",
                "E4-MC-SUSPICIOUS-SYMLINK",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")

    def test_xray_png_filters_block_model_fullbright_and_shaders(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)

            # 1. X-Ray resource pack using Paeth/Sub/Up/Avg filtered RGBA PNG with 50% transparent stone.png!
            xray_png = make_paeth_filtered_png(16, 16, alpha_zero_count=128)
            fullbright_lm = make_minimal_png(16, 16, (254, 254, 254, 255), 0)
            rp_zip = home / ".minecraft/resourcepacks/TotallyNotXray.zip"
            make_jar(
                rp_zip,
                {
                    "pack.mcmeta": b'{"pack":{"pack_format":34,"description":"FPS"}}',
                    "assets/minecraft/textures/block/stone.png": xray_png,
                    "assets/minecraft/optifine/lightmap/world0.png": fullbright_lm,
                    "assets/minecraft/models/block/deepslate.json": b'{"elements": []}',
                    "assets/minecraft/blockstates/netherrack.json": b'{"variants":{"":{"model":"minecraft:block/air"}}}',
                },
            )

            # 2. X-Ray Shader pack
            sp_zip = home / ".minecraft/shaderpacks/CaveVision.zip"
            make_jar(
                sp_zip,
                {
                    "shaders/gbuffers_terrain.fsh": (
                        b"uniform int mc_Entity;\nvoid main() {\n"
                        b"  if (mc_Entity != 14) { discard; }\n}\n"
                    ),
                },
            )

            # 3. Encrypted ZIP in Downloads (using system `zip` if available or crafted zip flag_bits=1)
            enc_zip = home / "Downloads/backup_mods.zip"
            raw_zip = io.BytesIO()
            with zipfile.ZipFile(raw_zip, "w") as zf:
                zf.writestr("secret.jar", b"dummy")
            zbytes = bytearray(raw_zip.getvalue())
            # Flip general purpose bit flag bit 0 (encrypted) in local header & central dir
            zbytes[6] |= 0x01
            cd_idx = zbytes.find(b"PK\x01\x02")
            if cd_idx != -1:
                zbytes[cd_idx + 8] |= 0x01
            enc_zip.write_bytes(bytes(zbytes))

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine4_deep_files.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E4-RP-XRAY-TEXTURE",
                "E4-RP-FULLBRIGHT-LIGHTMAP",
                "E4-RP-XRAY-EMPTY-MODEL",
                "E4-RP-XRAY-BLOCKSTATE",
                "E4-SHADER-XRAY",
                "E4-ZIP-ENCRYPTED",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")

    def test_glibc_runtime_skip_vs_trojanized_libc(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            ctx_clean = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            benign_libc = (
                b"\x7fELF" + b"\x00" * 60
                + b"\nGNU C Library (GNU libc) stable release version 2.40.\nptrace\nprocess_vm_writev\nprocess_vm_readv\n"
            )
            libc_path = root / "tmp/container_stage/libc.so.6"
            libc_path.parent.mkdir(parents=True, exist_ok=True)
            libc_path.write_bytes(benign_libc)
            engine4_deep_files.analyze_elf_binary(ctx_clean, libc_path, benign_libc)
            self.assertEqual([f for f in ctx_clean.findings if f.rule_id == "E4-ELF-SUSPICIOUS"], [])

            ctx_trojan = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            trojan_libc = benign_libc + b"Agent_OnLoad\nJava_me_vape_Bridge\n"
            engine4_deep_files.analyze_elf_binary(ctx_trojan, libc_path, trojan_libc)
            self.assertIn("E4-ELF-SUSPICIOUS", {f.rule_id for f in ctx_trojan.findings})


if __name__ == "__main__":
    unittest.main()

"""Dual-sided False-Positive Resistance + Zero-Bypass Anti-Cheat Regression Suite.

Every real-world benign case is paired directly with its adversarial attack counterpart
to prove false positives are eliminated WITHOUT opening any bypasses.
"""

from __future__ import annotations

import os
import sqlite3
import struct
import tempfile
import time
import unittest
from pathlib import Path

from ss_core import (
    engine1_integrity,
    engine2_live_proc,
    engine4_deep_files,
    engine5_minecraft,
    engine6_desktop_traces,
    engine7_network_usb,
    engine8_reporter,
    engine9_kernel,
)
from ss_core.models import ScanContext, Severity
from tests.sim_lab import (
    build_clean_baseline,
    make_jar,
    write_simulated_proc_entry,
)


def _minimal_class_bytes(utf8_entries: list[str]) -> bytes:
    """Build a valid minimal JVM .class file whose Constant Pool contains utf8_entries."""
    out = bytearray(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d")  # magic + Java 17 version
    cp_count = len(utf8_entries) + 1
    out.extend(struct.pack(">H", cp_count))
    for s in utf8_entries:
        b = s.encode("utf-8")
        out.append(1)  # CONSTANT_Utf8
        out.extend(struct.pack(">H", len(b)))
        out.extend(b)
    # access_flags, this_class, super_class, interfaces_count, fields_count, methods_count, attrs_count
    out.extend(struct.pack(">HHHHHHH", 0x0021, 0, 0, 0, 0, 0, 0))
    return bytes(out)


class TestFalsePositiveAndAntiBypassRegression(unittest.TestCase):
    # ------------------------------------------------------------------
    # 1. Ring-0 Self VMA / Hidden Helper PID / Distro LSM eBPF vs Real Attacks
    # ------------------------------------------------------------------
    def test_ring0_self_meipass_hidden_helper_and_userns_restrict_vs_attacks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            my_pid = os.getpid()
            # Benign Ring-0 snapshot matching real Bazzite desktop:
            # - MC-SS-Sentinel's own /tmp/_MEI.../libQt6Core.so.6 (shm=1, rwx=0)
            # - Exited helper child TGID=99100 sharing self_exe
            # - Distro built-in LSM eBPF 'userns_restrict' uid=0 (no sensitive hook target)
            benign_snap = {
                "ok": True,
                "lkm_loaded": True,
                "lkm_unloaded_cleanly": True,
                "proc_snapshots": {
                    "status": "STATUS|kernel=7.3.4-bazzite|module_ok=1",
                    "integrity": "",
                    "tasks_vma": (
                        f"TASK|pid={my_pid}|tgid={my_pid}|ppid=1|real_ppid=1|comm=MC-SS-Sentinel|exe=/usr/local/MC-SS-Sentinel|ptrace=0x0\n"
                        f"TASK|pid=99100|tgid=99100|ppid={my_pid}|real_ppid={my_pid}|comm=MC-SS-Sentinel|exe=/usr/local/MC-SS-Sentinel|ptrace=0x0\n"
                        f"VMA_ANOM|pid={my_pid}|comm=MC-SS-Sentinel|start=0x7f00|end=0x8f00|size=4096|rwx=0|anon=0|memfd=0|shm=1|del=0|elf=1|pe=0|jni_hits=0|file=/tmp/_MEIabc123/libQt6Core.so.6|head=7f454c46\n"
                        "VMA_ANOM|pid=5000|comm=AppImageApp|start=0x7f10|end=0x8f10|size=4096|rwx=0|anon=0|memfd=0|shm=1|del=0|elf=1|pe=0|jni_hits=0|file=/tmp/.mount_Lunar123/libfoo.so|head=7f454c46\n"
                    ),
                    "pci_iommu": "",
                    "events": "",
                },
                "root_extras": {
                    "proc_pids_at_lkm": [my_pid, 1],
                    "sentinel_self_pids": [my_pid],
                    "sentinel_self_meipasses": ["/tmp/_MEIabc123"],
                    "sentinel_self_exe": "/usr/local/MC-SS-Sentinel",
                    "native_probe": {
                        "bpf": {
                            "progs": [
                                {"id": 59, "type": "LSM", "name": "userns_restrict", "uid": 0, "jited_len": 715, "run_cnt": 0},
                            ],
                            "links": [],
                        }
                    },
                },
            }
            ctx_clean = ScanContext(
                home_dir=home, root_prefix=root, proc_root=proc, live_mode=False, kernel_snapshot_data=benign_snap
            )
            engine9_kernel.run(ctx_clean)
            clean_rids = {f.rule_id for f in ctx_clean.findings}
            self.assertNotIn("E9-KERNEL-VMA-REFLECTIVE-ELF", clean_rids)
            self.assertNotIn("E9-HIDDEN-PID-RING0", clean_rids)
            self.assertNotIn("E9-EBPF-SUSPICIOUS-PROG", clean_rids)

            # Adversarial counterparts MUST STILL FIRE CRITICAL!
            attack_snap = {
                "ok": True,
                "lkm_loaded": True,
                "lkm_unloaded_cleanly": True,
                "proc_snapshots": {
                    "status": "STATUS|kernel=7.3.4-bazzite|module_ok=1",
                    "integrity": "",
                    "tasks_vma": (
                        "TASK|pid=88888|tgid=88888|ppid=1|real_ppid=1|comm=evil_rk|exe=/tmp/evil_rk|ptrace=0x0\n"
                        "VMA_ANOM|pid=4444|comm=java|start=0x7f20|end=0x8f20|size=4096|rwx=0|anon=0|memfd=0|shm=1|del=0|elf=1|pe=0|jni_hits=0|file=/tmp/injected_cheat.so|head=7f454c46\n"
                    ),
                    "pci_iommu": "",
                    "events": "",
                },
                "root_extras": {
                    "proc_pids_at_lkm": [1, 4444],
                    "sentinel_self_pids": [my_pid],
                    "sentinel_self_meipasses": ["/tmp/_MEIabc123"],
                    "sentinel_self_exe": "/usr/local/MC-SS-Sentinel",
                    "native_probe": {
                        "bpf": {
                            "progs": [
                                # Rootkit impersonating 'userns_restrict' via KPROBE -> MUST BE CAUGHT!
                                {"id": 99, "type": "KPROBE", "name": "userns_restrict", "uid": 0, "jited_len": 1200, "run_cnt": 5, "attach_target": "__x64_sys_getdents64"},
                            ],
                            "links": [],
                        }
                    },
                },
            }
            ctx_atk = ScanContext(
                home_dir=home, root_prefix=root, proc_root=proc, live_mode=False, kernel_snapshot_data=attack_snap
            )
            engine9_kernel.run(ctx_atk)
            atk_rids = {f.rule_id for f in ctx_atk.findings}
            self.assertIn("E9-KERNEL-VMA-REFLECTIVE-ELF", atk_rids)
            self.assertIn("E9-HIDDEN-PID-RING0", atk_rids)
            self.assertIn("E9-EBPF-SUSPICIOUS-PROG", atk_rids)

    # ------------------------------------------------------------------
    # 2. dconf/user (deleted) + bazaar App Store + Wine rw-p vs Real RAM Cheat
    # ------------------------------------------------------------------
    def test_dconf_bazaar_and_wine_rwp_vs_real_ram_injection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            valid_elf = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8) + struct.pack("<H", 3) + (b"\x00" * 16)
            # Benign 1: /usr/bin/bazaar with dconf/user (deleted) and Flathub catalog text in heap
            write_simulated_proc_entry(
                proc,
                pid=67651,
                comm="bazaar",
                cmdline=["/usr/bin/bazaar"],
                exe_target="/usr/bin/bazaar",
                maps_lines=[
                    "55fa68190000-55fa681a0000 rw-p 00000000 00:00 0 [heap]",
                    "7f0000001000-7f0000005000 r--p 00000000 08:01 12 /var/home/COSMOS/.config/dconf/user (deleted)",
                ],
                mem_bytes=b"Flathub catalog: xyz.xclicker.xclicker blazing fast autoclicker".ljust(4096, b"\x00"),
            )
            # Benign 2: Wine javaw.exe with ELF bytes ONLY in non-executable rw-p anon buffer
            write_simulated_proc_entry(
                proc,
                pid=43573,
                comm="javaw.exe",
                cmdline=["C:\\java\\bin\\javaw.exe", "-Xmx2G", "net.minecraft.client.main.Main"],
                exe_target="/usr/bin/wine64-preloader",
                maps_lines=[
                    "00000000-00001000 rw-p 00000000 00:00 0",
                ],
                mem_bytes=valid_elf.ljust(4096, b"\x00"),
            )
            # Benign 3: Firefox Flatpak with LD_PRELOAD=libmozsandbox.so + Electron app with app.asar/libffmpeg.so + Gradle Daemon
            write_simulated_proc_entry(
                proc,
                pid=167419,
                comm="Web Content",
                cmdline=["/app/lib/firefox/firefox-bin", "-contentproc"],
                exe_target="/app/lib/firefox/firefox-bin",
                environ={"LD_PRELOAD": "libmozsandbox.so"},
                maps_lines=["7f0000100000-7f0000200000 r-xp 00000000 08:01 11 /app/lib/firefox/libmozsandbox.so"],
            )
            write_simulated_proc_entry(
                proc,
                pid=6629,
                comm="claude-desktop",
                cmdline=["/home/u/.local/opt/claude-desktop/claude-desktop"],
                exe_target="/home/u/.local/opt/claude-desktop/claude-desktop",
                maps_lines=[
                    "1a5b3ebdf000-1a5b3ebe7000 rwxp 00000000 00:00 0",
                    "563adaac0000-563afaac0000 rwxp 00000000 00:00 0",
                    "7f0000300000-7f0000400000 r--p 00000000 08:01 22 /home/u/.local/opt/claude-desktop/resources/app.asar",
                ],
            )
            write_simulated_proc_entry(
                proc,
                pid=61442,
                comm="java",
                cmdline=[
                    "java",
                    "-javaagent:/home/u/.gradle/wrapper/dists/gradle-9.8.0-bin/abc/gradle-9.8.0/lib/agents/gradle-instrumentation-agent-9.8.0.jar",
                    "org.gradle.launcher.daemon.bootstrap.GradleDaemon",
                ],
                exe_target="/usr/lib/jvm/java-21/bin/java",
                maps_lines=["7f0000500000-7f0000600000 r-xp 00000000 08:01 33 /usr/lib/jvm/java-21/lib/server/libjvm.so"],
            )
            ctx_clean = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False, enable_memory_scan=True)
            engine2_live_proc.run(ctx_clean)
            clean_rids = {f.rule_id for f in ctx_clean.findings}
            self.assertNotIn("E2-MAP-DELETED-BIN", clean_rids)
            self.assertNotIn("E2-RAM-STRICT-SIG", clean_rids)
            self.assertNotIn("E2-RAM-REFLECTIVE-ELF", clean_rids)
            self.assertNotIn("E2-PROC-LDPRELOAD", clean_rids)
            self.assertNotIn("E2-MAP-ANON-RWX", clean_rids)
            gradle_agents = [f for f in ctx_clean.findings if f.rule_id == "E2-JVM-AGENT-ARG"]
            self.assertEqual(1, len(gradle_agents))
            self.assertEqual(Severity.INFO, gradle_agents[0].severity)

            # Attack: Impersonator /tmp/bazaar + executable r-xp deleted .so + rwxp ELF + Minecraft spoofing gradle agent
            write_simulated_proc_entry(
                proc,
                pid=77700,
                comm="bazaar",
                cmdline=["/tmp/bazaar"],
                exe_target="/tmp/bazaar",
                maps_lines=[
                    "00000000-00001000 rwxp 00000000 00:00 0",
                    "7f1000000000-7f1000004000 r-xp 00000000 08:01 99 /tmp/ghost_inject.so (deleted)",
                ],
                mem_bytes=(valid_elf + b" vapev4_injector_payload ").ljust(4096, b"\x00"),
            )
            write_simulated_proc_entry(
                proc,
                pid=77701,
                comm="java",
                cmdline=[
                    "java",
                    "-javaagent:/home/u/.gradle/wrapper/dists/gradle-9.8.0-bin/abc/gradle-9.8.0/lib/agents/gradle-instrumentation-agent-9.8.0.jar",
                    "net.minecraft.client.main.Main",
                ],
                exe_target="/usr/lib/jvm/java-21/bin/java",
                environ={"LD_PRELOAD": "libmozsandbox.so"},
            )
            ctx_atk = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False, enable_memory_scan=True)
            engine2_live_proc.run(ctx_atk)
            atk_rids = {f.rule_id for f in ctx_atk.findings if f.pid == 77700}
            self.assertIn("E2-MAP-DELETED-BIN", atk_rids)
            self.assertIn("E2-RAM-STRICT-SIG", atk_rids)
            self.assertIn("E2-RAM-REFLECTIVE-ELF", atk_rids)
            mc_atk = [f for f in ctx_atk.findings if f.pid == 77701 and f.severity == Severity.CRITICAL]
            self.assertTrue(any(f.rule_id == "E2-JVM-AGENT-ARG" for f in mc_atk))
            self.assertTrue(any(f.rule_id == "E2-PROC-LDPRELOAD" for f in mc_atk))

    # ------------------------------------------------------------------
    # 3. Vanilla Minecraft / Fabric / Netty / Krypton / C2ME / Velocity / jctools vs Spoofed/Trojanized
    # ------------------------------------------------------------------
    def test_vanilla_fabric_krypton_c2me_velocity_vs_spoofed_krypton_and_trojan_native(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            mc_mods = home / ".minecraft/mods"
            mc_mods.mkdir(parents=True, exist_ok=True)

            # Benign 1: Vanilla MC + Fabric API + Netty constant pools
            make_jar(
                home / ".minecraft/versions/26.3/26.3.jar",
                {
                    "net/minecraft/client/main/Main.class": _minimal_class_bytes(["net/minecraft/Util", "startTimerHackThread", "TimerHack"]),
                    "net/minecraft/client/player/LocalPlayer.class": _minimal_class_bytes(["creativeFlight", "mayfly"]),
                },
            )
            make_jar(
                mc_mods / "fabric-registry-sync-v0-8.0.5.jar",
                {
                    "fabric.mod.json": b'{"id":"fabric-registry-sync-v0","name":"Fabric Registry Sync"}',
                    "net/fabricmc/fabric/mixin/registry/sync/MainMixin.class": _minimal_class_bytes(["startTimerHackThread", "TimerHack"]),
                },
            )
            make_jar(
                home / ".minecraft/libraries/io/netty/netty-buffer/4.2.16/netty-buffer-4.2.16.Final.jar",
                {
                    "io/netty/buffer/AdaptivePoolingAllocator.class": _minimal_class_bytes(["newChunks", "AdaptivePoolingAllocator"]),
                },
            )
            # Benign 2: Andrew Steinborn's legit Krypton + Velocity native + C2ME native + jctools Unsafe
            make_jar(
                mc_mods / "krypton-0.2.9.jar",
                {
                    "fabric.mod.json": b'{"id":"krypton","name":"Krypton","entrypoints":{"client":["me.steinborn.krypton.mod.client.KryptonClientInitializer"]}}',
                    "me/steinborn/krypton/mod/client/KryptonClientInitializer.class": _minimal_class_bytes(["me/steinborn/krypton/mod/client/KryptonClientInitializer"]),
                    "com/velocitypowered/natives/util/Natives.class": _minimal_class_bytes(["java/lang/System", "load", "java/lang/System.load", "sun/misc/Unsafe"]),
                    "macos_arm64/velocity-cipher.dylib": b"\xcf\xfa\xed\xfeVELOCITY_AES_CIPHER_CLEAN",
                },
            )
            make_jar(
                mc_mods / "c2me-opts-natives-math.jar",
                {
                    "fabric.mod.json": b'{"id":"c2me-opts-natives-math","name":"C2ME Math"}',
                    "linux-x86_64-libc2me-opts-natives-math.so": b"\x7fELF\x02\x01\x01\x00SIMD_MATH_CLEAN",
                },
            )
            make_jar(
                mc_mods / "jctools-core-4.0.5.jar",
                {
                    "org/jctools/counters/FixedSizeStripedLongCounter.class": _minimal_class_bytes(["sun/misc/Unsafe"]),
                },
            )
            # Benign 3: GammaUtils -> MEDIUM restricted utility, NOT CRITICAL!
            make_jar(
                mc_mods / "Gamma-Utils-Fabric-3.2.2.jar",
                {
                    "fabric.mod.json": b'{"id":"gammautils","name":"Gamma Utils"}',
                    "gammautils.mixins.json": b'{"package":"io.github.sjouwer.gammautils.mixin"}',
                    "io/github/sjouwer/gammautils/Commands.class": _minimal_class_bytes(["gammautils", "fullbright"]),
                },
            )

            ctx_clean = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine4_deep_files.run(ctx_clean)
            crit_or_high = [f for f in ctx_clean.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
            self.assertEqual([], crit_or_high, f"Unexpected CRITICAL/HIGH on clean mods: {crit_or_high}")
            rest_hits = [f for f in ctx_clean.findings if f.rule_id == "E4-JAR-RESTRICTED-MOD"]
            self.assertEqual(1, len(rest_hits))
            self.assertEqual(Severity.MEDIUM, rest_hits[0].severity)

            # Attacks: (a) Spoofed krypton-0.2.9.jar with cheat classes, (b) Trojanized velocity-cipher.so with Agent_OnLoad
            atk_mods = home / ".minecraft/mods"
            make_jar(
                atk_mods / "krypton-0.2.9-fake.jar",
                {
                    "fabric.mod.json": b'{"id":"krypton","name":"Krypton"}',
                    "dev/kryptonclient/module/KillAura.class": _minimal_class_bytes(["kryptonclient", "KillAura", "AutoCrystal"]),
                },
            )
            make_jar(
                atk_mods / "velocity-trojan.jar",
                {
                    "linux_x86_64/velocity-cipher.so": b"\x7fELF\x02\x01\x01\x00Agent_OnLoad\x00RedefineClasses\x00",
                },
            )
            ctx_atk = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine4_deep_files.run(ctx_atk)
            atk_rids = {f.rule_id for f in ctx_atk.findings}
            self.assertIn("E4-JAR-CLASS-CONSTANT-POOL", atk_rids)
            self.assertIn("E4-JAR-EMBEDDED-NATIVE", atk_rids)

    # ------------------------------------------------------------------
    # 4. RobloxInstaller PE & OceanLinux bare ptrace vs Real Cheat PE / Injector ELF
    # ------------------------------------------------------------------
    def test_roblox_pe_and_ocean_ptrace_vs_real_pe_and_elf_injectors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            dl = home / "Downloads"
            dl.mkdir(parents=True, exist_ok=True)

            # Benign Roblox installer containing "FluxClient" UI string
            roblox = dl / "RobloxPlayerInstaller.exe"
            roblox.write_bytes(b"MZ" + b"\x00" * 80 + b"Roblox Corporation\x00FluxClient\x00RobloxPlayerBeta")
            # Benign SS tool in Downloads importing bare ptrace only
            ocean = dl / "OceanLinux-ABC"
            ocean.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 60 + b"ptrace\x00libpthread.so.0")

            ctx_clean = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine4_deep_files.run(ctx_clean)
            self.assertEqual([], [f for f in ctx_clean.findings if f.rule_id in ("E4-PE-CHEAT-OR-INJECTOR", "E4-ELF-SUSPICIOUS")])

            # Attack: Trojanized RobloxInstaller with Win32 injection combo + ELF with ptrace + process_vm_writev
            evil_pe = dl / "RobloxPlayerInstaller_evil.exe"
            evil_pe.write_bytes(
                b"MZ" + b"\x00" * 80 + b"Roblox Corporation\x00FluxClient\x00VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread"
            )
            evil_elf = dl / "mem_inject.so"
            evil_elf.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 60 + b"ptrace\x00process_vm_writev\x00")
            ctx_atk = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine4_deep_files.run(ctx_atk)
            atk_rids = {f.rule_id for f in ctx_atk.findings}
            self.assertIn("E4-PE-CHEAT-OR-INJECTOR", atk_rids)
            self.assertIn("E4-ELF-SUSPICIOUS", atk_rids)

    # ------------------------------------------------------------------
    # 5. Browser Active Discord WI-ZOOM Download + SQLite Freelist vs Deleted Vape History
    # ------------------------------------------------------------------
    def test_active_discord_wizoom_no_fake_carve_vs_real_deleted_vape(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            prof = home / ".config/google-chrome/Default"
            prof.mkdir(parents=True, exist_ok=True)
            db = prof / "History"
            if db.exists():
                db.unlink()
            conn = sqlite3.connect(db)
            conn.execute("PRAGMA secure_delete = OFF")
            conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER)")
            conn.execute("CREATE TABLE keyword_search_terms (term TEXT)")
            conn.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, tab_url TEXT, target_path TEXT, start_time INTEGER)")
            conn.execute("CREATE TABLE downloads_url_chains (id INTEGER, url TEXT)")
            now_wk = int((time.time() + 11644473600) * 1_000_000)
            for i in range(30):
                conn.execute("INSERT INTO urls VALUES (?, ?, 'Site', ?)", (i + 1, f"https://example.org/{i}", now_wk))
            wizoom_url = "https://cdn.discordapp.com/attachments/123456789/987654321/WI-ZOOM-1.7-MC1.21.4.jar?ex=aaa&is=bbb&hm=ccc&"
            conn.execute("INSERT INTO downloads VALUES (1, ?, '/home/u/Downloads/WI-ZOOM-1.7-MC1.21.4.jar', ?)", (wizoom_url, now_wk))
            conn.execute("INSERT INTO downloads_url_chains VALUES (1, ?)", (wizoom_url,))
            conn.commit()
            conn.close()

            # Append trailing byte noise version of the SAME active URL into WAL (simulates SQLite page framing!)
            wal = Path(str(db) + "-wal")
            wal.write_bytes(b"\x00\x00" + (wizoom_url + "E").encode("ascii") + b"\x00")

            ctx_clean = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine6_desktop_traces.run(ctx_clean)
            self.assertNotIn("E6-BROWSER-SQLITE-FREELIST-CARVE", {f.rule_id for f in ctx_clean.findings})
            dl_findings = [f for f in ctx_clean.findings if f.rule_id == "E6-BROWSER-CHEAT-DOWNLOAD"]
            self.assertEqual(1, len(dl_findings))
            self.assertEqual(Severity.MEDIUM, dl_findings[0].severity)

            # Now write a genuinely deleted vape.gg download into WAL -> MUST fire CRITICAL carve!
            wal.write_bytes(b"\x00https://vape.gg/download/vapev4.exe\x00")
            ctx_atk = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine6_desktop_traces.run(ctx_atk)
            self.assertIn("E6-BROWSER-SQLITE-FREELIST-CARVE", {f.rule_id for f in ctx_atk.findings})

    # ------------------------------------------------------------------
    # 6. ciadpi Discord-only Proxy vs Game Proxy & Untimestamped journalctl vs history -c
    # ------------------------------------------------------------------
    def test_ciadpi_discord_proxy_and_untimestamped_journalctl_calibration(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            # Untimestamped routine journalctl --rotate -> MEDIUM (not CRITICAL)
            (home / ".bash_history").write_text("ls -la\nsudo journalctl --rotate\nsudo journalctl --vacuum-time=1s\n", encoding="utf-8")
            ctx_j = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine1_integrity.run(ctx_j)
            af = [f for f in ctx_j.findings if f.rule_id == "E1-HIST-ANTIFORENSIC-CMD"]
            self.assertEqual(1, len(af))
            self.assertEqual(Severity.MEDIUM, af[0].severity)

            # Explicit history -c -> MUST remain CRITICAL!
            (home / ".bash_history").write_text("history -c\n", encoding="utf-8")
            ctx_c = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine1_integrity.run(ctx_c)
            af_c = [f for f in ctx_c.findings if f.rule_id == "E1-HIST-ANTIFORENSIC-CMD"]
            self.assertEqual(Severity.CRITICAL, af_c[0].severity)

            # ciadpi listening on 127.0.0.1:1080 with ONLY Discord connected -> LOW
            write_simulated_proc_entry(proc, pid=3399, comm="ciadpi", cmdline=["ciadpi"], fds={"5": "socket:[50001]"})
            write_simulated_proc_entry(proc, pid=5330, comm="Discord", cmdline=["Discord"], fds={"6": "socket:[50002]"})
            (proc / "net").mkdir(parents=True, exist_ok=True)
            # 127.0.0.1 = 0100007F, port 1080 = 0438
            (proc / "net/tcp").write_text(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                "   0: 0100007F:0438 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 50001 1 0 0\n"
                "   1: 0100007F:C350 0100007F:0438 01 00000000:00000000 00:00000000 00000000  1000        0 50002 1 0 0\n",
                encoding="utf-8",
            )
            ctx_dpi = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine7_network_usb.run(ctx_dpi)
            px = [f for f in ctx_dpi.findings if f.rule_id == "E7-LOCAL-PROXY-ACTIVE"]
            self.assertEqual(1, len(px))
            self.assertEqual(Severity.LOW, px[0].severity)

            # Now Java connects to 127.0.0.1:1080 -> MUST escalate to HIGH!
            write_simulated_proc_entry(proc, pid=8888, comm="java", cmdline=["java", "-jar", "mc.jar"], fds={"7": "socket:[50003]"})
            (proc / "net/tcp").write_text(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                "   0: 0100007F:0438 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 50001 1 0 0\n"
                "   1: 0100007F:C351 0100007F:0438 01 00000000:00000000 00:00000000 00000000  1000        0 50003 1 0 0\n",
                encoding="utf-8",
            )
            ctx_game_px = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine7_network_usb.run(ctx_game_px)
            px_g = [f for f in ctx_game_px.findings if f.rule_id == "E7-LOCAL-PROXY-ACTIVE"]
            self.assertEqual(1, len(px_g))
            self.assertEqual(Severity.HIGH, px_g[0].severity)


if __name__ == "__main__":
    unittest.main()

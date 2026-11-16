"""Comprehensive hardening, error-path, security, correlation, and hardware fixture tests."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import sqlite3
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from ss_core import (
    engine1_integrity,
    engine2_live_proc,
    engine4_deep_files,
    engine5_minecraft,
    engine6_desktop_traces,
    engine8_reporter,
    engine9_kernel,
    orchestrator,
    priv_helper,
)
from ss_core.models import Confidence, Finding, ScanContext, ScanStatus, Severity
from ss_core.utils import safe_zip_read
from tests.sim_lab import build_clean_baseline, make_jar, write_simulated_proc_entry


def _write_clean_sysfs(root: Path, proc: Path, cmdline: str = "") -> None:
    (proc / "cmdline").write_text(
        cmdline
        or "BOOT_IMAGE=/vmlinuz intel_iommu=on iommu=force iommu.strict=1 iommu.passthrough=0\n",
        encoding="utf-8",
    )
    (proc / "cpuinfo").write_text("vendor_id\t: GenuineIntel\n", encoding="utf-8")
    (proc / "modules").write_text("ext4 102400 1 - Live 0x0000000000000000\n", encoding="utf-8")
    (proc / "sys/kernel").mkdir(parents=True, exist_ok=True)
    (proc / "sys/kernel/tainted").write_text("0\n", encoding="utf-8")
    (proc / "sys/kernel/modprobe").write_text("/usr/sbin/modprobe\n", encoding="utf-8")
    (proc / "sys/kernel/core_pattern").write_text("|/usr/lib/systemd/systemd-coredump\n", encoding="utf-8")
    (root / "sys/firmware/acpi/tables").mkdir(parents=True, exist_ok=True)
    (root / "sys/firmware/acpi/tables/DMAR").write_bytes(b"DMAR")
    (root / "sys/class/iommu/dmar0").mkdir(parents=True, exist_ok=True)
    (root / "sys/kernel/iommu_groups/0/devices").mkdir(parents=True, exist_ok=True)


def _deflated_bomb_bytes(payload_size: int = 2_000_000) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.txt", b"Z" * payload_size)
    return buf.getvalue()


class TestErrorPathsAndCoverage(unittest.TestCase):
    def test_e2_proc_mem_permission_denied_degrades_scan_quality(self) -> None:
        from ss_core import engine2_live_proc

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            write_simulated_proc_entry(
                proc,
                pid=4242,
                comm="java",
                cmdline=["/usr/bin/java", "-Xmx2G", "-jar", "minecraft.jar"],
                maps_lines=[
                    "7f0000000000-7f0000100000 rwxp 00000000 00:00 0 ",
                    "7f0000200000-7f0000300000 r--p 00000000 08:01 101 /usr/lib/libjvm.so",
                ],
                mem_bytes=b"placeholder",
            )
            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
                enable_memory_scan=True,
            )
            orig_os_open = os.open

            def _deny_mem_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
                if str(path).endswith("/4242/mem"):
                    raise PermissionError(13, "Permission denied", str(path))
                return orig_os_open(path, flags, *args, **kwargs)

            with mock.patch("os.open", side_effect=_deny_mem_open):
                engine2_live_proc.run(ctx)

            cov = ctx.telemetry.get("scan_coverage", {})
            self.assertEqual("PERMISSION_DENIED", cov["E2.proc_mem"]["status"])
            self.assertTrue(
                any(str(item).startswith("4242:") for item in ctx.telemetry.get("ram_scan_denied_pids", []))
            )
            ass = engine8_reporter.build_report_payload(ctx)["assessment"]
            self.assertLess(ass["scan_quality"], 100)
            self.assertTrue(any("E2.proc_mem" in g for g in ass["coverage_gaps"]))

    def test_e9_incomplete_snapshots_dropped_events_errno_hidepid_ret_and_unload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            _write_clean_sysfs(root, proc)
            snapshot = {
                "ok": True,
                "lkm_loaded": True,
                "lkm_unloaded_cleanly": False,
                "proc_snapshots": {
                    "status": "STATUS|kmod_loaded=1|tainted=0\n",
                    "integrity": "READ_ERR|Permission denied\n",
                    "tasks_vma": (
                        "TASK_VMA_SUM|pid=101|comm=java|rwx_anon=0|memfd_exec=0|del_exec=0|truncated=1\n"
                        "TRUNCATED|shown=200|total=350\n"
                    ),
                    "pci_iommu": "",
                    "events": (
                        "EVENT_META|cap=256|total=400|dropped=144\n"
                        "EVENT|seq=1|ts_ns=100|type=1|pid=999|comm=evil|arg0=0x1092|arg1=10|ret=-1|has_ret=1\n"
                        "EVENT|seq=2|ts_ns=200|type=2|pid=999|comm=evil|arg0=0x1092|arg1=10|ret=128|has_ret=1\n"
                    ),
                },
                "root_extras": {
                    "native_probe": {
                        "bpf": {"ok": 0, "errno": 1, "euid": 1000, "progs": []},
                        "pid_cross": {
                            "hidepid_detected": 1,
                            "euid": 1000,
                            "hidden_candidates": [{"pid": 123, "stat_ok": 0, "raw_only": 0}],
                        },
                        "pci_ext": [],
                    },
                },
            }
            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
                kernel_snapshot_data=snapshot,
            )
            engine9_kernel.run(ctx)

            rules = {f.rule_id: f for f in ctx.findings}
            self.assertIn("E9-LKM-SNAPSHOT-INCOMPLETE", rules)
            self.assertIn("E9-LKM-UNLOAD-INCOMPLETE", rules)
            self.assertNotIn("E9-HIDDEN-PID-READDIR", rules)

            cov = ctx.telemetry["scan_coverage"]
            self.assertEqual("ERROR", cov["E9.lkm.integrity"]["status"])
            self.assertEqual("PARTIAL", cov["E9.ring0_tasks"]["status"])
            self.assertEqual("PARTIAL", cov["E9.ring0_events"]["status"])
            self.assertEqual("PERMISSION_DENIED", cov["E9.ebpf"]["status"])
            self.assertEqual("PARTIAL", cov["E9.pid_cross"]["status"])

            failed_ev = rules["E9-EVT-PTRACE-INJECT"]
            succeeded_ev = rules["E9-EVT-VM-WRITEV-INJECT"]
            self.assertNotEqual(Confidence.CONFIRMED, failed_ev.confidence)
            self.assertNotEqual(Severity.CRITICAL, failed_ev.severity)
            self.assertEqual(Severity.CRITICAL, succeeded_ev.severity)
            self.assertEqual(Confidence.CONFIRMED, succeeded_ev.confidence)
            self.assertEqual(4242, succeeded_ev.pid)

    def test_priv_helper_marks_ok_false_when_rmmod_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ko_path = Path(td) / "mc_ss_kmod.ko"
            ko_path.write_bytes(b"\x7fELFdummyko")
            (Path(str(ko_path) + ".sha256")).write_text(
                hashlib.sha256(ko_path.read_bytes()).hexdigest() + "\n", encoding="utf-8"
            )
            fake_cp = subprocess.CompletedProcess(["insmod"], 0, stdout="", stderr="")
            with (
                mock.patch("os.geteuid", return_value=0),
                mock.patch.object(priv_helper, "_acquire_kmod_lock", return_value=object()),
                mock.patch.object(priv_helper, "_release_kmod_lock", return_value=None),
                mock.patch.object(priv_helper, "_is_trusted_artifact", return_value=True),
                mock.patch.object(
                    priv_helper,
                    "check_kernel_prereqs",
                    return_value={
                        "kernel_release": "6.8.0-test",
                        "lkm_vermagic": "6.8.0-test SMP preempt mod_unload ",
                        "lkm_vermagic_match": True,
                        "modules_disabled": "0",
                        "headers_present": True,
                    },
                ),
                mock.patch.object(
                    priv_helper,
                    "ensure_or_build_lkm_for_running_kernel",
                    return_value={"ok": True, "lkm_path": str(ko_path)},
                ),
                mock.patch.object(priv_helper, "find_native_probe", return_value=None),
                mock.patch.object(priv_helper, "_collect_root_extras", return_value={"errors": []}),
                mock.patch.object(priv_helper, "_stage_verified_artifact", return_value=ko_path),
                mock.patch.object(priv_helper, "_modinfo_vermagic", return_value="6.8.0-test SMP preempt mod_unload "),
                mock.patch.object(priv_helper, "_write_kmod_state", return_value=None),
                mock.patch.object(priv_helper, "_clear_kmod_state", return_value=None),
                mock.patch.object(priv_helper, "_rmmod_cleanly", return_value=False),
                mock.patch("subprocess.run", return_value=fake_cp),
                mock.patch("time.sleep", return_value=None),
            ):
                res = priv_helper.execute_kernel_snapshot_helper(
                    trace_window_ms=100, lkm_override=ko_path, target_os="ubuntu_24_04"
                )
            self.assertFalse(res["ok"])
            self.assertTrue(res["lkm_loaded"])
            self.assertFalse(res["lkm_unloaded_cleanly"])
            self.assertEqual("rmmod verification failed", res.get("cleanup_error"))

    def test_e5_broken_symlinks_in_logs_and_crashes_do_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            mc = home / ".minecraft"
            (mc / "logs").mkdir(parents=True, exist_ok=True)
            (mc / "crash-reports").mkdir(parents=True, exist_ok=True)
            (mc / "logs/latest.log").write_text("[main/INFO]: Sound engine started\n", encoding="utf-8")
            os.symlink("/nonexistent/target_prism.log", mc / "logs/PrismLauncher-1.log")
            os.symlink("/nonexistent/target_old.log.gz", mc / "logs/old.log.gz")
            os.symlink("/nonexistent/target_crash.txt", mc / "crash-reports/crash-1.txt")

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine5_minecraft.run(ctx)
            self.assertEqual([], ctx.errors)
            self.assertEqual("COMPLETED", ctx.telemetry["scan_coverage"]["E5.minecraft"]["status"])

    def test_e4_zip_bomb_blocked_and_sibling_minecraft_evil_symlink_caught(self) -> None:
        raw_bomb = _deflated_bomb_bytes(payload_size=2_000_000)
        with zipfile.ZipFile(io.BytesIO(raw_bomb)) as zf:
            info = zf.getinfo("payload.txt")
            with self.assertRaises(ValueError):
                safe_zip_read(zf, info, max_bytes=256 * 1024)
            info.file_size = 64
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                safe_zip_read(zf, info, max_bytes=256 * 1024)

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            evil_dir = home / ".minecraft_evil"
            evil_dir.mkdir(parents=True, exist_ok=True)
            evil_jar = evil_dir / "hidden.jar"
            make_jar(evil_jar, {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"})
            os.symlink(evil_jar, home / ".minecraft/mods/legit_link.jar")

            bombed_jar = home / ".minecraft/mods/bombed.jar"
            make_jar(bombed_jar, {"evil.mixin.json": b'{"k":"' + (b"A" * (600 * 1024)) + b'"}'})

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False, deep_home_scan=False)
            engine4_deep_files.run(ctx)
            rules = {f.rule_id for f in ctx.findings}
            self.assertIn("E4-MC-SUSPICIOUS-SYMLINK", rules)
            self.assertEqual([], ctx.errors)

    def test_orchestrator_engine_crash_isolation_and_cooperative_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)

            def _boom(_ctx: ScanContext) -> None:
                raise RuntimeError("synthetic E1 crash")

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            with mock.patch.object(
                orchestrator,
                "ENGINES",
                (("E1", _boom), ("E5", engine5_minecraft.run)),
            ):
                orchestrator.run_all_engines(ctx, selected_engines={"E1", "E5"})

            statuses = ctx.telemetry.get("engine_status", {})
            self.assertEqual("ERROR", statuses["E1"]["status"])
            self.assertEqual("COMPLETED", statuses["E5"]["status"])
            self.assertTrue(any("synthetic E1 crash" in err for err in ctx.errors))
            ass = engine8_reporter.build_report_payload(ctx)["assessment"]
            self.assertEqual("INCOMPLETE", ass["verdict_level"])
            self.assertTrue(ass["incomplete_scan"])

            ctx_cancel = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            ctx_cancel.request_cancel()
            with self.assertRaises(orchestrator.ScanCancelledError):
                orchestrator.run_all_engines(ctx_cancel, selected_engines={"E1", "E5"})
            self.assertTrue(ctx_cancel.telemetry.get("scan_cancelled"))

    def test_gui_cooperative_cancel_without_qthread_terminate(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtCore import QThread
        from PySide6.QtWidgets import QApplication
        import ss_gui

        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, _root, _proc = build_clean_baseline(base)
            desktop = base / "Desktop"
            desktop.mkdir(parents=True, exist_ok=True)
            win = ss_gui.SentinelMainWindow(home_dir=home, desktop_dir=desktop, enable_kernel_lkm_default=False)
            worker = ss_gui.ScanWorker(home_dir=home, desktop_dir=desktop)
            worker.request_cancel()
            worker.run()
            self.assertFalse(worker.isRunning())
            with mock.patch.object(QThread, "terminate", side_effect=AssertionError("terminate must never be called")):
                win.close()
                app.processEvents()


class TestPrivHelperSecurityContracts(unittest.TestCase):
    def test_trusted_bin_and_clean_priv_env(self) -> None:
        self.assertIsNone(priv_helper._trusted_bin("/bin/sh"))
        self.assertIsNone(priv_helper._trusted_bin("definitely_nonexistent_bin_xyz"))
        env = priv_helper._clean_priv_env()
        for bad in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PERL5LIB", "BASH_ENV", "IFS"):
            self.assertNotIn(bad, env)
        self.assertEqual("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", env["PATH"])

        with mock.patch("os.geteuid", return_value=0), mock.patch(
            "pathlib.Path.stat",
            return_value=os.stat_result((stat.S_IFREG | 0o755, 1, 1, 1, 1000, 1000, 10, 0, 0, 0)),
        ), mock.patch("os.access", return_value=True):
            self.assertIsNone(priv_helper._trusted_bin("sh"))

    def test_unprivileged_local_share_and_ancestor_sticky_vs_world_writable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            inv_home = base / "player"
            evil = inv_home / ".local/share/mc_ss/probe"
            evil.parent.mkdir(parents=True, exist_ok=True)
            evil.write_text("x", encoding="utf-8")

            with mock.patch("os.geteuid", return_value=0), mock.patch.dict(
                os.environ, {"PKEXEC_UID": "1000"}, clear=False
            ), mock.patch.object(priv_helper, "_invoker_home", return_value=inv_home):
                self.assertTrue(priv_helper._is_under_unprivileged_local_share(evil.resolve()))

            with mock.patch("os.geteuid", return_value=1000):
                self.assertFalse(priv_helper._is_under_unprivileged_local_share(evil.resolve()))

            non_sticky = os.stat_result((stat.S_IFDIR | 0o777, 1, 1, 2, 0, 0, 4096, 0, 0, 0))
            sticky_root = os.stat_result((stat.S_IFDIR | stat.S_ISVTX | 0o777, 1, 1, 2, 0, 0, 4096, 0, 0, 0))
            with mock.patch("os.stat", return_value=non_sticky):
                self.assertFalse(priv_helper._ancestor_dir_safe(base, {0}))
            with mock.patch("os.stat", return_value=sticky_root):
                self.assertTrue(priv_helper._ancestor_dir_safe(base, {0}))

    def test_stage_verified_artifact_tamper_and_write_with_backup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src_dir = base / "src"
            stage_dir = base / "stage"
            src_dir.mkdir(parents=True, exist_ok=True)
            stage_dir.mkdir(parents=True, exist_ok=True)
            art = src_dir / "ss_kernel_probe"
            art.write_bytes(b"\x7fELFprobe")
            os.chmod(art, 0o755)
            sidecar = Path(str(art) + ".sha256")
            sidecar.write_text(hashlib.sha256(art.read_bytes()).hexdigest() + "  ss_kernel_probe\n", encoding="utf-8")

            with mock.patch.object(priv_helper, "_ancestor_dir_safe", return_value=True):
                staged = priv_helper._stage_verified_artifact(art, stage_dir, require_exec=True)
                self.assertIsNotNone(staged)
                assert staged is not None
                self.assertEqual(b"\x7fELFprobe", staged.read_bytes())

                art.write_bytes(b"\x7fELFtampered")
                self.assertIsNone(priv_helper._stage_verified_artifact(art, stage_dir, require_exec=True))

            cfg = base / "etc/default/grub"
            cfg.parent.mkdir(parents=True, exist_ok=True)
            cfg.write_text("OLD=1\n", encoding="utf-8")
            priv_helper._write_with_backup(cfg, "NEW=2\n")
            self.assertEqual("NEW=2\n", cfg.read_text(encoding="utf-8"))
            self.assertEqual("OLD=1\n", (base / "etc/default/grub.mc_ss_sentinel.bak").read_text(encoding="utf-8"))

    def test_debian_ubuntu_kbuild_missing_gcc_hint_does_not_attributeerror(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            kdir = root / "lib/modules/6.8.0-45-generic/build"
            kdir.mkdir(parents=True, exist_ok=True)
            (kdir / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
            (kdir / ".config").write_text('CONFIG_CC_VERSION_TEXT="gcc-13"\n', encoding="utf-8")
            (root / "etc").mkdir(parents=True, exist_ok=True)
            (root / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8")

            fail_cp = subprocess.CompletedProcess(["make"], 2, stdout="", stderr="/bin/sh: 1: gcc-13: not found\n")
            with (
                mock.patch.object(priv_helper, "find_lkm_object", return_value=None),
                mock.patch.object(priv_helper, "_trusted_bin", side_effect=lambda n: f"/usr/bin/{n}"),
                mock.patch("subprocess.run", return_value=fail_cp),
            ):
                res = priv_helper.ensure_or_build_lkm_for_running_kernel(
                    kernel_release="6.8.0-45-generic",
                    root_prefix=root,
                    target_os="ubuntu_24_04",
                )
            self.assertFalse(res["ok"])
            self.assertIn("apt-get install -y gcc-13", res["headers_hint"])


class TestEngine8DomainSeparationAndCorrelationHardening(unittest.TestCase):
    def test_dedup_deterministic_order_xss_turkish_unicode_and_sha256_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            f1 = Finding(
                rule_id="E4-EXT-SPOOF",
                engine="E4",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category="File",
                title='XSS <script>alert("ğüşıöç")</script>',
                description="Açıklama İŞĞÜÖÇ",
                evidence=["kanıt-1 ğüşiöç"],
                path="/tmp/<img src=x onerror=alert(1)>",
            )
            f1_dup = Finding(
                rule_id="E4-EXT-SPOOF",
                engine="E4",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="File",
                title='XSS <script>alert("ğüşıöç")</script>',
                description="Açıklama İŞĞÜÖÇ",
                evidence=["kanıt-2"],
                path="/tmp/<img src=x onerror=alert(1)>",
            )
            f2 = Finding(
                rule_id="E5-CLIENT-LOG-CHEAT",
                engine="E5",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                category="Minecraft",
                title="Küçük log izi",
                description="Örnek açıklama",
                path="/home/user/.minecraft/logs/latest.log",
            )
            ctx_a = ScanContext(home_dir=base)
            ctx_a.add_finding(f2)
            ctx_a.add_finding(f1)
            ctx_a.add_finding(f1_dup)

            ctx_b = ScanContext(home_dir=base)
            ctx_b.add_finding(f1_dup)
            ctx_b.add_finding(f1)
            ctx_b.add_finding(f2)

            self.assertEqual(2, len(ctx_a.findings))
            self.assertEqual(Severity.HIGH, [f for f in ctx_a.findings if f.rule_id == "E4-EXT-SPOOF"][0].severity)

            p_a = engine8_reporter.build_report_payload(ctx_a)
            p_b = engine8_reporter.build_report_payload(ctx_b)
            self.assertEqual([x["rule_id"] for x in p_a["findings"]], [x["rule_id"] for x in p_b["findings"]])
            self.assertEqual(p_a["assessment"]["risk_score"], p_b["assessment"]["risk_score"])

            out_dir = base / "reports"
            files = engine8_reporter.write_reports(ctx_a, out_dir)
            html_txt = files["html"].read_text(encoding="utf-8")
            self.assertNotIn("<script>alert", html_txt)
            self.assertIn("&lt;script&gt;alert", html_txt)
            self.assertIn("ğüşıöç", html_txt)

            sha_manifest = files["sha256"].read_text(encoding="utf-8").splitlines()
            self.assertEqual(3, len(sha_manifest))
            for line in sha_manifest:
                digest, fname = line.split("  ", 1)
                self.assertEqual(digest, hashlib.sha256((out_dir / fname).read_bytes()).hexdigest())

            desktop_dir = base / "Desktop"
            txt_path, desktop_payload = engine8_reporter.write_desktop_txt_report(ctx_a, desktop_dir=desktop_dir)
            self.assertEqual(
                desktop_payload["desktop_txt_file_sha256"],
                hashlib.sha256(txt_path.read_bytes()).hexdigest(),
            )
            self.assertIn("ğüşıöç", txt_path.read_text(encoding="utf-8"))

    def test_correlation_independence_pid_path_scoping_and_domain_separation(self) -> None:
        # 1. Single CoW patch MUST NOT self-correlate into E8-CORR-KERNEL-FILELESS
        ctx_self = ScanContext()
        ctx_self.add_finding(
            Finding("E2-MAP-TEXT-COW-PATCH", "E2", Severity.HIGH, Confidence.HIGH, "Mem", "CoW", "desc", pid=555)
        )
        engine8_reporter.correlate_findings(ctx_self)
        self.assertNotIn("E8-CORR-KERNEL-FILELESS", {f.rule_id for f in ctx_self.findings})

        # 2. Different paths MUST NOT trigger SPOOFED-ARTIFACT; same path MUST trigger
        ctx_diff_path = ScanContext()
        ctx_diff_path.add_finding(Finding("E4-EXT-SPOOF", "E4", Severity.HIGH, Confidence.CONFIRMED, "F", "t", "d", path="/a.png"))
        ctx_diff_path.add_finding(Finding("E4-XATTR-CHEAT-URL", "E4", Severity.HIGH, Confidence.CONFIRMED, "F", "t", "d", path="/b.png"))
        engine8_reporter.correlate_findings(ctx_diff_path)
        self.assertNotIn("E8-CORR-SPOOFED-ARTIFACT", {f.rule_id for f in ctx_diff_path.findings})

        ctx_same_path = ScanContext()
        ctx_same_path.add_finding(Finding("E4-EXT-SPOOF", "E4", Severity.HIGH, Confidence.CONFIRMED, "F", "t", "d", path="/same.png"))
        ctx_same_path.add_finding(Finding("E4-XATTR-CHEAT-URL", "E4", Severity.HIGH, Confidence.CONFIRMED, "F", "t", "d", path="/same.png"))
        engine8_reporter.correlate_findings(ctx_same_path)
        self.assertIn("E8-CORR-SPOOFED-ARTIFACT", {f.rule_id for f in ctx_same_path.findings})

        # 3. Ring-0 single equivalence group ('ebpf' only) MUST NOT trigger RING0-ROOTKIT; two distinct groups DO
        ctx_ebpf_only = ScanContext()
        ctx_ebpf_only.add_finding(Finding("E9-EBPF-SUSPICIOUS-PROG", "E9", Severity.HIGH, Confidence.HIGH, "K", "t1", "d"))
        ctx_ebpf_only.add_finding(Finding("E9-EVT-LIVE-BPF-LOAD", "E9", Severity.HIGH, Confidence.HIGH, "K", "t2", "d"))
        engine8_reporter.correlate_findings(ctx_ebpf_only)
        self.assertNotIn("E8-CORR-RING0-ROOTKIT", {f.rule_id for f in ctx_ebpf_only.findings})

        ctx_ring0 = ScanContext()
        ctx_ring0.add_finding(Finding("E9-KERNEL-INLINE-HOOK", "E9", Severity.CRITICAL, Confidence.CONFIRMED, "K", "hook", "d"))
        ctx_ring0.add_finding(Finding("E9-HIDDEN-PID-RING0", "E9", Severity.CRITICAL, Confidence.CONFIRMED, "K", "hide", "d"))
        engine8_reporter.correlate_findings(ctx_ring0)
        self.assertIn("E8-CORR-RING0-ROOTKIT", {f.rule_id for f in ctx_ring0.findings})

        # 4. Different PIDs MUST NOT trigger KERNEL-FILELESS; same PID MUST trigger
        ctx_diff_pid = ScanContext()
        ctx_diff_pid.add_finding(Finding("E2-MAP-TEXT-COW-PATCH", "E2", Severity.HIGH, Confidence.HIGH, "M", "cow", "d", pid=111))
        ctx_diff_pid.add_finding(Finding("E9-EVT-MEMFD-EXEC", "E9", Severity.HIGH, Confidence.HIGH, "K", "memfd", "d", pid=222))
        engine8_reporter.correlate_findings(ctx_diff_pid)
        self.assertNotIn("E8-CORR-KERNEL-FILELESS", {f.rule_id for f in ctx_diff_pid.findings})

        ctx_same_pid = ScanContext()
        ctx_same_pid.add_finding(Finding("E2-MAP-TEXT-COW-PATCH", "E2", Severity.HIGH, Confidence.HIGH, "M", "cow", "d", pid=111))
        ctx_same_pid.add_finding(Finding("E9-EVT-MEMFD-EXEC", "E9", Severity.HIGH, Confidence.HIGH, "K", "memfd", "d", pid=111))
        engine8_reporter.correlate_findings(ctx_same_pid)
        self.assertIn("E8-CORR-KERNEL-FILELESS", {f.rule_id for f in ctx_same_pid.findings})

        # 5. Soft signals alone must not trigger WIPE-CHAIN
        ctx_wipe_soft = ScanContext()
        ctx_wipe_soft.add_finding(Finding("E6-HISTORY-FLOOD", "E6", Severity.LOW, Confidence.LOW, "Trace", "flood", "d"))
        ctx_wipe_soft.add_finding(Finding("E5-MODS-WIPED-MISMATCH", "E5", Severity.HIGH, Confidence.MEDIUM, "MC", "mods", "d"))
        engine8_reporter.correlate_findings(ctx_wipe_soft)
        self.assertNotIn("E8-CORR-WIPE-CHAIN", {f.rule_id for f in ctx_wipe_soft.findings})

        # 6. Domain separation & same-subject decay
        ctx_dma = ScanContext()
        ctx_dma.add_finding(Finding("E9-DMA-IOMMU-DISABLED", "E9", Severity.HIGH, Confidence.CONFIRMED, "DMA", "iommu", "d"))
        ctx_dma.add_finding(Finding("E9-DMA-VFIO-UIO-DEVICE", "E9", Severity.HIGH, Confidence.HIGH, "DMA", "vfio", "d"))
        ass_dma = engine8_reporter.build_report_payload(ctx_dma)["assessment"]
        self.assertEqual("CLEAN", ass_dma["cheat_verdict_level"])
        self.assertEqual("dma_hardware", ass_dma["primary_risk_domain"])
        self.assertEqual(0, ass_dma["domain_scores"]["cheat_evidence"])

        ctx_burst = ScanContext()
        for idx in range(5):
            ctx_burst.add_finding(
                Finding(f"E4-RULE-{idx}", "E4", Severity.HIGH, Confidence.CONFIRMED, "File", f"t{idx}", "d", path="/same/jar.jar")
            )
        ass_burst = engine8_reporter.build_report_payload(ctx_burst)["assessment"]
        self.assertLess(ass_burst["domain_scores"]["cheat_evidence"], 5 * 24)
        self.assertEqual(5, len(ass_burst["score_breakdown"]))


class TestCleanLinuxHardwareAndDistroFixtures(unittest.TestCase):
    def test_clean_nvidia_vbox_ebpf_qmk_plx_iommu_and_vfio_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            _write_clean_sysfs(root, proc)
            (proc / "sys/kernel/tainted").write_text("4096\n", encoding="utf-8")
            (proc / "modules").write_text(
                "nvidia_drm 122880 2 - Live 0xffffffffc0100000\n"
                "nvidia_modeset 1515520 3 nvidia_drm, Live 0xffffffffc0200000\n"
                "nvidia_uvm 1884160 0 - Live 0xffffffffc0400000\n"
                "nvidia 60293120 42 nvidia_modeset,nvidia_uvm, Live 0xffffffffc0800000\n"
                "vboxdrv 688128 0 - Live 0xffffffffc1000000\n",
                encoding="utf-8",
            )
            usb_dev = root / "sys/bus/usb/devices/1-2"
            usb_dev.mkdir(parents=True, exist_ok=True)
            (usb_dev / "idVendor").write_text("16c0\n", encoding="utf-8")
            (usb_dev / "idProduct").write_text("27db\n", encoding="utf-8")
            (usb_dev / "product").write_text("Keychron Q1 QMK Keyboard\n", encoding="utf-8")
            (usb_dev / "manufacturer").write_text("Keychron\n", encoding="utf-8")

            snapshot = {
                "ok": True,
                "lkm_loaded": True,
                "lkm_unloaded_cleanly": True,
                "proc_snapshots": {
                    "status": "STATUS|kmod_loaded=1|tainted=4096\n",
                    "integrity": (
                        "MOD|name=nvidia|state=Live|base=0xffffffffc0800000|init=0x0|core_sz=100|ro_sz=50|text_rw=0|hidden_sysfs=0|taints=4096\n"
                        "MOD|name=vboxdrv|state=Live|base=0xffffffffc1000000|init=0x0|core_sz=100|ro_sz=50|text_rw=0|hidden_sysfs=0|taints=4096\n"
                    ),
                    "tasks_vma": "TASK_VMA_SUM|pid=5000|comm=java|rwx_anon=0|memfd_exec=0|del_exec=0|truncated=0\n",
                    "pci_iommu": (
                        f"PCIDEV|bdf=0000:01:00.0|vid=0x10b5|did=0x8747|svid=0x10b5|sdid=0x8747|class=0x060400|rev=0x00|hdr=0x01|driver=pcieport|iommu_grp=2|iommu_dom=DMA_STRICT_OR_TRANSLATED|bme_hw=1|bme_sw=1|untrusted=0|ext_facing=0|tb=0|pcie_spd=3|pcie_w=4|has_dsn=0|dsn=0000000000000000|bar0=0x0|bar1=0x0|cfg_sz=256|d3cold=0|cap_loop=0|cfg_head={'00' * 64}\n"
                        f"PCIDEV|bdf=0000:02:00.0|vid=0x10ee|did=0x5014|svid=0x10ee|sdid=0x000e|class=0x048000|rev=0x00|hdr=0x00|driver=xilinx_dma|iommu_grp=3|iommu_dom=DMA_STRICT_OR_TRANSLATED|bme_hw=1|bme_sw=1|untrusted=0|ext_facing=0|tb=0|pcie_spd=3|pcie_w=4|has_dsn=1|dsn=e41d2d0300592104|bar0=0x0|bar1=0x0|cfg_sz=256|d3cold=0|cap_loop=0|cfg_head={'00' * 64}\n"
                        f"PCIDEV|bdf=0000:03:00.0|vid=0x10de|did=0x2684|svid=0x1458|sdid=0x408a|class=0x030000|rev=0x00|hdr=0x00|driver=vfio-pci|iommu_grp=4|iommu_dom=DMA_STRICT_OR_TRANSLATED|bme_hw=1|bme_sw=1|untrusted=0|ext_facing=0|tb=0|pcie_spd=4|pcie_w=16|has_dsn=1|dsn=e41d2d0300592105|bar0=0x0|bar1=0x0|cfg_sz=256|d3cold=0|cap_loop=0|cfg_head={'00' * 64}\n"
                    ),
                    "events": (
                        "EVENT|seq=1|ts_ns=100|type=5|pid=222|comm=bwrap|arg0=0|arg1=0x1000|ret=0|has_ret=1\n"
                    ),
                },
                "root_extras": {
                    "native_probe": {
                        "bpf": {
                            "ok": 1,
                            "errno": 0,
                            "euid": 0,
                            "progs": [
                                {"id": 10, "name": "bpftune_tcp", "type": 1, "gpl": 1, "btf_id": 5},
                                {"id": 11, "name": "scx_lavd_init", "type": 15, "gpl": 1, "btf_id": 6},
                            ],
                        },
                        "pid_cross": {"hidepid_detected": 0, "euid": 0, "hidden_candidates": []},
                        "pci_ext": [],
                    }
                },
            }

            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
                target_os="bazzite",
                kernel_snapshot_data=snapshot,
            )
            engine9_kernel.run(ctx)
            engine8_reporter.correlate_findings(ctx)
            ass = engine8_reporter.build_report_payload(ctx)["assessment"]

            rules = {f.rule_id: f for f in ctx.findings}
            self.assertNotIn("E9-UNKNOWN-OOT-MODULE", rules)
            self.assertNotIn("E9-EBPF-SUSPICIOUS-PROG", rules)
            self.assertNotIn("E9-EVT-EXECVEAT-FILELESS", rules)
            self.assertNotIn("E9-DMA-SPOOFED-PCIE-FW", rules)
            self.assertIn("E9-DMA-FPGA-HARDWARE", rules)
            self.assertEqual(Severity.HIGH, rules["E9-DMA-FPGA-HARDWARE"].severity)
            self.assertIn("E9-HW-USB-MACRO-MCU", rules)
            self.assertEqual(Severity.LOW, rules["E9-HW-USB-MACRO-MCU"].severity)
            self.assertIn("E9-DMA-VFIO-UIO-DEVICE", rules)
            self.assertEqual(Severity.HIGH, rules["E9-DMA-VFIO-UIO-DEVICE"].severity)
            self.assertEqual("CLEAN", ass["cheat_verdict_level"])


class TestReviewerAuditHardeningRegressions(unittest.TestCase):
    def test_e2_chromium_shm_sownza_input_remapper_and_lunar_ichor_no_false_high(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)

            # 1. Chromium /dev/shm/.org.chromium.Chromium.sOwnZa contains substring ".so" in ".sOwnZa"
            write_simulated_proc_entry(
                proc,
                pid=4100,
                comm="chrome",
                cmdline=["/usr/bin/chromium"],
                exe_target="/usr/bin/chromium",
                maps_lines=[
                    "7f0000000000-7f0000010000 rw-s 00000000 00:18 123 /dev/shm/.org.chromium.Chromium.sOwnZa (deleted)",
                ],
            )
            # 2. Benign running input-remapper-service daemon (truncated comm in Linux /proc)
            write_simulated_proc_entry(
                proc,
                pid=4101,
                comm="input-remapper-",
                cmdline=["/usr/bin/python3", "/usr/bin/input-remapper-service"],
                exe_target="/usr/bin/python3.14",
            )
            # 3. Genuine pure macro tool (ydotool) must remain E2-PROC-MACRO-BIN HIGH (xclicker hits E2-PROC-CHEAT-NAME)
            write_simulated_proc_entry(
                proc,
                pid=4102,
                comm="xclicker",
                cmdline=["/usr/bin/xclicker"],
                exe_target="/usr/bin/xclicker",
            )
            write_simulated_proc_entry(
                proc,
                pid=4104,
                comm="ydotool",
                cmdline=["/usr/bin/ydotool", "click", "1"],
                exe_target="/usr/bin/ydotool",
            )
            # 4. Lunar Client offline ichor agent in hsperfdata must remain INFO (not HIGH)
            hsdir = root / "tmp/hsperfdata_user"
            hsdir.mkdir(parents=True, exist_ok=True)
            (hsdir / "4103").write_bytes(
                b"\xca\xfe\xc0\xc0-javaagent:/home/user/.lunarclient/offline/multiver/ichor-1.0.jar\x00"
            )

            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
                enable_memory_scan=False,
            )
            engine2_live_proc.run(ctx)

            tmp_lib_findings = [f for f in ctx.findings if f.rule_id == "E2-MAP-TMP-LIB"]
            self.assertEqual([], tmp_lib_findings)

            macro_findings = {f.pid: f for f in ctx.findings if f.rule_id == "E2-PROC-MACRO-BIN"}
            self.assertEqual(Severity.LOW, macro_findings[4101].severity)
            self.assertEqual("os_security", engine8_reporter._classify_domain(macro_findings[4101]))
            self.assertEqual(Severity.HIGH, macro_findings[4104].severity)
            self.assertEqual("cheat_evidence", engine8_reporter._classify_domain(macro_findings[4104]))
            cheat_findings = {f.pid: f for f in ctx.findings if f.rule_id == "E2-PROC-CHEAT-NAME"}
            self.assertEqual(Severity.CRITICAL, cheat_findings[4102].severity)
            self.assertEqual("cheat_evidence", engine8_reporter._classify_domain(cheat_findings[4102]))

            hs_findings = [f for f in ctx.findings if f.rule_id == "E2-HSPERF-SUSPICIOUS"]
            self.assertEqual(1, len(hs_findings))
            self.assertEqual(Severity.INFO, hs_findings[0].severity)

    def test_e8_verdict_alignment_fileless_jvm_scope_quality_and_report_collision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            # 1. Medium cheat score (20) + high DMA must NOT produce CRITICAL "DOGRULANMIS HILE" verdict
            ctx_mix = ScanContext(home_dir=base)
            ctx_mix.add_finding(
                Finding("E9-DMA-IOMMU-DISABLED", "E9", Severity.CRITICAL, Confidence.CONFIRMED, "DMA", "iommu", "d")
            )
            ctx_mix.add_finding(
                Finding("E9-DMA-FPGA-HARDWARE", "E9", Severity.CRITICAL, Confidence.CONFIRMED, "DMA", "fpga", "d")
            )
            ctx_mix.add_finding(
                Finding("E4-JAR-OBFUSCATION", "E4", Severity.HIGH, Confidence.MEDIUM, "File", "obf", "d", path="/mods/a.jar")
            )
            ass_mix = engine8_reporter.build_report_payload(ctx_mix)["assessment"]
            self.assertNotEqual("CRITICAL", ass_mix["cheat_verdict_level"])
            self.assertNotIn("DOGRULANMIS HILE", ass_mix["verdict"])

            # 2. E2-MAP-TEXT-COW-PATCH + unrelated disk JAR obfuscation must NOT fabricate E8-CORR-KERNEL-FILELESS
            ctx_fl = ScanContext(home_dir=base)
            ctx_fl.add_finding(
                Finding("E2-MAP-TEXT-COW-PATCH", "E2", Severity.HIGH, Confidence.HIGH, "M", "cow", "d", pid=901)
            )
            ctx_fl.add_finding(
                Finding("E4-JAR-OBFUSCATION", "E4", Severity.HIGH, Confidence.HIGH, "F", "obf", "d", path="/mods/Sodium.jar")
            )
            # 3. Unrelated agent.jar vs other_obf.jar must NOT correlate into E8-CORR-JVM-INJECT-CHAIN
            ctx_fl.add_finding(
                Finding("E4-JAR-AGENT-MANIFEST", "E4", Severity.HIGH, Confidence.CONFIRMED, "F", "ag", "d", path="/mods/agent_alpha.jar")
            )
            engine8_reporter.correlate_findings(ctx_fl)
            rids = {f.rule_id for f in ctx_fl.findings}
            self.assertNotIn("E8-CORR-KERNEL-FILELESS", rids)
            self.assertNotIn("E8-CORR-JVM-INJECT-CHAIN", rids)

            # 4. Partial engine selection lowers scan_quality & skips majority -> INCOMPLETE when score < 15
            ctx_skip = ScanContext(home_dir=base)
            for idx in range(1, 9):
                ctx_skip.set_engine_status(f"E{idx}", ScanStatus.SKIPPED, "Filtrelendi")
            ctx_skip.set_engine_status("E9", ScanStatus.COMPLETED, "Tamamlandi")
            ctx_skip.set_coverage("E9.ebpf", ScanStatus.UNSUPPORTED, "No BTF")
            ass_skip = engine8_reporter.build_report_payload(ctx_skip)["assessment"]
            self.assertLess(ass_skip["scan_quality"], 75)
            self.assertTrue(ass_skip["incomplete_scan"])
            self.assertEqual("INCOMPLETE", ass_skip["verdict_level"])

            # 5. Back-to-back write_reports calls never overwrite prior files
            r1 = engine8_reporter.write_reports(ctx_mix, base / "out")
            r2 = engine8_reporter.write_reports(ctx_mix, base / "out")
            self.assertNotEqual(r1["txt"], r2["txt"])
            self.assertTrue(r1["txt"].exists() and r2["txt"].exists())

    def test_e9_has_ret_zero_failed_uinput_call_rel32_sysfs_vfio_and_no_lkm_as_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            _write_clean_sysfs(root, proc)
            (proc / "100").mkdir(parents=True, exist_ok=True)
            (root / "sys/kernel/iommu_groups/3").mkdir(parents=True, exist_ok=True)
            (root / "sys/kernel/iommu_groups/3/type").write_text("DMA\n", encoding="utf-8")

            # Clean non-LKM vfio-pci device inside active translated IOMMU group must NOT be CRITICAL
            pci_dev = root / "sys/bus/pci/devices/0000:04:00.0"
            pci_dev.mkdir(parents=True, exist_ok=True)
            (pci_dev / "vendor").write_text("0x10de\n", encoding="utf-8")
            (pci_dev / "device").write_text("0x2684\n", encoding="utf-8")
            (pci_dev / "subsystem_vendor").write_text("0x1458\n", encoding="utf-8")
            (pci_dev / "subsystem_device").write_text("0x408a\n", encoding="utf-8")
            (pci_dev / "class").write_text("0x030000\n", encoding="utf-8")
            (pci_dev / "uevent").write_text("DRIVER=vfio-pci\n", encoding="utf-8")
            os.symlink(root / "sys/kernel/iommu_groups/3", pci_dev / "iommu_group")

            snap = {
                "ok": True,
                "lkm_loaded": True,
                "lkm_unloaded_cleanly": True,
                "proc_snapshots": {
                    "status": "STATUS|kmod_loaded=1|tainted=0\n",
                    "integrity": (
                        "KHOOK|sym=do_syscall_64|addr=0xffffffff81000000|pte_lvl=1|pte_rw=0|pte_exec=1|"
                        "hook_class=CALL_REL32|jmp_target=0xffffffffc0beef00|jmp_sym=evil_hook+0x0/0x20 [rootkit]|bytes=e811223344\n"
                        "TRUNCATED|mods=1|max_mods=512\n"
                    ),
                    "tasks_vma": "",
                    "pci_iommu": "",
                    "events": (
                        "EVENT|seq=1|ts_ns=100|type=2|pid=700|tgid=700|comm=inj|arg0=0x10|arg1=0x0|has_ret=0\n"
                        "EVENT|seq=2|ts_ns=200|type=12|pid=701|tgid=701|comm=click|arg0=0x4|arg1=0x5501|ret=-1|has_ret=1\n"
                    ),
                },
                "root_extras": {"native_probe": {"bpf": {"progs": []}, "pid_cross": {"hidden_candidates": []}}},
            }
            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
                enable_kernel_lkm=True,
                kernel_snapshot_data=snap,
            )
            engine9_kernel.run(ctx)
            by_rule = {f.rule_id: f for f in ctx.findings}
            self.assertIn("E9-KERNEL-INLINE-HOOK", by_rule)
            self.assertIn("E9-LKM-SNAPSHOT-INCOMPLETE", by_rule)
            self.assertNotEqual(Severity.CRITICAL, by_rule["E9-EVT-VM-WRITEV-INJECT"].severity)
            self.assertEqual(Severity.LOW, by_rule["E9-EVT-LIVE-UINPUT-CREATED"].severity)
            self.assertEqual(Severity.HIGH, by_rule["E9-DMA-VFIO-UIO-DEVICE"].severity)

            # enable_kernel_lkm=False must pass load_lkm=False even when euid == 0
            ctx_root_nolkm = ScanContext(
                home_dir=home,
                root_prefix=Path("/"),
                proc_root=proc,
                live_mode=True,
                enable_kernel_lkm=False,
            )
            with (
                mock.patch("os.geteuid", return_value=0),
                mock.patch.object(
                    priv_helper,
                    "collect_privileged_kernel_snapshot",
                    return_value={"ok": True, "lkm_loaded": False, "root_extras": {}},
                ) as m_snap,
                mock.patch.object(engine9_kernel, "_analyze_kernel_surface_sysfs", return_value=None),
                mock.patch.object(engine9_kernel, "_run_unprivileged_native_probe", return_value=({}, "")),
            ):
                engine9_kernel.run(ctx_root_nolkm)
            self.assertEqual(False, m_snap.call_args.kwargs["load_lkm"])
            self.assertEqual("SKIPPED", ctx_root_nolkm.telemetry["scan_coverage"]["E9.lkm"]["status"])

    def test_e1_tail_read_e4_inside_mc_symlink_e5_gzip_bomb_e6_corrupt_sqlite_and_xbel(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)

            # E1: Large >2 MiB .bash_history with wipe command only at the tail + NaN window safety
            big_pad = ("ls -la\n" * 350_000).encode("utf-8")
            (home / ".bash_history").write_bytes(big_pad + b"shred -u ~/.minecraft/mods/wurst.jar\n")
            ctx1 = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False, time_window_hours=float("nan"))
            engine1_integrity.run(ctx1)
            self.assertIn("E1-HIST-ANTIFORENSIC-CMD", {f.rule_id for f in ctx1.findings})

            # E4: Symlink pointing to another folder inside same .minecraft root must NOT trigger E4-MC-SUSPICIOUS-SYMLINK
            (home / ".minecraft/config").mkdir(parents=True, exist_ok=True)
            (home / ".minecraft/config/target_mod.jar").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
            os.symlink(home / ".minecraft/config/target_mod.jar", home / ".minecraft/mods/legit_internal.jar")
            ctx4 = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False, deep_home_scan=False)
            engine4_deep_files._check_symlinks_in_mc_dirs(ctx4, [home / ".minecraft"])
            self.assertNotIn("E4-MC-SUSPICIOUS-SYMLINK", {f.rule_id for f in ctx4.findings})

            # E5: 10 MiB compressed-to-tiny gzip bomb must stay bounded <= 8 MiB without OOM
            gz_path = home / ".minecraft/logs/bomb.log.gz"
            gz_path.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(gz_path, "wb") as gf:
                gf.write(b"A" * (10 * 1024 * 1024))
            dec = engine5_minecraft._read_log_file_text(gz_path)
            self.assertEqual(8 * 1024 * 1024, len(dec))

            # E6: Corrupt Chrome History DB must NOT trigger false E6-BROWSER-HISTORY-WIPED;
            # deleted /tmp/mozilla_0/report.pdf in xbel must NOT trigger CRITICAL, whereas /tmp/ghost.jar DOES
            chrome_dir = home / ".config/google-chrome/Default"
            chrome_dir.mkdir(parents=True, exist_ok=True)
            (chrome_dir / "History").write_bytes(b"not a valid sqlite file")
            xbel_p = home / ".local/share/recently-used.xbel"
            xbel_p.parent.mkdir(parents=True, exist_ok=True)
            xbel_p.write_text(
                '<?xml version="1.0" encoding="UTF-8"?><xbel version="1.0">'
                '<bookmark href="file:///tmp/mozilla_0/invoice.pdf" modified="2026-01-01T00:00:00Z"/>'
                "</xbel>",
                encoding="utf-8",
            )
            ctx6 = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine6_desktop_traces.run(ctx6)
            r6 = {f.rule_id for f in ctx6.findings}
            self.assertNotIn("E6-BROWSER-HISTORY-WIPED", r6)
            self.assertNotIn("E6-XBEL-DELETED-ARTIFACT", r6)

            xbel_p.write_text(
                '<?xml version="1.0" encoding="UTF-8"?><xbel version="1.0">'
                '<bookmark href="file:///tmp/ghost.jar" modified="2026-01-01T00:00:00Z"/>'
                "</xbel>",
                encoding="utf-8",
            )
            ctx6b = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            engine6_desktop_traces.run(ctx6b)
            self.assertIn("E6-XBEL-DELETED-ARTIFACT", {f.rule_id for f in ctx6b.findings})

            # Corrupt SQLite should log error & orchestrator must still yield PARTIAL even if engine marks COMPLETED
            ctx_orch = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            def _bad_mod(c: ScanContext) -> None:
                c.add_error("E1", "synthetic non-fatal read error")
                c.set_engine_status("E1", ScanStatus.COMPLETED, "lied complete")
            with mock.patch("ss_core.orchestrator.ENGINES", [("E1", _bad_mod)]):
                orchestrator.run_all_engines(ctx_orch, selected_engines={"E1"})
            self.assertEqual("PARTIAL", ctx_orch.telemetry["engine_status"]["E1"]["status"])

    def test_priv_helper_root_manifest_pin_and_iommu_failure_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            # 1. Tampered kernel source + forged kernel_sources.sha256 rejected under euid=0 manifest pin
            ksrc = base / "kernel"
            ksrc.mkdir(parents=True, exist_ok=True)
            for name in ("mc_ss_kmod.c", "mc_ss_kmod.h", "Makefile"):
                (ksrc / name).write_text(f"// forged {name}\n", encoding="utf-8")
            (ksrc / "kernel_sources.sha256").write_text(
                "\n".join(
                    f"{hashlib.sha256((ksrc / n).read_bytes()).hexdigest()}  {n}"
                    for n in ("mc_ss_kmod.c", "mc_ss_kmod.h", "Makefile")
                ) + "\n",
                encoding="utf-8",
            )
            with mock.patch("os.geteuid", return_value=0):
                ok_src, msg_src = priv_helper.verify_kernel_sources(ksrc, require_manifest=True)
            self.assertFalse(ok_src)
            self.assertIn("mismatch", msg_src.lower())

            # 2. Failed grub-mkconfig rolls back /etc/default/grub cleanly
            grub_cfg = base / "etc/default/grub"
            grub_cfg.parent.mkdir(parents=True, exist_ok=True)
            orig_grub = 'GRUB_CMDLINE_LINUX="quiet splash"\n'
            grub_cfg.write_text(orig_grub, encoding="utf-8")
            fake_plan = {
                "needed": True,
                "can_auto_apply": True,
                "bootloader": "grub_update",
                "recommended_args": ["intel_iommu=on", "iommu.strict=1"],
                "remove_args": [],
                "bootloader_meta": {"grub_default": str(grub_cfg), "grub_cfg": str(base / "boot/grub/grub.cfg")},
            }
            fail_cp = subprocess.CompletedProcess(["update-grub"], 1, stdout="", stderr="syntax error")
            with (
                mock.patch("os.geteuid", return_value=0),
                mock.patch.object(priv_helper, "build_iommu_hardening_plan", return_value=fake_plan),
                mock.patch.object(priv_helper, "_trusted_bin", side_effect=lambda n: "/usr/sbin/update-grub" if n == "update-grub" else None),
                mock.patch("subprocess.run", return_value=fail_cp),
            ):
                res_rb = priv_helper.execute_iommu_hardening_as_root(root_prefix=Path("/"))
            self.assertFalse(res_rb["ok"])
            self.assertFalse(res_rb["changed"])
            self.assertEqual(orig_grub.strip(), grub_cfg.read_text(encoding="utf-8").strip())


if __name__ == "__main__":
    unittest.main()

"""Unit tests for multi-OS profiles, LKM build/discovery, multi-bootloader IOMMU, Snap/AUR/SteamOS forensics, and GUI OS selector."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.sim_lab import build_clean_baseline


class TestDistroDetectionAndProfiles(unittest.TestCase):
    def test_detect_all_tier1_and_tier2_distros(self) -> None:
        from ss_core.distro_profiles import detect_host_distro, TARGET_ORDER

        self.assertEqual(
            set(TARGET_ORDER),
            {"bazzite", "fedora_nobara", "ubuntu_24_04", "ubuntu_22_04", "debian", "arch_cachyos", "steamos"},
        )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "run").mkdir()
            (root / "run/ostree-booted").write_text("", encoding="utf-8")
            det_baz = detect_host_distro(
                root_prefix=root,
                os_release_text='ID=bazzite\nNAME="Bazzite"\nPRETTY_NAME="Bazzite (Fedora Atomic)"\nVARIANT_ID=bazzite\n',
                kernel_release="7.3.3-ogc1.1.fc45.x86_64",
            )
            self.assertEqual("bazzite", det_baz.target_id)
            self.assertTrue(det_baz.is_ostree)

            # Fedora Silverblue atomic maps to bazzite/fedora_atomic profile
            det_sb = detect_host_distro(
                root_prefix=root,
                os_release_text='ID=fedora\nVARIANT_ID=silverblue\nPRETTY_NAME="Fedora Linux 43 (Silverblue)"\n',
                kernel_release="6.14.0.fc43.x86_64",
            )
            self.assertEqual("bazzite", det_sb.target_id)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            det_fed = detect_host_distro(
                root_prefix=root,
                os_release_text='ID=nobara\nID_LIKE=fedora\nPRETTY_NAME="Nobara Linux 43"\n',
                kernel_release="6.14.2-200.fsync.fc43.x86_64",
            )
            self.assertEqual("fedora_nobara", det_fed.target_id)

            det_u24 = detect_host_distro(
                root_prefix=root,
                os_release_text='ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 24.04.2 LTS"\n',
                kernel_release="6.8.0-51-generic",
            )
            self.assertEqual("ubuntu_24_04", det_u24.target_id)

            det_mint21 = detect_host_distro(
                root_prefix=root,
                os_release_text='ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="21.3"\nUBUNTU_CODENAME=jammy\nPRETTY_NAME="Linux Mint 21.3"\n',
                kernel_release="5.15.0-125-generic",
            )
            self.assertEqual("ubuntu_22_04", det_mint21.target_id)

            det_deb = detect_host_distro(
                root_prefix=root,
                os_release_text='ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\nPRETTY_NAME="Debian GNU/Linux 12"\n',
                kernel_release="6.1.0-28-amd64",
            )
            self.assertEqual("debian", det_deb.target_id)

            det_cachy = detect_host_distro(
                root_prefix=root,
                os_release_text='ID=cachyos\nID_LIKE=arch\nPRETTY_NAME="CachyOS Linux"\n',
                kernel_release="6.13.4-2-cachyos-lto",
            )
            self.assertEqual("arch_cachyos", det_cachy.target_id)

            det_steam = detect_host_distro(
                root_prefix=root,
                os_release_text='ID=steamos\nID_LIKE=arch\nPRETTY_NAME="SteamOS Holo"\n',
                kernel_release="6.1.52-valve16-1-neptune-61",
            )
            self.assertEqual("steamos", det_steam.target_id)
            self.assertTrue(det_steam.is_steamos)

    def test_arch_headers_mapping_and_install_hints(self) -> None:
        from ss_core.distro_profiles import (
            arch_headers_package_for_release,
            format_kernel_headers_install_hint,
        )

        self.assertEqual("linux-headers", arch_headers_package_for_release("6.12.7-arch1-1"))
        self.assertEqual("linux-zen-headers", arch_headers_package_for_release("6.12.7-zen1-1-zen"))
        self.assertEqual("linux-lts-headers", arch_headers_package_for_release("6.6.68-1-lts"))
        self.assertEqual("linux-cachyos-headers", arch_headers_package_for_release("6.13.1-2-cachyos"))
        self.assertEqual("linux-cachyos-lto-headers", arch_headers_package_for_release("6.13.1-2-cachyos-lto"))
        self.assertEqual("linux612-headers", arch_headers_package_for_release("6.12.4-1-MANJARO"))

        hint_cachy = format_kernel_headers_install_hint("arch_cachyos", "6.13.1-2-cachyos-lto", needs_llvm=True)
        self.assertIn("linux-cachyos-lto-headers", hint_cachy)
        self.assertIn("clang", hint_cachy)
        self.assertIn("dnf", format_kernel_headers_install_hint("fedora_nobara", "6.14.0.fc43"))
        self.assertIn("linux-headers-5.15.0-generic", format_kernel_headers_install_hint("ubuntu_22_04", "5.15.0-generic"))


class TestMultiBootloaderIommuPlans(unittest.TestCase):
    def _prep_unhardened_sys(self, base: Path) -> tuple[Path, Path]:
        root = base / "root"
        proc = base / "proc"
        (root / "sys/firmware/acpi/tables").mkdir(parents=True, exist_ok=True)
        (root / "sys/firmware/acpi/tables/DMAR").write_bytes(b"DMAR")
        proc.mkdir(parents=True, exist_ok=True)
        (proc / "cpuinfo").write_text("vendor_id\t: GenuineIntel\n", encoding="utf-8")
        (proc / "cmdline").write_text("BOOT_IMAGE=/vmlinuz root=/dev/nvme0n1p2 quiet splash iommu=pt\n", encoding="utf-8")
        return root, proc

    def test_grub_ubuntu_and_dry_root_apply(self) -> None:
        from ss_core import priv_helper

        with tempfile.TemporaryDirectory() as td:
            root, proc = self._prep_unhardened_sys(Path(td))
            grub_def = root / "etc/default/grub"
            grub_def.parent.mkdir(parents=True, exist_ok=True)
            grub_def.write_text('GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX_DEFAULT="quiet splash iommu=pt"\n', encoding="utf-8")

            plan = priv_helper.build_iommu_hardening_plan(root_prefix=root, proc_root=proc, target_os="ubuntu_24_04")
            self.assertTrue(plan["needed"])
            self.assertEqual("grub_update", plan["bootloader"])
            self.assertEqual("update-grub", plan["commands"][1][0])

            res = priv_helper.execute_iommu_hardening_as_root(target_os="ubuntu_24_04", root_prefix=root, proc_root=proc)
            self.assertTrue(res["ok"])
            updated = grub_def.read_text(encoding="utf-8")
            self.assertIn("quiet splash", updated)
            self.assertNotIn("iommu=pt", updated)
            self.assertIn("intel_iommu=on", updated)
            self.assertIn("iommu=force", updated)
            self.assertIn("iommu.strict=1", updated)
            self.assertTrue(Path(str(grub_def) + ".mc_ss_sentinel.bak").is_file())

    def test_systemd_boot_limine_fedora_and_steamos(self) -> None:
        from ss_core import priv_helper

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, proc = self._prep_unhardened_sys(base)
            # 1) Fedora -> grubby
            plan_fed = priv_helper.build_iommu_hardening_plan(root_prefix=root, proc_root=proc, target_os="fedora_nobara")
            self.assertEqual("grubby", plan_fed["bootloader"])
            self.assertEqual("grubby", plan_fed["commands"][0][0])

            # 2) SteamOS -> inspect-only safety guard
            plan_steam = priv_helper.build_iommu_hardening_plan(root_prefix=root, proc_root=proc, target_os="steamos")
            self.assertEqual("steamos_readonly", plan_steam["bootloader"])
            self.assertFalse(plan_steam["can_auto_apply"])

            # 3) Arch systemd-boot
            entries = root / "boot/loader/entries"
            entries.mkdir(parents=True, exist_ok=True)
            (root / "boot/loader/loader.conf").write_text("default arch.conf\n", encoding="utf-8")
            main_ent = entries / "arch.conf"
            fb_ent = entries / "arch-fallback.conf"
            main_ent.write_text("title Arch\noptions root=UUID=123 rw iommu=pt\n", encoding="utf-8")
            fb_ent.write_text("title Arch Fallback\noptions root=UUID=123 rw\n", encoding="utf-8")

            plan_sd = priv_helper.build_iommu_hardening_plan(root_prefix=root, proc_root=proc, target_os="arch_cachyos")
            self.assertEqual("systemd_boot", plan_sd["bootloader"])
            res_sd = priv_helper.execute_iommu_hardening_as_root(target_os="arch_cachyos", root_prefix=root, proc_root=proc)
            self.assertTrue(res_sd["ok"])
            self.assertIn("iommu.strict=1", main_ent.read_text(encoding="utf-8"))
            self.assertNotIn("iommu=pt", main_ent.read_text(encoding="utf-8"))
            self.assertNotIn("iommu.strict=1", fb_ent.read_text(encoding="utf-8"))

        # 4) CachyOS Limine
        with tempfile.TemporaryDirectory() as td2:
            root2, proc2 = self._prep_unhardened_sys(Path(td2))
            lim_def = root2 / "etc/default/limine"
            lim_def.parent.mkdir(parents=True, exist_ok=True)
            lim_def.write_text('KERNEL_CMDLINE[default]+="quiet zswap.enabled=0"\n', encoding="utf-8")
            plan_lim = priv_helper.build_iommu_hardening_plan(root_prefix=root2, proc_root=proc2, target_os="arch_cachyos")
            self.assertEqual("limine", plan_lim["bootloader"])
            res_lim = priv_helper.execute_iommu_hardening_as_root(target_os="arch_cachyos", root_prefix=root2, proc_root=proc2)
            self.assertTrue(res_lim["ok"])
            self.assertIn("zswap.enabled=0", lim_def.read_text(encoding="utf-8"))
            self.assertIn("iommu=force", lim_def.read_text(encoding="utf-8"))


class TestMultiOsDiscoveryAndForensics(unittest.TestCase):
    def test_snap_browsers_and_steamos_media_discovery(self) -> None:
        from ss_core.models import ScanContext
        from ss_core.utils import discover_browser_databases, discover_minecraft_roots

        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            snap_ff = home / "snap/firefox/common/.mozilla/firefox/abc123.default"
            snap_chr = home / "snap/chromium/common/chromium/Default"
            snap_ff.mkdir(parents=True, exist_ok=True)
            snap_chr.mkdir(parents=True, exist_ok=True)
            (snap_ff / "places.sqlite").write_bytes(b"SQLite format 3\x00")
            (snap_chr / "History").write_bytes(b"SQLite format 3\x00")

            sd_mc = root / "run/media/mmcblk0p1/PrismLauncher"
            sd_mc.mkdir(parents=True, exist_ok=True)

            ctx = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            dbs = discover_browser_databases(ctx)
            labels = [lbl for lbl, _t, _p in dbs]
            self.assertTrue(any("Snap Firefox" in lbl for lbl in labels), f"Got {labels}")
            self.assertTrue(any("Snap Chromium" in lbl for lbl in labels), f"Got {labels}")

            roots = discover_minecraft_roots(ctx)
            mc_paths = [p.resolve() for _lbl, p in roots]
            self.assertIn(sd_mc.resolve(), mc_paths)

    def test_distro_pkg_logs_aur_and_mac_forensics(self) -> None:
        from ss_core import engine1_integrity
        from ss_core.models import ScanContext

        with tempfile.TemporaryDirectory() as td:
            home, root, proc = build_clean_baseline(Path(td))
            # Pacman log truncated (0 bytes) while pacman local DB exists + AUR suspicious cache
            (root / "var/lib/pacman/local").mkdir(parents=True, exist_ok=True)
            (root / "var/log/pacman.log").parent.mkdir(parents=True, exist_ok=True)
            (root / "var/log/pacman.log").write_text("", encoding="utf-8")

            # APT history suspicious install
            (root / "var/log/apt").mkdir(parents=True, exist_ok=True)
            (root / "var/log/apt/history.log").write_text(
                "Start-Date: 2026-11-15  20:00:00\nInstall: scanmem:amd64 (0.17)\n",
                encoding="utf-8",
            )

            # AUR suspicious build cache
            aur_pkg = home / ".cache/yay/pcileech-git"
            aur_pkg.mkdir(parents=True, exist_ok=True)

            # MAC permissive SELinux on bazzite profile
            (root / "sys/fs/selinux").mkdir(parents=True, exist_ok=True)
            (root / "sys/fs/selinux/enforce").write_text("0\n", encoding="utf-8")

            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
                target_os="bazzite",
            )
            engine1_integrity.run(ctx)
            rids = {f.rule_id for f in ctx.findings}
            self.assertIn("E1-PKG-LOG-TAMPERED", rids)
            self.assertIn("E1-PKG-SUSPICIOUS-INSTALL", rids)
            self.assertIn("E1-AUR-SUSPICIOUS-PACKAGE", rids)
            self.assertIn("E1-MAC-SELINUX-PERMISSIVE", rids)


class TestLkmVersioningAndClangDetection(unittest.TestCase):
    def test_clang_config_detection_and_versioned_lkm_sha(self) -> None:
        from ss_core import priv_helper

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            kdir = base / "kdir"
            kdir.mkdir()
            (kdir / ".config").write_text("CONFIG_CC_IS_CLANG=y\nCONFIG_LTO_CLANG_THIN=y\n", encoding="utf-8")
            self.assertTrue(priv_helper._kdir_uses_clang(kdir))

            (kdir / ".config").write_text("CONFIG_CC_IS_GCC=y\n", encoding="utf-8")
            self.assertFalse(priv_helper._kdir_uses_clang(kdir))

            # Versioned prebuilt LKM discovery + SHA-256 verification
            rel = "6.13.4-2-cachyos-lto"
            pre = base / "kernel/prebuilt" / rel
            pre.mkdir(parents=True, exist_ok=True)
            ko = pre / "mc_ss_kmod.ko"
            ko.write_bytes(b"\x7fELFfake-ko")
            (pre / "mc_ss_kmod.ko.sha256").write_text(
                hashlib.sha256(ko.read_bytes()).hexdigest() + "\n",
                encoding="utf-8",
            )
            found = priv_helper.find_lkm_object(root=base, kernel_release=rel)
            self.assertEqual(ko, found)

            # Corrupt .sha256 rejects module cleanly
            (pre / "mc_ss_kmod.ko.sha256").write_text("0" * 64 + "\n", encoding="utf-8")
            self.assertIsNone(priv_helper.find_lkm_object(root=base, kernel_release=rel))

    def test_kernel_sources_sha_verification(self) -> None:
        from ss_core import priv_helper

        with tempfile.TemporaryDirectory() as td:
            ksrc = Path(td)
            for name in ("mc_ss_kmod.c", "mc_ss_kmod.h", "Makefile"):
                (ksrc / name).write_text(f"// {name}\n", encoding="utf-8")
            lines = [
                f"{hashlib.sha256((ksrc / name).read_bytes()).hexdigest()}  {name}"
                for name in ("mc_ss_kmod.c", "mc_ss_kmod.h", "Makefile")
            ]
            (ksrc / "kernel_sources.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
            ok, _ = priv_helper.verify_kernel_sources(ksrc)
            self.assertTrue(ok)

            # Tamper mc_ss_kmod.c -> must fail verification
            (ksrc / "mc_ss_kmod.c").write_text("// tampered\n", encoding="utf-8")
            ok2, msg2 = priv_helper.verify_kernel_sources(ksrc)
            self.assertFalse(ok2)
            self.assertIn("mismatch", msg2.lower())


class TestTargetOsDialogAndPackagingRecipes(unittest.TestCase):
    def test_target_os_dialog_offscreen_and_main_window_report(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtCore import QEventLoop, QTimer
        from PySide6.QtWidgets import QApplication
        import ss_gui
        from ss_core.distro_profiles import TARGET_ORDER

        app = QApplication.instance() or QApplication([])
        dlg = ss_gui.TargetOSDialog(default_target_os="ubuntu_24_04")
        dlg.show()
        app.processEvents()

        self.assertFalse(dlg.windowIcon().isNull())
        self.assertIn("#000000", dlg.styleSheet())
        self.assertEqual(set(TARGET_ORDER), set(dlg.option_buttons.keys()))
        self.assertEqual("ubuntu_24_04", dlg.selected_target_os)

        dlg.option_buttons["arch_cachyos"].setChecked(True)
        app.processEvents()
        self.assertEqual("arch_cachyos", dlg.selected_target_os)
        self.assertIn("LLVM=1", dlg.detail_label.text())
        dlg.close()

        with tempfile.TemporaryDirectory() as td:
            home, _root, _proc = build_clean_baseline(Path(td))
            desktop = home / "Desktop"
            desktop.mkdir(parents=True, exist_ok=True)
            win = ss_gui.SentinelMainWindow(
                home_dir=home,
                desktop_dir=desktop,
                target_os="ubuntu_24_04",
            )
            self.assertIn("Ubuntu 24.04", win.os_badge_label.text())

            loop = QEventLoop()
            finished_ok: list[bool] = []
            QTimer.singleShot(120000, loop.quit)
            try:
                win.scan_button.click()
                assert win._worker is not None
                win._worker.scan_completed.connect(lambda _p, _pl: (finished_ok.append(True), loop.quit()))
                win._worker.scan_failed.connect(lambda _e: (finished_ok.append(False), loop.quit()))
                loop.exec()
                app.processEvents()
            finally:
                if win._worker is not None and win._worker.isRunning():
                    win._worker.wait(10000)
                win.close()

            self.assertEqual([True], finished_ok)
            txts = list(desktop.glob("MC_SS_Raporu_*.txt"))
            self.assertEqual(1, len(txts))
            report_txt = txts[0].read_text(encoding="utf-8")
            self.assertIn("Ubuntu 24.04", report_txt)

    def test_packaging_recipes_and_dry_run_builder(self) -> None:
        repo = Path(__file__).resolve().parent.parent
        targets_json = repo / "packaging/targets.json"
        self.assertTrue(targets_json.is_file())
        data = json.loads(targets_json.read_text(encoding="utf-8"))
        targets = data["targets"]
        self.assertEqual(7, len(targets))
        for tid, cfg in targets.items():
            self.assertTrue((repo / cfg["dockerfile"]).is_file(), f"Missing Dockerfile for {tid}")

        builder = repo / "scripts/build_distro_targets.py"
        cp = subprocess.run(
            [sys.executable, str(builder), "--all", "--dry-run"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, cp.returncode, cp.stderr)
        for tid in targets:
            self.assertIn(f"targets/{tid}", cp.stdout)


if __name__ == "__main__":
    unittest.main()

"""Isolated simulation tests for Engine 9: Ring-0 Kernel, DMA/IOMMU, 4KB PCIe & eBPF."""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path

from ss_core import engine8_reporter, engine9_kernel, orchestrator, priv_helper
from ss_core.models import ScanContext
from tests.sim_lab import build_clean_baseline


def _write_clean_sysfs_kernel_surface(root: Path, proc: Path) -> None:
    (proc / "cmdline").write_text(
        "BOOT_IMAGE=/vmlinuz root=UUID=test intel_iommu=on iommu=force iommu.strict=1 iommu.passthrough=0\n",
        encoding="utf-8",
    )
    (proc / "cpuinfo").write_text("vendor_id\t: GenuineIntel\n", encoding="utf-8")
    (proc / "modules").write_text("ext4 102400 1 - Live 0x0000000000000000\n", encoding="utf-8")
    (proc / "sys" / "kernel").mkdir(parents=True, exist_ok=True)
    (proc / "sys" / "kernel" / "tainted").write_text("0\n", encoding="utf-8")
    (proc / "sys" / "kernel" / "modprobe").write_text("/usr/sbin/modprobe\n", encoding="utf-8")
    (proc / "sys" / "kernel" / "core_pattern").write_text("|/usr/lib/systemd/systemd-coredump\n", encoding="utf-8")

    (root / "sys" / "firmware" / "acpi" / "tables").mkdir(parents=True, exist_ok=True)
    (root / "sys" / "firmware" / "acpi" / "tables" / "DMAR").write_bytes(b"DMAR")
    (root / "sys" / "class" / "iommu" / "dmar0").mkdir(parents=True, exist_ok=True)
    (root / "sys" / "kernel" / "iommu_groups" / "0" / "devices").mkdir(parents=True, exist_ok=True)
    (root / "sys" / "module" / "ext4").mkdir(parents=True, exist_ok=True)
    (root / "sys" / "module" / "ext4" / "initstate").write_text("live\n", encoding="utf-8")


class TestEngine9KernelAndDma(unittest.TestCase):
    def test_engine9_weights_sum_100_and_clean_ring0_baseline(self) -> None:
        self.assertEqual(100, sum(orchestrator.ENGINE_WEIGHTS.values()))
        self.assertIn("E9", orchestrator.ENGINE_WEIGHTS)
        self.assertTrue(any(code == "E9" for code, _ in orchestrator.ENGINES))

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            _write_clean_sysfs_kernel_surface(root, proc)
            (proc / "100").mkdir(parents=True, exist_ok=True)

            ring0_mock = {
                "ok": True,
                "lkm_loaded": True,
                "lkm_unloaded_cleanly": True,
                "proc_snapshots": {
                    "status": "STATUS|version=2.0.0-ring0|kernel=7.3.3|nonce=abc|taint_str=Not tainted|live_probes=1\n",
                    "integrity": "\n".join([
                        "KHOOK|sym=do_syscall_64|addr=0xffffffff81001000|resolved=do_syscall_64+0x0/0x100|pte_lvl=1|pte_rw=0|pte_exec=1|hook_class=CANONICAL_FENTRY_NOP|jmp_target=0x0|jmp_sym=NONE|bytes=f30f1efa0f1f4400",
                        "VFSHOOK|mount=/proc|iterate_shared=0xffffffff81200000|iter_sym=proc_root_readdir+0x0/0x50|open=0xffffffff81200100|open_sym=proc_root_open+0x0/0x40",
                        "MODINFO|name=ext4|state=0|taints=0x0|sig_ok=1|text=0xffffffffc0010000-0xffffffffc0050000|init=0x0-0x0|rw_anom=0",
                        "MODXSCAN|start=0xffffffffc0010000|end=0xffffffffc0050000|pages=64|rw=0|covered=1|mod=ext4|sym=ext4_fill_super|elf_carve=0|vermagic_carve=0|head=00",
                    ]),
                    "tasks_vma": "TASK|pid=100|tgid=100|ppid=1|real_ppid=1|uid=1000|ptrace=0x0|comm=bash|exe=/usr/bin/bash|deleted=0\n",
                    "pci_iommu": "PCIDEV|bdf=0000:00:1f.6|vid=0x8086|did=0x15b8|svid=0x8086|sdid=0x0000|class=0x020000|rev=0x11|hdr=0x00|driver=e1000e|iommu_grp=1|iommu_dom=DMA_STRICT_OR_TRANSLATED|bme_hw=1|bme_sw=1|untrusted=0|ext_facing=0|tb=0|pcie_spd=1|pcie_w=1|dsn=1122334455667788|cfg_sz=256|cap_loop=0|cfg_head=00",
                    "events": "",
                },
                "root_extras": {"native_probe": {"bpf": {"progs": []}, "pid_cross": {"hidden_candidates": []}}},
            }

            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
                kernel_snapshot_data=ring0_mock,
            )
            orchestrator.run_all_engines(ctx, selected_engines={"E9"})
            bad = [f for f in ctx.findings if f.severity.rank >= 2]
            self.assertEqual([], bad, f"Clean Ring-0 baseline produced findings: {bad}")

            txt = engine8_reporter.render_txt_report(engine8_reporter.build_report_payload(ctx))
            self.assertIn("[Ring-0 Kernel / DMA / IOMMU / eBPF Ozeti]", txt)
            self.assertIn("AKTIF TARANDI", txt)

    def test_ring0_rootkit_hooks_orphan_elf_and_hidden_pid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            _write_clean_sysfs_kernel_surface(root, proc)
            (proc / "100").mkdir(parents=True, exist_ok=True)

            ring0_mock = {
                "ok": True,
                "lkm_loaded": True,
                "lkm_unloaded_cleanly": True,
                "proc_snapshots": {
                    "status": "STATUS|version=2.0.0-ring0|kernel=7.3.3|taint_str=Tainted: P OE\nTAINT|bit=12|char=O|desc=OOT module\nTAINT|bit=13|char=E|desc=unsigned module\n",
                    "integrity": "\n".join([
                        "KHOOK|sym=filldir64|addr=0xffffffff81300000|resolved=filldir64+0x0/0x90|pte_lvl=1|pte_rw=1|pte_exec=1|hook_class=JMP_REL32_HOOK|jmp_target=0xffffffffc0a00100|jmp_sym=0xffffffffc0a00100|bytes=e9abcdef00",
                        "VFSHOOK|mount=/proc|iterate_shared=0xffffffffc0a00500|iter_sym=0xffffffffc0a00500|open=0xffffffff81200100|open_sym=proc_root_open+0x0/0x40",
                        "MODINFO|name=diamorphine|state=0|taints=0x3000|sig_ok=0|text=0xffffffffc0a00000-0xffffffffc0a04000|init=0x0-0x0|rw_anom=1",
                        "MODXSCAN|start=0xffffffffc0b00000|end=0xffffffffc0b04000|pages=4|rw=1|covered=0|mod=ORPHAN|sym=0xffffffffc0b00000|elf_carve=1|vermagic_carve=1|head=7f454c4602010100",
                    ]),
                    "tasks_vma": "\n".join([
                        "TASK|pid=9999|tgid=9999|ppid=1|real_ppid=1|uid=0|ptrace=0x0|comm=stealth_rk|exe=/dev/shm/rk|deleted=0",
                        "VMA_ANOM|pid=100|comm=java|start=0x7f0010000000|end=0x7f0010010000|size=65536|flags=0x7|rwx=1|anon=1|memfd=0|shm=0|del=0|read=4096|elf=1|pe=0|jni_hits=2|jni_mask=0x5|file=[anon]|head=7f454c4602010100",
                    ]),
                    "pci_iommu": "",
                    "events": "\n".join([
                        "EVENT|ts_ns=1234|type=2|pid=555|tgid=555|uid=1000|comm=inj|arg0=0x64|arg1=0x1|detail=sys_process_vm_writev",
                        "EVENT|ts_ns=1235|type=11|pid=555|tgid=555|uid=1000|comm=macro|arg0=0x6|arg1=0x0|detail=bus=0x6 vid=0x0000 pid=0x0000 name=virtmouse",
                    ]),
                },
                "root_extras": {
                    "native_probe": {
                        "bpf": {
                            "progs": [
                                {"id": 42, "type": "KPROBE", "name": "hide_getdents", "uid": 0, "jited_len": 320, "run_cnt": 50}
                            ]
                        },
                        "pid_cross": {"hidden_candidates": [{"pid": 9999, "stat_ok": 1, "tgid": 9999}]},
                    }
                },
            }

            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
                kernel_snapshot_data=ring0_mock,
            )
            orchestrator.run_all_engines(ctx, selected_engines={"E9"})
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E9-LKM-WRITABLE-KTEXT",
                "E9-KERNEL-INLINE-HOOK",
                "E9-VFS-HOOK-HIJACK",
                "E9-KNOWN-ROOTKIT-LKM",
                "E9-HIDDEN-LKM-CROSSVIEW",
                "E9-ORPHAN-KERNEL-ELF",
                "E9-HIDDEN-PID-RING0",
                "E9-HIDDEN-PID-READDIR",
                "E9-KERNEL-VMA-REFLECTIVE-ELF",
                "E9-KERNEL-VMA-JNI-AGENT",
                "E9-EVT-VM-WRITEV-INJECT",
                "E9-EVT-LIVE-UINPUT-CREATED",
                "E9-EBPF-SUSPICIOUS-PROG",
                "E8-CORR-RING0-ROOTKIT",
                "E8-CORR-KERNEL-FILELESS",
            ):
                self.assertIn(expected, rids, f"Missing expected rule {expected}; got {sorted(rids)}")

    def test_dma_fpga_screamer_iommu_disabled_usb_mcu_and_hijack(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            _write_clean_sysfs_kernel_surface(root, proc)
            (proc / "100").mkdir(parents=True, exist_ok=True)

            # Simulate ACPI DMAR present YET zero IOMMU groups (like misconfigured host cmdline)
            (proc / "cmdline").write_text("BOOT_IMAGE=/vmlinuz ostree=/ostree/boot.0 rw\n", encoding="utf-8")
            for sub in list((root / "sys" / "class" / "iommu").iterdir()):
                sub.rmdir()
            (root / "sys" / "kernel" / "iommu_groups" / "0" / "devices").rmdir()
            (root / "sys" / "kernel" / "iommu_groups" / "0").rmdir()

            # Simulate hijacked modprobe_path & /etc/ld.so.preload
            (proc / "sys" / "kernel" / "modprobe").write_text("/tmp/.evil_modprobe\n", encoding="utf-8")
            (root / "etc" / "ld.so.preload").write_text("/dev/shm/libcloak.so\n", encoding="utf-8")

            # Simulate sysfs fallback PCI device with Bus Master bit ON and unbound driver
            pci_dev = root / "sys" / "bus" / "pci" / "devices" / "0000:03:00.0"
            pci_dev.mkdir(parents=True, exist_ok=True)
            (pci_dev / "vendor").write_text("0x10ee\n", encoding="utf-8")
            (pci_dev / "device").write_text("0x0666\n", encoding="utf-8")
            (pci_dev / "subsystem_vendor").write_text("0x10ee\n", encoding="utf-8")
            (pci_dev / "subsystem_device").write_text("0x0007\n", encoding="utf-8")
            (pci_dev / "class").write_text("0x020000\n", encoding="utf-8")
            (pci_dev / "uevent").write_text("PCI_ID=10EE:0666\n", encoding="utf-8")
            cfg = bytearray(64)
            struct.pack_into("<HHH", cfg, 0, 0x10EE, 0x0666, 0x0006)  # Bus Master enabled (0x4) + Mem (0x2)
            cfg[14] = 0x00  # Endpoint hdr_type=0
            (pci_dev / "config").write_bytes(bytes(cfg))

            # Simulate Arduino Leonardo BadUSB / hardware macro device
            usb_dev = root / "sys" / "bus" / "usb" / "devices" / "1-4"
            usb_dev.mkdir(parents=True, exist_ok=True)
            (usb_dev / "idVendor").write_text("2341\n", encoding="utf-8")
            (usb_dev / "idProduct").write_text("8036\n", encoding="utf-8")
            (usb_dev / "product").write_text("Arduino Leonardo\n", encoding="utf-8")
            (usb_dev / "manufacturer").write_text("Arduino LLC\n", encoding="utf-8")

            ctx = ScanContext(
                home_dir=home,
                root_prefix=root,
                proc_root=proc,
                live_mode=False,
                enable_kernel_lkm=True,
            )
            orchestrator.run_all_engines(ctx, selected_engines={"E9"})
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E9-DMA-IOMMU-DISABLED",
                "E9-DMA-FPGA-HARDWARE",
                "E9-DMA-UNBOUND-BUSMASTER",
                "E9-SYSCTL-MODPROBE-HIJACK",
                "E9-PERSIST-LD-SO-PRELOAD",
                "E9-HW-USB-MACRO-MCU",
                "E8-CORR-DMA-EXPOSURE",
                "E9-LKM-UNPRIVILEGED-FALLBACK",
            ):
                self.assertIn(expected, rids, f"Missing expected rule {expected}; got {sorted(rids)}")

            # Verify ostree hardening plan targets intel_iommu=on & iommu.strict=1
            plan = priv_helper.build_iommu_hardening_plan(root_prefix=root, proc_root=proc)
            self.assertTrue(plan["needed"])
            self.assertEqual("rpm-ostree", plan["commands"][0][0])
            self.assertIn("--append-if-missing=intel_iommu=on", plan["commands"][0])


class TestHardeningRegressions(unittest.TestCase):
    def test_bazzite_oot_modules_d3cold_chipset_uart_and_vpn_no_false_positives(self) -> None:
        from ss_core import engine1_integrity, engine3_input_macro, engine7_network_usb

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            _write_clean_sysfs_kernel_surface(root, proc)
            (proc / "100").mkdir(parents=True, exist_ok=True)

            # Real Bazzite (OE) taint bitmask (O+E=12288) with safe OOT modules + going module (state=2)
            (proc / "sys/kernel/tainted").write_text("12288\n", encoding="utf-8")
            (proc / "modules").write_text(
                "vhba 32768 0 - Live 0xffffffffc0100000 (OE)\n"
                "hid_fanatec 45056 0 - Live 0xffffffffc0110000 (OE)\n"
                "hid_logitech_new 65536 0 - Live 0xffffffffc0120000 (OE)\n"
                "hid_tmff_new 40960 0 - Live 0xffffffffc0130000 (OE)\n"
                "gcadapter_oc 16384 0 - Live 0xffffffffc0140000 (OE)\n"
                "system76_io 20480 0 - Live 0xffffffffc0150000 (OE)\n"
                "kvmfr 28672 0 - Live 0xffffffffc0160000 (OE)\n",
                encoding="utf-8",
            )

            # D3cold PCIe device (vid=0xffff / power_state=d3cold) + unbound Intel SRAM 0x050000 & GNA 0x088000
            d3_dev = root / "sys/bus/pci/devices/0000:04:00.0"
            d3_dev.mkdir(parents=True, exist_ok=True)
            (d3_dev / "vendor").write_text("0x10de\n", encoding="utf-8")
            (d3_dev / "device").write_text("0x2504\n", encoding="utf-8")
            (d3_dev / "subsystem_vendor").write_text("0x10de\n", encoding="utf-8")
            (d3_dev / "subsystem_device").write_text("0x1234\n", encoding="utf-8")
            (d3_dev / "class").write_text("0x030000\n", encoding="utf-8")
            (d3_dev / "power_state").write_text("d3cold\n", encoding="utf-8")
            (d3_dev / "config").write_bytes(b"\xff" * 64)

            # CH340 USB-Serial adapter (vendor interface 0xff, NOT HID 0x03) -> must not trigger macro MCU
            uart = root / "sys/bus/usb/devices/1-9"
            (uart / "1-9:1.0").mkdir(parents=True, exist_ok=True)
            (uart / "idVendor").write_text("1a86\n", encoding="utf-8")
            (uart / "idProduct").write_text("7523\n", encoding="utf-8")
            (uart / "product").write_text("USB Serial\n", encoding="utf-8")
            (uart / "manufacturer").write_text("1a86\n", encoding="utf-8")
            (uart / "bDeviceClass").write_text("ff\n", encoding="utf-8")
            (uart / "1-9:1.0/bInterfaceClass").write_text("ff\n", encoding="utf-8")

            # Polychromatic RGB wave lighting effect containing 'delay' and 'repeat' (NOT a mouse macro)
            rgb_dir = home / ".config/polychromatic/effects"
            rgb_dir.mkdir(parents=True, exist_ok=True)
            (rgb_dir / "wave.json").write_text('{"name":"Wave","delay":50,"repeat":true}', encoding="utf-8")

            # Populated bash history + 0B unused python history -> only LOW E1-HIST-ZERO
            (home / ".python_history").write_text("", encoding="utf-8")

            # Down tap0 & kernel default tunl0 -> must NOT trigger E7-VPN-ACTIVE
            (root / "sys/class/net/tap0").mkdir(parents=True, exist_ok=True)
            (root / "sys/class/net/tap0/operstate").write_text("down\n", encoding="utf-8")
            (root / "sys/class/net/tunl0").mkdir(parents=True, exist_ok=True)
            (root / "sys/class/net/tunl0/operstate").write_text("down\n", encoding="utf-8")

            snap = {
                "ok": True,
                "lkm_loaded": True,
                "lkm_unloaded_cleanly": True,
                "proc_snapshots": {
                    "status": "STATUS|version=2.0.0-ring0|kernel=7.3.3|nonce=clean|taint_str=Tainted: OE\nTAINT|bit=12|char=O|desc=out-of-tree module loaded\nTAINT|bit=13|char=E|desc=unsigned module loaded\n",
                    "integrity": (
                        "SYSCALL_ENTRY|msr_lstar=0xffffffff81000100|lstar_sym=entry_SYSCALL_64+0x0/0x80\n"
                        "MODINFO|name=vhba|state=0|taints=0x3000|sig_ok=0|text=0xffffffffc0100000-0xffffffffc0108000|init=0x0-0x0|rw_anom=0\n"
                        "MODINFO|name=going_mod|state=2|taints=0x0|sig_ok=1|text=0xffffffffc0200000-0xffffffffc0202000|init=0x0-0x0|rw_anom=0\n"
                    ),
                    "tasks_vma": "",
                    "pci_iommu": (
                        "PCIDEV|bdf=0000:00:08.0|vid=0x8086|did=0x464f|svid=0x8086|sdid=0x0000|class=0x088000|rev=0x01|hdr=0x00|driver=unbound|iommu_grp=1|iommu_dom=DMA_STRICT_OR_TRANSLATED|bme_hw=1|bme_sw=0|untrusted=0|ext_facing=0|tb=0|pcie_spd=0|pcie_w=0|dsn=0000000000000000|cfg_sz=256|d3cold=0|cap_loop=0|cfg_head=00\n"
                        "PCIDEV|bdf=0000:00:14.2|vid=0x8086|did=0x7aa7|svid=0x8086|sdid=0x0000|class=0x050000|rev=0x11|hdr=0x00|driver=unbound|iommu_grp=2|iommu_dom=DMA_STRICT_OR_TRANSLATED|bme_hw=1|bme_sw=0|untrusted=0|ext_facing=0|tb=0|pcie_spd=0|pcie_w=0|dsn=0000000000000000|cfg_sz=256|d3cold=1|cap_loop=1|cfg_head=ff\n"
                    ),
                    "events": (
                        "EVENT|ts_ns=1|type=1|pid=900|tgid=900|uid=1000|comm=wineserver|arg0=0x10|arg1=0x0|detail=sys_ptrace\n"
                        "EVENT|ts_ns=2|type=4|pid=901|tgid=901|uid=1000|comm=java|arg0=0x0|arg1=0x1|detail=sys_memfd_create\n"
                    ),
                },
                "root_extras": {"native_probe": {"bpf": {"progs": [], "links": []}, "pid_cross": {"hidden_candidates": []}}},
            }

            ctx = ScanContext(
                home_dir=home, root_prefix=root, proc_root=proc, live_mode=False,
                enable_kernel_lkm=True, kernel_snapshot_data=snap,
            )
            engine1_integrity.run(ctx)
            engine3_input_macro.run(ctx)
            engine7_network_usb.run(ctx)
            engine9_kernel.run(ctx)

            rids = {f.rule_id for f in ctx.findings}
            for fp in (
                "E9-UNKNOWN-OOT-MODULE",
                "E9-HIDDEN-LKM-CROSSVIEW",
                "E9-DMA-UNBOUND-BUSMASTER",
                "E9-DMA-SPOOFED-PCIE-FW",
                "E9-HW-USB-MACRO-MCU",
                "E9-EVT-PTRACE-INJECT",
                "E9-EVT-MEMFD-EXEC",
                "E9-MSR-LSTAR-HOOK",
                "E3-RAZER-MACRO",
                "E7-VPN-ACTIVE",
            ):
                self.assertNotIn(fp, rids, f"Unexpected false positive {fp} in {rids}")

            hist_zero = [f for f in ctx.findings if f.rule_id == "E1-HIST-ZERO"]
            self.assertEqual(len(hist_zero), 1)
            self.assertEqual(hist_zero[0].severity.value, "LOW")

    def test_renamed_ebpf_links_msr_lstar_ftrace_and_ram_denied_detected(self) -> None:
        from unittest.mock import patch
        from ss_core import engine2_live_proc, engine8_reporter
        from tests.sim_lab import write_simulated_proc_entry

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            _write_clean_sysfs_kernel_surface(root, proc)
            (proc / "100").mkdir(parents=True, exist_ok=True)

            # World-writable dir must be rejected by _is_trusted_artifact
            ww_dir = base / "world_dir"
            ww_dir.mkdir(mode=0o777)
            os.chmod(ww_dir, 0o777)
            fake_ko = ww_dir / "mc_ss_kmod.ko"
            fake_ko.write_bytes(b"ELF")
            self.assertFalse(priv_helper._is_trusted_artifact(fake_ko))

            snap = {
                "ok": True,
                "lkm_loaded": True,
                "lkm_unloaded_cleanly": True,
                "proc_snapshots": {
                    "status": "STATUS|version=2.0.0-ring0|kernel=7.3.3|nonce=bad|taint_str=Not tainted\n",
                    "integrity": "SYSCALL_ENTRY|msr_lstar=0xffffffffc0999000|lstar_sym=hooked_syscall [singularity]\n",
                    "tasks_vma": (
                        "VMA_ANOM|pid=4242|comm=java|start=0x7f0000100000|end=0x7f0000101000|size=4096|flags=0x8000071|rwx=0|anon=0|memfd=0|shm=0|del=0|read=4096|elf=1|pe=0|jni_hits=2|jni_mask=0x5|file=/memfd:ro_stealth (deleted)|head=7f454c4602010100\n"
                    ),
                    "pci_iommu": (
                        "PCIDEV|bdf=0000:05:00.0|vid=0x8086|did=0x1234|svid=0x10ee|sdid=0x0666|class=0x050000|rev=0x00|hdr=0x00|driver=unbound|iommu_grp=1|iommu_dom=DMA_STRICT_OR_TRANSLATED|bme_hw=1|bme_sw=1|untrusted=0|ext_facing=0|tb=0|pcie_spd=1|pcie_w=1|dsn=0000000000000000|cfg_sz=256|d3cold=0|cap_loop=0|cfg_head=00\n"
                    ),
                    "events": "",
                },
                "root_extras": {
                    "ftrace_enabled_functions": ["__x64_sys_getdents64 (1) I M  trampoline=0xffffffffc0998000 [singularity]"],
                    "native_probe": {
                        "bpf": {
                            "progs": [
                                {"id": 42, "type": "KPROBE", "name": "telemetry_benign", "uid": 0, "jited_len": 256, "run_cnt": 5},
                            ],
                            "links": [
                                {"id": 7, "type_id": 7, "prog_id": 42, "tp_name": "filldir64"},
                            ],
                        },
                        "pid_cross": {"hidden_candidates": []},
                    },
                },
            }

            ctx = ScanContext(
                home_dir=home, root_prefix=root, proc_root=proc, live_mode=False,
                enable_kernel_lkm=True, kernel_snapshot_data=snap,
            )
            engine9_kernel.run(ctx)
            engine8_reporter.correlate_findings(ctx)
            rids = {f.rule_id for f in ctx.findings}
            for expected in (
                "E9-MSR-LSTAR-HOOK",
                "E9-KERNEL-FOREIGN-FTRACE",
                "E9-EBPF-SUSPICIOUS-PROG",
                "E9-KERNEL-VMA-REFLECTIVE-ELF",
                "E9-KERNEL-VMA-JNI-AGENT",
                "E9-DMA-UNBOUND-BUSMASTER",
                "E9-DMA-SPOOFED-PCIE-FW",
                "E8-CORR-RING0-ROOTKIT",
            ):
                self.assertIn(expected, rids, f"Missing {expected} in {rids}")

            # Verify E2-RAM-ACCESS-DENIED when target Java/Minecraft /proc/<pid>/mem raises PermissionError
            write_simulated_proc_entry(
                proc,
                pid=4243,
                comm="java",
                cmdline=["/usr/bin/java", "-Xmx2G", "net.minecraft.client.main.Main"],
                maps_lines=["7f0000000000-7f0000010000 r-xp 00000000 00:00 0 "],
            )
            (proc / "4243" / "mem").write_bytes(b"")
            ctx2 = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False)
            real_open = os.open

            def _deny_mem_open(path, flags, *a, **kw):
                if str(path).endswith("/4243/mem"):
                    raise PermissionError("Operation not permitted")
                return real_open(path, flags, *a, **kw)

            with patch("os.open", side_effect=_deny_mem_open):
                engine2_live_proc.run(ctx2)
            self.assertIn("E2-RAM-ACCESS-DENIED", {f.rule_id for f in ctx2.findings})

    def test_gap_closures_ebpf_btf_events_cow_smaps_dsn_and_rawdev(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home, root, proc = build_clean_baseline(base)
            # World-readable /dev/mem and /dev/uio0
            dev = root / "dev"
            dev.mkdir(parents=True, exist_ok=True)
            (dev / "mem").write_bytes(b"")
            os.chmod(dev / "mem", 0o666)
            (dev / "uio0").write_bytes(b"")
            (proc / "100").mkdir(exist_ok=True)
            (proc / "6100").mkdir(exist_ok=True)

            snap = {
                "lkm_loaded": True,
                "lkm_unloaded_cleanly": True,
                "proc_snapshots": {
                    "status": "VERSION|ver=2.0.0-ring0|nonce=abc|taints=0x0|taint_str=NONE|events=4|kernel=7.3.3",
                    "integrity": "SYSCALL_ENTRY|msr_lstar=0xffffffff81000000|lstar_sym=entry_SYSCALL_64+0x0/0x50",
                    "tasks_vma": "\n".join([
                        "TASK|pid=100|tgid=100|ppid=1|real_ppid=1|uid=1000|ptrace=0x0|comm=bash|exe=/usr/bin/bash|deleted=0",
                        "TASK|pid=6100|tgid=6100|ppid=1|real_ppid=1|uid=1000|ptrace=0x0|comm=java|exe=/usr/bin/java|deleted=0",
                        "VMA_ANOM|pid=6100|comm=java|start=0x7f1000|end=0x7f3000|size=8192|flags=0x7|rwx=1|anon=1|memfd=0|shm=0|del=0|read=8192|elf=0|pe=0|jni_hits=1|jni_mask=0x40|file=[anon]|head=55505821",
                        "VMA_ANOM|pid=6100|comm=java|start=0x7f4000|end=0x7f6000|size=8192|flags=0x5|rwx=0|anon=1|memfd=0|shm=0|del=0|read=8192|elf=0|pe=0|jni_hits=1|jni_mask=0x20|file=[anon]|head=44656669",
                    ]),
                    "pci_iommu": (
                        "PCIDEV|bdf=0000:07:00.0|vid=0x8086|did=0x15b8|svid=0x8086|sdid=0x0000|class=0x020000|rev=0x01|hdr=0x00|driver=e1000e|iommu_grp=1|iommu_dom=DMA_STRICT_OR_TRANSLATED|bme_hw=1|bme_sw=1|untrusted=0|ext_facing=0|tb=0|pcie_spd=1|pcie_w=1|has_dsn=1|dsn=0000000000000000|cfg_sz=256|d3cold=0|cap_loop=0|cfg_head=00\n"
                    ),
                    "events": "\n".join([
                        "EVENT|ts_ns=10|type=5|pid=6100|tgid=6100|uid=1000|comm=inj|arg0=0x3|arg1=0x1000|detail=sys_execveat",
                        "EVENT|ts_ns=11|type=7|pid=6101|tgid=6101|uid=0|comm=evil_loader|arg0=0x5|arg1=0x0|detail=sys_bpf",
                        "EVENT|ts_ns=12|type=8|pid=6102|tgid=6102|uid=0|comm=rawdma|arg0=0x6e|arg1=0x3|detail=sys_rawio_port",
                        "EVENT|ts_ns=13|type=12|pid=6103|tgid=6103|uid=1000|comm=autoclick|arg0=0x4|arg1=0x5501|detail=sys_ioctl_ui_dev_create",
                    ]),
                },
                "root_extras": {
                    "bpf_pinned": ["/sys/fs/bpf/evil_hide_link"],
                    "native_probe": {
                        "bpf": {
                            "progs": [
                                {"id": 91, "type": "TRACING", "name": "trace_innocent", "attach_target": "tcp4_seq_show", "uid": 0, "jited_len": 128, "run_cnt": 1},
                                {"id": 92, "type": "KPROBE", "name": "sys_metric", "attach_target": "", "uid": 0, "jited_len": 64, "run_cnt": 2},
                            ],
                            "links": [],
                        },
                        "pid_cross": {"hidden_candidates": []},
                    },
                },
            }
            ctx = ScanContext(
                home_dir=home, root_prefix=root, proc_root=proc, live_mode=False,
                enable_kernel_lkm=True, kernel_snapshot_data=snap,
            )
            engine9_kernel.run(ctx)
            engine8_reporter.correlate_findings(ctx)
            rids9 = {f.rule_id for f in ctx.findings}
            for expected in (
                "E9-EBPF-SUSPICIOUS-PROG",
                "E9-EBPF-PINNED-OBJ",
                "E9-KERNEL-VMA-PACKED-CODE",
                "E9-KERNEL-VMA-JNI-AGENT",
                "E9-DMA-SPOOFED-PCIE-FW",
                "E9-EVT-EXECVEAT-FILELESS",
                "E9-EVT-LIVE-BPF-LOAD",
                "E9-EVT-RAW-IO-PORT",
                "E9-EVT-LIVE-UINPUT-CREATED",
                "E9-DMA-UIO-DEVICE-NODE",
                "E9-RAW-MEM-DEV-EXPOSED",
                "E8-CORR-RING0-ROOTKIT",
                "E8-CORR-KERNEL-FILELESS",
            ):
                self.assertIn(expected, rids9, f"Missing {expected} in {rids9}")

            # Verify Engine 2 smaps Copy-on-Write .text tamper detection + raw /dev/mem FD
            from ss_core import engine2_live_proc
            from tests.sim_lab import write_simulated_proc_entry

            write_simulated_proc_entry(
                proc,
                pid=6200,
                comm="java",
                cmdline=["/usr/bin/java", "-Xmx2G", "net.minecraft.client.main.Main"],
                maps_lines=["7f0000000000-7f0000100000 r-xp 00000000 fd:01 99 /usr/lib/jvm/libjvm.so"],
                fds={"4": "/dev/mem"},
            )
            (proc / "6200" / "smaps").write_text(
                "7f0000000000-7f0000100000 r-xp 00000000 fd:01 99 /usr/lib/jvm/libjvm.so\n"
                "Size: 1024 kB\nPrivate_Dirty: 4 kB\nAnonymous: 4 kB\n"
                "7f0000200000-7f0000210000 r-xp 00000000 fd:01 100 /usr/lib/libffi.so.8\n"
                "Size: 64 kB\nPrivate_Dirty: 4 kB\nAnonymous: 4 kB\n",
                encoding="utf-8",
            )
            ctx_e2 = ScanContext(home_dir=home, root_prefix=root, proc_root=proc, live_mode=False, enable_memory_scan=False)
            engine2_live_proc.run(ctx_e2)
            rids2 = {f.rule_id for f in ctx_e2.findings}
            self.assertIn("E2-MAP-TEXT-COW-PATCH", rids2)
            self.assertIn("E2-FD-RAW-DEV-ACCESS", rids2)
            cow_ev = " ".join(f.evidence[0] for f in ctx_e2.findings if f.rule_id == "E2-MAP-TEXT-COW-PATCH")
            self.assertNotIn("libffi", cow_ev)


if __name__ == "__main__":
    unittest.main()

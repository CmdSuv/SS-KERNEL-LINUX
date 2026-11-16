"""Engine 9: Ring-0 Kernel Integrity, DMA/IOMMU Guard, 4KB PCIe & eBPF Forensics."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import struct
import subprocess
from pathlib import Path
from typing import Any

from . import priv_helper
from .models import Confidence, Finding, ScanContext, Severity
from .utils import emit_scan_progress, record_scan_region

ENGINE_NAME = "Engine 9: Ring-0 Kernel, DMA/IOMMU & Donanim Forensigi"

_ROOTKIT_MOD_NAMES = (
    "diamorphine",
    "reptile",
    "suterusu",
    "kovid",
    "singularity",
    "nurupo",
    "azazel",
    "adore",
    "knark",
    "modhide",
    "hideme",
    "vegile",
    "rooty",
    "beurk",
)

_KNOWN_SAFE_OOT_MOD_PREFIXES = (
    "nvidia",
    "vbox",
    "vmware",
    "vmw_",
    "v4l2",
    "openrazer",
    "razer",
    "xone",
    "xpadneo",
    "zenergy",
    "ryzen_smu",
    "zenpower",
    "it87",
    "nct",
    "evdi",
    "vhba",
    "hid_fanatec",
    "hid_logitech_new",
    "hid_tmff_new",
    "gcadapter_oc",
    "system76",
    "kvmfr",
    "asus_",
    "msi_",
    "tuxedo_",
    "clevo_",
    "binder_linux",
    "ashmem_linux",
    "r8168",
    "wl",
    "rtl",
    "acer_wmi",
    "apple_bce",
    "framework_laptop",
    "virtualbox",
    "mc_ss_kmod",
)

_KNOWN_SAFE_EBPF_NAMES = (
    "bpftune",
    "systemd",
    "sd_",
    "dumpcap",
    "hid_bpf_",
    "hidraw_",
    "pasta",
    "cilium",
    "kube",
    "restrict_files",
    "bind_v4",
    "bind_v6",
    "sock_addr",
    "tetragon",
    "falco",
    "plymouth",
    "udev_",
    "firewalld",
    "nftables",
    "libbpf_",
)

_SUSPICIOUS_HOOK_CLASSES = {
    "JMP_REL32_HOOK",
    "JMP_SHORT_HOOK",
    "JMP_IND_RIP_HOOK",
    "MOV_IMM64_TRAMPOLINE",
    "INT3_BREAKPOINT",
}

_SAFE_FS_MOD_HINTS = (
    "proc",
    "ext4",
    "btrfs",
    "xfs",
    "erofs",
    "squashfs",
    "bcachefs",
    "zfs",
    "tmpfs",
    "overlay",
    "ovl_",
    "fuse",
    "vfs",
    "simple_dir",
    "dcache",
    "sysfs",
    "nfs",
    "exfat",
    "ntfs3",
    "vfat",
    "fat",
)

_FPGA_VENDOR_IDS = {
    "0x10ee": "Xilinx FPGA (PCILeech / Screamer / Enigma yaygın yongası)",
    "0x1172": "Altera / Intel FPGA",
    "0x1204": "Lattice Semiconductor FPGA",
    "0x10b5": "PLX Technology PCIe Köprüsü",
}

_KNOWN_PCILEECH_VID_DIDS = {
    ("0x10ee", "0x0666"),
    ("0x10ee", "0x0007"),
    ("0x10ee", "0x7024"),
    ("0x10ee", "0x7021"),
    ("0x10ee", "0x7028"),
    ("0x10ee", "0x9034"),
}

_USB_MACRO_MCU_VENDORS = {
    "2341": "Arduino SA",
    "2a03": "Arduino LLC",
    "1b4f": "SparkFun / Pro Micro",
    "239a": "Adafruit",
    "16c0": "Van Ooijen / Teensyduino HID",
    "2e8a": "Raspberry Pi RP2040 / Pico",
    "1a86": "WCH CH340/CH552 Bridge",
    "36b0": "Hardware HID Bridge",
}

_USB_MACRO_KW_RE = re.compile(
    r"(arduino|leonardo|teensy|pro micro|rp2040|kmbox|makcu|badusb|hid-gadget|ch340|stm32.*hid)",
    re.IGNORECASE,
)


def parse_pipe_kv_lines(text: str, prefix: str) -> list[dict[str, str]]:
    """Parse structured `PREFIX|key=val|key2=val2` records from /proc/mc_ss_sentinel/*."""
    records: list[dict[str, str]] = []
    if not text:
        return records
    want = prefix + "|"
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith(want):
            continue
        item: dict[str, str] = {}
        parts = line.split("|")[1:]
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                item[k] = v
        records.append(item)
    return records


def _extract_mod_from_sym(sym: str) -> str:
    m = re.search(r"\[([A-Za-z0-9_\-]+)\]", sym or "")
    return m.group(1) if m else ""


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return ""


def _analyze_lkm_status_and_taint(ctx: ScanContext, status_txt: str, modinfos: list[dict[str, str]]) -> None:
    statuses = parse_pipe_kv_lines(status_txt, "STATUS")
    if statuses:
        st = statuses[0]
        ctx.telemetry["kernel_lkm_status"] = st
        taint_str = st.get("taint_str", "")
        if "Tainted:" in taint_str or st.get("taint_str"):
            ctx.telemetry["kernel_taint_summary"] = taint_str

    taints = parse_pipe_kv_lines(status_txt, "TAINT")
    active_bits = {int(t["bit"]): t for t in taints if t.get("bit", "").isdigit()}
    if not active_bits:
        # Also evaluate via /proc/sys/kernel/tainted
        raw_t = _read_text(ctx.proc_root / "sys" / "kernel" / "tainted")
        if raw_t.isdigit() and int(raw_t) > 0:
            val = int(raw_t)
            for b in range(20):
                if val & (1 << b):
                    active_bits[b] = {"bit": str(b), "desc": f"Kernel taint bit {b}"}

    if 1 in active_bits or 3 in active_bits or 10 in active_bits:
        ctx.add_finding(
            Finding(
                rule_id="E9-KERNEL-TAINT-FORCED",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Kernel Integrity",
                title="Çekirdek zorla yüklenmiş / güvensiz modül taint bayrağı taşıyor",
                description="Çekirdekte TAINT_FORCED_MODULE (F), TAINT_FORCED_RMMOD (R) veya TAINT_CRAP (C) bayrağı tespit edildi.",
                path=str(ctx.proc_root / "sys" / "kernel" / "tainted"),
                evidence=[f"bit {b}: {d.get('desc', '')}" for b, d in sorted(active_bits.items())],
                recommendation="`lsmod` ve `journalctl -k` ile son yüklenen modülleri inceleyin.",
            )
        )

    # Out-of-tree / unsigned check: distinguish Nvidia/VBox/OOT GPU drivers from unknown modules
    if 12 in active_bits or 13 in active_bits:
        unknown_oot: list[str] = []
        proc_mods = _read_text(ctx.proc_root / "modules")
        mod_names = [line.split()[0] for line in proc_mods.splitlines() if line.strip()]
        if modinfos:
            for mi in modinfos:
                if mi.get("state") == "2":
                    continue
                nm = mi.get("name", "")
                if nm and nm not in mod_names:
                    mod_names.append(nm)

        for nm in mod_names:
            low = nm.lower()
            if nm == "mc_ss_kmod" or any(low.startswith(pref) for pref in _KNOWN_SAFE_OOT_MOD_PREFIXES):
                continue
            # Check in /sys/module/<nm>/taint (O = OOT, E = unsigned)
            taint_f = _read_text(ctx.sys_path(f"/sys/module/{nm}/taint"))
            if "O" in taint_f or "E" in taint_f or "F" in taint_f:
                unknown_oot.append(f"{nm} (taint={taint_f})")

        for mi in modinfos:
            if mi.get("state") == "2":
                continue
            nm = mi.get("name", "")
            low = nm.lower()
            if nm == "mc_ss_kmod" or any(low.startswith(pref) for pref in _KNOWN_SAFE_OOT_MOD_PREFIXES):
                continue
            try:
                tmask = int(mi.get("taints", "0"), 16)
            except ValueError:
                tmask = 0
            if (tmask & ((1 << 12) | (1 << 13))) and not any(u.startswith(nm + " ") for u in unknown_oot):
                unknown_oot.append(f"{nm} (ring0_taints=0x{tmask:x})")

        if unknown_oot:
            ctx.add_finding(
                Finding(
                    rule_id="E9-UNKNOWN-OOT-MODULE",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Kernel Integrity",
                    title="Bilinmeyen imzasız / dış kaynaklı (OOT) çekirdek modülü tespit edildi",
                    description="Bilinen GPU/donanım sürücüleri dışında imzasız veya out-of-tree bir LKM yüklü.",
                    evidence=unknown_oot[:12],
                    recommendation="Bu modülün kaynağını `modinfo <isim>` ile doğrulayın.",
                )
            )


def _analyze_ring0_integrity(ctx: ScanContext, integ_txt: str) -> list[dict[str, str]]:
    syscall_entries = parse_pipe_kv_lines(integ_txt, "SYSCALL_ENTRY")
    khooks = parse_pipe_kv_lines(integ_txt, "KHOOK")
    vfshooks = parse_pipe_kv_lines(integ_txt, "VFSHOOK")
    tp_cbs = parse_pipe_kv_lines(integ_txt, "TPCALLBACK")
    modinfos = parse_pipe_kv_lines(integ_txt, "MODINFO")
    modxscans = parse_pipe_kv_lines(integ_txt, "MODXSCAN")

    ctx.telemetry["kernel_khook_checked"] = len(khooks)
    ctx.telemetry["kernel_modinfo_count"] = len(modinfos)
    ctx.telemetry["kernel_modxscan_count"] = len(modxscans)

    # 0. MSR_LSTAR syscall entry integrity
    for se in syscall_entries:
        lsym = se.get("lstar_sym", "")
        low_lsym = lsym.lower()
        mod_lstar = _extract_mod_from_sym(lsym)
        if lsym and (
            mod_lstar
            or lsym.startswith("0x")
            or not any(k in low_lsym for k in ("entry_syscall_64", "xen_syscall", "entry_syscall"))
        ):
            ctx.add_finding(
                Finding(
                    rule_id="E9-MSR-LSTAR-HOOK",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Ring-0 Rootkit Detection",
                    title=f"MSR_LSTAR sistem çağrısı giriş vektörü değiştirilmiş: {lsym}",
                    description="x86_64 MSR_LSTAR yazmacı standart çekirdek syscall giriş noktası dışına yönlendirilmiş.",
                    evidence=[f"msr_lstar={se.get('msr_lstar')} sym={lsym}"],
                )
            )

    # 1. Syscall / critical kernel function prologue + CR3 PTE writeability audit
    for kh in khooks:
        sym = kh.get("sym", "")
        hcls = kh.get("hook_class", "")
        if sym == "do_syscall_64" and hcls == "UNRESOLVED":
            continue
        pte_rw = kh.get("pte_rw", "-1")
        jmp_sym = kh.get("jmp_sym", "NONE")
        if pte_rw == "1":
            ctx.add_finding(
                Finding(
                    rule_id="E9-LKM-WRITABLE-KTEXT",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Ring-0 Rootkit Detection",
                    title=f"Çekirdek .text sayfası yazılabilir (RW) işaretli: {sym}",
                    description="CR3 sayfa tablosunda salt-okunur olması gereken çekirdek kodu _PAGE_RW olarak tespit edildi (inline hook / WP manipülasyonu).",
                    evidence=[
                        f"Sembol: {sym} addr={kh.get('addr')}",
                        f"PTE level={kh.get('pte_lvl')} rw={pte_rw} exec={kh.get('pte_exec')}",
                        f"Prolog (32B): {kh.get('bytes', '')}",
                    ],
                )
            )
        if hcls in _SUSPICIOUS_HOOK_CLASSES:
            ctx.add_finding(
                Finding(
                    rule_id="E9-KERNEL-INLINE-HOOK",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Ring-0 Rootkit Detection",
                    title=f"Kritik çekirdek fonksiyonunda inline hook/trambolin tespit edildi: {sym}",
                    description="Çekirdek fonksiyon girişinde olağan dışı JMP / int3 kancası bulundu.",
                    evidence=[
                        f"Fonksiyon: {sym} ({kh.get('addr')})",
                        f"Hook Türü: {hcls} -> Hedef: {kh.get('jmp_target')} ({jmp_sym})",
                        f"Ham Baytlar: {kh.get('bytes', '')}",
                    ],
                )
            )

    # 2. VFS /proc & / pointer hijack verification
    for vh in vfshooks:
        mount = vh.get("mount", "")
        isym = vh.get("iter_sym", "")
        mod = _extract_mod_from_sym(isym)
        low_sym = isym.lower()
        is_unresolved = isym.startswith("0x") or isym == "NULL"
        suspicious_mod = mod and not any(mod.lower().startswith(p) for p in _SAFE_FS_MOD_HINTS)
        if (is_unresolved and isym != "NULL") or suspicious_mod or (
            mount == "/proc" and isym and not any(h in low_sym for h in ("proc_", "simple_", "vfs"))
        ):
            ctx.add_finding(
                Finding(
                    rule_id="E9-VFS-HOOK-HIJACK",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Ring-0 Rootkit Detection",
                    title=f"VFS dizin operasyon tablosunda (f_op) yabancı kanca: {mount}",
                    description="Dosya/süreç gizlemek için kullanılan VFS iterate_shared işaretçisi beklenen çekirdek/FS sembolü dışına yönlendirilmiş.",
                    evidence=[
                        f"Mount: {mount}",
                        f"iterate_shared={vh.get('iterate_shared')} -> {isym}",
                        f"open={vh.get('open')} -> {vh.get('open_sym')}",
                    ],
                )
            )

    # 3. Kernel Tracepoint foreign callback check
    for tp in tp_cbs:
        if tp.get("is_self") == "1":
            continue
        sym = tp.get("sym", "")
        mod = _extract_mod_from_sym(sym)
        if sym.startswith("0x") or (
            tp.get("tp") in ("sys_enter", "sched_process_exec")
            and mod
            and mod != "mc_ss_kmod"
            and not any(mod.lower().startswith(p) for p in _KNOWN_SAFE_OOT_MOD_PREFIXES)
        ):
            ctx.add_finding(
                Finding(
                    rule_id="E9-KERNEL-TP-UNKNOWN",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Ring-0 Rootkit Detection",
                    title=f"Çekirdek tracepoint üzerinde tanınmayan callback: {tp.get('tp')}",
                    description="Çekirdeğin olay izleme noktasında bilinmeyen veya sembolsüz bir fonksiyon kancalı.",
                    evidence=[f"tp={tp.get('tp')} func={tp.get('func')} sym={sym}"],
                )
            )

    # 4. Module integrity + RW text + known rootkit names + cross-view
    proc_mods_txt = _read_text(ctx.proc_root / "modules")
    proc_mod_set = {ln.split()[0] for ln in proc_mods_txt.splitlines() if ln.strip()}
    sys_mod_dir = ctx.sys_path("/sys/module")
    sys_mod_set = set()
    if sys_mod_dir.is_dir():
        try:
            sys_mod_set = {p.name for p in sys_mod_dir.iterdir() if p.is_dir()}
        except OSError:
            pass

    for mi in modinfos:
        name = mi.get("name", "")
        low = name.lower()
        if any(rk in low for rk in _ROOTKIT_MOD_NAMES):
            ctx.add_finding(
                Finding(
                    rule_id="E9-KNOWN-ROOTKIT-LKM",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Ring-0 Rootkit Detection",
                    title=f"Bilinen Linux kernel rootkit modülü tespit edildi: {name}",
                    description="Ring-0 modül listesinde bilinen bir rootkit adı eşleşti.",
                    evidence=[f"name={name} text={mi.get('text')} taints={mi.get('taints')}"],
                )
            )
        if mi.get("rw_anom") == "1" and name != "mc_ss_kmod":
            ctx.add_finding(
                Finding(
                    rule_id="E9-LKM-RW-TEXT",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category="Ring-0 Rootkit Detection",
                    title=f"Yüklü çekirdek modülünün .text kodu yazılabilir (RW): {name}",
                    description="Salt-okunur olması gereken modül kod alanında yazma izni tespit edildi.",
                    evidence=[f"name={name} text={mi.get('text')}"],
                )
            )
        # Skip MODULE_STATE_GOING (state == "2") transient unloads in cross-view
        if mi.get("state") == "2":
            continue
        if proc_mod_set and name and name != "mc_ss_kmod" and name not in proc_mod_set and name not in sys_mod_set:
            ctx.add_finding(
                Finding(
                    rule_id="E9-HIDDEN-LKM-CROSSVIEW",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Ring-0 Rootkit Detection",
                    title=f"/proc/modules ve /sys/module içinden gizlenmiş çekirdek modülü: {name}",
                    description="Modül Ring-0 bellek ağacında mevcut ancak userspace listelerinden gizlenmiş.",
                    evidence=[f"Ring-0 MODINFO={name} text={mi.get('text')} (/proc/modules içinde yok!)"],
                )
            )

    # Also cross-check /sys/module (initstate=live) vs /proc/modules without LKM
    if proc_mod_set and sys_mod_set:
        for sm in sorted(sys_mod_set - proc_mod_set):
            if sm == "mc_ss_kmod":
                continue
            initstate = _read_text(ctx.sys_path(f"/sys/module/{sm}/initstate"))
            if initstate == "live":
                ctx.add_finding(
                    Finding(
                        rule_id="E9-HIDDEN-LKM-SYSFS-DIFF",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category="Ring-0 Rootkit Detection",
                        title=f"/sys/module'da canlı görünüp /proc/modules'dan gizlenmiş modül: {sm}",
                        description="Modül /proc/modules çıktısından filtrelenmiş görünüyor.",
                        evidence=[f"/sys/module/{sm}/initstate=live ancak /proc/modules içinde yok"],
                    )
                )

    # 5. CR3 Page-table executable scan in MODULES_VADDR..MODULES_END + ELF carve
    for mx in modxscans:
        if mx.get("covered") == "1":
            continue
        sym = mx.get("sym", "")
        elf_carve = mx.get("elf_carve") == "1"
        vm_carve = mx.get("vermagic_carve") == "1"
        # eBPF JIT buffers resolve cleanly as bpf_prog_* in kallsyms; real orphan LKM pages do not
        if elf_carve or vm_carve:
            ctx.add_finding(
                Finding(
                    rule_id="E9-ORPHAN-KERNEL-ELF",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Ring-0 Rootkit Detection",
                    title="Sahipsiz yürütülebilir çekirdek belleğinde gizli ELF/LKM kazındı!",
                    description="MODULES_VADDR içinde kayıtlı hiçbir modüle ait olmayan yürütülebilir sayfalarda ham ELF başlığı veya vermagic= izi bulundu (unlinked rootkit).",
                    evidence=[
                        f"Aralık: {mx.get('start')}..{mx.get('end')} ({mx.get('pages')} sayfa, rw={mx.get('rw')})",
                        f"elf_carve={mx.get('elf_carve')} vermagic_carve={mx.get('vermagic_carve')} sym={sym}",
                        f"İlk 16B: {mx.get('head')}",
                    ],
                )
            )
        elif sym.startswith("0x") and mx.get("rw") == "1":
            ctx.add_finding(
                Finding(
                    rule_id="E9-ORPHAN-RWX-KERNEL-MEM",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category="Ring-0 Rootkit Detection",
                    title="MODULES_VADDR içinde sembolsüz sahipsiz RWX çekirdek sayfaları",
                    description="Hiçbir görünür modül veya BPF JIT sembolüne ait olmayan yazılabilir+yürütülebilir çekirdek alanı tespit edildi.",
                    evidence=[
                        f"Aralık: {mx.get('start')}..{mx.get('end')} rw={mx.get('rw')} head={mx.get('head')}"
                    ],
                )
            )

    return modinfos


def _analyze_ring0_tasks_and_vmas(ctx: ScanContext, tasks_txt: str) -> None:
    tasks = parse_pipe_kv_lines(tasks_txt, "TASK")
    vma_anoms = parse_pipe_kv_lines(tasks_txt, "VMA_ANOM")
    ctx.telemetry["ring0_task_count"] = len(tasks)
    ctx.telemetry["ring0_vma_anomalies"] = len(vma_anoms)

    if tasks:
        # Cross-check Ring-0 init_task TGIDs vs userspace /proc enumeration
        ring0_tgids = {int(t["tgid"]) for t in tasks if t.get("tgid", "").isdigit()}
        proc_dirs: set[int] = set()
        snap = ctx.kernel_snapshot_data or {}
        lkm_pids = (snap.get("root_extras") or {}).get("proc_pids_at_lkm")
        if isinstance(lkm_pids, list):
            for x in lkm_pids:
                if isinstance(x, int):
                    proc_dirs.add(x)
        try:
            for p in ctx.proc_root.iterdir():
                if p.name.isdigit():
                    proc_dirs.add(int(p.name))
        except OSError:
            pass

        missing_from_proc = sorted(ring0_tgids - proc_dirs) if proc_dirs else []
        # Filter ultra-short kernel helper threads; verify if PID exists via task record not transient
        real_hidden: list[str] = []
        if missing_from_proc:
            by_tgid = {int(t["tgid"]): t for t in tasks if t.get("tgid", "").isdigit()}
            for mpid in missing_from_proc:
                # Re-stat single /proc/<pid> to guard race conditions cleanly
                if not (ctx.proc_root / str(mpid)).exists():
                    info = by_tgid.get(mpid, {})
                    comm = info.get("comm", "")
                    if comm and comm not in ("kworker", "sh", "true"):
                        real_hidden.append(f"TGID={mpid} comm={comm} exe={info.get('exe', '')}")

        if real_hidden:
            ctx.add_finding(
                Finding(
                    rule_id="E9-HIDDEN-PID-RING0",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Ring-0 Process Forensics",
                    title="Çekirdek init_task ağacında olup /proc içinden gizlenmiş süreç tespit edildi!",
                    description="Ring-0 görev listesinde canlı olan süreç(ler) userspace /proc dizininde görünmüyor (rootkit gizleme).",
                    evidence=real_hidden[:15],
                )
            )

        for t in tasks:
            comm = t.get("comm", "")
            ptrace_val = t.get("ptrace", "0x0")
            exe = t.get("exe", "")
            pid = int(t["pid"]) if t.get("pid", "").isdigit() else None
            if ptrace_val != "0x0" and "java" in comm.lower():
                ctx.add_finding(
                    Finding(
                        rule_id="E9-KERNEL-PTRACE-ACTIVE",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category="Ring-0 Process Forensics",
                        title=f"Java/Minecraft süreci çekirdek ptrace bayrağıyla izleniyor/müdahale altında (PID {pid})",
                        description="Ring-0 task_struct->ptrace sıfır değil; harici debugger/enjektör bağlı olabilir.",
                        pid=pid,
                        path=exe,
                        evidence=[f"comm={comm} ptrace={ptrace_val} ppid={t.get('ppid')} real_ppid={t.get('real_ppid')}"],
                    )
                )

    # Byte-level VMA & access_process_vm findings
    for va in vma_anoms:
        pid = int(va["pid"]) if va.get("pid", "").isdigit() else None
        comm = va.get("comm", "")
        elf = va.get("elf") == "1"
        pe = va.get("pe") == "1"
        jni_hits = int(va.get("jni_hits", "0") or 0)
        vfile = va.get("file", "")
        vfile_low = vfile.lower()
        is_memfd = va.get("memfd") == "1" or vfile_low.startswith("/memfd:")
        is_shm = va.get("shm") == "1" or vfile_low.startswith(("/dev/shm/", "/tmp/", "/var/tmp/"))
        is_del = va.get("del") == "1" or "(deleted)" in vfile_low
        is_rwx = va.get("rwx") == "1"

        if elf and (va.get("anon") == "1" or is_memfd or is_shm or is_del):
            ctx.add_finding(
                Finding(
                    rule_id="E9-KERNEL-VMA-REFLECTIVE-ELF",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Ring-0 Memory Forensics",
                    title=f"Anonim/dosyasız yürütülebilir VMA içinde ham ELF ikilisi tespit edildi ({comm})",
                    description="Ring-0 access_process_vm bayt taraması disk eşlemesi olmayan yürütülebilir bellekte \\x7fELF yükü yakaladı (Reflective SO / Fileless Cheat).",
                    pid=pid,
                    path=vfile,
                    evidence=[
                        f"Aralık: {va.get('start')}..{va.get('end')} boyut={va.get('size')} rwx={is_rwx}",
                        f"memfd={is_memfd} shm={is_shm} del={is_del} head={va.get('head')}",
                    ],
                )
            )
        if jni_hits > 0 and (va.get("anon") == "1" or is_memfd or is_shm or is_del):
            try:
                jmask = int(va.get("jni_mask", "0") or "0", 16)
            except ValueError:
                jmask = 0
            if (jmask == 0) or (jmask & 0x3F):
                ctx.add_finding(
                    Finding(
                        rule_id="E9-KERNEL-VMA-JNI-AGENT",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="Ring-0 Memory Forensics",
                        title=f"Dosyasız/anonim VMA içinde JNI/JVMTI enjeksiyon ajanı imzaları ({comm})",
                        description="Çekirdek bellek okumasında gizli yürütülebilir sayfa içinde Agent_OnAttach / DefineClass / RedefineClasses / jvmtiEnv imzaları bulundu.",
                        pid=pid,
                        path=vfile,
                        evidence=[
                            f"Aralık: {va.get('start')}..{va.get('end')} jni_hits={jni_hits} mask={va.get('jni_mask')}",
                            f"head={va.get('head')}",
                        ],
                    )
                )
            if jmask & 0x40:
                ctx.add_finding(
                    Finding(
                        rule_id="E9-KERNEL-VMA-PACKED-CODE",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category="Ring-0 Memory Forensics",
                        title=f"Dosyasız/anonim VMA içinde UPX/VMProtect paketlenmiş kod imzası ({comm})",
                        description="Çekirdek bellek okumasında gizli yürütülebilir sayfada UPX!/VMProtect packer başlığı tespit edildi.",
                        pid=pid,
                        path=vfile,
                        evidence=[
                            f"Aralık: {va.get('start')}..{va.get('end')} mask={va.get('jni_mask')}",
                            f"head={va.get('head')}",
                        ],
                    )
                )
        if pe and va.get("anon") == "1" and "java" in comm.lower():
            ctx.add_finding(
                Finding(
                    rule_id="E9-KERNEL-VMA-INJECTED-PE",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category="Ring-0 Memory Forensics",
                    title=f"Java süreci anonim belleğinde PE/MZ Windows yükü tespit edildi ({comm})",
                    description="Java yürütülebilir anonim belleğinde gömülü PE enjeksiyon başlığı bulundu.",
                    pid=pid,
                    path=vfile,
                    evidence=[f"Aralık: {va.get('start')}..{va.get('end')} head={va.get('head')}"],
                )
            )


def _analyze_dma_pci_iommu(
    ctx: ScanContext,
    pci_txt: str,
    native_pci_ext: list[dict[str, Any]],
) -> None:
    iommu = priv_helper.inspect_iommu_compliance(root_prefix=ctx.root_prefix, proc_root=ctx.proc_root)
    ctx.telemetry["iommu_compliance"] = iommu
    record_scan_region(ctx, "E9", "Donanım ACPI DMAR/IVRS + /sys/kernel/iommu_groups + PCIe 4KB Config")

    # 1. System-wide IOMMU posture rules
    if (iommu["acpi_dmar_present"] or iommu["acpi_ivrs_present"]) and not iommu["iommu_active"]:
        ctx.add_finding(
            Finding(
                rule_id="E9-DMA-IOMMU-DISABLED",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="DMA & IOMMU Hardware Protection",
                title="Donanımda IOMMU desteği var (DMAR/IVRS) ancak çekirdekte AKTİF DEĞİL!",
                description=(
                    "Anakart VT-d/AMD-Vi tablosu sunmasına rağmen çekirdek şu anda IOMMU grupları oluşturmuyor; "
                    "herhangi bir PCIe DMA/FPGA cihazı fiziksel RAM'e doğrudan sınırsız erişebilir."
                ),
                evidence=[
                    f"CPU={iommu['cpu_vendor']} DMAR={iommu['acpi_dmar_present']} IVRS={iommu['acpi_ivrs_present']}",
                    f"/sys/kernel/iommu_groups={iommu['iommu_group_count']} /sys/class/iommu={len(iommu['iommu_hw_units'])}",
                    f"Önerilen parametreler: {' '.join(iommu['recommended_kargs'])}",
                ],
                recommendation="BIOS VT-d/AMD-Vi ayarının açık olduğunu doğrulayın ve araçtaki 'IOMMU & DMA Korumasını Aç' seçeneğini uygulayın.",
            )
        )
    if iommu["forced_off"]:
        ctx.add_finding(
            Finding(
                rule_id="E9-DMA-IOMMU-FORCED-OFF",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="DMA & IOMMU Hardware Protection",
                title="Çekirdek başlangıç parametrelerinde IOMMU bilinçli olarak kapatılmış!",
                description="Kernel cmdline üzerinde iommu=off / intel_iommu=off / amd_iommu=off bayrağı bulundu (DMA koruma devredışı).",
                path=str(ctx.proc_root / "cmdline"),
                evidence=[iommu["cmdline"]],
            )
        )
    elif iommu["passthrough_enabled"]:
        ctx.add_finding(
            Finding(
                rule_id="E9-DMA-IOMMU-PASSTHROUGH",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="DMA & IOMMU Hardware Protection",
                title="IOMMU passthrough modu aktif (iommu=pt / passthrough=1) — DMA koruması zayıf",
                description="Passthrough modunda PCIe aygıtları fiziksel bellek çevirisi olmadan doğrudan DMA yapabilir.",
                path=str(ctx.proc_root / "cmdline"),
                evidence=[iommu["cmdline"]],
            )
        )
    elif iommu["iommu_active"] and not iommu["strict_enabled"]:
        ctx.add_finding(
            Finding(
                rule_id="E9-DMA-IOMMU-LAZY",
                engine=ENGINE_NAME,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="DMA & IOMMU Hardware Protection",
                title="IOMMU aktif ancak katı TLB temizleme (iommu.strict=1) kapalı (lazy mod)",
                description="Sert DMA izolasyonu için iommu.strict=1 önerilir.",
                evidence=[iommu["cmdline"]],
            )
        )
    if iommu["acs_override"]:
        ctx.add_finding(
            Finding(
                rule_id="E9-DMA-ACS-OVERRIDE",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="DMA & IOMMU Hardware Protection",
                title="pcie_acs_override çekirdek yaması/parametresi aktif (IOMMU izolasyon kırılması)",
                description="PCIe ACS izolasyonunu bypass eden parametre aktif.",
                evidence=[iommu["cmdline"]],
            )
        )

    # 2. Per-device PCIe & IOMMU inspection (Ring-0 snapshot preferred, sysfs fallback)
    ext_by_bdf = {item.get("bdf"): item for item in native_pci_ext if item.get("bdf")}
    pci_records = parse_pipe_kv_lines(pci_txt, "PCIDEV")

    if not pci_records:
        # Unprivileged / non-LKM fallback directly from /sys/bus/pci/devices/* (world-readable 64B config!)
        pci_root = ctx.sys_path("/sys/bus/pci/devices")
        if pci_root.is_dir():
            for dev_dir in sorted(pci_root.iterdir()):
                if not dev_dir.is_dir():
                    continue
                vid = _read_text(dev_dir / "vendor").lower()
                did = _read_text(dev_dir / "device").lower()
                svid = _read_text(dev_dir / "subsystem_vendor").lower()
                sdid = _read_text(dev_dir / "subsystem_device").lower()
                cls_val = _read_text(dev_dir / "class").lower()
                uevent = _read_text(dev_dir / "uevent")
                drv = "unbound"
                for uln in uevent.splitlines():
                    if uln.startswith("DRIVER="):
                        drv = uln.split("=", 1)[1].strip()
                        break
                bme_hw = "0"
                cap_loop = "0"
                d3cold_sysfs = "0"
                cfg_sz = "0"
                hdr_hex = "0x00"
                power_state = _read_text(dev_dir / "power_state").lower()
                if power_state == "d3cold" or vid == "0xffff":
                    d3cold_sysfs = "1"
                cfg_file = dev_dir / "config"
                if d3cold_sysfs == "0" and cfg_file.is_file():
                    try:
                        cfg_bytes = cfg_file.read_bytes()
                        cfg_sz = str(len(cfg_bytes))
                        if len(cfg_bytes) >= 16:
                            cfg_vid = struct.unpack_from("<H", cfg_bytes, 0)[0]
                            if cfg_vid == 0xFFFF:
                                d3cold_sysfs = "1"
                            else:
                                cmd_word = struct.unpack_from("<H", cfg_bytes, 4)[0]
                                bme_hw = "1" if (cmd_word & 0x4) else "0"
                                hdr_hex = f"0x{cfg_bytes[14] & 0x7f:02x}"
                    except OSError:
                        pass
                grp_link = dev_dir / "iommu_group"
                iommu_grp = grp_link.resolve().name if grp_link.exists() else "-1"
                pci_records.append(
                    {
                        "bdf": dev_dir.name,
                        "vid": vid,
                        "did": did,
                        "svid": svid,
                        "sdid": sdid,
                        "class": cls_val,
                        "hdr": hdr_hex,
                        "driver": drv,
                        "iommu_grp": iommu_grp,
                        "iommu_dom": "UNKNOWN_NO_LKM",
                        "bme_hw": bme_hw,
                        "bme_sw": bme_hw,
                        "untrusted": "0",
                        "ext_facing": "0",
                        "tb": "0",
                        "pcie_spd": "0",
                        "pcie_w": "0",
                        "dsn": "0000000000000000",
                        "cfg_sz": cfg_sz,
                        "d3cold": d3cold_sysfs,
                        "cap_loop": cap_loop,
                    }
                )

    ctx.telemetry["pci_device_count"] = len(pci_records)

    for rec in pci_records:
        bdf = rec.get("bdf", "")
        vid = rec.get("vid", "").lower()
        did = rec.get("did", "").lower()
        svid = rec.get("svid", "").lower()
        sdid = rec.get("sdid", "").lower()
        cls_raw = rec.get("class", "0x0").lower()
        drv = rec.get("driver", "unbound")
        dom = rec.get("iommu_dom", "")
        d3cold = rec.get("d3cold") == "1" or vid == "0xffff"
        bme = False if d3cold else (rec.get("bme_hw") == "1")
        ext_info = ext_by_bdf.get(bdf, {})

        # FPGA / PCILeech hardware check
        if vid in _FPGA_VENDOR_IDS or (vid, did) in _KNOWN_PCILEECH_VID_DIDS:
            ctx.add_finding(
                Finding(
                    rule_id="E9-DMA-FPGA-HARDWARE",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="DMA & IOMMU Hardware Protection",
                    title=f"PCIe FPGA / DMA Screamer donanım kimliği tespit edildi ({bdf})",
                    description=f"{_FPGA_VENDOR_IDS.get(vid, 'FPGA')} — donanım DMA kartı izi!",
                    evidence=[
                        f"BDF={bdf} VID:DID={vid}:{did} SVID:SDID={svid}:{sdid}",
                        f"driver={drv} iommu_dom={dom} bme={bme} cfg_sz={rec.get('cfg_sz')}",
                    ],
                )
            )

        # VFIO / UIO raw DMA driver attached with Bus Master or unmanaged IOMMU
        if drv in ("vfio-pci", "uio_pci_generic", "uio") or dom == "UNMANAGED_VFIO":
            ctx.add_finding(
                Finding(
                    rule_id="E9-DMA-VFIO-UIO-DEVICE",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="DMA & IOMMU Hardware Protection",
                    title=f"Kullanıcı alanına doğrudan DMA/MMIO açan sürücü bağlı: {drv} ({bdf})",
                    description="vfio-pci / UIO ile PCIe aygıtı kullanıcı alanı DMA kontrolüne geçirilmiş.",
                    evidence=[
                        f"BDF={bdf} VID:DID={vid}:{did} class={cls_raw} driver={drv} iommu_dom={dom} bme={bme}"
                    ],
                )
            )

        # Active hardware Bus Master on unbound PCIe endpoint
        # Skip host/PCI bridges (0x06), plus standard Intel/AMD internal chipset SRAM/GNA/SMBus (0x05/0x08/0x0c05)
        try:
            hdr_type = int(rec.get("hdr", "0"), 16) & 0x7F
        except ValueError:
            hdr_type = 0
        is_chipset_internal = (
            vid in ("0x8086", "0x1022", "0x1002")
            and svid not in _FPGA_VENDOR_IDS
            and cls_raw.startswith(("0x05", "0x06", "0x08", "0x0c05"))
        )
        if drv == "unbound" and bme and hdr_type == 0 and not cls_raw.startswith("0x06") and not is_chipset_internal:
            ctx.add_finding(
                Finding(
                    rule_id="E9-DMA-UNBOUND-BUSMASTER",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category="DMA & IOMMU Hardware Protection",
                    title=f"Çekirdek sürücüsü olmadan Bus Master DMA yetkisi açık PCIe aygıtı ({bdf})",
                    description="Herhangi bir sürücüye bağlı olmayan PCI aygıtında donanımsal PCI_COMMAND_MASTER (DMA) biti aktif!",
                    evidence=[f"BDF={bdf} VID:DID={vid}:{did} class={cls_raw} iommu_dom={dom}"],
                )
            )

        # Spoofed FPGA firmware heuristics
        is_spoofed = False
        spoof_reasons: list[str] = []
        if not d3cold and (rec.get("cap_loop") == "1" or ext_info.get("cap_loop") == 1):
            is_spoofed = True
            spoof_reasons.append("PCIe capability list döngü/bozulma hatası")
        if svid in _FPGA_VENDOR_IDS and vid not in _FPGA_VENDOR_IDS:
            is_spoofed = True
            spoof_reasons.append(f"Ana VID ({vid}) maskelenmiş ancak Subsystem VID FPGA ({svid})!")
        # High-throughput device masquerading over Gen1/Gen2 x1 FPGA bridge with dead DSN or zero SVID
        try:
            spd = int(rec.get("pcie_spd", "0"))
            width = int(rec.get("pcie_w", "0"))
        except ValueError:
            spd, width = 0, 0
        if cls_raw.startswith("0x0108") and spd in (1,) and width == 1:
            is_spoofed = True
            spoof_reasons.append("NVMe sınıfı aygıt PCIe Gen1 x1 dar geçidinde (FPGA Screamer belirtisi)")
        dsn_val = rec.get("dsn", "").lower()
        if (
            not d3cold
            and hdr_type == 0
            and rec.get("has_dsn") == "1"
            and dsn_val in {
                "0000000000000000",
                "0000000101000a35",
                "1122334455667788",
                "0123456789abcdef",
                "deadbeefdeadbeef",
            }
        ):
            is_spoofed = True
            spoof_reasons.append(f"PCIe Device Serial Number (DSN) yeteneği sahte/varsayılan desen içeriyor ({dsn_val})")
        if not d3cold and hdr_type == 0 and not is_chipset_internal and bme and svid == "0x0000":
            try:
                csz = int(rec.get("cfg_sz", "0") or 0)
            except ValueError:
                csz = 0
            if csz >= 256:
                is_spoofed = True
                spoof_reasons.append("Bus Master aktif PCIe endpoint için Subsystem Vendor ID=0x0000")
        if (rec.get("untrusted") == "1" or rec.get("tb") == "1") and dom in ("IDENTITY_PASSTHROUGH", "NONE"):
            ctx.add_finding(
                Finding(
                    rule_id="E9-DMA-THUNDERBOLT-EXPOSED",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="DMA & IOMMU Hardware Protection",
                    title=f"Güvenilmeyen / harici Thunderbolt PCIe aygıtında IOMMU koruması yok ({bdf})",
                    description="Harici DMA yapabilen cihaz doğrudan fiziksel adreslemeye açık (passthru/none).",
                    evidence=[f"BDF={bdf} untrusted={rec.get('untrusted')} tb={rec.get('tb')} dom={dom}"],
                )
            )
        if is_spoofed:
            ctx.add_finding(
                Finding(
                    rule_id="E9-DMA-SPOOFED-PCIE-FW",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="DMA & IOMMU Hardware Protection",
                    title=f"Maskelenmiş / sahte PCIe aygıt yazılımı şüphesi ({bdf})",
                    description="PCIe config space alanları standart üretici donanım tutarlılığı göstermiyor.",
                    evidence=[
                        f"BDF={bdf} VID:DID={vid}:{did} SVID:SDID={svid}:{sdid} dsn={rec.get('dsn')}",
                        *spoof_reasons,
                    ],
                )
            )


def _analyze_ebpf_and_pid_cross(
    ctx: ScanContext,
    native_probe: dict[str, Any],
    root_extras: dict[str, Any] | None = None,
) -> None:
    if root_extras:
        pinned = root_extras.get("bpf_pinned") or []
        bad_pinned = [
            p
            for p in pinned
            if not any(
                s in Path(p).name.lower()
                for s in ("systemd", "bpftune", "cilium", "tetragon", "falco", "plymouth", "firewalld")
            )
            and any(
                k in p.lower()
                for k in ("hide", "rootkit", "boop", "triple", "kprobe", "getdents", "cheat", "uinput", "ptrace")
            )
        ]
        if bad_pinned:
            ctx.add_finding(
                Finding(
                    rule_id="E9-EBPF-PINNED-OBJ",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="eBPF Rootkit Forensics",
                    title="/sys/fs/bpf altında şüpheli kalıcı (pinned) eBPF nesnesi tespit edildi!",
                    description="Yeniden yükleme/gizleme amaçlı bpffs içine sabitlenmiş şüpheli eBPF bağlantısı veya haritası bulundu.",
                    evidence=bad_pinned[:15],
                )
            )

    if not native_probe:
        return

    # 1. Native C PID cross-view check (readdir vs kill(0) + stat)
    pid_cross = native_probe.get("pid_cross", {})
    if isinstance(pid_cross, dict):
        ctx.telemetry["native_pid_cross"] = pid_cross
        hidden = pid_cross.get("hidden_candidates") or []
        if hidden:
            ctx.add_finding(
                Finding(
                    rule_id="E9-HIDDEN-PID-READDIR",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Stealth Process / Hook",
                    title="/proc dizin okumasından (getdents64/LD_PRELOAD) gizlenmiş süreçler!",
                    description="kill(0)+stat yanıt veren süreç readdir('/proc') çıktısında gizlenmiş (libprocesshider veya kernel getdents hook).",
                    evidence=[json.dumps(h) for h in hidden[:15]],
                )
            )

    # 2. Direct sys_bpf() enumeration of active kernel eBPF programs & links
    bpf = native_probe.get("bpf", {})
    progs = bpf.get("progs") or []
    links = bpf.get("links") or []
    links_by_prog: dict[int, list[dict[str, Any]]] = {}
    for ln in links:
        pid_key = ln.get("prog_id")
        if isinstance(pid_key, int):
            links_by_prog.setdefault(pid_key, []).append(ln)

    ctx.telemetry["ebpf_prog_count"] = len(progs)
    ctx.telemetry["ebpf_link_count"] = len(links)
    if progs:
        suspicious_types = {
            "KPROBE",
            "TRACEPOINT",
            "RAW_TRACEPOINT",
            "RAW_TRACEPOINT_WRITABLE",
            "TRACING",
            "LSM",
            "XDP",
            "SOCK_OPS",
            "EXT",
        }
        high_risk_hook_types = {
            "KPROBE",
            "RAW_TRACEPOINT",
            "RAW_TRACEPOINT_WRITABLE",
            "TRACING",
            "LSM",
            "EXT",
        }
        sensitive_targets = (
            "getdents",
            "filldir",
            "ptrace",
            "process_vm",
            "tcp4_seq_show",
            "tcp6_seq_show",
            "uinput",
            "input_event",
            "do_sys_open",
            "vfs_read",
            "memfd",
            "iterate_dir",
            "proc_pid_readdir",
        )
        flagged_progs: list[str] = []
        for pr in progs:
            ptype = str(pr.get("type", ""))
            pname = str(pr.get("name", ""))
            low = pname.lower()
            if ptype not in suspicious_types:
                continue

            attached = links_by_prog.get(pr.get("id", -1), [])
            link_targets = [str(ln.get("tp_name", "")) for ln in attached if ln.get("tp_name")]
            attach_target = str(pr.get("attach_target", ""))
            all_targets = [t for t in ([attach_target] + link_targets) if t]
            has_sensitive_target = any(
                st in lt.lower() for lt in all_targets for st in sensitive_targets
            )
            has_multi_hook = any(
                "kprobe_multi(" in lt or "tracing_multi(" in lt for lt in all_targets
            )

            if any(low.startswith(safe) for safe in _KNOWN_SAFE_EBPF_NAMES) and not has_sensitive_target:
                continue
            # Flag unnamed progs, sensitive-target hooks, rootkit keywords, multi-kprobes,
            # or unattributed high-risk KPROBE/TRACING/LSM/RAW_TRACEPOINT hooks
            if (
                not pname
                or has_sensitive_target
                or has_multi_hook
                or ptype in high_risk_hook_types
                or any(
                    kw in low
                    for kw in ("hide", "rootkit", "boop", "triple", "ptrace", "getdents", "uinput", "cheat", "bypass")
                )
            ):
                tgt_suffix = f" targets={all_targets}" if all_targets else ""
                flagged_progs.append(
                    f"id={pr.get('id')} type={ptype} name={pname!r} uid={pr.get('uid')} "
                    f"jited={pr.get('jited_len')}B run_cnt={pr.get('run_cnt')}{tgt_suffix}"
                )
        if flagged_progs:
            is_crit = any(
                k in x.lower()
                for x in flagged_progs
                for k in (
                    "hide",
                    "getdents",
                    "filldir",
                    "ptrace",
                    "process_vm",
                    "tcp4_seq_show",
                    "tcp6_seq_show",
                    "uinput",
                    "proc_pid_readdir",
                )
            )
            ctx.add_finding(
                Finding(
                    rule_id="E9-EBPF-SUSPICIOUS-PROG",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL if is_crit else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="eBPF Rootkit Forensics",
                    title="Çekirdekte şüpheli/isimsiz veya kritik çağrıya bağlı eBPF programı aktif",
                    description="Modern Linux rootkitleri LKM yüklemeden eBPF kancalarıyla dosya/süreç/ağ gizleyebilir.",
                    evidence=flagged_progs[:15],
                )
            )


def _analyze_live_events(ctx: ScanContext, events_txt: str) -> None:
    events = parse_pipe_kv_lines(events_txt, "EVENT")
    ctx.telemetry["ring0_captured_events"] = len(events)
    if not events:
        return

    my_pid = os.getpid()
    ptrace_hits: list[str] = []
    vmw_hits: list[str] = []
    memfd_hits: list[str] = []
    execveat_hits: list[str] = []
    bpf_hits: list[str] = []
    iopl_hits: list[str] = []
    mod_hits: list[str] = []
    uinput_hits: list[str] = []

    benign_ptrace_comms = {
        "gdb", "lldb", "strace", "perf", "systemd-coredum", "systemd-coredump",
        "drkonqi", "wine", "wine64", "wine-preloader", "wine64-preload",
        "wineserver", "crashpad_handl", "breakpad", "bwrap",
    }
    benign_bpf_comms = {
        "systemd", "systemd-journal", "bpftune", "firewalld", "podman", "conmon",
        "ss_kernel_probe", "cilium", "plymouthd",
    }

    for ev in events:
        etype = ev.get("type", "")
        pid_str = ev.get("pid", "")
        if pid_str.isdigit() and int(pid_str) == my_pid:
            continue
        comm = ev.get("comm", "")
        desc = f"comm={comm} pid={pid_str} tgid={ev.get('tgid')} arg0={ev.get('arg0')} arg1={ev.get('arg1')} detail={ev.get('detail')}"
        if etype == "1":  # SS_EVT_SYSCALL_PTRACE
            if comm in benign_ptrace_comms:
                continue
            try:
                req = int(ev.get("arg0", "0"), 16)
            except ValueError:
                req = 0
            # PTRACE_TRACEME (0) and PTRACE_CONT (7) inside child setup are routine; focus on attach/seize/poke/setregs
            if req in (4, 5, 13, 16, 0x4206) or req not in (0, 7):
                ptrace_hits.append(desc)
        elif etype == "2":  # SS_EVT_SYSCALL_VM_WRITEV
            vmw_hits.append(desc)
        elif etype == "4":  # SS_EVT_SYSCALL_MEMFD
            # Flag explicit MFD_EXEC (0x10) unconditionally
            try:
                fl = int(ev.get("arg1", "0"), 16)
            except ValueError:
                fl = 0
            if fl & 0x10:
                memfd_hits.append(desc)
        elif etype == "5":  # SS_EVT_SYSCALL_EXECVEAT
            try:
                fl = int(ev.get("arg1", "0"), 16)
            except ValueError:
                fl = 0
            if fl & 0x1000:  # AT_EMPTY_PATH fileless memfd/fd execution
                execveat_hits.append(desc)
        elif etype == "7":  # SS_EVT_SYSCALL_BPF
            if comm.lower() in benign_bpf_comms:
                continue
            try:
                cmd = int(ev.get("arg0", "0"), 16)
            except ValueError:
                cmd = -1
            if cmd in (5, 28, 32):  # BPF_PROG_LOAD, BPF_LINK_CREATE, BPF_ITER_CREATE
                bpf_hits.append(desc)
        elif etype == "8":  # SS_EVT_SYSCALL_IOPL
            if comm not in ("Xorg", "Xwayland"):
                iopl_hits.append(desc)
        elif etype in ("6", "10"):  # MOD_LOAD / MODULE_NOTIFY
            if "mc_ss_kmod" not in desc:
                mod_hits.append(desc)
        elif etype == "11":  # INPUT_REGISTER
            if ev.get("arg0") == "0x6":  # BUS_VIRTUAL
                uinput_hits.append(desc)
        elif etype == "12":  # SS_EVT_SYSCALL_UINPUT_CREATE (UI_DEV_CREATE ioctl)
            uinput_hits.append(desc)

    if vmw_hits:
        ctx.add_finding(
            Finding(
                rule_id="E9-EVT-VM-WRITEV-INJECT",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Ring-0 Runtime Syscall Trace",
                title="Tarama sırasında canlı process_vm_writev bellek yazma çağrısı yakalandı!",
                description="Harici bir süreç başka bir sürecin RAM alanına doğrudan yazma girişiminde bulundu.",
                evidence=vmw_hits[:10],
            )
        )
    if ptrace_hits:
        ctx.add_finding(
            Finding(
                rule_id="E9-EVT-PTRACE-INJECT",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Ring-0 Runtime Syscall Trace",
                title="Tarama sırasında aktif ptrace müdahale çağrısı yakalandı",
                description="Çekirdek sys_enter tracepoint'i tanınmayan süreçten gelen ptrace çağrısı kaydetti.",
                evidence=ptrace_hits[:10],
            )
        )
    if memfd_hits:
        ctx.add_finding(
            Finding(
                rule_id="E9-EVT-MEMFD-EXEC",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Ring-0 Runtime Syscall Trace",
                title="Tarama sırasında şüpheli memfd_create (dosyasız RAM dosyası) çağrısı",
                description="MFD_EXEC veya şüpheli süreç bağlamında bellek içi yürütme hazırlığı gözlendi.",
                evidence=memfd_hits[:10],
            )
        )
    if uinput_hits:
        ctx.add_finding(
            Finding(
                rule_id="E9-EVT-LIVE-UINPUT-CREATED",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Ring-0 Input Trace",
                title="Tarama sırasında çekirdekte canlı sanal /dev/uinput cihazı oluşturuldu!",
                description="input_register_device(BUS_VIRTUAL) canlı makro/enjeksiyon cihazı açılışı kaydetti.",
                evidence=uinput_hits[:10],
            )
        )
    if mod_hits:
        ctx.add_finding(
            Finding(
                rule_id="E9-EVT-RUNTIME-MODULE-LOAD",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="Ring-0 Module Trace",
                title="Tarama sırasında çekirdeğe modül yükleme/kaldırma olayı gerçekleşti!",
                description="module_notifier kontrol sırasında başka bir LKM hareketliliği kaydetti.",
                evidence=mod_hits[:10],
            )
        )
    if execveat_hits:
        ctx.add_finding(
            Finding(
                rule_id="E9-EVT-EXECVEAT-FILELESS",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Ring-0 Runtime Syscall Trace",
                title="Tarama sırasında dosya tanıtıcısı (execveat AT_EMPTY_PATH) üzerinden dosyasız yürütme yakalandı!",
                description="memfd/O_PATH tanıtıcısı üzerinden doğrudan çekirdek düzeyinde yürütme çağrısı yapıldı.",
                evidence=execveat_hits[:10],
            )
        )
    if bpf_hits:
        ctx.add_finding(
            Finding(
                rule_id="E9-EVT-LIVE-BPF-LOAD",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="Ring-0 Runtime Syscall Trace",
                title="Tarama sırasında tanınmayan süreçten canlı bpf() program yükleme/bağlama çağrısı yakalandı",
                description="sys_enter tracepoint'i tarama penceresinde BPF_PROG_LOAD/BPF_LINK_CREATE işlemi kaydetti.",
                evidence=bpf_hits[:10],
            )
        )
    if iopl_hits:
        ctx.add_finding(
            Finding(
                rule_id="E9-EVT-RAW-IO-PORT",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Ring-0 Runtime Syscall Trace",
                title="Tarama sırasında ham donanım port erişimi (iopl/ioperm) çağrısı yakalandı!",
                description="Kullanıcı alanı süreci donanım I/O portlarına doğrudan erişim yetkisi istedi.",
                evidence=iopl_hits[:10],
            )
        )


def _analyze_kernel_surface_sysfs(ctx: ScanContext, root_extras: dict[str, Any]) -> None:
    record_scan_region(ctx, "E9", "/proc/sys/kernel, /etc/ld.so.preload, USB HID MCU & /dev/{mem,vfio,uio}")

    # 1. modprobe_path hijack + core_pattern hijack + ld.so.preload
    modprobe_path = _read_text(ctx.proc_root / "sys" / "kernel" / "modprobe")
    if modprobe_path and not (
        modprobe_path.endswith("/modprobe") and modprobe_path.startswith(("/sbin/", "/usr/sbin/", "/usr/bin/"))
    ):
        ctx.add_finding(
            Finding(
                rule_id="E9-SYSCTL-MODPROBE-HIJACK",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Kernel Persistence / Hijack",
                title=f"kernel.modprobe yolu değiştirilmiş (modprobe_path Rootkit tekniği!): {modprobe_path}",
                description="Çekirdek modprobe çağrılarında yetkisiz/zararlı bir script tetiklenecek şekilde modprobe_path kurcalanmış.",
                path=str(ctx.proc_root / "sys" / "kernel" / "modprobe"),
                evidence=[f"kernel.modprobe={modprobe_path}"],
            )
        )

    core_pat = _read_text(ctx.proc_root / "sys" / "kernel" / "core_pattern")
    if core_pat.startswith("|") and any(d in core_pat for d in ("/tmp/", "/dev/shm/", "/var/tmp/", "/home/")):
        ctx.add_finding(
            Finding(
                rule_id="E9-SYSCTL-COREPATTERN-HIJACK",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Kernel Persistence / Hijack",
                title="kernel.core_pattern şüpheli kullanıcı alanı borusuna (|) yönlendirilmiş",
                description="Crash anında root yetkili zararlı çalıştırmak için core_pattern değiştirilmiş.",
                path=str(ctx.proc_root / "sys" / "kernel" / "core_pattern"),
                evidence=[core_pat],
            )
        )

    preload_etc = ctx.sys_path("/etc/ld.so.preload")
    if preload_etc.is_file():
        content = _read_text(preload_etc)
        if content:
            ctx.add_finding(
                Finding(
                    rule_id="E9-PERSIST-LD-SO-PRELOAD",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Global Linker Rootkit",
                    title="Sistem genelinde /etc/ld.so.preload dosyası aktif (tüm süreçlere enjeksiyon)",
                    description="Her yeni başlatılan Linux sürecine otomatik olarak kütüphane enjekte eden dosya mevcut.",
                    path=str(preload_etc),
                    evidence=content.splitlines()[:10],
                )
            )

    # 2. USB HID Hardware Macro Microcontrollers (Arduino, Teensy, RP2040, KMBox/Makcu, CH340+HID)
    usb_dir = ctx.sys_path("/sys/bus/usb/devices")
    if usb_dir.is_dir():
        try:
            for dev in sorted(usb_dir.iterdir()):
                if not dev.is_dir() or ":" in dev.name:
                    continue
                vid = _read_text(dev / "idVendor").lower()
                pid = _read_text(dev / "idProduct").lower()
                prod = _read_text(dev / "product")
                manu = _read_text(dev / "manufacturer")
                serial = _read_text(dev / "serial")
                dev_cls = _read_text(dev / "bDeviceClass").lower()
                iface_classes = {_read_text(p).lower() for p in dev.glob("*:*/bInterfaceClass") if _read_text(p)}
                has_hid_iface = ("03" in iface_classes) or (dev_cls == "03")
                combined = f"{manu} {prod} {serial}".strip()
                explicit_macro_kw = bool(
                    re.search(r"(kmbox|makcu|badusb|hid-gadget|ch552)", combined, re.IGNORECASE)
                )
                # Ignore pure UART/storage cables on real Linux sysfs unless HID (03) or explicit BadUSB/KMBox
                if (vid in _USB_MACRO_MCU_VENDORS or _USB_MACRO_KW_RE.search(combined)) and (
                    has_hid_iface or not iface_classes or explicit_macro_kw
                ):
                    ctx.add_finding(
                        Finding(
                            rule_id="E9-HW-USB-MACRO-MCU",
                            engine=ENGINE_NAME,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="Hardware Macro / BadUSB",
                            title=f"Programlanabilir USB mikrodenetleyici / donanım makro cihazı bağlı: {prod or vid + ':' + pid}",
                            description="Arduino/Teensy/RP2040/HID köprüsü donanım düzeyinde tıklama ve aim makrosu enjekte edebilir.",
                            path=str(dev),
                            evidence=[
                                f"VID:PID={vid}:{pid} ({_USB_MACRO_MCU_VENDORS.get(vid, 'Özel Üretici')})",
                                f"Ürün={prod} Üretici={manu} Seri={serial} HID={has_hid_iface}",
                            ],
                        )
                    )
        except OSError:
            pass

    # 3. Direct /dev/vfio, /dev/uio, /dev/mem device presence / permission check
    vfio_dir = ctx.sys_path("/dev/vfio")
    if vfio_dir.is_dir():
        try:
            vfio_nodes = [p.name for p in vfio_dir.iterdir() if p.name not in ("vfio",)]
            if vfio_nodes:
                ctx.add_finding(
                    Finding(
                        rule_id="E9-DMA-VFIO-ACTIVE-NODE",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="DMA & IOMMU Hardware Protection",
                        title=f"Aktif /dev/vfio aygıt düğümü tespit edildi ({len(vfio_nodes)} grup)",
                        description="PCIe aygıtı VFIO DMA passthrough grubu olarak açılmış.",
                        path=str(vfio_dir),
                        evidence=[f"/dev/vfio/{n}" for n in vfio_nodes[:10]],
                    )
                )
        except OSError:
            pass

    dev_dir = ctx.sys_path("/dev")
    if dev_dir.is_dir():
        try:
            uio_nodes = sorted(p.name for p in dev_dir.iterdir() if p.name.startswith("uio"))
            if uio_nodes:
                ctx.add_finding(
                    Finding(
                        rule_id="E9-DMA-UIO-DEVICE-NODE",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="DMA & IOMMU Hardware Protection",
                        title=f"Kullanıcı alanı MMIO/DMA /dev/uio düğümü aktif ({len(uio_nodes)} adet)",
                        description="UIO aygıt düğümü PCIe bellek alanını kullanıcı alanı DMA kontrolüne açabilir.",
                        path=str(dev_dir),
                        evidence=[f"/dev/{n}" for n in uio_nodes[:10]],
                    )
                )
        except OSError:
            pass

    exposed_mem_devs: list[str] = []
    for raw_name in ("mem", "kmem", "port"):
        raw_p = ctx.sys_path(f"/dev/{raw_name}")
        if raw_p.exists():
            try:
                mode = stat.S_IMODE(os.stat(raw_p).st_mode)
                if mode & 0o006:
                    exposed_mem_devs.append(f"/dev/{raw_name} mode={oct(mode)}")
            except OSError:
                pass
    if exposed_mem_devs:
        ctx.add_finding(
            Finding(
                rule_id="E9-RAW-MEM-DEV-EXPOSED",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Physical Memory Exposure",
                title="Fiziksel bellek/port aygıtı herkese açık (world r/w) izinlerle ayarlanmış!",
                description="/dev/mem, /dev/kmem veya /dev/port root dışındaki kullanıcılara açık bırakılmış.",
                evidence=exposed_mem_devs,
            )
        )

    # 4. Root-collected foreign kprobes & dmesg anomalies
    kprobes = root_extras.get("kprobes_list") or []
    foreign_kp = [
        kp for kp in kprobes
        if "mc_ss_kmod" not in kp and "input_register_device" not in kp and any(
            t in kp for t in ("getdents", "filldir", "ptrace", "execve", "tcp", "uinput", "memfd")
        )
    ]
    if foreign_kp:
        ctx.add_finding(
            Finding(
                rule_id="E9-KERNEL-FOREIGN-KPROBE",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Ring-0 Rootkit Detection",
                title="Çekirdekte kritik sistem çağrılarında yabancı kprobe aktif!",
                description="/sys/kernel/debug/kprobes/list içinde gizleme/enjeksiyon hedefli aktif kprobe bulundu.",
                evidence=foreign_kp[:15],
            )
        )

    ftrace_lines = (root_extras.get("ftrace_enabled_functions") or []) + (
        root_extras.get("ftrace_filter") or []
    )
    ftrace_hits: list[str] = []
    for fln in ftrace_lines:
        low_f = fln.lower()
        if "mc_ss_kmod" in low_f or fln.strip().startswith("#"):
            continue
        if any(
            t in low_f
            for t in (
                "getdents",
                "filldir",
                "proc_pid_readdir",
                "tcp4_seq_show",
                "tcp6_seq_show",
                "ptrace_attach",
                "input_event",
                "iterate_dir",
            )
        ):
            ftrace_hits.append(fln.strip())
    if ftrace_hits:
        ctx.add_finding(
            Finding(
                rule_id="E9-KERNEL-FOREIGN-FTRACE",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category="Ring-0 Rootkit Detection",
                title="ftrace üzerinde kritik çekirdek fonksiyonlarına kanca (trampoline) bağlı!",
                description="enabled_functions/set_ftrace_filter içinde gizleme veya girdi enjeksiyonu hedefli aktif ftrace kancası görüldü (Singularity/ftrace rootkit tekniği).",
                evidence=ftrace_hits[:15],
            )
        )

    dmesg_lines = root_extras.get("dmesg_tail") or []
    dmar_faults = [ln for ln in dmesg_lines if "DMAR:" in ln and ("fault" in ln.lower() or "blocked" in ln.lower() or "error" in ln.lower())]
    if dmar_faults:
        ctx.add_finding(
            Finding(
                rule_id="E9-DMA-DMAR-FAULT-LOG",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="DMA & IOMMU Hardware Protection",
                title="Çekirdek günlüğünde DMAR/IOMMU bellek erişim ihlali (DMA Fault) kaydı!",
                description="Bir donanım cihazı yetkisiz bellek adresine DMA erişimi denedi.",
                evidence=dmar_faults[-8:],
            )
        )

    audit_lines = root_extras.get("audit_syscalls_tail") or []
    audit_inj = [
        ln for ln in audit_lines
        if any(s in ln for s in ("process_vm_writev", "finit_module", "init_module"))
    ]
    if audit_inj:
        ctx.add_finding(
            Finding(
                rule_id="E9-AUDIT-INJECT-SYSCALL",
                engine=ENGINE_NAME,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="Kernel Audit Telemetry",
                title="Linux Audit günlüklerinde process_vm_writev / init_module kaydı",
                description="Yakın geçmişte hassas bellek yazma veya modül yükleme sistem çağrısı denetlenmiş.",
                evidence=audit_inj[-8:],
            )
        )


def _run_unprivileged_native_probe(ctx: ScanContext) -> dict[str, Any]:
    probe = priv_helper.find_native_probe()
    if not probe:
        return {}
    try:
        cp = subprocess.run(
            [str(probe), "all"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if cp.stdout.strip():
            return json.loads(cp.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        pass
    return {}


def run(ctx: ScanContext) -> None:
    """Execute Engine 9: Multi-layer Ring-0 Kernel, DMA/IOMMU, 4KB PCIe & eBPF Audit."""
    emit_scan_progress(ctx, 0.05, "Çekirdek ve IOMMU/DMA ön kontrolleri yapılıyor...")
    record_scan_region(ctx, "E9", "Linux Çekirdek Yüzeyi, Ring-0 LKM (mc_ss_kmod), IOMMU & eBPF")

    target_os = getattr(ctx, "target_os", "auto")
    prereqs = priv_helper.check_kernel_prereqs(
        root_prefix=ctx.root_prefix,
        proc_root=ctx.proc_root,
        target_os=target_os,
    )
    ctx.telemetry["kernel_prereqs"] = prereqs

    ring0_data: dict[str, Any] = {}
    preloaded = getattr(ctx, "kernel_snapshot_data", None)
    if isinstance(preloaded, dict) and preloaded:
        ring0_data = preloaded
    elif ctx.live_mode and str(ctx.root_prefix) == "/":
        enable_lkm = getattr(ctx, "enable_kernel_lkm", False)
        if enable_lkm or os.geteuid() == 0:
            emit_scan_progress(ctx, 0.20, "Yetkili Ring-0 sürücüsü yükleniyor ve çekirdek taranıyor...")
            ring0_data = priv_helper.collect_privileged_kernel_snapshot(
                trace_window_ms=getattr(ctx, "kernel_trace_ms", 1500),
                allow_pkexec=enable_lkm,
                target_os=target_os,
            )

    proc_snaps = ring0_data.get("proc_snapshots") or {}
    root_extras = ring0_data.get("root_extras") or {}
    native_probe = root_extras.get("native_probe") or (
        _run_unprivileged_native_probe(ctx) if (ctx.live_mode and str(ctx.root_prefix) == "/") else {}
    )

    lkm_loaded = bool(ring0_data.get("lkm_loaded"))
    ctx.telemetry["kernel_lkm_active"] = lkm_loaded
    ctx.telemetry["kernel_lkm_unloaded_cleanly"] = ring0_data.get("lkm_unloaded_cleanly", True)

    if not lkm_loaded and getattr(ctx, "enable_kernel_lkm", False):
        reason = ring0_data.get("lkm_error") or ring0_data.get("error") or "Modül yüklenemedi"
        ctx.add_finding(
            Finding(
                rule_id="E9-LKM-UNPRIVILEGED-FALLBACK",
                engine=ENGINE_NAME,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category="Kernel Scan Coverage",
                title="Ring-0 LKM derin tarama aktif edilmedi (Userspace + Sysfs düşümlü mod)",
                description=(
                    "mc_ss_kmod.ko yüklenemediği için Ring-0 prolog/CR3/init_task katmanları "
                    "yerine erişilebilir çekirdek yüzeyi ve IOMMU/PCI/USB kontrolleri çalıştırıldı."
                ),
                evidence=[f"Neden: {reason}"],
            )
        )

    if lkm_loaded and ring0_data.get("lkm_unloaded_cleanly") is False:
        ctx.add_finding(
            Finding(
                rule_id="E9-LKM-UNLOAD-INCOMPLETE",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="Kernel Lifecycle",
                title="Geçici Ring-0 tarama modülü çıkış doğrulamasını geçemedi",
                description="Tarama bitiminde `rmmod mc_ss_kmod` sonrası /sys/module/mc_ss_kmod hala görünüyor.",
                recommendation="Yönetici olarak `sudo rmmod mc_ss_kmod` çalıştırın.",
            )
        )

    emit_scan_progress(ctx, 0.45, "Ring-0 çekirdek bütünlüğü, VFS & kancalar analiz ediliyor...")
    modinfos = _analyze_ring0_integrity(ctx, proc_snaps.get("integrity", ""))
    _analyze_lkm_status_and_taint(ctx, proc_snaps.get("status", ""), modinfos)

    emit_scan_progress(ctx, 0.65, "Ring-0 süreç ağacı ve VMA bellek baytları taranıyor...")
    _analyze_ring0_tasks_and_vmas(ctx, proc_snaps.get("tasks_vma", ""))

    emit_scan_progress(ctx, 0.80, "PCIe 4KB config uzayı, DMA ve IOMMU koruması denetleniyor...")
    native_pci_ext = native_probe.get("pci_ext") or []
    _analyze_dma_pci_iommu(ctx, proc_snaps.get("pci_iommu", ""), native_pci_ext)

    emit_scan_progress(ctx, 0.92, "eBPF programları, canlı trace olayları ve USB donanımlar taranıyor...")
    _analyze_ebpf_and_pid_cross(ctx, native_probe, root_extras=root_extras)
    _analyze_live_events(ctx, proc_snaps.get("events", ""))
    _analyze_kernel_surface_sysfs(ctx, root_extras)

    emit_scan_progress(ctx, 1.0, "Engine 9 Kernel & DMA/IOMMU analizi tamamlandı.")

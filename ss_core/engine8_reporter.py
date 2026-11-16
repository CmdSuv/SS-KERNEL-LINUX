"""Engine 8: Cross-Engine Correlation, Risk Scoring & Multi-Format Reporting (HTML, TXT, JSON)."""

from __future__ import annotations

import hashlib
import html
import json
import textwrap
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Confidence, Finding, ScanContext, Severity

ENGINE_NAME = "Engine 8: Korelasyon & Risk Raporlama"


def correlate_findings(ctx: ScanContext) -> None:
    """Synthesize multi-engine correlation findings across Engines 1..7."""
    rule_ids = {f.rule_id for f in ctx.findings}

    def _has_any(*ids: str) -> list[str]:
        return [rid for rid in ids if rid in rule_ids]

    # 1. Anti-forensic coverup chain
    wipe_sources = _has_any(
        "E1-HIST-ZERO",
        "E1-HIST-DEVNULL",
        "E1-HIST-ANTIFORENSIC-CMD",
        "E1-HIST-TIMESTOMP",
        "E1-RC-HIST-DISABLE",
        "E1-RC-ANTIFORENSIC-HOOK",
        "E1-REBOOT-RECENT",
        "E6-BROWSER-HISTORY-WIPED",
    )
    artifact_wipe = _has_any(
        "E5-LOG-MISSING-LATEST",
        "E5-LOG-ZEROED",
        "E5-LOG-MISSING-CHEAT-MOD",
        "E5-LOG-MODLIST-MISMATCH",
        "E6-TRASH-SUSPICIOUS",
        "E6-XBEL-DELETED-ARTIFACT",
        "E6-BROWSER-SQLITE-FREELIST-CARVE",
    )
    if wipe_sources and artifact_wipe:
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-WIPE-CHAIN",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Cross-Engine Correlation",
                title="Koordineli adli iz temizleme zinciri tespit edildi",
                description="Birden fazla katmanda (gecmis/log/tarayici/cop kutusu) es zamanli silme ve manipule etme bulgulari eslesti.",
                evidence=[
                    f"Sistem/Gecmis sinyalleri: {', '.join(wipe_sources)}",
                    f"Dosya/Log/Tarayici sinyalleri: {', '.join(artifact_wipe)}",
                ],
                recommendation="Oyuncunun kontrol oncesi bilerek iz temizledigi yuksek olasilikla dogrulandi.",
            )
        )

    # 2. Stealth autoclicker / macro chain
    live_input = _has_any(
        "E3-VIRTUAL-UINPUT-DEVICE",
        "E3-VIRTUAL-UINPUT-SYSFS",
        "E2-FD-UINPUT-ACCESS",
        "E3-YDOTOOL-SOCKET",
        "E3-SYSTEMD-MACRO-SVC",
        "E9-EVT-LIVE-UINPUT-CREATED",
    )
    cfg_macro = _has_any(
        "E3-INPUT-REMAPPER-MACRO",
        "E3-SOLAAR-RULE",
        "E3-RAZER-MACRO",
        "E3-HOTKEY-MACRO",
        "E3-MACRO-SCRIPT",
        "E3-XCLICKER-CONFIG",
    )
    if live_input and cfg_macro:
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-STEALTH-MACRO",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Cross-Engine Correlation",
                title="Aktif Linux/Wayland uinput makro + yapilandirma zinciri",
                description="Hem canli uinput/makro servisi hem de kayitli makro profili/scripti ayni anda tespit edildi.",
                evidence=[
                    f"Canli girdi katmani: {', '.join(live_input)}",
                    f"Makro yapilandirmasi: {', '.join(cfg_macro)}",
                ],
            )
        )

    # 3. Spoofed mod verification chain
    spoof_base = _has_any("E4-JAR-SPOOFED-MOD-NAME", "E4-EXT-SPOOF", "E4-POLYGLOT-PAYLOAD")
    spoof_proof = _has_any(
        "E4-XATTR-UNVERIFIED-URL",
        "E4-XATTR-CHEAT-URL",
        "E4-TIMESTOMP-ANOMALY",
        "E4-JAR-CLASS-CONSTANT-POOL",
        "E4-JAR-DANGEROUS-API",
        "E4-JAR-CHEAT-METADATA",
    )
    if spoof_base and spoof_proof:
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-SPOOFED-ARTIFACT",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Cross-Engine Correlation",
                title="Sahte isim / uzanti gizleme + bit duzeyi icerik dogrulamasi",
                description="Mesru gorunumlu bir dosya adinin arkasinda bytecode/xattr/timestomp ile dogrulanmis gizli yuk bulundu.",
                evidence=[f"Gizleme: {', '.join(spoof_base)}", f"Dogrulama: {', '.join(spoof_proof)}"],
            )
        )

    # 4. RAM-only Ghost Client chain
    ram_ghost = _has_any("E2-MAP-DELETED-BIN", "E2-FD-DELETED-FILE", "E2-RAM-STRICT-SIG", "E2-RAM-MODULE-CLUSTER")
    disk_gone = _has_any("E6-TRASH-SUSPICIOUS", "E6-XBEL-DELETED-ARTIFACT", "E5-LOG-MISSING-CHEAT-MOD")
    if ram_ghost and disk_gone:
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-GHOST-RAM",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Cross-Engine Correlation",
                title="Diskten silinip RAM'de yasamaya devam eden Ghost Client zinciri",
                description="Hile dosyasi diskten kaldirilmis/cop kutusuna atilmis ancak bellek ve acik fd/log katmanlarinda yakalandi.",
                evidence=[f"RAM/FD katmani: {', '.join(ram_ghost)}", f"Disk silme katmani: {', '.join(disk_gone)}"],
            )
        )

    # 5. Acquisition -> Execution/Deletion chain
    browser_hit = _has_any("E6-BROWSER-CHEAT-URL", "E6-BROWSER-CHEAT-DOWNLOAD", "E6-BROWSER-SQLITE-FREELIST-CARVE")
    local_hit = _has_any("E4-XATTR-CHEAT-URL", "E6-TRASH-SUSPICIOUS", "E6-XBEL-DELETED-ARTIFACT", "E1-HIST-CHEAT-CMD")
    if browser_hit and local_hit:
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-ACQUISITION-CHAIN",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Cross-Engine Correlation",
                title="Tarayici indirme + yerel kullanim/silme zinciri dogrulandi",
                description="Web gecmisi/indirme kaydi ile yerel dosya/xattr/terminal izleri birbirini dogruladi.",
                evidence=[f"Tarayici: {', '.join(browser_hit)}", f"Yerel iz: {', '.join(local_hit)}"],
            )
        )

    # 6. JVM / Linker Injection -> Bytecode/RAM Payload chain (ignore benign INFO agents like Lunar Ichor)
    non_info_rules = {f.rule_id for f in ctx.findings if f.severity != Severity.INFO}
    inj_vectors = [
        rid
        for rid in (
            "E2-JVM-AGENT-ARG",
            "E2-PROC-JAVA-ENV-INJECT",
            "E2-JVM-BOOTCLASSPATH",
            "E2-PROC-LDPRELOAD",
            "E2-PROC-LDAUDIT",
            "E2-JVM-DISABLE-ATTACH",
            "E2-JVM-PERF-DISABLE",
            "E2-JCMD-FLAGS",
            "E2-JCMD-ATTACH-LOADED",
            "E1-RC-LDPRELOAD",
            "E1-RC-LDAUDIT",
            "E1-RC-JAVA-TOOL-OPTS",
            "E4-JAR-AGENT-MANIFEST",
            "E5-LAUNCHER-JVM-AGENT",
            "E5-INSTANCE-JVM-AGENT",
        )
        if rid in non_info_rules
    ]
    payload_proofs = _has_any(
        "E4-JAR-SUSPICIOUS-MIXIN",
        "E4-JAR-CLASS-CONSTANT-POOL",
        "E4-JAR-DANGEROUS-API",
        "E4-JAR-CHEAT-METADATA",
        "E4-JAR-OBFUSCATION",
        "E4-STANDALONE-CLASS-CHEAT",
        "E4-ELF-SUSPICIOUS",
        "E4-PE-CHEAT-OR-INJECTOR",
        "E2-RAM-STRICT-SIG",
        "E2-RAM-MODULE-CLUSTER",
        "E2-JCMD-CHEAT-CLASSES",
        "E2-MAP-EXEC-MEMFD",
        "E2-MAP-DELETED-BIN",
        "E2-MAP-TEXT-COW-PATCH",
    )
    if inj_vectors and payload_proofs:
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-JVM-INJECT-CHAIN",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Cross-Engine Correlation",
                title="JVM / Linker enjeksiyonu + zararli bytecode/RAM yuk zinciri",
                description="Enjeksiyon vektörü (agent/LD_PRELOAD/LD_AUDIT/attach engeli) ile zararli kod kaniti ayni oturumda eslesti.",
                evidence=[f"Enjeksiyon: {', '.join(inj_vectors)}", f"Payload: {', '.join(payload_proofs)}"],
            )
        )

    # 7. Ring-0 Rootkit / Hidden Kernel / Inline Hook correlation
    ring0_rk = _has_any(
        "E9-KERNEL-INLINE-HOOK",
        "E9-MSR-LSTAR-HOOK",
        "E9-LKM-WRITABLE-KTEXT",
        "E9-VFS-HOOK-HIJACK",
        "E9-HIDDEN-LKM-CROSSVIEW",
        "E9-HIDDEN-LKM-SYSFS-DIFF",
        "E9-ORPHAN-KERNEL-ELF",
        "E9-ORPHAN-RWX-KERNEL-MEM",
        "E9-HIDDEN-PID-RING0",
        "E9-HIDDEN-PID-READDIR",
        "E9-KNOWN-ROOTKIT-LKM",
        "E9-SYSCTL-MODPROBE-HIJACK",
        "E9-KERNEL-FOREIGN-KPROBE",
        "E9-KERNEL-FOREIGN-FTRACE",
        "E9-EBPF-SUSPICIOUS-PROG",
        "E9-EBPF-PINNED-OBJ",
        "E9-EVT-LIVE-BPF-LOAD",
        "E9-EVT-RAW-IO-PORT",
    )
    if len(ring0_rk) >= 2:
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-RING0-ROOTKIT",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Cross-Engine Correlation",
                title="Coklu Ring-0 Kernel Rootkit / Kanca kaniti dogrulandi!",
                description="Cekirdek seviyesinde birden fazla bagimsiz gizleme/kanca bulgusu ayni anda tespit edildi.",
                evidence=[f"Ring-0 Bulgular: {', '.join(ring0_rk)}"],
            )
        )

    # 8. Unprotected IOMMU + DMA Hardware/VFIO Exposure chain
    iommu_weak = _has_any(
        "E9-DMA-IOMMU-DISABLED",
        "E9-DMA-IOMMU-FORCED-OFF",
        "E9-DMA-IOMMU-PASSTHROUGH",
        "E9-DMA-ACS-OVERRIDE",
    )
    dma_dev = _has_any(
        "E9-DMA-FPGA-HARDWARE",
        "E9-DMA-VFIO-UIO-DEVICE",
        "E9-DMA-UNBOUND-BUSMASTER",
        "E9-DMA-SPOOFED-PCIE-FW",
        "E9-DMA-THUNDERBOLT-EXPOSED",
        "E9-DMA-VFIO-ACTIVE-NODE",
        "E9-DMA-UIO-DEVICE-NODE",
        "E9-RAW-MEM-DEV-EXPOSED",
        "E2-FD-RAW-DEV-ACCESS",
    )
    if iommu_weak and dma_dev:
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-DMA-EXPOSURE",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Cross-Engine Correlation",
                title="Korunmasiz IOMMU + aktif DMA/FPGA/VFIO donanim maruziyeti",
                description="IOMMU izolasyonu devredisi/zayifken donanim duzeyinde DMA yapabilen supheli aygit tespit edildi.",
                evidence=[f"IOMMU: {', '.join(iommu_weak)}", f"DMA Aygit: {', '.join(dma_dev)}"],
            )
        )

    # 9. Ring-0 Fileless / Syscall Memory Injection chain
    k_ram = _has_any(
        "E9-KERNEL-VMA-REFLECTIVE-ELF",
        "E9-KERNEL-VMA-JNI-AGENT",
        "E9-KERNEL-VMA-PACKED-CODE",
        "E9-KERNEL-VMA-INJECTED-PE",
        "E2-MAP-TEXT-COW-PATCH",
    )
    k_evt = _has_any(
        "E9-EVT-VM-WRITEV-INJECT",
        "E9-EVT-PTRACE-INJECT",
        "E9-EVT-MEMFD-EXEC",
        "E9-EVT-EXECVEAT-FILELESS",
        "E2-MAP-EXEC-MEMFD",
        "E2-MAP-DELETED-BIN",
        "E2-MAP-TEXT-COW-PATCH",
    )
    if k_ram and (k_evt or payload_proofs):
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-KERNEL-FILELESS",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Cross-Engine Correlation",
                title="Ring-0 VMA bayt enjeksiyonu + dosyasiz bellek yurutmeleri eslesti",
                description="Cekirdek VMA taramasi ile memfd/ptrace/RAM sinyalleri ayni anda dogrulandi.",
                evidence=[f"VMA Bayt: {', '.join(k_ram)}", f"Olay/RAM: {', '.join(k_evt or payload_proofs)}"],
            )
        )


def compute_risk_assessment(findings: list[Finding]) -> dict[str, Any]:
    counts = {s.value: 0 for s in Severity}
    by_rule: dict[str, list[Finding]] = defaultdict(list)

    for f in findings:
        counts[f.severity.value] += 1
        by_rule[f.rule_id].append(f)

    raw_score = 0.0
    decay = (1.0, 0.45, 0.25, 0.15)
    for rid, group in by_rule.items():
        # Sort highest effective score first
        group_sorted = sorted(group, key=lambda x: x.effective_score, reverse=True)
        for idx, item in enumerate(group_sorted):
            mult = decay[idx] if idx < len(decay) else 0.08
            raw_score += item.effective_score * mult

    score = min(100, int(round(raw_score)))

    has_confirmed_crit = any(
        f.severity == Severity.CRITICAL and f.confidence == Confidence.CONFIRMED for f in findings
    )
    has_any_crit = counts["CRITICAL"] > 0
    has_confirmed_high = any(
        f.severity == Severity.HIGH and f.confidence == Confidence.CONFIRMED for f in findings
    )

    if has_confirmed_crit:
        score = max(score, 68)
    elif has_any_crit:
        score = max(score, 52)
    elif has_confirmed_high:
        score = max(score, 30)

    if score >= 65:
        verdict = "KRITIK - DOGRULANMIS HILE / ENJEKSIYON / ADLI MANIPULASYON"
        verdict_level = "CRITICAL"
    elif score >= 35:
        verdict = "YUKSEK RISK - OLASI HILE VEYA IZ TEMIZLEME"
        verdict_level = "HIGH"
    elif score >= 15:
        verdict = "SUPHELI - MANUEL INCELEME GEREKLI"
        verdict_level = "MEDIUM"
    else:
        verdict = "TEMIZ / DUSUK RISK"
        verdict_level = "CLEAN"

    return {
        "risk_score": score,
        "verdict": verdict,
        "verdict_level": verdict_level,
        "counts": counts,
        "total_findings": len(findings),
    }


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.severity.rank, f.effective_score), reverse=True)


def build_report_payload(ctx: ScanContext) -> dict[str, Any]:
    ordered = _sorted_findings(ctx.findings)
    assessment = compute_risk_assessment(ordered)
    payload_core = {
        "schema_version": "2.0",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target_home": str(ctx.home_dir),
        "target_os": ctx.telemetry.get("target_os") or getattr(ctx, "target_os", "auto"),
        "target_os_name": ctx.telemetry.get("target_os_name") or getattr(ctx, "target_os", "auto"),
        "host_os_name": ctx.telemetry.get("host_pretty_name") or "",
        "live_mode": ctx.live_mode,
        "memory_scan_enabled": ctx.enable_memory_scan,
        "time_window_hours": ctx.time_window_hours,
        "assessment": assessment,
        "telemetry": ctx.telemetry,
        "findings": [f.to_dict() for f in ordered],
        "errors": ctx.errors,
    }
    canonical = json.dumps(payload_core, sort_keys=True, ensure_ascii=False).encode("utf-8")
    payload_core["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload_core


_ENGINE_TITLES: dict[str, str] = {
    "E1": "E1 — Sistem Butunlugu, Saat ve Kabuk Gecmisi",
    "E2": "E2 — Canli Surecler, /proc Haritalari ve RAM",
    "E3": "E3 — Donanim Makro, uinput ve Sanal Girdi",
    "E4": "E4 — Derin Dosya, Mod JAR ve Bytecode Analizi",
    "E5": "E5 — Minecraft Ayarlari, Loglar ve Launcher Izleri",
    "E6": "E6 — Masaustu, Tarayici SQLite, Cop ve Wine Izleri",
    "E7": "E7 — Ag Soketleri, VPN/Proxy ve USB Donanim",
    "E8": "E8 — Capraz Korelasyon ve Risk Puanlama",
    "E9": "E9 — Ring-0 Cekirdek, eBPF, PCIe 4KB ve DMA/IOMMU",
}

_SEVERITY_TR: dict[str, str] = {
    "CRITICAL": "KRITIK",
    "HIGH": "YUKSEK",
    "MEDIUM": "ORTA",
    "LOW": "DUSUK",
    "INFO": "BILGI",
}

_CONFIDENCE_TR: dict[str, str] = {
    "CONFIRMED": "Dogrulanmis",
    "HIGH": "Yuksek Guven",
    "MEDIUM": "Orta Guven",
    "LOW": "Dusuk Guven",
}


def _format_uptime(sec_raw: Any) -> str:
    try:
        secs = float(sec_raw)
    except (TypeError, ValueError):
        return str(sec_raw)
    mins, rem_s = divmod(int(secs), 60)
    hours, rem_m = divmod(mins, 60)
    days, rem_h = divmod(hours, 24)
    if days > 0:
        return f"{secs:.1f} sn ({days} gun {rem_h} sa {rem_m} dk)"
    if hours > 0:
        return f"{secs:.1f} sn ({hours} sa {rem_m} dk)"
    return f"{secs:.1f} sn ({mins} dk {rem_s} sn)"


def _format_compact_value(val: Any, limit: int = 360) -> str:
    if isinstance(val, bool):
        return "Evet" if val else "Hayir"
    if isinstance(val, dict):
        if not val:
            return "(yok)"
        parts = [f"{k}={_format_compact_value(v, 120)}" for k, v in sorted(val.items())]
        return ", ".join(parts)[:limit]
    if isinstance(val, list):
        if not val:
            return "(yok)"
        if len(val) <= 4:
            return ", ".join(str(x) for x in val)[:limit]
        return f"{', '.join(str(x) for x in val[:3])} ... (+{len(val) - 3} ek kayit)"[:limit]
    return str(val)[:limit]


def _wrap_indented(prefix: str, text: str, width: int = 96, cont_indent: str = "                 ") -> list[str]:
    clean = " ".join(str(text).splitlines()).strip()
    if not clean:
        return [prefix.rstrip()]
    wrapped = textwrap.wrap(
        clean,
        width=max(40, width - len(cont_indent)),
        break_long_words=True,
        break_on_hyphens=False,
    )
    if not wrapped:
        return [prefix.rstrip()]
    out = [f"{prefix}{wrapped[0]}"]
    for extra in wrapped[1:]:
        out.append(f"{cont_indent}{extra}")
    return out


def _build_structured_telemetry_groups(telem: dict[str, Any]) -> list[tuple[str, list[tuple[str, Any]]]]:
    """Translate raw telemetry dict into clean, Turkish, logically grouped rows."""
    consumed: set[str] = {
        "scanned_regions",
        "engine_timings_sec",
        "target_os",
        "target_os_name",
        "host_os",
        "host_pretty_name",
        "engine4_mc_dirs_scanned",
        "engine4_hot_dirs_scanned",
        "ram_scanned_bytes",
    }

    def take(key: str, default: Any = None) -> Any:
        consumed.add(key)
        return telem.get(key, default)

    sys_rows: list[tuple[str, Any]] = []
    prod = take("hardware_product")
    if prod:
        sys_rows.append(("Donanim / Model", prod))
    krel = take("kernel_release")
    if krel:
        sys_rows.append(("Cekirdek Surumu (uname -r)", krel))
    sess = take("session_type")
    w_disp = take("wayland_display")
    x_disp = take("x11_display")
    if sess or w_disp or x_disp:
        disp_parts = [p for p in (w_disp and f"Wayland={w_disp}", x_disp and f"X11={x_disp}") if p]
        sys_rows.append(("Oturum ve Ekran", f"{sess or 'bilinmiyor'} ({', '.join(disp_parts) or 'ekran yok'})"))
    mons = take("connected_monitors")
    if mons:
        sys_rows.append(("Bagli Monitorler", _format_compact_value(mons)))
    up = take("uptime_seconds")
    if up is not None:
        sys_rows.append(("Sistem Acilis Suresi", _format_uptime(up)))
    td_map = take("timedatectl")
    if isinstance(td_map, dict) and td_map:
        td_parts = []
        if td_map.get("Timezone"):
            td_parts.append(f"Bolge={td_map['Timezone']}")
        ntp = td_map.get("NTP") or td_map.get("NTPSynchronized")
        if ntp:
            td_parts.append(f"NTP={ntp}")
        if td_map.get("SystemClockSynchronized"):
            td_parts.append(f"SaatEsitli={td_map['SystemClockSynchronized']}")
        if td_parts:
            sys_rows.append(("Saat Dilimi ve NTP Senkronu", " | ".join(td_parts)))

    mac = take("mac_framework")
    se = take("selinux_enforce")
    aa = take("apparmor_enabled")
    ro = take("steamos_readonly_status")
    pt = take("ptrace_scope")
    pt_note = take("ptrace_note")
    if mac or se is not None or aa is not None or ro is not None:
        mac_lbl = mac or "yok"
        if se is not None:
            mac_lbl += f" (SELinux={se})"
        if aa is not None:
            mac_lbl += f" (AppArmor={aa})"
        if ro is not None:
            mac_lbl += f" (SteamOS readonly={ro})"
        sys_rows.append(("Zorunlu Erisim Kontrolu (MAC)", mac_lbl))
    if pt is not None:
        sys_rows.append(("ptrace Bellek Koruma Seviyesi", f"{pt}" + (f" — {pt_note}" if pt_note else "")))
    tool_hash = take("tool_self_sha256_prefix")
    if tool_hash:
        sys_rows.append(("Arac Butunluk Parmak Izi", tool_hash))

    r0_rows: list[tuple[str, Any]] = []
    lkm_act = take("kernel_lkm_active", False)
    lkm_clean = take("kernel_lkm_unloaded_cleanly", True)
    lkm_status = take("kernel_lkm_status")
    taint_sum = take("kernel_taint_summary")
    iommu = take("iommu_compliance")
    pid_cross = take("native_pid_cross")

    r0_rows.append((
        "Ring-0 LKM Durumu",
        f"{'AKTIF TARANDI' if lkm_act else 'KAPALI (Userspace/Sysfs Fallback)'} | Temiz Cikis (rmmod): {lkm_clean}",
    ))
    if lkm_status:
        r0_rows.append(("LKM Modul Bilgisi", _format_compact_value(lkm_status)))
    if taint_sum:
        r0_rows.append(("Cekirdek Taint Durumu", taint_sum))
    if isinstance(iommu, dict) and iommu:
        r0_rows.append((
            "IOMMU / DMA Donanim Korumasi",
            f"Aktif={'Evet' if iommu.get('iommu_active') else 'Hayir'} | "
            f"Grup={iommu.get('iommu_group_count', 0)} | "
            f"DMAR={iommu.get('acpi_dmar_present')} | IVRS={iommu.get('acpi_ivrs_present')} | "
            f"Strict={iommu.get('strict_enabled')}",
        ))
    r0_rows.append((
        "Ring-0 Sayaclari",
        f"Gorev={take('ring0_task_count', 0)} | "
        f"VMA Anomali={take('ring0_vma_anomalies', 0)} | "
        f"Olay={take('ring0_captured_events', 0)} | "
        f"Hook Kontrol={take('kernel_khook_checked', 0)} | "
        f"Modul={take('kernel_modinfo_count', 0)} (xscan={take('kernel_modxscan_count', 0)})",
    ))
    r0_rows.append((
        "PCIe / eBPF Yuzeyi",
        f"PCIe Aygit={take('pci_device_count', 0)} | "
        f"eBPF Prog={take('ebpf_prog_count', 'N/A')} | "
        f"eBPF Link={take('ebpf_link_count', 'N/A')}",
    ))
    if isinstance(pid_cross, dict) and pid_cross:
        r0_rows.append((
            "PID Cross-View (readdir vs getdents64)",
            f"readdir={pid_cross.get('readdir_count', '?')} | "
            f"raw_getdents={pid_cross.get('raw_getdents_count', '?')} | "
            f"gizli={len(pid_cross.get('hidden_pids', []) or [])}",
        ))
    prereqs = take("kernel_prereqs")
    if isinstance(prereqs, dict) and prereqs:
        pr_parts = [
            f"Root={'Evet' if prereqs.get('is_root') else 'Hayir'}",
            f"Basliklar={'Mevcut' if prereqs.get('headers_present') else 'Eksik'}",
            f"GCC={'Var' if prereqs.get('gcc_available') else 'Yok'}",
            f"Clang={'Var' if prereqs.get('clang_available') else 'Yok'}",
            f"kptr_restrict={prereqs.get('kptr_restrict', '?')}",
        ]
        if prereqs.get("headers_install_hint"):
            pr_parts.append(f"Kurulum Notu={prereqs['headers_install_hint']}")
        r0_rows.append(("Ring-0 On Gereksinimler", " | ".join(pr_parts)))

    env_rows: list[tuple[str, Any]] = []
    tot_p = take("total_processes", 0)
    j_pids = take("java_pids", []) or []
    mc_pids = take("minecraft_pids", []) or []
    env_rows.append((
        "Calisan Surecler",
        f"Toplam: {tot_p} | Java PID: {len(j_pids)} ({_format_compact_value(j_pids[:6]) if j_pids else 'yok'}) | "
        f"Minecraft PID: {len(mc_pids)} ({_format_compact_value(mc_pids[:6]) if mc_pids else 'yok'})",
    ))
    deep_f = take("engine4_files_deep_scanned")
    if deep_f is not None:
        env_rows.append(("Derin Taranan Dosya Sayisi", f"{deep_f} dosya (JAR/class/ELF/PE/script)"))
    mc_inst = take("minecraft_instances")
    if mc_inst is not None:
        env_rows.append(("Kesfedilen Minecraft Profilleri", mc_inst if mc_inst else "Bulunamadi"))
    u_mode = take("uinput_mode")
    u_write = take("uinput_user_writable")
    if u_mode is not None or u_write is not None:
        env_rows.append(("/dev/uinput Sanal Girdi Izni", f"Mod={u_mode} | Kullaniciya Acik={'Evet (Risk)' if u_write else 'Hayir'}"))
    rbag = take("ratbag_devices")
    if rbag:
        env_rows.append(("Ratbag / Makro Donanimlari", rbag))
    bdbs = take("browser_dbs_found")
    if bdbs is not None:
        env_rows.append(("Incelenen Tarayici Veritabanlari", bdbs if bdbs else "Bulunamadi"))
    jsocks = take("java_established_sockets")
    if jsocks:
        env_rows.append(("Aktif Java Ag Soketleri", jsocks))

    extra_rows: list[tuple[str, Any]] = []
    for k in sorted(telem.keys()):
        if k in consumed:
            continue
        extra_rows.append((k, telem[k]))

    groups: list[tuple[str, list[tuple[str, Any]]]] = [
        ("Sistem, Oturum ve Guvenlik Ortami", sys_rows),
        ("Ring-0 Kernel / DMA / IOMMU / eBPF Ozeti", r0_rows),
        ("Minecraft, Surecler, Girdi ve Tarayici Ortami", env_rows),
    ]
    if extra_rows:
        groups.append(("Ek Teknik Kayitlar", extra_rows))
    return groups


def _render_finding_txt(idx: int, f: dict[str, Any]) -> list[str]:
    sev = f.get("severity", "INFO")
    sev_lbl = _SEVERITY_TR.get(sev, sev)
    conf = _CONFIDENCE_TR.get(f.get("confidence", ""), f.get("confidence", ""))
    lines: list[str] = [
        "",
        f"  [{idx}] [{sev_lbl} | {conf}] {f.get('title', '')}",
        f"      Kural / Motor : {f.get('rule_id', '')} | {f.get('engine', '')} | Etki Skoru: {f.get('effective_score', 0)}",
    ]
    if f.get("path"):
        lines.extend(_wrap_indented("      Dosya / Konum : ", str(f["path"]), cont_indent="                      "))
    if f.get("pid") is not None:
        lines.append(f"      Surec PID     : {f['pid']}")
    if f.get("description"):
        lines.extend(_wrap_indented("      Ne Tespit Edi.: ", str(f["description"]), cont_indent="                      "))
    ev_list = f.get("evidence") or []
    if ev_list:
        ev_counts: dict[str, int] = {}
        for ev in ev_list:
            s = str(ev)
            ev_counts[s] = ev_counts.get(s, 0) + 1
        lines.append("      Kanitlar      :")
        for ev_text, rep in ev_counts.items():
            suffix = f" ({rep} tekrar)" if rep > 1 else ""
            lines.extend(_wrap_indented("        - ", f"{ev_text}{suffix}", cont_indent="          "))
    if f.get("recommendation"):
        lines.extend(_wrap_indented("      Admin Notu    : ", str(f["recommendation"]), cont_indent="                      "))
    return lines


def _verdict_guidance_text(ass: dict[str, Any]) -> str:
    lvl = ass.get("verdict_level", "CLEAN")
    counts = ass.get("counts", {})
    if lvl == "CRITICAL":
        return (
            f"DIKKAT: {counts.get('CRITICAL', 0)} adet KRITIK hile/enjeksiyon veya adli iz temizleme kaniti "
            "dogrulandi. Oncelikle Bolum 1 ve 2A'daki dosya yollarini ve kanitlari inceleyin."
        )
    if lvl == "HIGH":
        return (
            "UYARI: Yuksek riskli hile, makro veya gizleme izi bulundu. Kesin karar oncesi "
            "Bolum 1 ve 2A'da listelenen kanitlari kontrol edin."
        )
    if lvl == "MEDIUM":
        return (
            "INCELEME GEREKLI: Supheli bulgular tespit edildi ancak tek basina kesin hile "
            "olmayabilir. Bolum 2B'deki maddeleri elle dogrulayin."
        )
    return (
        "TEMIZ: Bilinen hile istemcisi, RAM/JVM enjeksiyonu, aktif makro veya iz temizleme "
        "bulgusu saptanmadi. Alt katmanlardaki bilgi notlarini istege bagli inceleyebilirsiniz."
    )


def render_txt_report(payload: dict[str, Any], saved_path: Path | None = None) -> str:
    ass = payload["assessment"]
    counts = ass["counts"]
    telem = payload.get("telemetry", {}) or {}
    findings = payload.get("findings", []) or []
    timings = telem.get("engine_timings_sec", {}) or {}
    total_dur = round(sum(float(v) for v in timings.values() if isinstance(v, (int, float))), 3)
    local_now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    deep_count = telem.get("engine4_files_deep_scanned", 0)
    total_procs = telem.get("total_processes", 0)
    java_pids = telem.get("java_pids", []) or []
    mc_pids = telem.get("minecraft_pids", []) or []
    mc_inst = telem.get("minecraft_instances", []) or []
    lkm_act = telem.get("kernel_lkm_active", False)
    iommu_info = telem.get("iommu_compliance") or {}
    iommu_lbl = "Aktif" if isinstance(iommu_info, dict) and iommu_info.get("iommu_active") else "Kapali/Belirsiz"

    lines: list[str] = [
        "=" * 88,
        "          MC SS SENTINEL — ANLASILIR ADLI HILE KONTROL (SS) RAPORU",
        "=" * 88,
        f"KARAR (VERDICT)      : {ass['verdict']}",
        f"RISK PUANI           : {ass['risk_score']} / 100",
    ]
    lines.extend(_wrap_indented("OZET DEGERLENDIRME   : ", _verdict_guidance_text(ass), cont_indent="                       "))
    lines.extend([
        "-" * 88,
        f"Bulgu Dagilimi       : KRITIK={counts['CRITICAL']} | YUKSEK={counts['HIGH']} | ORTA={counts['MEDIUM']} | DUSUK={counts['LOW']} | BILGI={counts['INFO']} (Toplam: {ass['total_findings']})",
        f"Tarama Kapsami       : {total_procs} surec (Java={len(java_pids)}, Minecraft={len(mc_pids)}) | {deep_count} derin dosya | {len(mc_inst)} MC profili | {total_dur} sn",
        f"Ring-0 / IOMMU       : LKM={'AKTIF TARANDI' if lkm_act else 'KAPALI (Userspace/Sysfs Fallback)'} | IOMMU Korumasi={iommu_lbl}",
        f"Tarih (Yerel / UTC)  : {local_now}  ({payload['generated_utc']})",
        f"Hedef Ev Dizini      : {payload['target_home']}",
        f"Hedef OS / Host OS   : {payload.get('target_os_name', 'auto')} ({payload.get('target_os', 'auto')}) / {payload.get('host_os_name') or 'bilinmiyor'}",
        f"Canli Mod / RAM      : {'Acik' if payload['live_mode'] else 'Kapali'} / {'Acik' if payload['memory_scan_enabled'] else 'Kapali'}",
        "",
        "=" * 88,
        "1. ONCELIKLI BULGULAR OZETI (HILE / SUPHELI TESPITLER)",
        "=" * 88,
    ])

    flagged = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")]
    if not flagged:
        lines.append("  [TEMIZ] Kritik, yuksek veya orta riskli herhangi bir hile/enjeksiyon/makro bulunamadi.")
    else:
        for idx, f in enumerate(flagged, 1):
            sev_lbl = _SEVERITY_TR.get(f["severity"], f["severity"])
            loc = f.get("path") or (f"Surec PID {f['pid']}" if f.get("pid") is not None else "Sistem / Cekirdek / Bellek")
            lines.append(f"  {idx}. [{sev_lbl}] {f['title']}  ({f['rule_id']} | Skor: {f['effective_score']})")
            lines.extend(_wrap_indented("     Konum : ", str(loc), cont_indent="             "))
            if f.get("evidence"):
                lines.extend(_wrap_indented("     Kanit : ", str(f["evidence"][0]), cont_indent="             "))

    lines.extend([
        "",
        "=" * 88,
        "2. DETAYLI ADLI BULGULAR VE KANITLAR (ONEM SIRASINA GORE)",
        "=" * 88,
    ])
    if not findings:
        lines.append("  (Hicbir bulgu kaydedilmedi.)")
    else:
        crit_high = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
        medium = [f for f in findings if f.get("severity") == "MEDIUM"]
        low_info = [f for f in findings if f.get("severity") in ("LOW", "INFO")]

        lines.append("")
        lines.append("  --- 2A. KRITIK VE YUKSEK RISKLI BULGULAR (DOGRUDAN HILE / ENJEKSIYON / MANIPULASYON) ---")
        if crit_high:
            for idx, f in enumerate(crit_high, 1):
                lines.extend(_render_finding_txt(idx, f))
        else:
            lines.append("  (Kritik veya yuksek riskli bulgu yok.)")

        lines.append("")
        lines.append("  --- 2B. ORTA SEVIYE BULGULAR (MANUEL KONTROL GEREKTIRIR) ---")
        if medium:
            for idx, f in enumerate(medium, 1):
                lines.extend(_render_finding_txt(idx, f))
        else:
            lines.append("  (Orta seviye supheli bulgu yok.)")

        lines.append("")
        lines.append("  --- 2C. DUSUK SEVIYE VE BILGILENDIRME KAYITLARI (DESTEKLEYICI IZLER) ---")
        if low_info:
            for idx, f in enumerate(low_info, 1):
                lines.extend(_render_finding_txt(idx, f))
        else:
            lines.append("  (Dusuk seviye veya bilgi kaydi yok.)")

    lines.extend([
        "",
        "=" * 88,
        "3. SISTEM, RING-0 CEKIRDEK, DONANIM VE OYUN ORTAMI OZETI",
        "=" * 88,
    ])
    for grp_title, rows in _build_structured_telemetry_groups(telem):
        lines.append(f"  [{grp_title}]")
        for label, val in rows:
            if isinstance(val, list) and len(val) > 1:
                lines.append(f"    - {label} ({len(val)} kayit):")
                for item in val[:25]:
                    lines.extend(_wrap_indented("        * ", str(item), cont_indent="          "))
                if len(val) > 25:
                    lines.append(f"        ... (+{len(val) - 25} kayit daha — JSON raporunda mevcut)")
            else:
                v_str = val[0] if isinstance(val, list) and len(val) == 1 else _format_compact_value(val, 400)
                lines.extend(_wrap_indented(f"    - {label}: ", str(v_str), cont_indent="        "))
        lines.append("")

    lines.extend([
        "=" * 88,
        "4. TARANAN BOLGELER VE MOTOR KAPSAMI",
        "=" * 88,
    ])
    scanned_regions = telem.get("scanned_regions") or {}
    if isinstance(scanned_regions, dict) and scanned_regions:
        for eng_code in sorted(scanned_regions.keys()):
            dur = timings.get(eng_code)
            dur_lbl = f" ({dur} sn)" if dur is not None else ""
            title = _ENGINE_TITLES.get(eng_code, eng_code)
            lines.append(f"  [{title}]{dur_lbl}")
            for reg in scanned_regions[eng_code]:
                lines.extend(_wrap_indented("    - ", str(reg), cont_indent="      "))
    else:
        lines.append("  (Bolge kaydi bulunamadi; standart 9 motor calistirildi.)")

    if telem.get("engine4_mc_dirs_scanned"):
        lines.append("  [Kesfedilen Minecraft Kok Dizinleri]")
        for mc_d in telem["engine4_mc_dirs_scanned"]:
            lines.append(f"    - {mc_d}")

    if telem.get("engine4_hot_dirs_scanned"):
        lines.append("  [Taranan Sicak Klasorler (Downloads / Desktop / /tmp / /dev/shm)]")
        for hd in telem["engine4_hot_dirs_scanned"]:
            lines.append(f"    - {hd}")

    ram_bytes = telem.get("ram_scanned_bytes") or {}
    if isinstance(ram_bytes, dict) and ram_bytes:
        total_mb = round(sum(int(v) for v in ram_bytes.values()) / (1024 * 1024), 2)
        lines.append(f"  [Canli RAM Bellek Taramasi Kapsami: {len(ram_bytes)} surec, toplam {total_mb} MB]")
        items = sorted(ram_bytes.items(), key=lambda kv: int(kv[1]), reverse=True)
        for rpid, rbytes in items[:25]:
            mb = round(int(rbytes) / (1024 * 1024), 2)
            lines.append(f"    - PID {rpid}: {mb} MB ({rbytes} bayt) tarandi")
        if len(items) > 25:
            lines.append(f"    ... ve {len(items) - 25} ek surec daha tarandi.")

    if payload.get("errors"):
        lines.append("")
        lines.append("-" * 88)
        lines.append("5. TARAMA UYARILARI / HATALARI:")
        for e in payload["errors"]:
            lines.extend(_wrap_indented("  ! ", str(e), cont_indent="    "))

    lines.extend([
        "",
        "=" * 88,
        "                        KISA SONUC OZETI (TARAMA OZETI)",
        "=" * 88,
        f"Genel Karar        : {ass['verdict']} (Seviye: {ass.get('verdict_level', 'N/A')})",
        f"Genel Risk Puani   : {ass['risk_score']} / 100",
        f"Bulgu Dagilimi     : CRITICAL={counts['CRITICAL']} | HIGH={counts['HIGH']} | MEDIUM={counts['MEDIUM']} | LOW={counts['LOW']} | INFO={counts['INFO']} (Toplam: {ass['total_findings']})",
        f"Taranan Kapsam     : {deep_count} derin dosya | {total_procs} surec (Java={len(java_pids)}, MC={len(mc_pids)}) | {len(mc_inst)} MC profili | {total_dur}s",
    ])
    if flagged:
        lines.append("Bayraklanan Baslica Bulgular:")
        for f in flagged[:12]:
            loc = f.get("path") or (f"PID {f['pid']}" if f.get("pid") is not None else "Genel")
            loc_suffix = "" if loc in f["title"] else f" ({loc})"
            lines.append(f"  * [{f['severity']}] {f['rule_id']} — {f['title']}{loc_suffix}")
        if len(flagged) > 12:
            lines.append(f"  ... ve {len(flagged) - 12} adet ek supheli bulgu (yukaridaki Bolum 2'de listelenmistir).")
    else:
        lines.append("Sonuc Yorumu       : TEMIZ — Hile istemcisi, RAM enjeksiyonu, makro veya gizli mod izi tespit edilmedi.")
    if saved_path is not None:
        lines.append(f"Rapor Dosyasi      : {saved_path}")
    lines.append(f"Rapor SHA-256      : {payload['report_sha256']}")
    lines.append("=" * 88)
    return "\n".join(lines) + "\n"


def render_html_report(payload: dict[str, Any]) -> str:
    ass = payload["assessment"]
    counts = ass["counts"]
    score = ass["risk_score"]
    vlevel = ass["verdict_level"]
    badge_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "CLEAN": "#22c55e",
    }.get(vlevel, "#64748b")

    esc = html.escape

    finding_cards: list[str] = []
    for f in payload["findings"]:
        sev = f["severity"]
        ev_items = "".join(f"<li><code>{esc(str(e))}</code></li>" for e in f.get("evidence", []))
        path_html = f"<div><strong>Yol:</strong> <code>{esc(str(f['path']))}</code></div>" if f.get("path") else ""
        pid_html = f"<div><strong>PID:</strong> <code>{esc(str(f['pid']))}</code></div>" if f.get("pid") is not None else ""
        rec_html = (
            f"<div class='rec'><strong>SS Kontrol Onerisi:</strong> {esc(f['recommendation'])}</div>"
            if f.get("recommendation")
            else ""
        )
        finding_cards.append(
            f"""
            <article class="card sev-{esc(sev)}" data-sev="{esc(sev)}" data-engine="{esc(f['engine'])}" data-search="{esc((f['rule_id'] + ' ' + f['title'] + ' ' + f['description'] + ' ' + str(f.get('path') or '') + ' ' + ' '.join(f.get('evidence', []))).lower())}">
              <div class="card-head">
                <span class="pill pill-{esc(sev)}">{esc(sev)}</span>
                <span class="pill pill-conf">{esc(f['confidence'])}</span>
                <span class="rule-id">{esc(f['rule_id'])}</span>
                <span class="eng-tag">{esc(f['engine'])}</span>
              </div>
              <h3>{esc(f['title'])}</h3>
              <p class="desc">{esc(f['description'])}</p>
              <div class="meta-row">
                <div><strong>Kategori:</strong> {esc(f['category'])}</div>
                <div><strong>Etki Skoru:</strong> {esc(str(f['effective_score']))}</div>
                {path_html}
                {pid_html}
              </div>
              {f"<ul class='ev-list'>{ev_items}</ul>" if ev_items else ""}
              {rec_html}
            </article>
            """
        )

    telem_row_list: list[str] = []
    for grp_title, rows in _build_structured_telemetry_groups(payload["telemetry"]):
        telem_row_list.append(
            f"<tr><td colspan='2' style='background:#0f172a;color:#93c5fd;font-weight:700'>{esc(grp_title)}</td></tr>"
        )
        for label, val in rows:
            val_fmt = _format_compact_value(val, 600) if not isinstance(val, str) else val
            telem_row_list.append(f"<tr><td>{esc(label)}</td><td><code>{esc(val_fmt)}</code></td></tr>")
    telem_rows = "".join(telem_row_list)

    err_html = ""
    if payload["errors"]:
        items = "".join(f"<li><code>{esc(e)}</code></li>" for e in payload["errors"])
        err_html = f"<section class='panel'><h2>Tarama Notlari / Hatalar</h2><ul>{items}</ul></section>"

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MC SS Sentinel - Adli Kontrol Raporu</title>
<style>
  :root {{
    --bg: #0b0f17;
    --panel: #121826;
    --card: #161e2e;
    --border: #253047;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --crit: #ef4444;
    --high: #f97316;
    --med: #eab308;
    --low: #38bdf8;
    --info: #64748b;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }}
  .wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px 18px 60px; }}
  .hero {{
    background: linear-gradient(135deg, #111827, #1e293b);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 24px;
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 20px;
    align-items: center;
  }}
  .hero h1 {{ margin: 0 0 6px; font-size: 1.65rem; letter-spacing: 0.3px; }}
  .verdict {{
    display: inline-block;
    padding: 6px 14px;
    border-radius: 8px;
    font-weight: 700;
    background: {badge_color}22;
    color: {badge_color};
    border: 1px solid {badge_color};
    margin-top: 6px;
  }}
  .score-box {{
    text-align: center;
    background: #0b101b;
    border: 2px solid {badge_color};
    border-radius: 12px;
    padding: 14px 22px;
    min-width: 140px;
  }}
  .score-num {{ font-size: 2.5rem; font-weight: 800; color: {badge_color}; line-height: 1.1; }}
  .score-lbl {{ font-size: 0.78rem; color: var(--muted); text-transform: uppercase; }}
  .stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin: 18px 0;
  }}
  .stat {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 14px;
  }}
  .stat .num {{ font-size: 1.5rem; font-weight: 700; }}
  .stat .lbl {{ font-size: 0.8rem; color: var(--muted); }}
  .controls {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 18px 0;
    align-items: center;
  }}
  .btn {{
    background: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 7px 13px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.85rem;
  }}
  .btn.active, .btn:hover {{ border-color: #60a5fa; background: #1e293b; }}
  input.search {{
    flex: 1;
    min-width: 220px;
    background: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 0.9rem;
  }}
  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-left: 5px solid var(--info);
    border-radius: 10px;
    padding: 16px 18px;
    margin-bottom: 12px;
  }}
  .sev-CRITICAL {{ border-left-color: var(--crit); }}
  .sev-HIGH {{ border-left-color: var(--high); }}
  .sev-MEDIUM {{ border-left-color: var(--med); }}
  .sev-LOW {{ border-left-color: var(--low); }}
  .card-head {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 8px; }}
  .pill {{
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 0.74rem;
    font-weight: 700;
  }}
  .pill-CRITICAL {{ background: #ef444433; color: #fca5a5; }}
  .pill-HIGH {{ background: #f9731633; color: #fdba74; }}
  .pill-MEDIUM {{ background: #eab30833; color: #fde047; }}
  .pill-LOW {{ background: #38bdf833; color: #7dd3fc; }}
  .pill-INFO {{ background: #64748b33; color: #cbd5e1; }}
  .pill-conf {{ background: #334155; color: #e2e8f0; }}
  .rule-id {{ font-family: monospace; color: #93c5fd; font-size: 0.85rem; }}
  .eng-tag {{ margin-left: auto; color: var(--muted); font-size: 0.8rem; }}
  .card h3 {{ margin: 4px 0 6px; font-size: 1.08rem; }}
  .desc {{ margin: 0 0 10px; color: #cbd5e1; font-size: 0.93rem; }}
  .meta-row {{ display: flex; flex-wrap: wrap; gap: 14px; font-size: 0.83rem; color: var(--muted); margin-bottom: 8px; }}
  .ev-list {{
    background: #0b101b;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 10px 14px 10px 28px;
    margin: 8px 0 0;
    overflow-x: auto;
  }}
  .ev-list li {{ margin: 4px 0; font-size: 0.84rem; word-break: break-all; }}
  .rec {{
    margin-top: 10px;
    padding: 8px 12px;
    border-radius: 7px;
    background: #172554;
    color: #bfdbfe;
    font-size: 0.85rem;
  }}
  .panel {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px;
    margin-top: 24px;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.84rem; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #1e293b; vertical-align: top; word-break: break-all; }}
  td:first-child {{ width: 240px; color: var(--muted); font-weight: 600; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  .meta-foot {{ margin-top: 10px; font-size: 0.78rem; color: var(--muted); word-break: break-all; }}
</style>
</head>
<body>
<div class="wrap">
  <section class="hero">
    <div>
      <h1>MC SS Sentinel — Derin Linux Adli Kontrol Raporu</h1>
      <div class="verdict">{esc(ass['verdict'])}</div>
      <div class="meta-foot">
        UTC: {esc(payload['generated_utc'])} | Ev Dizini: <code>{esc(payload['target_home'])}</code> |
        OS Profili: <code>{esc(str(payload.get('target_os_name', 'auto')))}</code> |
        Rapor SHA-256: <code>{esc(payload['report_sha256'])}</code>
      </div>
    </div>
    <div class="score-box">
      <div class="score-num">{score}</div>
      <div class="score-lbl">Risk Puani / 100</div>
    </div>
  </section>

  <section class="stats">
    <div class="stat"><div class="num" style="color:var(--crit)">{counts['CRITICAL']}</div><div class="lbl">CRITICAL</div></div>
    <div class="stat"><div class="num" style="color:var(--high)">{counts['HIGH']}</div><div class="lbl">HIGH</div></div>
    <div class="stat"><div class="num" style="color:var(--med)">{counts['MEDIUM']}</div><div class="lbl">MEDIUM</div></div>
    <div class="stat"><div class="num" style="color:var(--low)">{counts['LOW']}</div><div class="lbl">LOW</div></div>
    <div class="stat"><div class="num">{ass['total_findings']}</div><div class="lbl">Toplam Bulgu</div></div>
  </section>

  <section class="controls">
    <button class="btn active" onclick="filterSev('ALL', this)">Tumu</button>
    <button class="btn" onclick="filterSev('CRITICAL', this)">CRITICAL</button>
    <button class="btn" onclick="filterSev('HIGH', this)">HIGH</button>
    <button class="btn" onclick="filterSev('MEDIUM', this)">MEDIUM</button>
    <button class="btn" onclick="filterSev('LOW', this)">LOW</button>
    <button class="btn" onclick="filterSev('INFO', this)">INFO</button>
    <input class="search" type="search" id="searchBox" placeholder="Bulgu, dosya yolu, PID veya kural ara..." oninput="applyFilters()">
  </section>

  <section id="findings">
    {"".join(finding_cards) if finding_cards else "<div class='panel'>Hicbir supheli bulgu tespit edilmedi.</div>"}
  </section>

  <section class="panel">
    <h2>Sistem Telemetrisi</h2>
    <table>{telem_rows}</table>
  </section>
  {err_html}
</div>
<script>
let currentSev = 'ALL';
function filterSev(sev, btn) {{
  currentSev = sev;
  document.querySelectorAll('.controls .btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}}
function applyFilters() {{
  const q = document.getElementById('searchBox').value.trim().toLowerCase();
  document.querySelectorAll('#findings .card').forEach(card => {{
    const s = card.getAttribute('data-sev');
    const txt = card.getAttribute('data-search') || '';
    const okSev = (currentSev === 'ALL' || s === currentSev);
    const okQ = (!q || txt.includes(q));
    card.style.display = (okSev && okQ) ? 'block' : 'none';
  }});
}}
</script>
</body>
</html>
"""


def write_reports(ctx: ScanContext, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = build_report_payload(ctx)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    html_path = out_dir / f"ss_report_{stamp}.html"
    txt_path = out_dir / f"ss_report_{stamp}.txt"
    json_path = out_dir / f"ss_report_{stamp}.json"

    html_path.write_text(render_html_report(payload), encoding="utf-8")
    txt_path.write_text(render_txt_report(payload, saved_path=txt_path), encoding="utf-8")
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    return {"html": html_path, "txt": txt_path, "json": json_path}


def write_desktop_txt_report(
    ctx: ScanContext, desktop_dir: Path | None = None
) -> tuple[Path, dict[str, Any]]:
    """Write comprehensive forensic .txt report directly to the user's Desktop."""
    from .utils import resolve_desktop_dir

    target_desktop = desktop_dir if desktop_dir is not None else resolve_desktop_dir(ctx.home_dir)
    target_desktop.mkdir(parents=True, exist_ok=True)

    payload = build_report_payload(ctx)
    local_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = target_desktop / f"MC_SS_Raporu_{local_stamp}.txt"
    counter = 1
    while txt_path.exists():
        txt_path = target_desktop / f"MC_SS_Raporu_{local_stamp}_{counter}.txt"
        counter += 1

    txt_path.write_text(render_txt_report(payload, saved_path=txt_path), encoding="utf-8")
    return txt_path, payload

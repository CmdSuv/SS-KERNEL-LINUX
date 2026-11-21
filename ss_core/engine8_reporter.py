"""Engine 8: Cross-Engine Correlation, Risk Scoring & Multi-Format Reporting (HTML, TXT, JSON)."""

from __future__ import annotations

import hashlib
import html
import json
import re
import textwrap
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Confidence, Finding, ScanContext, ScanStatus, Severity

ENGINE_NAME = "Engine 8: Korelasyon & Risk Raporlama"

_DOMAINS = (
    "cheat_evidence",
    "forensic_tampering",
    "kernel_integrity",
    "dma_hardware",
    "os_security",
    "scan_coverage",
)

_FORENSIC_TAMPERING_RULES = {
    "E1-HIST-ZERO",
    "E1-HIST-DEVNULL",
    "E1-HIST-ANTIFORENSIC-CMD",
    "E1-HIST-TIMESTOMP",
    "E1-HIST-MISSING",
    "E1-HIST-TRUNCATED",
    "E1-RC-HIST-DISABLE",
    "E1-RC-ANTIFORENSIC-HOOK",
    "E1-REBOOT-RECENT",
    "E1-JOURNAL-CLEARED",
    "E1-TIMESTOMP-ANOMALY",
    "E1-XBEL-DEVNULL",
    "E1-XBEL-WIPED",
    "E1-PKG-LOG-TAMPERED",
    "E4-TIMESTOMP-ANOMALY",
    "E4-TIME-FUTURE",
    "E5-LOG-MISSING-LATEST",
    "E5-LOG-ZEROED",
    "E5-LOG-MISSING-CHEAT-MOD",
    "E5-LOG-MODLIST-MISMATCH",
    "E6-BROWSER-HISTORY-WIPED",
    "E6-BROWSER-SQLITE-FREELIST-CARVE",
    "E6-TRASH-SUSPICIOUS",
    "E6-XBEL-DELETED-ARTIFACT",
    "E8-CORR-WIPE-CHAIN",
}

_SCAN_COVERAGE_RULES = {
    "E2-RAM-ACCESS-DENIED",
    "E9-LKM-UNPRIVILEGED-FALLBACK",
    "E9-LKM-SNAPSHOT-INCOMPLETE",
    "E9-LKM-UNLOAD-INCOMPLETE",
}

_DMA_HARDWARE_RULES = {
    "E9-RAW-MEM-DEV-EXPOSED",
    "E9-HW-USB-MACRO-MCU",
    "E2-FD-RAW-DEV-ACCESS",
    "E8-CORR-DMA-EXPOSURE",
}

_KERNEL_INTEGRITY_RULES = {
    "E9-KERNEL-INLINE-HOOK",
    "E9-KERNEL-TP-UNKNOWN",
    "E9-KERNEL-FOREIGN-KPROBE",
    "E9-KERNEL-FOREIGN-FTRACE",
    "E9-KERNEL-TAINT-FORCED",
    "E9-UNKNOWN-OOT-MODULE",
    "E9-PERSIST-LD-SO-PRELOAD",
    "E9-EVT-RUNTIME-MODULE-LOAD",
    "E9-EVT-LIVE-BPF-LOAD",
    "E9-EVT-RAW-IO-PORT",
    "E8-CORR-RING0-ROOTKIT",
}

_CHEAT_EVIDENCE_EXPLICIT = {
    "E1-HIST-CHEAT-CMD",
    "E1-ENV-LD-PRELOAD",
    "E1-ENV-LD-AUDIT",
    "E1-ETC-LD-PRELOAD",
    "E1-PATH-SHADOW-ELF",
    "E1-PATH-SHADOW-SCRIPT",
    "E2-FD-DELETED-FILE",
    "E2-FD-CHEAT-PATH",
    "E2-FD-UINPUT-ACCESS",
    "E2-PROC-LDPRELOAD",
    "E2-PROC-LDAUDIT",
    "E2-PROC-LDLIBPATH-TMP",
    "E2-PROC-JAVA-ENV-INJECT",
    "E2-PROC-CHEAT-NAME",
    "E2-PROC-MASQUERADE",
    "E2-PROC-MEMFD-EXE",
    "E2-PROC-TMP-EXE",
    "E2-PROC-TRACERPID",
    "E2-HSPERF-SUSPICIOUS",
    "E4-ELF-SUSPICIOUS",
    "E4-FILE-CHEAT-NAME",
    "E4-HIDDEN-MC-ARTIFACT",
    "E4-MC-SUSPICIOUS-SYMLINK",
    "E4-STANDALONE-CLASS-CHEAT",
    "E4-SCRIPT-CHEAT-OR-ANTIFORENSIC",
    "E4-FILE-RESTRICTED-MOD",
    "E4-EXT-SPOOF",
    "E4-POLYGLOT-PAYLOAD",
    "E4-RESOURCEPACK-XRAY",
    "E4-RP-XRAY-TEXTURE",
    "E4-RP-XRAY-EMPTY-MODEL",
    "E4-RP-XRAY-BLOCKSTATE",
    "E4-RP-FULLBRIGHT-LIGHTMAP",
    "E4-SHADER-XRAY",
    "E4-XATTR-CHEAT-URL",
    "E4-PE-CHEAT-OR-INJECTOR",
    "E6-BROWSER-BOOKMARK-CHEAT",
    "E6-BROWSER-CHEAT-URL",
    "E6-BROWSER-CHEAT-DOWNLOAD",
    "E6-CLIPBOARD-HIT",
    "E6-JAVA-USERPREFS-CHEAT",
    "E6-PERSISTENCE-AUTOSTART",
    "E6-XBEL-CHEAT-FILE",
    "E7-CHEAT-PORT-LISTEN",
    "E7-HOSTS-SPOOF",
    "E8-CORR-STEALTH-MACRO",
    "E8-CORR-SPOOFED-ARTIFACT",
    "E8-CORR-GHOST-RAM",
    "E8-CORR-ACQUISITION-CHAIN",
    "E8-CORR-JVM-INJECT-CHAIN",
    "E8-CORR-KERNEL-FILELESS",
    "E9-AUDIT-INJECT-SYSCALL",
    "E9-KERNEL-VMA-REFLECTIVE-ELF",
    "E9-KERNEL-VMA-JNI-AGENT",
    "E9-KERNEL-VMA-PACKED-CODE",
    "E9-KERNEL-VMA-INJECTED-PE",
    "E9-KERNEL-PTRACE-ACTIVE",
    "E9-EVT-VM-WRITEV-INJECT",
    "E9-EVT-PTRACE-INJECT",
    "E9-EVT-MEMFD-EXEC",
    "E9-EVT-EXECVEAT-FILELESS",
    "E9-EVT-LIVE-UINPUT-CREATED",
}


def _classify_domain(f: Finding) -> str:
    rid = f.rule_id
    if rid in _SCAN_COVERAGE_RULES:
        return "scan_coverage"
    if rid in _FORENSIC_TAMPERING_RULES:
        return "forensic_tampering"
    if rid in _DMA_HARDWARE_RULES or rid.startswith("E9-DMA-"):
        return "dma_hardware"
    if (
        rid in _KERNEL_INTEGRITY_RULES
        or rid.startswith(("E9-MSR-", "E9-VFS-", "E9-KNOWN-ROOTKIT-", "E9-HIDDEN-", "E9-ORPHAN-", "E9-EBPF-", "E9-SYSCTL-", "E9-LKM-"))
    ):
        return "kernel_integrity"
    if rid == "E2-PROC-MACRO-BIN":
        if f.metadata.get("remapper_daemon") or f.severity.rank <= Severity.LOW.rank:
            return "os_security"
        return "cheat_evidence"
    if rid == "E2-PROC-DELETED-EXE":
        ev_blob = " ".join(str(x) for x in f.evidence[:2])
        if "exe=/usr/" in ev_blob or "exe=/lib" in ev_blob or "exe=/opt/" in ev_blob:
            return "os_security"
        return "cheat_evidence"
    if rid == "E2-HSPERF-SUSPICIOUS" and f.severity == Severity.INFO:
        return "os_security"
    if (
        rid in _CHEAT_EVIDENCE_EXPLICIT
        or rid.startswith(("E2-RAM-", "E2-MAP-", "E2-JVM-", "E2-JCMD-", "E4-JAR-", "E5-", "E6-WINE-"))
        or (
            rid.startswith("E3-")
            and rid not in ("E3-UINPUT-WRITABLE", "E3-UINPUT-WORLD-WRITABLE", "E3-UINPUT-PERM")
        )
    ):
        return "cheat_evidence"
    return "os_security"


_BDF_RE = re.compile(r"\b[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\b")


def _extract_subject_key(f: Finding) -> str:
    if f.pid is not None:
        return f"pid:{f.pid}"
    if f.path:
        return f"path:{Path(f.path).as_posix()}"
    blob = f"{f.title} {' '.join(str(e) for e in f.evidence[:2])}"
    bdf_m = _BDF_RE.search(blob)
    if bdf_m:
        return f"bdf:{bdf_m.group(0).lower()}"
    return f"rule:{f.rule_id}"


def _norm_path(p: str | None) -> str:
    if not p:
        return ""
    return Path(p).as_posix().rstrip("/")


def _extract_stems(f: Finding) -> set[str]:
    stems: set[str] = set()
    if f.path:
        stems.add(Path(f.path).name.lower())
        stems.add(Path(f.path).stem.lower())
    for ev in f.evidence[:4]:
        for tok in re.findall(r"[a-z0-9_\-\.]{4,}", str(ev).lower()):
            if tok.endswith((".jar", ".so", ".exe", ".dll", ".class", ".sh", ".py")):
                stems.add(tok)
                stems.add(tok.rsplit(".", 1)[0])
    stems.discard("")
    return stems


def _pids_compatible(a: Finding, b: Finding) -> bool:
    if a.pid is not None and b.pid is not None:
        return a.pid == b.pid
    return True


def _paths_compatible(a: Finding, b: Finding) -> bool:
    pa = _norm_path(a.path)
    pb = _norm_path(b.path)
    if pa and pb:
        return pa == pb
    return False


def correlate_findings(ctx: ScanContext) -> None:
    """Synthesize evidence-independent, subject-scoped cross-engine correlations."""
    active = [f for f in ctx.findings if f.severity != Severity.INFO]
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in active:
        by_rule[f.rule_id].append(f)

    def _findings_for(*ids: str, min_rank: int = Severity.LOW.rank) -> list[Finding]:
        out: list[Finding] = []
        for rid in ids:
            for item in by_rule.get(rid, ()):
                if item.severity.rank >= min_rank:
                    out.append(item)
        return out

    # 1. Anti-forensic coverup chain (avoid firing on soft pair alone: REBOOT + MODLIST_MISMATCH)
    wipe_sources = _findings_for(
        "E1-HIST-ZERO",
        "E1-HIST-DEVNULL",
        "E1-HIST-ANTIFORENSIC-CMD",
        "E1-HIST-TIMESTOMP",
        "E1-HIST-TRUNCATED",
        "E1-XBEL-DEVNULL",
        "E1-XBEL-WIPED",
        "E1-PKG-LOG-TAMPERED",
        "E1-RC-HIST-DISABLE",
        "E1-RC-ANTIFORENSIC-HOOK",
        "E1-REBOOT-RECENT",
        "E6-BROWSER-HISTORY-WIPED",
        min_rank=Severity.MEDIUM.rank,
    )
    artifact_wipe = _findings_for(
        "E5-LOG-MISSING-LATEST",
        "E5-LOG-ZEROED",
        "E5-LOG-MISSING-CHEAT-MOD",
        "E5-LOG-MODLIST-MISMATCH",
        "E6-TRASH-SUSPICIOUS",
        "E6-XBEL-DELETED-ARTIFACT",
        "E6-BROWSER-SQLITE-FREELIST-CARVE",
        min_rank=Severity.MEDIUM.rank,
    )
    if wipe_sources and artifact_wipe:
        strong_wipe = [f for f in wipe_sources if f.rule_id != "E1-REBOOT-RECENT"]
        strong_art = [f for f in artifact_wipe if f.rule_id != "E5-LOG-MODLIST-MISMATCH"]
        if strong_wipe and strong_art:
            both_high = (
                any(f.severity.rank >= Severity.HIGH.rank for f in strong_wipe)
                and any(f.severity.rank >= Severity.HIGH.rank for f in strong_art)
            )
            ctx.add_finding(
                Finding(
                    rule_id="E8-CORR-WIPE-CHAIN",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL if both_high else Severity.HIGH,
                    confidence=Confidence.CONFIRMED if both_high else Confidence.HIGH,
                    category="Cross-Engine Correlation",
                    title="Koordineli adli iz temizleme zinciri tespit edildi",
                    description="Birden fazla bagimsiz katmanda (kabuk/tarayici gecmisi ile oyun logu/dosya izleri) es zamanli silme ve manipule etme bulgulari eslesti.",
                    evidence=[
                        f"Sistem/Gecmis sinyalleri: {', '.join(sorted({f.rule_id for f in wipe_sources}))}",
                        f"Dosya/Log/Tarayici sinyalleri: {', '.join(sorted({f.rule_id for f in artifact_wipe}))}",
                    ],
                    recommendation="Oyuncunun kontrol oncesi bilerek iz temizledigi yuksek olasilikla degerlendirildi.",
                )
            )

    # 2. Stealth autoclicker / macro chain
    live_input = _findings_for(
        "E3-VIRTUAL-UINPUT-DEVICE",
        "E3-VIRTUAL-UINPUT-SYSFS",
        "E2-FD-UINPUT-ACCESS",
        "E3-YDOTOOL-SOCKET",
        "E3-SYSTEMD-MACRO-SVC",
        "E9-EVT-LIVE-UINPUT-CREATED",
        min_rank=Severity.MEDIUM.rank,
    )
    cfg_macro = _findings_for(
        "E3-INPUT-REMAPPER-MACRO",
        "E3-SOLAAR-RULE",
        "E3-RAZER-MACRO",
        "E3-HOTKEY-MACRO",
        "E3-MACRO-SCRIPT",
        "E3-XCLICKER-CONFIG",
        min_rank=Severity.MEDIUM.rank,
    )
    if live_input and cfg_macro:
        active_runtime = any(
            f.rule_id in {"E2-FD-UINPUT-ACCESS", "E9-EVT-LIVE-UINPUT-CREATED", "E3-SYSTEMD-MACRO-SVC", "E3-YDOTOOL-SOCKET", "E3-VIRTUAL-UINPUT-DEVICE"}
            and f.severity.rank >= Severity.HIGH.rank
            for f in live_input
        )
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-STEALTH-MACRO",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL if active_runtime else Severity.HIGH,
                confidence=Confidence.CONFIRMED if active_runtime else Confidence.HIGH,
                category="Cross-Engine Correlation",
                title="Aktif Linux/Wayland uinput makro + yapilandirma zinciri",
                description="Hem canli uinput/makro servisi hem de kayitli makro profili/scripti ayni anda tespit edildi.",
                evidence=[
                    f"Canli girdi katmani: {', '.join(sorted({f.rule_id for f in live_input}))}",
                    f"Makro yapilandirmasi: {', '.join(sorted({f.rule_id for f in cfg_macro}))}",
                ],
            )
        )

    # 3. Spoofed mod verification chain (MUST match on the same file path!)
    spoof_base = _findings_for("E4-JAR-SPOOFED-MOD-NAME", "E4-EXT-SPOOF", "E4-POLYGLOT-PAYLOAD", min_rank=Severity.MEDIUM.rank)
    spoof_proof = _findings_for(
        "E4-XATTR-UNVERIFIED-URL",
        "E4-XATTR-CHEAT-URL",
        "E4-TIMESTOMP-ANOMALY",
        "E4-JAR-CLASS-CONSTANT-POOL",
        "E4-JAR-DANGEROUS-API",
        "E4-JAR-CHEAT-METADATA",
        min_rank=Severity.LOW.rank,
    )
    spoof_pairs = [
        (b, p)
        for b in spoof_base
        for p in spoof_proof
        if b.rule_id != p.rule_id and _paths_compatible(b, p)
    ]
    if spoof_pairs:
        semantic_proofs = {"E4-XATTR-CHEAT-URL", "E4-JAR-CLASS-CONSTANT-POOL", "E4-JAR-CHEAT-METADATA"}
        strong_pair = any(p.rule_id in semantic_proofs for _, p in spoof_pairs)
        matched_paths = sorted({_norm_path(b.path) for b, _ in spoof_pairs if b.path})
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-SPOOFED-ARTIFACT",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL if strong_pair else Severity.HIGH,
                confidence=Confidence.CONFIRMED if strong_pair else Confidence.HIGH,
                category="Cross-Engine Correlation",
                title="Sahte isim / uzanti gizleme + ayni dosyada bit duzeyi icerik dogrulamasi",
                description="Ayni dosya yolu uzerinde mesru gorunumlu dosya adinin arkasinda bytecode/xattr/timestomp ile dogrulanmis gizli yuk bulundu.",
                path=matched_paths[0] if len(matched_paths) == 1 else None,
                evidence=[
                    f"Gizleme: {', '.join(sorted({b.rule_id for b, _ in spoof_pairs}))}",
                    f"Dogrulama: {', '.join(sorted({p.rule_id for _, p in spoof_pairs}))}",
                    *[f"Eslenen Dosya: {mp}" for mp in matched_paths[:5]],
                ],
            )
        )

    # 4. RAM-only Ghost Client chain
    ram_ghost = _findings_for("E2-MAP-DELETED-BIN", "E2-FD-DELETED-FILE", "E2-RAM-STRICT-SIG", "E2-RAM-MODULE-CLUSTER", min_rank=Severity.HIGH.rank)
    disk_gone = _findings_for("E6-TRASH-SUSPICIOUS", "E6-XBEL-DELETED-ARTIFACT", "E5-LOG-MISSING-CHEAT-MOD", min_rank=Severity.HIGH.rank)
    if ram_ghost and disk_gone:
        ram_stems = set().union(*(_extract_stems(f) for f in ram_ghost))
        disk_stems = set().union(*(_extract_stems(f) for f in disk_gone))
        has_sig_and_cheat_wipe = (
            any(f.rule_id in {"E2-RAM-STRICT-SIG", "E2-RAM-MODULE-CLUSTER"} for f in ram_ghost)
            and any(f.rule_id in {"E5-LOG-MISSING-CHEAT-MOD", "E6-TRASH-SUSPICIOUS"} for f in disk_gone)
        )
        shared_stem = bool(ram_stems & disk_stems)
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-GHOST-RAM",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED if (shared_stem or has_sig_and_cheat_wipe) else Confidence.HIGH,
                category="Cross-Engine Correlation",
                title="Diskten silinip RAM'de yasamaya devam eden Ghost Client zinciri",
                description="Hile dosyasi diskten kaldirilmis/cop kutusuna atilmis ancak bellek ve acik fd/log katmanlarinda yakalandi.",
                evidence=[
                    f"RAM/FD katmani: {', '.join(sorted({f.rule_id for f in ram_ghost}))}",
                    f"Disk silme katmani: {', '.join(sorted({f.rule_id for f in disk_gone}))}",
                ],
            )
        )

    # 5. Acquisition -> Execution/Deletion chain
    browser_hit = _findings_for("E6-BROWSER-CHEAT-URL", "E6-BROWSER-CHEAT-DOWNLOAD", "E6-BROWSER-SQLITE-FREELIST-CARVE", min_rank=Severity.MEDIUM.rank)
    local_hit = _findings_for("E4-XATTR-CHEAT-URL", "E6-TRASH-SUSPICIOUS", "E6-XBEL-DELETED-ARTIFACT", "E1-HIST-CHEAT-CMD", min_rank=Severity.MEDIUM.rank)
    if browser_hit and local_hit:
        b_stems = set().union(*(_extract_stems(f) for f in browser_hit))
        l_stems = set().union(*(_extract_stems(f) for f in local_hit))
        both_strong = any(f.severity.rank >= Severity.HIGH.rank for f in browser_hit) and any(
            f.severity.rank >= Severity.HIGH.rank for f in local_hit
        )
        confirmed_acq = bool(b_stems & l_stems) or (
            any(f.rule_id == "E6-BROWSER-CHEAT-DOWNLOAD" for f in browser_hit)
            and any(f.rule_id in {"E4-XATTR-CHEAT-URL", "E6-TRASH-SUSPICIOUS", "E1-HIST-CHEAT-CMD"} for f in local_hit)
        )
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-ACQUISITION-CHAIN",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL if both_strong else Severity.HIGH,
                confidence=Confidence.CONFIRMED if confirmed_acq else Confidence.HIGH,
                category="Cross-Engine Correlation",
                title="Tarayici indirme + yerel kullanim/silme zinciri dogrulandi",
                description="Web gecmisi/indirme kaydi ile yerel dosya/xattr/terminal izleri birbirini dogruladi.",
                evidence=[
                    f"Tarayici: {', '.join(sorted({f.rule_id for f in browser_hit}))}",
                    f"Yerel iz: {', '.join(sorted({f.rule_id for f in local_hit}))}",
                ],
            )
        )

    # 6. JVM / Linker Injection -> Bytecode/RAM Payload chain (PID-scoped when both have PID)
    inj_vectors = _findings_for(
        "E2-JVM-AGENT-ARG",
        "E2-PROC-JAVA-ENV-INJECT",
        "E2-JVM-BOOTCLASSPATH",
        "E2-PROC-LDPRELOAD",
        "E2-PROC-LDAUDIT",
        "E2-JVM-DISABLE-ATTACH",
        "E2-JVM-PERF-DISABLE",
        "E2-JCMD-FLAGS",
        "E2-JCMD-ATTACH-LOADED",
        "E1-ENV-LD-PRELOAD",
        "E1-ENV-LD-AUDIT",
        "E1-ETC-LD-PRELOAD",
        "E1-RC-LDPRELOAD",
        "E1-RC-LDAUDIT",
        "E1-RC-JAVA-TOOL-OPTS",
        "E4-JAR-AGENT-MANIFEST",
        "E5-LAUNCHER-JVM-AGENT",
        "E5-INSTANCE-JVM-AGENT",
        min_rank=Severity.MEDIUM.rank,
    )
    payload_proofs = _findings_for(
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
        min_rank=Severity.MEDIUM.rank,
    )
    def _artifact_scope_compatible(a: Finding, b: Finding) -> bool:
        if not _pids_compatible(a, b):
            return False
        if b.rule_id.startswith("E2-MAP-") and a.pid is None:
            if not (_extract_stems(a) & _extract_stems(b)):
                return False
        pa = _norm_path(a.path)
        pb = _norm_path(b.path)
        if pa and pb and pa != pb:
            art_exts = {".jar", ".so", ".dll", ".class", ".exe", ".elf"}
            ext_a = Path(pa).suffix.lower()
            ext_b = Path(pb).suffix.lower()
            if (ext_a in art_exts and ext_b in art_exts) or (a.pid is not None and b.rule_id == "E4-ELF-SUSPICIOUS"):
                stems_a = _extract_stems(a)
                stems_b = _extract_stems(b)
                ev_a = " ".join(str(e).lower() for e in a.evidence)
                ev_b = " ".join(str(e).lower() for e in b.evidence)
                name_a = Path(pa).name.lower()
                name_b = Path(pb).name.lower()
                if not (stems_a & stems_b) and name_b not in ev_a and name_a not in ev_b:
                    return False
        return True

    jvm_pairs = [
        (iv, pp)
        for iv in inj_vectors
        for pp in payload_proofs
        if iv.rule_id != pp.rule_id and _artifact_scope_compatible(iv, pp)
    ]
    if jvm_pairs:
        high_conf_pair = any(
            iv.severity.rank >= Severity.HIGH.rank and pp.severity.rank >= Severity.HIGH.rank
            for iv, pp in jvm_pairs
        )
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-JVM-INJECT-CHAIN",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL if high_conf_pair else Severity.HIGH,
                confidence=Confidence.CONFIRMED if high_conf_pair else Confidence.HIGH,
                category="Cross-Engine Correlation",
                title="JVM / Linker enjeksiyonu + zararli bytecode/RAM yuk zinciri",
                description="Enjeksiyon vektoru (agent/LD_PRELOAD/LD_AUDIT/attach engeli) ile zararli kod kaniti ayni oturum/surecte eslesti.",
                evidence=[
                    f"Enjeksiyon: {', '.join(sorted({iv.rule_id for iv, _ in jvm_pairs}))}",
                    f"Payload: {', '.join(sorted({pp.rule_id for _, pp in jvm_pairs}))}",
                ],
            )
        )

    # 7. Ring-0 Rootkit / Hidden Kernel / Inline Hook correlation (independent mechanism groups!)
    ring0_groups: dict[str, tuple[str, ...]] = {
        "khook_inline": ("E9-KERNEL-INLINE-HOOK", "E9-LKM-WRITABLE-KTEXT"),
        "msr_lstar": ("E9-MSR-LSTAR-HOOK",),
        "vfs_hook": ("E9-VFS-HOOK-HIJACK",),
        "hidden_lkm": ("E9-HIDDEN-LKM-CROSSVIEW", "E9-HIDDEN-LKM-SYSFS-DIFF"),
        "orphan_mem": ("E9-ORPHAN-KERNEL-ELF", "E9-ORPHAN-RWX-KERNEL-MEM"),
        "hidden_pid": ("E9-HIDDEN-PID-RING0", "E9-HIDDEN-PID-READDIR"),
        "known_rk_lkm": ("E9-KNOWN-ROOTKIT-LKM",),
        "sysctl_modprobe": ("E9-SYSCTL-MODPROBE-HIJACK",),
        "foreign_probe": ("E9-KERNEL-FOREIGN-KPROBE", "E9-KERNEL-FOREIGN-FTRACE"),
        "ebpf_rk": ("E9-EBPF-SUSPICIOUS-PROG", "E9-EBPF-PINNED-OBJ", "E9-EVT-LIVE-BPF-LOAD"),
        "raw_io": ("E9-EVT-RAW-IO-PORT",),
    }
    matched_rk_groups: dict[str, list[Finding]] = {}
    for gname, g_rules in ring0_groups.items():
        hits = _findings_for(*g_rules, min_rank=Severity.HIGH.rank)
        if hits:
            matched_rk_groups[gname] = hits
    if len(matched_rk_groups) >= 2:
        matched_rids = sorted({f.rule_id for fl in matched_rk_groups.values() for f in fl})
        confirmed_grps = sum(
            1 for fl in matched_rk_groups.values() if any(f.confidence == Confidence.CONFIRMED for f in fl)
        )
        is_conf = len(matched_rk_groups) >= 3 or confirmed_grps >= 2
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-RING0-ROOTKIT",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED if is_conf else Confidence.HIGH,
                category="Cross-Engine Correlation",
                title="Coklu bagimsiz Ring-0 Kernel Rootkit / Kanca kaniti tespit edildi!",
                description=(
                    f"Cekirdek seviyesinde {len(matched_rk_groups)} farkli mekanizma grubunda "
                    "bagimsiz gizleme/kanca bulgulari eslesti."
                ),
                evidence=[
                    f"Bagimsiz Gruplar ({len(matched_rk_groups)}): {', '.join(sorted(matched_rk_groups.keys()))}",
                    f"Ring-0 Bulgular: {', '.join(matched_rids)}",
                ],
            )
        )

    # 8. Unprotected IOMMU + DMA Hardware/VFIO Exposure chain (DMA domain, NOT cheat!)
    iommu_weak = _findings_for(
        "E9-DMA-IOMMU-DISABLED",
        "E9-DMA-IOMMU-FORCED-OFF",
        "E9-DMA-IOMMU-PASSTHROUGH",
        "E9-DMA-ACS-OVERRIDE",
        min_rank=Severity.HIGH.rank,
    )
    dma_dev = _findings_for(
        "E9-DMA-FPGA-HARDWARE",
        "E9-DMA-VFIO-UIO-DEVICE",
        "E9-DMA-UNBOUND-BUSMASTER",
        "E9-DMA-SPOOFED-PCIE-FW",
        "E9-DMA-THUNDERBOLT-EXPOSED",
        "E9-DMA-VFIO-ACTIVE-NODE",
        "E9-DMA-UIO-DEVICE-NODE",
        "E9-RAW-MEM-DEV-EXPOSED",
        "E2-FD-RAW-DEV-ACCESS",
        min_rank=Severity.MEDIUM.rank,
    )
    if iommu_weak and dma_dev:
        hard_iommu_off = any(f.rule_id in {"E9-DMA-IOMMU-DISABLED", "E9-DMA-IOMMU-FORCED-OFF"} for f in iommu_weak)
        hard_dma_risk = any(
            f.rule_id in {"E9-DMA-FPGA-HARDWARE", "E9-DMA-UNBOUND-BUSMASTER", "E9-DMA-SPOOFED-PCIE-FW", "E9-DMA-THUNDERBOLT-EXPOSED", "E9-RAW-MEM-DEV-EXPOSED"}
            and f.severity == Severity.CRITICAL
            for f in dma_dev
        )
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-DMA-EXPOSURE",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL if (hard_iommu_off or hard_dma_risk) else Severity.HIGH,
                confidence=Confidence.CONFIRMED if (hard_iommu_off and hard_dma_risk) else Confidence.HIGH,
                category="DMA & Hardware Security Correlation",
                title="Korunmasiz IOMMU + aktif DMA/FPGA/VFIO donanim maruziyeti",
                description="IOMMU izolasyonu devredisi/zayifken donanim duzeyinde DMA yapabilen aygit/dugum tespit edildi (tek basina oyun hilesi kaniti degildir).",
                evidence=[
                    f"IOMMU: {', '.join(sorted({f.rule_id for f in iommu_weak}))}",
                    f"DMA Aygit: {', '.join(sorted({f.rule_id for f in dma_dev}))}",
                ],
            )
        )

    # 9. Ring-0 Fileless / Syscall Memory Injection chain (PID-scoped, NO E2-MAP-TEXT-COW-PATCH self-correlation!)
    k_ram = _findings_for(
        "E9-KERNEL-VMA-REFLECTIVE-ELF",
        "E9-KERNEL-VMA-JNI-AGENT",
        "E9-KERNEL-VMA-PACKED-CODE",
        "E9-KERNEL-VMA-INJECTED-PE",
        "E2-MAP-TEXT-COW-PATCH",
        min_rank=Severity.HIGH.rank,
    )
    k_evt = _findings_for(
        "E9-EVT-VM-WRITEV-INJECT",
        "E9-EVT-PTRACE-INJECT",
        "E9-EVT-MEMFD-EXEC",
        "E9-EVT-EXECVEAT-FILELESS",
        "E2-MAP-EXEC-MEMFD",
        "E2-MAP-DELETED-BIN",
        min_rank=Severity.MEDIUM.rank,
    )
    fileless_evt_pairs = [
        (kr, ke)
        for kr in k_ram
        for ke in k_evt
        if kr.rule_id != ke.rule_id and _pids_compatible(kr, ke)
    ]
    fileless_disk_pairs = [
        (kr, pp)
        for kr in k_ram
        for pp in payload_proofs
        if kr.rule_id.startswith("E9-KERNEL-VMA-")
        and kr.rule_id != pp.rule_id
        and _pids_compatible(kr, pp)
        and (
            (kr.pid is not None and pp.pid is not None and kr.pid == pp.pid)
            or bool(_extract_stems(kr) & _extract_stems(pp))
        )
    ]
    if fileless_evt_pairs or fileless_disk_pairs:
        matched_pairs = fileless_evt_pairs or fileless_disk_pairs
        runtime_confirmed = any(
            kr.severity.rank >= Severity.HIGH.rank
            and ke.severity.rank >= Severity.HIGH.rank
            and (kr.pid is None or ke.pid is None or kr.pid == ke.pid)
            for kr, ke in fileless_evt_pairs
        )
        ctx.add_finding(
            Finding(
                rule_id="E8-CORR-KERNEL-FILELESS",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL if fileless_evt_pairs else Severity.HIGH,
                confidence=Confidence.CONFIRMED if runtime_confirmed else Confidence.HIGH,
                category="Cross-Engine Correlation",
                title="Ring-0 VMA bayt enjeksiyonu + dosyasiz bellek yurutmeleri eslesti",
                description="Cekirdek VMA taramasi ile ayni surecte memfd/ptrace/RAM sinyalleri birbirini dogruladi.",
                pid=next((kr.pid for kr, _ in matched_pairs if kr.pid is not None), None),
                evidence=[
                    f"VMA Bayt: {', '.join(sorted({kr.rule_id for kr, _ in matched_pairs}))}",
                    f"Olay/RAM: {', '.join(sorted({ke.rule_id for _, ke in matched_pairs}))}",
                ],
            )
        )

    ctx.set_coverage("E8.correlation", ScanStatus.COMPLETED, f"9 correlation rules evaluated over {len(active)} active findings")


def _compute_scan_quality(
    coverage: dict[str, Any] | None,
    errors: list[str] | None,
    engine_status: dict[str, Any] | None,
) -> tuple[int, bool, list[str]]:
    gaps: list[str] = []
    penalty = 0
    fatal_error = False

    if errors:
        fatal_error = True
        for err in errors[:10]:
            gaps.append(f"Hata: {err}")
        penalty += min(40, len(errors) * 15)

    if isinstance(engine_status, dict):
        for ecode, info in sorted(engine_status.items()):
            if not isinstance(info, dict):
                continue
            st = str(info.get("status", "")).upper()
            det = str(info.get("detail", ""))
            if st in ("ERROR", "CANCELLED", "TIMED_OUT"):
                fatal_error = True
                gaps.append(f"Motor {ecode} {st}: {det}")
                penalty += 20
            elif st == "PARTIAL":
                gaps.append(f"Motor {ecode} PARTIAL: {det}")
                penalty += 8
            elif st == "SKIPPED":
                gaps.append(f"Motor {ecode} SKIPPED: {det}")
                penalty += 5

    if isinstance(coverage, dict):
        for comp, info in sorted(coverage.items()):
            if not isinstance(info, dict):
                continue
            st = str(info.get("status", "")).upper()
            det = str(info.get("detail", ""))
            # Optional unprivileged fallback for E9.lkm when --kernel-lkm not active is normal
            if comp == "E9.lkm" and st == "SKIPPED":
                continue
            if st == "ERROR":
                penalty += 12
                gaps.append(f"{comp}: ERROR ({det})")
            elif st == "PERMISSION_DENIED":
                # Unprivileged host eBPF EPERM is informational; denied target /proc/<pid>/mem is a critical gap
                if comp == "E2.proc_mem":
                    penalty += 20
                else:
                    penalty += 5
                gaps.append(f"{comp}: PERMISSION_DENIED ({det})")
            elif st in ("PARTIAL", "TIMED_OUT", "CANCELLED"):
                penalty += 8
                gaps.append(f"{comp}: {st} ({det})")
            elif st == "UNSUPPORTED":
                penalty += 6
                gaps.append(f"{comp}: UNSUPPORTED ({det})")
            elif st == "SKIPPED":
                penalty += 10 if comp == "E2.proc_mem" else 4
                gaps.append(f"{comp}: SKIPPED ({det})")

    quality = max(0, min(100, 100 - penalty))
    return quality, fatal_error, gaps


def compute_risk_assessment(
    findings: list[Finding],
    coverage: dict[str, Any] | None = None,
    errors: list[str] | None = None,
    engine_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    counts = {s.value: 0 for s in Severity}
    domain_counts: dict[str, int] = {d: 0 for d in _DOMAINS}
    by_rule: dict[str, list[Finding]] = defaultdict(list)

    for f in findings:
        counts[f.severity.value] += 1
        dom = _classify_domain(f)
        domain_counts[dom] = domain_counts.get(dom, 0) + 1
        by_rule[f.rule_id].append(f)

    # Pass 1: within-rule decay
    rule_contributions: list[tuple[Finding, str, str, float, float, float]] = []
    rule_decay = (1.0, 0.45, 0.25, 0.15)
    for rid, group in sorted(by_rule.items()):
        group_sorted = sorted(group, key=lambda x: x.effective_score, reverse=True)
        for idx, item in enumerate(group_sorted):
            dom = _classify_domain(item)
            subj = _extract_subject_key(item)
            mult1 = rule_decay[idx] if idx < len(rule_decay) else 0.08
            rule_contributions.append((item, dom, subj, item.effective_score, mult1, item.effective_score * mult1))

    # Pass 2: subject-level decay across distinct rules targeting same (domain, subject)
    subj_groups: dict[tuple[str, str], list[tuple[Finding, str, str, float, float, float]]] = defaultdict(list)
    for entry in rule_contributions:
        item, dom, subj, *_ = entry
        if item.rule_id.startswith("E8-CORR-"):
            subj_groups[(dom, f"corr:{item.rule_id}")].append(entry)
        else:
            subj_groups[(dom, subj)].append(entry)

    subj_decay = (1.0, 0.60, 0.35, 0.20)
    domain_raw: dict[str, float] = {d: 0.0 for d in _DOMAINS if d != "scan_coverage"}
    breakdown: list[dict[str, Any]] = []

    for (_dom, _subj), entries in sorted(subj_groups.items()):
        entries_sorted = sorted(entries, key=lambda t: t[5], reverse=True)
        for s_idx, (item, dom, subj, raw_eff, mult1, after_r) in enumerate(entries_sorted):
            mult2 = 1.0 if item.rule_id.startswith("E8-CORR-") else (subj_decay[s_idx] if s_idx < len(subj_decay) else 0.15)
            contrib = round(after_r * mult2, 2)
            if dom in domain_raw:
                domain_raw[dom] += contrib
            if contrib > 0:
                breakdown.append({
                    "rule_id": item.rule_id,
                    "domain": dom,
                    "subject": subj,
                    "raw_score": round(raw_eff, 2),
                    "multiplier": round(mult1 * mult2, 3),
                    "contributed": contrib,
                })

    breakdown.sort(key=lambda b: (-float(b["contributed"]), str(b["rule_id"])))

    # Compute domain scores with severity/confidence integrity floors scoped by domain
    domain_findings: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        domain_findings[_classify_domain(f)].append(f)

    domain_scores: dict[str, int] = {}
    for dom in ("cheat_evidence", "forensic_tampering", "kernel_integrity", "dma_hardware", "os_security"):
        d_val = domain_raw[dom]
        d_items = domain_findings.get(dom, [])
        has_cc = any(f.severity == Severity.CRITICAL and f.confidence == Confidence.CONFIRMED for f in d_items)
        has_c = any(f.severity == Severity.CRITICAL for f in d_items)
        has_hc = any(f.severity == Severity.HIGH and f.confidence == Confidence.CONFIRMED for f in d_items)
        if has_cc:
            d_val = max(d_val, 68.0)
        elif has_c:
            d_val = max(d_val, 52.0)
        elif has_hc:
            d_val = max(d_val, 30.0)
        domain_scores[dom] = min(100, int(round(d_val)))

    scan_quality, fatal_error, coverage_gaps = _compute_scan_quality(coverage, errors, engine_status)
    domain_scores["scan_coverage"] = scan_quality
    incomplete_scan = fatal_error or scan_quality < 75

    # Overall weighted score separating cheat/tampering/kernel from passive OS/DMA posture
    cheat_s = domain_scores["cheat_evidence"]
    forensic_s = domain_scores["forensic_tampering"]
    kernel_s = domain_scores["kernel_integrity"]
    dma_s = domain_scores["dma_hardware"]
    os_s = domain_scores["os_security"]

    core_raw = domain_raw["cheat_evidence"] + domain_raw["forensic_tampering"] + domain_raw["kernel_integrity"]
    passive_cap = min(35.0, domain_raw["os_security"] * 0.7) + min(55.0, domain_raw["dma_hardware"] * 0.65)
    overall_raw = core_raw + (passive_cap * 0.65 if core_raw < 10.0 else passive_cap * 0.45)

    # Apply cheat/tampering/kernel floors so confirmed cheat/wipe/rootkit hits stay CRITICAL/HIGH
    core_findings = domain_findings["cheat_evidence"] + domain_findings["forensic_tampering"] + domain_findings["kernel_integrity"]
    has_core_cc = any(f.severity == Severity.CRITICAL and f.confidence == Confidence.CONFIRMED for f in core_findings)
    has_core_c = any(f.severity == Severity.CRITICAL for f in core_findings)
    has_core_hc = any(f.severity == Severity.HIGH and f.confidence == Confidence.CONFIRMED for f in core_findings)

    raw_score = min(100, int(round(overall_raw)))
    score = raw_score
    if has_core_cc:
        score = max(score, 68)
    elif has_core_c:
        score = max(score, 52)
    elif has_core_hc:
        score = max(score, 30)
    floor_uplift = max(0, score - raw_score)

    # Cheat-specific verdict level (pure OS/DMA issues NEVER yield confirmed cheat!)
    cheat_comb = max(cheat_s, int(round(cheat_s * 0.8 + forensic_s * 0.55)))
    if cheat_s >= 65 or (cheat_s >= 35 and forensic_s >= 45):
        cheat_verdict_level = "CRITICAL"
    elif cheat_s >= 35 or forensic_s >= 65 or cheat_comb >= 35:
        cheat_verdict_level = "HIGH"
    elif cheat_s >= 15 or forensic_s >= 15:
        cheat_verdict_level = "MEDIUM"
    else:
        cheat_verdict_level = "CLEAN"

    nonzero_domains = [
        (d, domain_scores[d])
        for d in ("cheat_evidence", "forensic_tampering", "kernel_integrity", "dma_hardware", "os_security")
        if domain_scores[d] > 0
    ]
    primary_domain = max(nonzero_domains, key=lambda kv: kv[1])[0] if nonzero_domains else "none"

    # Overall verdict & verdict_level cleanly distinguished by root cause + scan quality
    if cheat_verdict_level == "CRITICAL":
        verdict = "KRITIK - DOGRULANMIS HILE / ENJEKSIYON / ADLI MANIPULASYON"
        verdict_level = "CRITICAL"
    elif forensic_s >= 65:
        verdict = "KRITIK - KOORDINELI ADLI IZ MANIPULASYONU / SILME ZINCIRI"
        verdict_level = "CRITICAL"
    elif kernel_s >= 65:
        verdict = "KRITIK - CEKIRDEK BUTUNLUGU IHLALI / ROOTKIT SUPHESI"
        verdict_level = "CRITICAL"
    elif score >= 35 or dma_s >= 50:
        verdict_level = "HIGH"
        if cheat_verdict_level in ("CRITICAL", "HIGH"):
            verdict = "YUKSEK RISK - OLASI HILE VEYA IZ TEMIZLEME"
        elif kernel_s >= max(dma_s, os_s):
            verdict = "YUKSEK CEKIRDEK GUVENLIK RISKI - DOGRUDAN HILE KANITI YOK"
        elif dma_s >= os_s:
            verdict = "YUKSEK DONANIM / DMA MARUZIYETI - DOGRUDAN HILE KANITI YOK"
        else:
            verdict = "YUKSEK ISLETIM SISTEMI GUVENLIK RISKI - DOGRUDAN HILE KANITI YOK"
    elif score >= 15:
        verdict = "SUPHELI - MANUEL INCELEME GEREKLI"
        verdict_level = "MEDIUM"
    elif incomplete_scan:
        verdict = "TARAMA EKSIK / HATALI — TEMIZ KABUL EDILEMEZ"
        verdict_level = "INCOMPLETE"
    else:
        verdict = "TEMIZ / DUSUK RISK"
        verdict_level = "CLEAN"

    return {
        "risk_score": score,
        "raw_risk_score": raw_score,
        "floor_uplift": floor_uplift,
        "verdict": verdict,
        "verdict_level": verdict_level,
        "cheat_verdict_level": cheat_verdict_level,
        "primary_risk_domain": primary_domain,
        "domain_scores": domain_scores,
        "domain_counts": domain_counts,
        "scan_quality": scan_quality,
        "incomplete_scan": incomplete_scan,
        "coverage_gaps": coverage_gaps,
        "score_breakdown": breakdown,
        "counts": counts,
        "total_findings": len(findings),
    }


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            -f.severity.rank,
            -f.effective_score,
            f.rule_id,
            str(f.path or ""),
            f.pid if f.pid is not None else -1,
            f.title,
        ),
    )


def build_report_payload(ctx: ScanContext) -> dict[str, Any]:
    ordered = _sorted_findings(ctx.findings)
    assessment = compute_risk_assessment(
        ordered,
        coverage=getattr(ctx, "coverage", None),
        errors=getattr(ctx, "errors", None),
        engine_status=getattr(ctx, "engine_status", None),
    )
    serialized_findings: list[dict[str, Any]] = []
    for f in ordered:
        d = f.to_dict()
        d["domain"] = _classify_domain(f)
        serialized_findings.append(d)

    payload_core = {
        "schema_version": "2.1",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generated_local": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "target_home": str(ctx.home_dir),
        "target_os": ctx.telemetry.get("target_os") or getattr(ctx, "target_os", "auto"),
        "target_os_name": ctx.telemetry.get("target_os_name") or getattr(ctx, "target_os", "auto"),
        "host_os_name": ctx.telemetry.get("host_pretty_name") or "",
        "live_mode": ctx.live_mode,
        "memory_scan_enabled": ctx.enable_memory_scan,
        "time_window_hours": ctx.time_window_hours,
        "assessment": assessment,
        "engine_status": getattr(ctx, "engine_status", {}),
        "coverage": getattr(ctx, "coverage", {}),
        "telemetry": ctx.telemetry,
        "findings": serialized_findings,
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
        hidden_list = pid_cross.get("hidden_candidates") or pid_cross.get("hidden_pids") or []
        r0_rows.append((
            "PID Cross-View (readdir vs getdents64)",
            f"readdir={pid_cross.get('readdir_count', '?')} | "
            f"raw_getdents={pid_cross.get('raw_getdents_count', '?')} | "
            f"gizli={len(hidden_list)} | "
            f"hidepid={pid_cross.get('hidepid_detected', 0)}",
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
    dom = f.get("domain", "")
    dom_part = f" | Alan: {dom}" if dom else ""
    lines: list[str] = [
        "",
        f"  [{idx}] [{sev_lbl} | {conf}] {f.get('title', '')}",
        f"      Kural / Motor : {f.get('rule_id', '')} | {f.get('engine', '')}{dom_part} | Etki Skoru: {f.get('effective_score', 0)}",
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
    cheat_lvl = ass.get("cheat_verdict_level", lvl)
    counts = ass.get("counts", {})
    if lvl == "INCOMPLETE":
        return (
            "EKSIK TARAMA: Bazi motorlar veya kritik sistem alanlari hata/yetki nedeniyle taranamadi. "
            "Hata ve kapsam tablosunu incelemeden temiz karar vermeyin."
        )
    if lvl == "CRITICAL":
        if cheat_lvl in ("CRITICAL", "HIGH"):
            return (
                f"DIKKAT: {counts.get('CRITICAL', 0)} adet KRITIK hile/enjeksiyon veya adli iz temizleme kaniti "
                "dogrulandi. Oncelikle Bolum 1 ve 2A'daki dosya yollarini ve kanitlari inceleyin."
            )
        return (
            "DIKKAT: Dogrudan hile istemcisinden ziyade cekirdek butunlugu / rootkit veya kritik "
            "donanim guvenlik riski tespit edildi. Bolum 2A'daki kanitlari inceleyin."
        )
    if lvl == "HIGH":
        if cheat_lvl in ("CRITICAL", "HIGH"):
            return (
                "UYARI: Yuksek riskli hile, makro veya gizleme izi bulundu. Kesin karar oncesi "
                "Bolum 1 ve 2A'da listelenen kanitlari kontrol edin."
            )
        return (
            "UYARI: Yuksek seviyede sistem/DMA/IOMMU guvenlik maruziyeti saptandi ancak dogrulanmis "
            "Minecraft hile kaniti bulunamadi. Alan skorlarini ve Bolum 2A'yi kontrol edin."
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
    local_now = payload.get("generated_local") or datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    deep_count = telem.get("engine4_files_deep_scanned", 0)
    total_procs = telem.get("total_processes", 0)
    java_pids = telem.get("java_pids", []) or []
    mc_pids = telem.get("minecraft_pids", []) or []
    mc_inst = telem.get("minecraft_instances", []) or []
    lkm_act = telem.get("kernel_lkm_active", False)
    iommu_info = telem.get("iommu_compliance") or {}
    iommu_lbl = "Aktif" if isinstance(iommu_info, dict) and iommu_info.get("iommu_active") else "Kapali/Belirsiz"
    dscores = ass.get("domain_scores") or {}

    lines: list[str] = [
        "=" * 88,
        "          MC SS SENTINEL — ANLASILIR ADLI HILE KONTROL (SS) RAPORU",
        "=" * 88,
        f"KARAR (VERDICT)      : {ass['verdict']}",
        f"RISK PUANI           : {ass['risk_score']} / 100  (Hile Seviyesi: {ass.get('cheat_verdict_level', ass.get('verdict_level', 'N/A'))} | Birincil Alan: {ass.get('primary_risk_domain', 'none')})",
        f"ALAN PUANLARI (0-100): Hile={dscores.get('cheat_evidence', 0)} | Manipulasyon={dscores.get('forensic_tampering', 0)} | Cekirdek={dscores.get('kernel_integrity', 0)} | DMA={dscores.get('dma_hardware', 0)} | Sistem={dscores.get('os_security', 0)} | Kapsam={ass.get('scan_quality', 100)}/100",
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

    breakdown = ass.get("score_breakdown") or []
    if breakdown:
        lines.extend([
            "",
            "=" * 88,
            "1B. RISK PUANLAMA ACIKLAMASI (HANGI BULGU KAC PUAN EKLEDI)",
            "=" * 88,
        ])
        for br in breakdown[:25]:
            lines.append(
                f"  - {br.get('rule_id', '')} [{br.get('domain', '')}] ({br.get('subject', '')}): "
                f"{br.get('raw_score', 0)} x {br.get('multiplier', 1.0)} = +{br.get('contributed', 0)}"
            )

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
    engine_status = payload.get("engine_status") or {}
    if isinstance(engine_status, dict) and engine_status:
        lines.append("  [Motor Calisma Durumlari]")
        for ecode in sorted(engine_status.keys()):
            einfo = engine_status[ecode]
            if isinstance(einfo, dict):
                lines.append(f"    - {ecode}: {einfo.get('status', '?')} ({einfo.get('detail', '')})")
    cov_map = payload.get("coverage") or {}
    if isinstance(cov_map, dict) and cov_map:
        lines.append(f"  [Veri Toplama Kapsami — Kalite Skoru: {ass.get('scan_quality', 100)}/100]")
        for cname in sorted(cov_map.keys()):
            cinfo = cov_map[cname]
            if isinstance(cinfo, dict):
                lines.append(f"    - {cname}: {cinfo.get('status', '?')} — {cinfo.get('detail', '')}")

    scanned_regions = telem.get("scanned_regions") or {}
    if isinstance(scanned_regions, dict) and scanned_regions:
        for eng_code in sorted(scanned_regions.keys()):
            dur = timings.get(eng_code)
            dur_lbl = f" ({dur} sn)" if dur is not None else ""
            title = _ENGINE_TITLES.get(eng_code, eng_code)
            lines.append(f"  [{title}]{dur_lbl}")
            for reg in scanned_regions[eng_code]:
                lines.extend(_wrap_indented("    - ", str(reg), cont_indent="      "))
    elif not engine_status and not cov_map:
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
        f"Genel Karar        : {ass['verdict']} (Seviye: {ass.get('verdict_level', 'N/A')} | Hile Seviyesi: {ass.get('cheat_verdict_level', 'N/A')})",
        f"Genel Risk Puani   : {ass['risk_score']} / 100 (Tarama Kalitesi: {ass.get('scan_quality', 100)}/100)",
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
    elif ass.get("incomplete_scan"):
        lines.append("Sonuc Yorumu       : EKSIK KAPSAM — Hata veya yetki kisiti nedeniyle tarama tam tamamlanamadi.")
    else:
        lines.append("Sonuc Yorumu       : TEMIZ — Hile istemcisi, RAM enjeksiyonu, makro veya gizli mod izi tespit edilmedi.")
    if saved_path is not None:
        lines.append(f"Rapor Dosyasi      : {saved_path}")
    lines.append(f"Veri Ozeti SHA-256 : {payload['report_sha256']}")
    lines.append("=" * 88)
    return "\n".join(lines) + "\n"


def _safe_json_for_html_script(obj: Any) -> str:
    """Serialize JSON safely for embedding inside an HTML <script type='application/json'> block."""
    raw = json.dumps(obj, ensure_ascii=False)
    return (
        raw.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_html_report(payload: dict[str, Any], saved_path: Path | None = None) -> str:
    ass = payload["assessment"]
    counts = ass["counts"]
    score = ass["risk_score"]
    vlevel = ass["verdict_level"]
    domain_scores = ass.get("domain_scores") or {}
    telem = payload.get("telemetry", {}) or {}
    findings = payload.get("findings", []) or []
    timings = telem.get("engine_timings_sec", {}) or {}
    total_dur = round(sum(float(v) for v in timings.values() if isinstance(v, (int, float))), 3)
    local_now = payload.get("generated_local") or datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    deep_count = telem.get("engine4_files_deep_scanned", 0)
    total_procs = telem.get("total_processes", 0)
    java_pids = telem.get("java_pids", []) or []
    mc_pids = telem.get("minecraft_pids", []) or []
    mc_inst = telem.get("minecraft_instances", []) or []
    lkm_act = telem.get("kernel_lkm_active", False)
    iommu_info = telem.get("iommu_compliance") or {}
    iommu_lbl = "Aktif" if isinstance(iommu_info, dict) and iommu_info.get("iommu_active") else "Kapalı / Belirsiz"

    badge_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "INCOMPLETE": "#f59e0b",
        "CLEAN": "#22c55e",
    }.get(vlevel, "#64748b")

    def esc(val: Any) -> str:
        return html.escape(str(val), quote=True)

    domain_labels = {
        "cheat_evidence": "Hile Kanıt Düzeyi",
        "forensic_tampering": "Adli İz Manipülasyonu",
        "kernel_integrity": "Çekirdek Bütünlüğü",
        "dma_hardware": "DMA / Donanım Maruziyeti",
        "os_security": "İS Güvenlik Riski",
        "scan_coverage": "Tarama Kapsamı / Kalitesi",
    }

    sev_labels_tr = {
        "CRITICAL": "KRİTİK",
        "HIGH": "YÜKSEK",
        "MEDIUM": "ORTA",
        "LOW": "DÜŞÜK",
        "INFO": "BİLGİ",
    }

    engines_seen: list[str] = []
    seen_eng_set: set[str] = set()
    finding_cards: list[str] = []
    priority_items: list[str] = []

    for idx, f in enumerate(findings, 1):
        sev = str(f["severity"])
        eng = str(f["engine"])
        if eng not in seen_eng_set:
            seen_eng_set.add(eng)
            engines_seen.append(eng)
        raw_evs = f.get("evidence", []) or []
        shown_evs = raw_evs[:8]
        extra_evs = raw_evs[8:50]
        ev_items = "".join(f"<li><code>{esc(e)}</code></li>" for e in shown_evs)
        extra_html = ""
        if extra_evs:
            more_li = "".join(f"<li><code>{esc(e)}</code></li>" for e in extra_evs)
            if len(raw_evs) > 50:
                more_li += f"<li><code>... (+{len(raw_evs) - 50} ek kanıt JSON raporunda)</code></li>"
            extra_html = (
                f"<details class='ev-more'><summary>+{len(raw_evs) - len(shown_evs)} ek kanıtı göster</summary>"
                f"<ul class='ev-list'>{more_li}</ul></details>"
            )
        path_html = f"<div><strong>Yol:</strong> <code>{esc(f['path'])}</code></div>" if f.get("path") else ""
        pid_html = f"<div><strong>PID:</strong> <code>{esc(f['pid'])}</code></div>" if f.get("pid") is not None else ""
        dom_key = str(f.get("domain", ""))
        dom_lbl = domain_labels.get(dom_key, dom_key)
        dom_html = f"<div><strong>Alan:</strong> {esc(dom_lbl)}</div>" if dom_key else ""
        rec_html = (
            f"<div class='rec'><strong>SS Kontrol Önerisi:</strong> {esc(f['recommendation'])}</div>"
            if f.get("recommendation")
            else ""
        )
        search_blob = (
            f"{f.get('rule_id', '')} {f.get('title', '')} {f.get('description', '')} "
            f"{f.get('category', '')} {dom_lbl} {eng} {f.get('path') or ''} "
            f"{' '.join(str(x) for x in raw_evs[:30])}"
        ).lower()
        card_id = f"finding-{idx}"
        finding_cards.append(
            f"""
            <article id="{card_id}" class="card sev-{esc(sev)}" data-sev="{esc(sev)}" data-engine="{esc(eng)}" data-domain="{esc(dom_key)}" data-search="{esc(search_blob)}">
              <div class="card-head">
                <span class="pill pill-{esc(sev)}">{esc(sev_labels_tr.get(sev, sev))} ({esc(sev)})</span>
                <span class="pill pill-conf">{esc(f['confidence'])}</span>
                <span class="rule-id">{esc(f['rule_id'])}</span>
                <span class="eng-tag">{esc(eng)}</span>
              </div>
              <h3>{esc(f['title'])}</h3>
              <p class="desc">{esc(f['description'])}</p>
              <div class="meta-row">
                <div><strong>Kategori:</strong> {esc(f['category'])}</div>
                {dom_html}
                <div><strong>Etki Skoru:</strong> {esc(f['effective_score'])}</div>
                {path_html}
                {pid_html}
              </div>
              {f"<ul class='ev-list'>{ev_items}</ul>" if ev_items else ""}
              {extra_html}
              {rec_html}
            </article>
            """
        )
        if sev in ("CRITICAL", "HIGH", "MEDIUM"):
            loc = f.get("path") or (f"Süreç PID {f['pid']}" if f.get("pid") is not None else "Sistem / Çekirdek / Bellek")
            ev0 = f"<div class='prio-ev'><code>{esc(raw_evs[0])}</code></div>" if raw_evs else ""
            priority_items.append(
                f"<a class='prio-item prio-{esc(sev)}' href='#{card_id}' onclick=\"jumpToFinding('{card_id}')\">"
                f"<div class='prio-top'><span class='pill pill-{esc(sev)}'>{esc(sev_labels_tr.get(sev, sev))}</span>"
                f"<span class='prio-title'>{esc(f['title'])}</span>"
                f"<span class='rule-id'>{esc(f['rule_id'])} · Skor {esc(f['effective_score'])}</span></div>"
                f"<div class='prio-loc'>Konum: <code>{esc(loc)}</code></div>{ev0}</a>"
            )

    priority_section_html = (
        f"<section id='priority' class='panel'><h2>1. Öncelikli Bulgular Özeti ({len(priority_items)} tespit)</h2>"
        f"<div class='prio-list'>{''.join(priority_items)}</div></section>"
        if priority_items
        else "<section id='priority' class='panel clean-box'><h2>1. Öncelikli Bulgular Özeti</h2>"
        "<p class='clean-msg'>[TEMİZ] Kritik, yüksek veya orta riskli herhangi bir hile, enjeksiyon veya makro bulgusu saptanmadı.</p></section>"
    )

    domain_cards_html = ""
    if domain_scores:
        d_items = []
        for dk, dlbl in domain_labels.items():
            dval = int(domain_scores.get(dk, 100 if dk == "scan_coverage" else 0))
            if dk == "scan_coverage":
                bar_col = "#22c55e" if dval >= 85 else ("#eab308" if dval >= 70 else "#ef4444")
            else:
                bar_col = "#ef4444" if dval >= 65 else ("#f97316" if dval >= 35 else ("#eab308" if dval >= 15 else "#22c55e"))
            d_items.append(
                f"<div class='stat'>"
                f"<div class='stat-top'><span class='num' style='color:{bar_col}'>{dval}</span><span class='stat-unit'>/100</span></div>"
                f"<div class='lbl'>{esc(dlbl)}</div>"
                f"<div class='bar-track'><div class='bar-fill' style='width:{max(0, min(100, dval))}%;background:{bar_col}'></div></div>"
                f"</div>"
            )
        domain_cards_html = f"<section class='stats domain-grid'>{''.join(d_items)}</section>"

    breakdown_rows = []
    for br in (ass.get("score_breakdown") or [])[:30]:
        breakdown_rows.append(
            "<tr>"
            f"<td><code>{esc(br.get('rule_id', ''))}</code></td>"
            f"<td>{esc(domain_labels.get(str(br.get('domain', '')), str(br.get('domain', ''))))}</td>"
            f"<td><code>{esc(br.get('subject', ''))}</code></td>"
            f"<td>{esc(br.get('raw_score', 0))} × {esc(br.get('multiplier', 1.0))} = <strong>+{esc(br.get('contributed', 0))}</strong></td>"
            "</tr>"
        )
    breakdown_html = (
        f"<section id='scoring' class='panel'><h2>Risk Puanlama Açıklaması (İlk 30 Katkı)</h2>"
        f"<div class='table-wrap'><table><thead><tr><th>Kural</th><th>Alan</th><th>Konu / Hedef</th><th>Puan Katkısı</th></tr></thead>"
        f"<tbody>{''.join(breakdown_rows)}</tbody></table></div></section>"
        if breakdown_rows
        else ""
    )

    eng_status_rows: list[str] = []
    engine_status = payload.get("engine_status") or {}
    if isinstance(engine_status, dict):
        for ecode in sorted(engine_status.keys()):
            einfo = engine_status[ecode]
            if isinstance(einfo, dict):
                st = str(einfo.get("status", "?")).upper()
                st_cls = "st-ok" if st == "COMPLETED" else ("st-warn" if st in ("PARTIAL", "SKIPPED") else "st-err")
                dur = timings.get(ecode)
                dur_str = f"{dur} sn" if dur is not None else "-"
                eng_status_rows.append(
                    f"<tr><td><code>{esc(ecode)}</code> · {esc(_ENGINE_TITLES.get(ecode, ecode))}</td>"
                    f"<td><span class='st-pill {st_cls}'>{esc(st)}</span></td>"
                    f"<td><code>{esc(dur_str)}</code></td>"
                    f"<td>{esc(einfo.get('detail', ''))}</td></tr>"
                )

    cov_rows: list[str] = []
    coverage_map = payload.get("coverage") or {}
    if isinstance(coverage_map, dict):
        for comp in sorted(coverage_map.keys()):
            cinfo = coverage_map[comp]
            if isinstance(cinfo, dict):
                st = str(cinfo.get("status", "?")).upper()
                st_cls = "st-ok" if st == "COMPLETED" else ("st-warn" if st in ("PARTIAL", "SKIPPED", "UNSUPPORTED") else "st-err")
                cov_rows.append(
                    f"<tr><td><code>{esc(comp)}</code></td>"
                    f"<td><span class='st-pill {st_cls}'>{esc(st)}</span></td>"
                    f"<td>{esc(cinfo.get('detail', ''))}</td></tr>"
                )

    gaps = ass.get("coverage_gaps") or []
    gaps_html = ""
    if gaps:
        gap_li = "".join(f"<li><code>{esc(g)}</code></li>" for g in gaps)
        gaps_html = f"<div class='warn-box'><strong>Kapsam Notları / Eksikler:</strong><ul>{gap_li}</ul></div>"

    regions_blocks: list[str] = []
    scanned_regions = telem.get("scanned_regions") or {}
    if isinstance(scanned_regions, dict) and scanned_regions:
        for eng_code in sorted(scanned_regions.keys()):
            dur = timings.get(eng_code)
            dur_lbl = f" ({dur} sn)" if dur is not None else ""
            li_html = "".join(f"<li><code>{esc(r)}</code></li>" for r in scanned_regions[eng_code])
            regions_blocks.append(
                f"<div class='reg-group'><h4>{esc(_ENGINE_TITLES.get(eng_code, eng_code))}{esc(dur_lbl)}</h4><ul>{li_html}</ul></div>"
            )
    if telem.get("engine4_mc_dirs_scanned"):
        li_mc = "".join(f"<li><code>{esc(d)}</code></li>" for d in telem["engine4_mc_dirs_scanned"])
        regions_blocks.append(f"<div class='reg-group'><h4>Keşfedilen Minecraft Kök Dizinleri</h4><ul>{li_mc}</ul></div>")
    if telem.get("engine4_hot_dirs_scanned"):
        li_hd = "".join(f"<li><code>{esc(d)}</code></li>" for d in telem["engine4_hot_dirs_scanned"])
        regions_blocks.append(f"<div class='reg-group'><h4>Taranan Sıcak Klasörler</h4><ul>{li_hd}</ul></div>")
    ram_bytes = telem.get("ram_scanned_bytes") or {}
    if isinstance(ram_bytes, dict) and ram_bytes:
        total_mb = round(sum(int(v) for v in ram_bytes.values()) / (1024 * 1024), 2)
        ram_items = sorted(ram_bytes.items(), key=lambda kv: int(kv[1]), reverse=True)[:25]
        li_ram = "".join(
            f"<li><code>PID {esc(rpid)}: {round(int(rb) / (1024 * 1024), 2)} MB ({esc(rb)} bayt)</code></li>"
            for rpid, rb in ram_items
        )
        regions_blocks.append(
            f"<div class='reg-group'><h4>Canlı RAM Taraması ({len(ram_bytes)} süreç, {total_mb} MB)</h4><ul>{li_ram}</ul></div>"
        )

    regions_details_html = (
        f"<details class='sub-details'><summary>Taranan Bölgeler, Klasörler ve RAM Kapsamı</summary>"
        f"<div class='reg-grid'>{''.join(regions_blocks)}</div></details>"
        if regions_blocks
        else ""
    )

    cov_html = (
        f"<section id='coverage' class='panel'><h2>Tarama Kapsamı, Motor Durumları ve Veri Kalitesi ({esc(ass.get('scan_quality', 100))}/100)</h2>"
        f"{gaps_html}"
        + (
            f"<h3>Motor Çalışma Durumları</h3><div class='table-wrap'><table><thead><tr><th>Motor</th><th>Durum</th><th>Süre</th><th>Detay</th></tr></thead><tbody>{''.join(eng_status_rows)}</tbody></table></div>"
            if eng_status_rows
            else ""
        )
        + (
            f"<h3 style='margin-top:16px'>Veri Toplama Bileşenleri</h3><div class='table-wrap'><table><thead><tr><th>Bileşen</th><th>Durum</th><th>Detay</th></tr></thead><tbody>{''.join(cov_rows)}</tbody></table></div>"
            if cov_rows
            else ""
        )
        + regions_details_html
        + "</section>"
    )

    telem_groups_html: list[str] = []
    for idx_g, (grp_title, rows) in enumerate(_build_structured_telemetry_groups(telem)):
        tr_list = []
        for label, val in rows:
            if isinstance(val, list) and len(val) > 1:
                items_li = "".join(f"<li><code>{esc(x)}</code></li>" for x in val[:25])
                if len(val) > 25:
                    items_li += f"<li><code>... (+{len(val) - 25} kayıt daha JSON raporunda)</code></li>"
                val_cell = f"<details><summary>{len(val)} kayıt göster</summary><ul class='mini-list'>{items_li}</ul></details>"
            else:
                val_fmt = val[0] if isinstance(val, list) and len(val) == 1 else (_format_compact_value(val, 600) if not isinstance(val, str) else val)
                val_cell = f"<code>{esc(val_fmt)}</code>"
            tr_list.append(f"<tr><td>{esc(label)}</td><td>{val_cell}</td></tr>")
        open_attr = " open" if idx_g < 2 else ""
        telem_groups_html.append(
            f"<details class='telem-details'{open_attr}><summary>{esc(grp_title)}</summary>"
            f"<div class='table-wrap'><table><tbody>{''.join(tr_list)}</tbody></table></div></details>"
        )

    err_html = ""
    if payload["errors"]:
        items = "".join(f"<li><code>{esc(e)}</code></li>" for e in payload["errors"])
        err_html = f"<section class='panel err-panel'><h2>Tarama Uyarıları / Hataları</h2><ul>{items}</ul></section>"

    engine_options = "".join(f"<option value='{esc(e)}'>{esc(e)}</option>" for e in engines_seen)
    domain_options = "".join(f"<option value='{esc(dk)}'>{esc(dlbl)}</option>" for dk, dlbl in domain_labels.items())

    txt_export_str = render_txt_report(payload, saved_path=saved_path)
    export_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_export_blob = _safe_json_for_html_script({"filename": f"MC_SS_Raporu_{export_stamp}.txt", "content": txt_export_str})
    json_export_blob = _safe_json_for_html_script({"filename": f"MC_SS_Raporu_{export_stamp}.json", "content": json.dumps(payload, indent=2, ensure_ascii=False)})
    saved_path_row = f"<div><span class='mk'>Rapor Dosyası:</span> <code>{esc(saved_path)}</code></div>" if saved_path is not None else ""

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:;">
<title>MC SS Sentinel — Adli Hile Kontrol Raporu ({score}/100)</title>
<style>
  :root {{
    --bg: #070b12;
    --surface: #0e1523;
    --panel: #111a2b;
    --card: #152035;
    --border: #23324d;
    --text: #e6edf7;
    --muted: #93a4be;
    --accent: #3b82f6;
    --crit: #ef4444;
    --high: #f97316;
    --med: #eab308;
    --low: #38bdf8;
    --info: #64748b;
    --ok: #22c55e;
  }}
  * {{ box-sizing: border-box; }}
  html {{ scroll-behavior: smooth; }}
  body {{
    margin: 0;
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", sans-serif;
    background: radial-gradient(circle at top right, #101b30 0%, var(--bg) 52%);
    color: var(--text);
    line-height: 1.55;
  }}
  .topbar {{
    position: sticky;
    top: 0;
    z-index: 40;
    background: rgba(7, 11, 18, 0.92);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--border);
  }}
  .topbar-inner {{
    max-width: 1240px;
    margin: 0 auto;
    padding: 10px 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    justify-content: space-between;
  }}
  .brand {{
    display: flex;
    align-items: center;
    gap: 9px;
    font-weight: 800;
    letter-spacing: 0.2px;
    color: #f8fafc;
    font-size: 0.98rem;
  }}
  .nav-links {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }}
  .nav-links a {{
    color: var(--muted);
    text-decoration: none;
    font-size: 0.84rem;
    font-weight: 600;
    padding: 5px 10px;
    border-radius: 7px;
  }}
  .nav-links a:hover {{ color: #fff; background: #172338; }}
  .top-actions {{ display: flex; flex-wrap: wrap; gap: 6px; }}
  .act-btn {{
    background: #142034;
    color: #dbeafe;
    border: 1px solid #2b4166;
    border-radius: 7px;
    padding: 6px 11px;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
  }}
  .act-btn:hover {{ background: #1d2f4d; border-color: #60a5fa; color: #fff; }}
  .wrap {{ max-width: 1240px; margin: 0 auto; padding: 22px 18px 68px; }}
  .hero {{
    background: linear-gradient(135deg, #0f172a 0%, #17243d 100%);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 22px;
    align-items: center;
    box-shadow: 0 12px 32px rgba(0,0,0,0.35);
  }}
  .hero h1 {{ margin: 0 0 8px; font-size: 1.55rem; letter-spacing: 0.2px; }}
  .verdict {{
    display: inline-block;
    padding: 7px 14px;
    border-radius: 9px;
    font-weight: 800;
    font-size: 0.96rem;
    background: {badge_color}20;
    color: {badge_color};
    border: 1px solid {badge_color};
  }}
  .guidance {{
    margin: 12px 0 14px;
    color: #dbe6f5;
    font-size: 0.93rem;
    background: rgba(7, 11, 18, 0.45);
    border: 1px solid #1f2e47;
    border-radius: 10px;
    padding: 11px 14px;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 6px 18px;
    font-size: 0.81rem;
    color: var(--muted);
  }}
  .mk {{ color: #cbd5e1; font-weight: 600; }}
  .sha-row {{
    margin-top: 10px;
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    font-size: 0.79rem;
    color: var(--muted);
  }}
  .copy-btn {{
    background: #172338;
    color: #93c5fd;
    border: 1px solid #2b4166;
    border-radius: 6px;
    padding: 2px 8px;
    font-size: 0.74rem;
    cursor: pointer;
    font-weight: 600;
  }}
  .copy-btn:hover {{ background: #1e3150; color: #fff; }}
  .score-box {{
    text-align: center;
    background: #080d17;
    border: 2px solid {badge_color};
    border-radius: 14px;
    padding: 16px 24px;
    min-width: 158px;
    box-shadow: inset 0 0 24px {badge_color}18;
  }}
  .score-num {{ font-size: 2.75rem; font-weight: 900; color: {badge_color}; line-height: 1.05; }}
  .score-lbl {{ font-size: 0.76rem; color: var(--muted); text-transform: uppercase; margin-top: 4px; letter-spacing: 0.5px; }}
  .score-sub {{ font-size: 0.78rem; color: #cbd5e1; margin-top: 8px; padding-top: 8px; border-top: 1px solid #1d2a40; }}
  .stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
    margin: 18px 0;
  }}
  .stat {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 13px 15px;
    transition: border-color 0.15s ease, transform 0.12s ease;
  }}
  .stat.clickable {{ cursor: pointer; }}
  .stat.clickable:hover {{ border-color: #60a5fa; transform: translateY(-1px); }}
  .stat-top {{ display: flex; align-items: baseline; gap: 3px; }}
  .stat .num {{ font-size: 1.55rem; font-weight: 800; line-height: 1.15; }}
  .stat-unit {{ font-size: 0.76rem; color: var(--muted); }}
  .stat .lbl {{ font-size: 0.8rem; color: var(--muted); margin-top: 3px; }}
  .bar-track {{
    margin-top: 8px;
    height: 6px;
    background: #090e18;
    border-radius: 999px;
    overflow: hidden;
    border: 1px solid #1e2a40;
  }}
  .bar-fill {{ height: 100%; border-radius: 999px; }}
  .panel {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 20px;
    margin-top: 22px;
  }}
  .panel h2 {{ margin: 0 0 12px; font-size: 1.14rem; color: #f1f5f9; }}
  .panel h3 {{ margin: 0 0 10px; font-size: 0.96rem; color: #cbd5e1; }}
  .clean-box {{ border-color: #166534; background: #0b1b14; }}
  .clean-msg {{ margin: 0; color: #86efac; font-weight: 600; }}
  .prio-list {{ display: grid; gap: 9px; }}
  .prio-item {{
    display: block;
    text-decoration: none;
    color: inherit;
    background: #0c1320;
    border: 1px solid var(--border);
    border-left: 4px solid var(--med);
    border-radius: 9px;
    padding: 10px 13px;
  }}
  .prio-item:hover {{ border-color: #60a5fa; background: #121c2e; }}
  .prio-CRITICAL {{ border-left-color: var(--crit); }}
  .prio-HIGH {{ border-left-color: var(--high); }}
  .prio-top {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
  .prio-title {{ font-weight: 700; color: #f8fafc; font-size: 0.92rem; }}
  .prio-loc {{ margin-top: 4px; font-size: 0.8rem; color: var(--muted); word-break: break-all; }}
  .prio-ev {{ margin-top: 3px; font-size: 0.79rem; color: #cbd5e1; word-break: break-all; }}
  .controls {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 22px 0 12px;
    align-items: center;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 12px 14px;
  }}
  .btn {{
    background: #0d1422;
    color: var(--text);
    border: 1px solid var(--border);
    padding: 6px 11px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.82rem;
  }}
  .btn.active, .btn:hover {{ border-color: #60a5fa; background: #1b2a44; color: #fff; }}
  select.filter-sel, input.search {{
    background: #0b111d;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 7px 10px;
    font-size: 0.84rem;
  }}
  input.search {{ flex: 1; min-width: 220px; }}
  .match-count {{ width: 100%; font-size: 0.8rem; color: var(--muted); display: flex; justify-content: space-between; align-items: center; }}
  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-left: 5px solid var(--info);
    border-radius: 11px;
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
    font-size: 0.72rem;
    font-weight: 700;
  }}
  .pill-CRITICAL {{ background: #ef44442e; color: #fca5a5; border: 1px solid #ef444466; }}
  .pill-HIGH {{ background: #f973162e; color: #fdba74; border: 1px solid #f9731666; }}
  .pill-MEDIUM {{ background: #eab3082e; color: #fde047; border: 1px solid #eab30866; }}
  .pill-LOW {{ background: #38bdf82e; color: #7dd3fc; border: 1px solid #38bdf866; }}
  .pill-INFO {{ background: #64748b2e; color: #cbd5e1; border: 1px solid #64748b66; }}
  .pill-conf {{ background: #26344b; color: #e2e8f0; }}
  .rule-id {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: #93c5fd; font-size: 0.82rem; }}
  .eng-tag {{ margin-left: auto; color: var(--muted); font-size: 0.79rem; }}
  .card h3 {{ margin: 4px 0 6px; font-size: 1.04rem; color: #f8fafc; }}
  .desc {{ margin: 0 0 10px; color: #cbd5e1; font-size: 0.91rem; }}
  .meta-row {{ display: flex; flex-wrap: wrap; gap: 10px 16px; font-size: 0.82rem; color: var(--muted); margin-bottom: 8px; }}
  .ev-list {{
    background: #0a101b;
    border: 1px solid #1d2a40;
    border-radius: 8px;
    padding: 10px 14px 10px 26px;
    margin: 8px 0 0;
    overflow-x: auto;
  }}
  .ev-list li {{ margin: 4px 0; font-size: 0.82rem; word-break: break-all; }}
  .ev-more summary {{ cursor: pointer; color: #93c5fd; font-size: 0.82rem; margin-top: 8px; font-weight: 600; }}
  .rec {{
    margin-top: 10px;
    padding: 9px 12px;
    border-radius: 8px;
    background: #13254a;
    border: 1px solid #1e3a6e;
    color: #dbeafe;
    font-size: 0.84rem;
  }}
  .st-pill {{ display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.74rem; font-weight: 700; }}
  .st-ok {{ background: #14532d66; color: #86efac; border: 1px solid #16a34a66; }}
  .st-warn {{ background: #713f1266; color: #fde047; border: 1px solid #ca8a0466; }}
  .st-err {{ background: #7f1d1d66; color: #fca5a5; border: 1px solid #dc262666; }}
  .warn-box {{
    background: #2b1d0b;
    border: 1px solid #92400e;
    border-radius: 8px;
    padding: 10px 14px;
    margin-bottom: 14px;
    color: #fde68a;
    font-size: 0.84rem;
  }}
  .warn-box ul {{ margin: 6px 0 0; padding-left: 20px; }}
  .err-panel {{ border-color: #7f1d1d; }}
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.83rem; }}
  th {{ color: #93c5fd; background: #0c1321; font-weight: 700; }}
  td, th {{ padding: 8px 10px; border-bottom: 1px solid #1d293e; vertical-align: top; word-break: break-word; text-align: left; }}
  td:first-child {{ width: 260px; color: #cbd5e1; font-weight: 600; }}
  .telem-details, .sub-details {{
    margin-top: 10px;
    border: 1px solid #1e2c44;
    border-radius: 9px;
    background: #0c1320;
    padding: 8px 12px;
  }}
  .telem-details summary, .sub-details summary {{
    cursor: pointer;
    font-weight: 700;
    color: #93c5fd;
    font-size: 0.9rem;
    padding: 3px 0;
  }}
  .mini-list {{ margin: 6px 0 0; padding-left: 18px; }}
  .mini-list li {{ margin: 2px 0; font-size: 0.8rem; word-break: break-all; }}
  .reg-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin-top: 10px; }}
  .reg-group {{ background: #09101c; border: 1px solid #1d293e; border-radius: 8px; padding: 10px 12px; }}
  .reg-group h4 {{ margin: 0 0 6px; font-size: 0.84rem; color: #bfdbfe; }}
  .reg-group ul {{ margin: 0; padding-left: 18px; font-size: 0.78rem; color: var(--muted); }}
  .footer-summary {{
    margin-top: 24px;
    border: 1px solid var(--border);
    border-radius: 12px;
    background: linear-gradient(135deg, #0b1220, #121b2e);
    padding: 18px 20px;
    font-size: 0.85rem;
    color: #cbd5e1;
  }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.92em; }}
  @media (max-width: 720px) {{
    .hero {{ grid-template-columns: 1fr; }}
    .score-box {{ width: 100%; }}
  }}
  @media print {{
    body {{ background: #fff !important; color: #111 !important; }}
    .topbar, .controls, .act-btn, .copy-btn {{ display: none !important; }}
    .hero, .panel, .card, .stat, .footer-summary {{
      background: #fff !important;
      color: #111 !important;
      border-color: #cbd5e1 !important;
      box-shadow: none !important;
    }}
    .desc, .meta-row, .meta-grid, .lbl, .prio-loc, .prio-ev {{ color: #334155 !important; }}
    .ev-list, .rec {{ background: #f8fafc !important; color: #111 !important; border-color: #cbd5e1 !important; }}
  }}
</style>
</head>
<body>
<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M12 2L4 5v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V5l-8-3z" fill="{badge_color}33" stroke="{badge_color}" stroke-width="2"/>
        <path d="M9 12l2 2 4-4" stroke="#f8fafc" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span>MC SS Sentinel</span>
    </div>
    <nav class="nav-links">
      <a href="#summary">Özet</a>
      <a href="#priority">Öncelikli</a>
      <a href="#findings-sec">Bulgular ({ass['total_findings']})</a>
      <a href="#coverage">Kapsam</a>
      <a href="#telemetry">Telemetri</a>
    </nav>
    <div class="top-actions">
      <button class="act-btn" type="button" onclick="downloadBlob('ss-txt-blob', 'text/plain;charset=utf-8')">TXT İndir</button>
      <button class="act-btn" type="button" onclick="downloadBlob('ss-json-blob', 'application/json;charset=utf-8')">JSON İndir</button>
      <button class="act-btn" type="button" onclick="window.print()">Yazdır / PDF</button>
    </div>
  </div>
</header>

<div class="wrap">
  <section id="summary" class="hero">
    <div>
      <h1>MC SS Sentinel — Adli Hile Kontrol (SS) Raporu</h1>
      <div class="verdict">{esc(ass['verdict'])}</div>
      <div class="guidance">{esc(_verdict_guidance_text(ass))}</div>
      <div class="meta-grid">
        <div><span class="mk">Tarih (Yerel):</span> <code>{esc(local_now)}</code></div>
        <div><span class="mk">Tarih (UTC):</span> <code>{esc(payload['generated_utc'])}</code></div>
        <div><span class="mk">Hedef Ev Dizini:</span> <code>{esc(payload['target_home'])}</code></div>
        <div><span class="mk">Hedef OS / Host OS:</span> <code>{esc(payload.get('target_os_name', 'auto'))}</code> / <code>{esc(payload.get('host_os_name') or 'bilinmiyor')}</code></div>
        <div><span class="mk">Tarama Kapsamı:</span> <code>{total_procs} süreç (Java={len(java_pids)}, MC={len(mc_pids)}) · {deep_count} derin dosya · {len(mc_inst)} MC profili · {total_dur} sn</code></div>
        <div><span class="mk">Ring-0 / IOMMU:</span> <code>LKM={'AKTİF' if lkm_act else 'KAPALI (Userspace Fallback)'} · IOMMU={esc(iommu_lbl)}</code></div>
        {saved_path_row}
      </div>
      <div class="sha-row">
        <span><span class="mk">Veri Özeti SHA-256:</span> <code id="shaVal">{esc(payload['report_sha256'])}</code></span>
        <button class="copy-btn" type="button" onclick="copySha(this)">Kopyala</button>
      </div>
    </div>
    <div class="score-box">
      <div class="score-num">{score}</div>
      <div class="score-lbl">Risk Puanı / 100</div>
      <div class="score-sub">
        Hile Seviyesi: <strong>{esc(ass.get('cheat_verdict_level', vlevel))}</strong><br>
        Kalite: <strong>{esc(ass.get('scan_quality', 100))}/100</strong>
      </div>
    </div>
  </section>

  <section class="stats">
    <div class="stat clickable" onclick="quickFilter('CRITICAL')"><div class="num" style="color:var(--crit)">{counts['CRITICAL']}</div><div class="lbl">KRİTİK (CRITICAL)</div></div>
    <div class="stat clickable" onclick="quickFilter('HIGH')"><div class="num" style="color:var(--high)">{counts['HIGH']}</div><div class="lbl">YÜKSEK (HIGH)</div></div>
    <div class="stat clickable" onclick="quickFilter('MEDIUM')"><div class="num" style="color:var(--med)">{counts['MEDIUM']}</div><div class="lbl">ORTA (MEDIUM)</div></div>
    <div class="stat clickable" onclick="quickFilter('LOW')"><div class="num" style="color:var(--low)">{counts['LOW']}</div><div class="lbl">DÜŞÜK (LOW)</div></div>
    <div class="stat clickable" onclick="quickFilter('INFO')"><div class="num" style="color:var(--info)">{counts['INFO']}</div><div class="lbl">BİLGİ (INFO)</div></div>
    <div class="stat clickable" onclick="quickFilter('ALL')"><div class="num">{ass['total_findings']}</div><div class="lbl">Toplam Bulgu</div></div>
  </section>

  {domain_cards_html}
  {priority_section_html}

  <section id="findings-sec">
    <div class="controls">
      <button class="btn active" data-sev-btn="ALL" onclick="filterSev('ALL', this)">Tümü ({ass['total_findings']})</button>
      <button class="btn" data-sev-btn="CRITICAL" onclick="filterSev('CRITICAL', this)">CRITICAL ({counts['CRITICAL']})</button>
      <button class="btn" data-sev-btn="HIGH" onclick="filterSev('HIGH', this)">HIGH ({counts['HIGH']})</button>
      <button class="btn" data-sev-btn="MEDIUM" onclick="filterSev('MEDIUM', this)">MEDIUM ({counts['MEDIUM']})</button>
      <button class="btn" data-sev-btn="LOW" onclick="filterSev('LOW', this)">LOW ({counts['LOW']})</button>
      <button class="btn" data-sev-btn="INFO" onclick="filterSev('INFO', this)">INFO ({counts['INFO']})</button>
      <select class="filter-sel" id="engineFilter" onchange="applyFilters()" aria-label="Motor filtresi">
        <option value="ALL">Tüm Motorlar</option>
        {engine_options}
      </select>
      <select class="filter-sel" id="domainFilter" onchange="applyFilters()" aria-label="Alan filtresi">
        <option value="ALL">Tüm Alanlar</option>
        {domain_options}
      </select>
      <input class="search" type="search" id="searchBox" placeholder="Bulgu, dosya yolu, PID, kural veya imza ara..." oninput="applyFilters()">
      <button class="btn" type="button" onclick="resetFilters()">Sıfırla</button>
      <div class="match-count">
        <span id="visibleCount">Gösterilen: {ass['total_findings']} / {ass['total_findings']} bulgu</span>
        <span>%100 Çevrimdışı Yerel Rapor · MC SS Sentinel</span>
      </div>
    </div>

    <div id="findings">
      {"".join(finding_cards) if finding_cards else "<div class='panel clean-box'><p class='clean-msg'>Hiçbir şüpheli bulgu tespit edilmedi.</p></div>"}
    </div>
  </section>

  {breakdown_html}
  {cov_html}

  <section id="telemetry" class="panel">
    <h2>Sistem, Ring-0 Çekirdek, Donanım ve Oyun Ortamı Telemetrisi</h2>
    {"".join(telem_groups_html)}
  </section>
  {err_html}

  <footer class="footer-summary">
    <strong>Kısa Sonuç Özeti:</strong> {esc(ass['verdict'])} —
    Risk Puanı <strong>{score}/100</strong> · Hile Seviyesi <strong>{esc(ass.get('cheat_verdict_level', vlevel))}</strong> ·
    Tarama Kalitesi <strong>{esc(ass.get('scan_quality', 100))}/100</strong> ·
    Veri Özeti SHA-256: <code>{esc(payload['report_sha256'])}</code>
  </footer>
</div>

<script id="ss-txt-blob" type="application/json">{txt_export_blob}</script>
<script id="ss-json-blob" type="application/json">{json_export_blob}</script>
<script>
let currentSev = 'ALL';
function filterSev(sev, btn) {{
  currentSev = sev;
  document.querySelectorAll('.controls [data-sev-btn]').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyFilters();
}}
function quickFilter(sev) {{
  const targetBtn = document.querySelector('.controls [data-sev-btn="' + sev + '"]');
  filterSev(sev, targetBtn);
  const sec = document.getElementById('findings-sec');
  if (sec) sec.scrollIntoView({{ behavior: 'smooth' }});
}}
function resetFilters() {{
  document.getElementById('engineFilter').value = 'ALL';
  document.getElementById('domainFilter').value = 'ALL';
  document.getElementById('searchBox').value = '';
  const allBtn = document.querySelector('.controls [data-sev-btn="ALL"]');
  filterSev('ALL', allBtn);
}}
function jumpToFinding(id) {{
  resetFilters();
  const el = document.getElementById(id);
  if (el) el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
}}
function applyFilters() {{
  const q = document.getElementById('searchBox').value.trim().toLowerCase();
  const eng = document.getElementById('engineFilter').value;
  const dom = document.getElementById('domainFilter').value;
  const cards = document.querySelectorAll('#findings .card');
  let shown = 0;
  cards.forEach(card => {{
    const s = card.getAttribute('data-sev');
    const e = card.getAttribute('data-engine');
    const d = card.getAttribute('data-domain');
    const txt = card.getAttribute('data-search') || '';
    const ok = (currentSev === 'ALL' || s === currentSev)
      && (eng === 'ALL' || e === eng)
      && (dom === 'ALL' || d === dom)
      && (!q || txt.includes(q));
    card.style.display = ok ? 'block' : 'none';
    if (ok) shown += 1;
  }});
  const vc = document.getElementById('visibleCount');
  if (vc) vc.textContent = 'Gösterilen: ' + shown + ' / ' + cards.length + ' bulgu';
}}
function copySha(btn) {{
  const sha = document.getElementById('shaVal').textContent || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(sha).then(() => {{
      const prev = btn.textContent;
      btn.textContent = 'Kopyalandı';
      setTimeout(() => btn.textContent = prev, 1500);
    }});
  }}
}}
function downloadBlob(elemId, mimeType) {{
  const raw = document.getElementById(elemId);
  if (!raw) return;
  const parsed = JSON.parse(raw.textContent);
  const blob = new Blob([parsed.content], {{ type: mimeType }});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = parsed.filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}}
</script>
</body>
</html>
"""


def _write_text_strict(path: Path, content: str) -> str:
    data = content.encode("utf-8")
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def write_reports(
    ctx: ScanContext,
    out_dir: Path,
    payload: dict[str, Any] | None = None,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    if payload is None:
        payload = build_report_payload(ctx)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    tag = stamp
    counter = 1
    while any(
        (out_dir / f"ss_report_{tag}.{ext}").exists()
        for ext in ("html", "txt", "json", "sha256")
    ):
        tag = f"{stamp}_{counter}"
        counter += 1

    html_path = out_dir / f"ss_report_{tag}.html"
    txt_path = out_dir / f"ss_report_{tag}.txt"
    json_path = out_dir / f"ss_report_{tag}.json"
    sha_path = out_dir / f"ss_report_{tag}.sha256"

    html_sha = _write_text_strict(html_path, render_html_report(payload, saved_path=html_path))
    txt_sha = _write_text_strict(txt_path, render_txt_report(payload, saved_path=txt_path))
    json_sha = _write_text_strict(json_path, json.dumps(payload, indent=2, ensure_ascii=False))
    sha_lines = [
        f"{html_sha}  {html_path.name}",
        f"{txt_sha}  {txt_path.name}",
        f"{json_sha}  {json_path.name}",
    ]
    _write_text_strict(sha_path, "\n".join(sha_lines) + "\n")

    return {"html": html_path, "txt": txt_path, "json": json_path, "sha256": sha_path}


def write_desktop_html_report(
    ctx: ScanContext, desktop_dir: Path | None = None
) -> tuple[Path, dict[str, Any]]:
    """Write self-contained clickable offline HTML web report directly to the user's Desktop."""
    from .utils import resolve_desktop_dir

    target_desktop = desktop_dir if desktop_dir is not None else resolve_desktop_dir(ctx.home_dir)
    target_desktop.mkdir(parents=True, exist_ok=True)

    payload = build_report_payload(ctx)
    local_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = target_desktop / f"MC_SS_Raporu_{local_stamp}.html"
    counter = 1
    while html_path.exists():
        html_path = target_desktop / f"MC_SS_Raporu_{local_stamp}_{counter}.html"
        counter += 1

    file_sha = _write_text_strict(html_path, render_html_report(payload, saved_path=html_path))
    payload["desktop_html_file_sha256"] = file_sha
    payload["desktop_report_path"] = str(html_path)
    return html_path, payload


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

    file_sha = _write_text_strict(txt_path, render_txt_report(payload, saved_path=txt_path))
    payload["desktop_txt_file_sha256"] = file_sha
    return txt_path, payload

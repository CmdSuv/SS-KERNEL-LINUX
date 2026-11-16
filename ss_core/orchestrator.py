"""Orchestrator coordinating all 9 forensic engines and self-integrity telemetry."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Callable

from . import (
    engine1_integrity,
    engine2_live_proc,
    engine3_input_macro,
    engine4_deep_files,
    engine5_minecraft,
    engine6_desktop_traces,
    engine7_network_usb,
    engine8_reporter,
    engine9_kernel,
)
from .models import ScanContext, ScanStatus


class ScanCancelledError(Exception):
    """Raised cooperatively when a scan is cancelled by the user."""


ENGINES: tuple[tuple[str, Callable[[ScanContext], None]], ...] = (
    ("E1", engine1_integrity.run),
    ("E2", engine2_live_proc.run),
    ("E3", engine3_input_macro.run),
    ("E4", engine4_deep_files.run),
    ("E5", engine5_minecraft.run),
    ("E6", engine6_desktop_traces.run),
    ("E7", engine7_network_usb.run),
    ("E9", engine9_kernel.run),
)


def compute_tool_self_hash() -> str:
    pkg_dir = Path(__file__).resolve().parent
    h = hashlib.sha256()
    for p in sorted(pkg_dir.glob("*.py")):
        try:
            h.update(p.name.encode("utf-8"))
            h.update(p.read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:16]


ENGINE_WEIGHTS: dict[str, int] = {
    "E1": 7,
    "E2": 18,
    "E3": 7,
    "E4": 38,
    "E5": 7,
    "E6": 5,
    "E7": 3,
    "E9": 12,
    "E8": 3,
}

ENGINE_DESCRIPTIONS: dict[str, str] = {
    "E1": "Sistem butunlugu, saat ve ortam kontrolleri",
    "E2": "Canli surecler, /proc haritalari ve RAM taramasi",
    "E3": "Donanim makro, uinput ve sanal girdi kontrolleri",
    "E4": "Derin dosya, mod JAR, bytecode ve imza taramasi",
    "E5": "Minecraft log, ayar ve hesap kalintilari",
    "E6": "Masaustu, tarayici, cop kutusu ve Wine izleri",
    "E7": "Ag soketleri, VPN/proxy, hosts ve USB izleri",
    "E9": "Ring-0 Kernel butunlugu, DMA/IOMMU, PCIe 4KB & eBPF taramasi",
    "E8": "Capraz korelasyon, risk puanlama ve raporlama",
}


def run_all_engines(
    ctx: ScanContext,
    selected_engines: set[str] | None = None,
    progress_cb: Callable[[str], None] | None = None,
    progress_pct_cb: Callable[[int, str], None] | None = None,
) -> dict[str, float]:
    ctx.telemetry["tool_self_sha256_prefix"] = compute_tool_self_hash()
    ctx.telemetry["scan_cancelled"] = False
    timings: dict[str, float] = {}

    active: list[tuple[str, Callable[[ScanContext], None]]] = []
    for code, fn in ENGINES:
        if selected_engines is None or code in selected_engines:
            active.append((code, fn))
        else:
            ctx.set_engine_status(code, ScanStatus.SKIPPED, "Secili motor filtresi disinda birakildi")
    active.append(("E8", engine8_reporter.correlate_findings))

    total_weight = max(1, sum(ENGINE_WEIGHTS.get(c, 5) for c, _ in active))
    last_pct = 0

    def _emit_pct(pct: int, msg: str) -> None:
        nonlocal last_pct
        clamped = max(last_pct, min(100, pct))
        last_pct = clamped
        if progress_pct_cb:
            progress_pct_cb(clamped, msg)

    _emit_pct(0, "Tarama baslatiliyor...")
    acc_weight = 0.0

    for code, fn in active:
        if ctx.is_cancelled():
            ctx.set_engine_status(code, ScanStatus.CANCELLED, "Kullanici tarafindan iptal edildi")
            ctx.telemetry["scan_cancelled"] = True
            raise ScanCancelledError("Tarama kullanici tarafindan iptal edildi.")

        w = ENGINE_WEIGHTS.get(code, 5)
        start_pct = (acc_weight / total_weight) * 100.0
        end_pct = ((acc_weight + w) / total_weight) * 100.0
        desc = ENGINE_DESCRIPTIONS.get(code, code)

        if progress_cb:
            if code == "E8":
                progress_cb("[*] E8 Korelasyon ve skorlama calistiriliyor...")
            else:
                progress_cb(f"[*] {code} calistiriliyor...")

        _emit_pct(int(start_pct), f"{code}: {desc}...")

        def _sub_cb(frac: float, detail: str, _s: float = start_pct, _e: float = end_pct, _c: str = code) -> None:
            if ctx.is_cancelled():
                raise ScanCancelledError("Tarama kullanici tarafindan iptal edildi.")
            raw = _s + max(0.0, min(1.0, frac)) * (_e - _s)
            cap = 100 if _c == "E8" else min(99, int(round(_e)))
            _emit_pct(min(cap, int(raw)), f"{_c}: {detail}")

        err_before = len(ctx.errors)
        ctx._engine_progress_cb = _sub_cb
        t0 = time.monotonic()
        try:
            fn(ctx)
        except ScanCancelledError:
            ctx.set_engine_status(code, ScanStatus.CANCELLED, "Kullanici tarafindan iptal edildi")
            ctx.telemetry["scan_cancelled"] = True
            raise
        except Exception as exc:
            ctx.add_error(code, f"Motor calisma hatasi: {exc}")
            ctx.set_engine_status(code, ScanStatus.ERROR, str(exc))
        else:
            existing_status = (ctx.telemetry.get("engine_status") or {}).get(code)
            existing_state = str(existing_status.get("status", "")).upper() if isinstance(existing_status, dict) else ""
            if len(ctx.errors) > err_before:
                if existing_status is None or existing_state == "COMPLETED":
                    ctx.set_engine_status(
                        code,
                        ScanStatus.PARTIAL,
                        f"{len(ctx.errors) - err_before} hata ile tamamlandi",
                    )
            elif existing_status is None:
                ctx.set_engine_status(code, ScanStatus.COMPLETED, "Tamamlandi")
        finally:
            ctx._engine_progress_cb = None
        timings[code] = round(time.monotonic() - t0, 3)

        acc_weight += w
        done_cap = 100 if code == "E8" else min(99, int(round(end_pct)))
        _emit_pct(done_cap, f"{code} tamamlandi ({timings[code]}s)")

    _emit_pct(100, "Analiz ve korelasyon tamamlandi.")
    ctx.telemetry["engine_timings_sec"] = timings
    return timings

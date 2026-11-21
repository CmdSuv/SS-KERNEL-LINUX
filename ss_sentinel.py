#!/usr/bin/env python3
"""MC SS Sentinel — Multi-Layered Linux Minecraft Forensic Cheat-Check (SS) Tool."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ss_core import engine8_reporter, orchestrator, priv_helper
from ss_core.models import ScanContext, Severity


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ss_sentinel",
        description="Linux Minecraft Derin Adli Hile Kontrolu (SS) — Ring-0 Kernel + 9 Katmanli Tarayici",
    )
    parser.add_argument(
        "--home",
        type=Path,
        default=Path.home(),
        help="Taranacak kullanici ev dizini (varsayilan: mevcut $HOME)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "reports",
        help="HTML/TXT/JSON rapor cikti klasoru",
    )
    parser.add_argument(
        "--hours",
        type=float,
        default=2.0,
        help="Yakin zamanli iz/timestomp/journal/tarayici penceresi (saat, varsayilan: 2.0)",
    )
    parser.add_argument(
        "--no-mem-scan",
        action="store_true",
        help="Canli /proc/<pid>/mem RAM byte taramasini devre disi birak",
    )
    parser.add_argument(
        "--no-deep-home",
        action="store_true",
        help="Ev dizinindeki son degisen tum dosyalarin taramasini atla",
    )
    parser.add_argument(
        "--offline-only",
        action="store_true",
        help="jcmd/journalctl/timedatectl/podman gibi canli sistem komutlarini calistirma",
    )
    parser.add_argument(
        "--engines",
        type=str,
        default="",
        help="Sadece secili motorlari calistir (orn: E1,E2,E4,E9)",
    )
    parser.add_argument(
        "--kernel-lkm",
        action="store_true",
        help="Yetkili (pkexec/root) gecici Ring-0 kernel surucusu (Gir-Tara-Cik) modunu etkinlestir",
    )
    parser.add_argument(
        "--trace-ms",
        type=int,
        default=1500,
        help="Ring-0 aktif olay penceresi suresi ms (varsayilan: 1500)",
    )
    parser.add_argument(
        "--target-os",
        type=str,
        default="auto",
        help="Hedef Linux dagitimi profili (auto, bazzite, fedora_nobara, ubuntu_24_04, ubuntu_22_04, debian, arch_cachyos, steamos)",
    )
    parser.add_argument(
        "--check-iommu",
        action="store_true",
        help="Sadece donanim DMAR/IVRS ve IOMMU DMA koruma planini JSON olarak goster",
    )
    parser.add_argument(
        "--apply-iommu-hardening",
        action="store_true",
        help="Kullanici onayi ile cekirdek IOMMU DMA koruma parametrelerini uygula",
    )
    parser.add_argument(
        "--apply-iommu-helper",
        action="store_true",
        help="Dahili root (pkexec) IOMMU önyükleyici yapilandirma yardimcisi",
    )
    parser.add_argument(
        "--kernel-snapshot-helper",
        action="store_true",
        help="Dahili root (pkexec) Ring-0 tarama yardimcisi (baslat-tara-cik)",
    )
    parser.add_argument(
        "--json-stdout",
        action="store_true",
        help="Ozet yerine ham JSON ciktisini stdout'a yaz",
    )
    return parser.parse_args(argv)


def _color(sev: str) -> str:
    return {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[93m",
        "MEDIUM": "\033[33m",
        "LOW": "\033[36m",
        "INFO": "\033[90m",
    }.get(sev, "")


RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.kernel_snapshot_helper:
        snap = priv_helper.execute_kernel_snapshot_helper(
            trace_window_ms=args.trace_ms,
            target_os=args.target_os,
        )
        print(json.dumps(snap, ensure_ascii=False))
        return 0 if snap.get("ok") else 1

    if args.apply_iommu_helper:
        res = priv_helper.execute_iommu_hardening_as_root(target_os=args.target_os)
        print(json.dumps(res, ensure_ascii=False))
        return 0 if res.get("ok") else 1

    if args.check_iommu:
        print(json.dumps(priv_helper.build_iommu_hardening_plan(target_os=args.target_os), indent=2, ensure_ascii=False))
        return 0

    if args.apply_iommu_hardening:
        res = priv_helper.apply_iommu_hardening(target_os=args.target_os)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res.get("ok") else 1

    selected: set[str] | None = None
    if args.engines.strip():
        selected = {x.strip().upper() for x in args.engines.split(",") if x.strip()}

    ctx = ScanContext(
        home_dir=args.home.expanduser().resolve(),
        live_mode=not args.offline_only,
        enable_memory_scan=not args.no_mem_scan,
        enable_kernel_lkm=bool(args.kernel_lkm),
        kernel_trace_ms=args.trace_ms,
        target_os=args.target_os,
        deep_home_scan=not args.no_deep_home,
        time_window_hours=args.hours,
    )

    def _log(msg: str) -> None:
        if not args.json_stdout:
            print(msg, file=sys.stderr)

    orchestrator.run_all_engines(ctx, selected_engines=selected, progress_cb=_log)
    payload = engine8_reporter.build_report_payload(ctx)
    paths = engine8_reporter.write_reports(ctx, args.out_dir, payload=payload)

    if args.json_stdout:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    ass = payload["assessment"]
    counts = ass["counts"]
    print("\n" + "=" * 74)
    print(f" MC SS SENTINEL SONUCU | RISK PUANI: {ass['risk_score']}/100")
    print(f" KARAR: {ass['verdict']}")
    print(
        f" CRITICAL={counts['CRITICAL']}  HIGH={counts['HIGH']}  "
        f"MEDIUM={counts['MEDIUM']}  LOW={counts['LOW']}  INFO={counts['INFO']}"
    )
    print("=" * 74)

    top = [
        f
        for f in payload["findings"]
        if f["severity"] in (Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value)
    ][:15]
    if not top:
        print(" [+] Yuksek veya kritik seviyede supheli bulgu yok.")
    else:
        for f in top:
            c = _color(f["severity"])
            print(f" {c}[{f['severity']}]{RESET} {f['rule_id']} - {f['title']}")
            if f.get("path"):
                print(f"     Yol: {f['path']}")
            if f.get("evidence"):
                print(f"     Kanit: {f['evidence'][0]}")

    print("-" * 74)
    print(f" HTML Rapor : {paths['html']}")
    print(f" TXT Rapor  : {paths['txt']}")
    print(f" JSON Rapor : {paths['json']}")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

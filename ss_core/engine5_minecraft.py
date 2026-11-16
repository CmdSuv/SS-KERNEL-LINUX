"""Engine 5: Minecraft Launchers, Configs, Keybinds, Logs, Crash Reports & Mod Cross-Verification."""

from __future__ import annotations

import gzip
import io
import json
import os
import re
import zipfile
from pathlib import Path

from .models import Confidence, Finding, ScanContext, ScanStatus, Severity
from .utils import (
    discover_minecraft_roots,
    emit_scan_progress,
    match_cheat_signatures,
    record_scan_region,
    safe_read_bytes,
    safe_read_text,
    safe_zip_read,
    statx_timestamps,
)

ENGINE_NAME = "Engine 5: Minecraft Config, Log, Keybind & Mod Dogrulama"

BUILTIN_OR_NOISE_MODIDS: frozenset[str] = frozenset(
    {
        "minecraft",
        "java",
        "fabricloader",
        "fabric-loader",
        "quilt_loader",
        "forge",
        "neoforge",
        "fml",
        "mixinextras",
        "org_lwjgl",
        "com_mojang",
    }
)

CHEAT_FOLDER_NAMES: frozenset[str] = frozenset(
    {
        "wurst",
        "meteor-client",
        "meteor",
        "liquidbounce",
        "baritone",
        "aristois",
        "doomsday",
        "rusherhack",
        "future",
        "impact",
        "thunderhack",
        "bleachhack",
        "earthhack",
        "3arthh4ck",
        "boze",
        "kami",
        "kamiblue",
        "salhack",
        "phobos",
        "vape",
    }
)

_FABRIC_LOG_MOD_RE = re.compile(r"^\s*-\s+([a-z0-9_.-]{2,64})\s+([^\s]+)\s*$", re.IGNORECASE)


def _expand_instance_dirs(mc_roots: list[tuple[str, Path]]) -> list[tuple[str, Path]]:
    instances: list[tuple[str, Path]] = []
    seen: set[Path] = set()

    def _add(label: str, d: Path) -> None:
        try:
            rp = d.resolve()
            if rp not in seen and d.is_dir():
                seen.add(rp)
                instances.append((label, d))
        except OSError:
            pass

    for label, root in mc_roots:
        _add(label, root)
        for sub_name in ("instances", "profiles", "offline"):
            sub = root / sub_name
            if not sub.is_dir():
                continue
            try:
                for inst in sub.iterdir():
                    if not inst.is_dir():
                        continue
                    for mc_sub in (".minecraft", "minecraft"):
                        if (inst / mc_sub).is_dir():
                            _add(f"{label}/{inst.name}", inst / mc_sub)
                    if any(
                        (inst / m).exists()
                        for m in ("mods", "options.txt", "optionsLC.txt", "logs", "config", "resourcepacks", "shaderpacks")
                    ):
                        _add(f"{label}/{inst.name}", inst)
                    ver_dir = inst / "versions"
                    if ver_dir.is_dir():
                        for vchild in ver_dir.iterdir():
                            if vchild.is_dir():
                                _add(f"{label}/{inst.name}/{vchild.name}", vchild)
            except OSError:
                continue
    return instances


def _collect_current_mod_ids(mods_dir: Path) -> set[str]:
    """Collect all mod IDs currently present in mods/*.jar (including JiJ nested jars)."""
    present: set[str] = set()
    if not mods_dir.is_dir():
        return present

    def _extract_from_zip(zf: zipfile.ZipFile, depth: int = 0) -> None:
        if depth > 2:
            return
        for info in zf.infolist():
            fn_low = info.filename.lower()
            if fn_low in ("fabric.mod.json", "quilt.mod.json"):
                try:
                    obj = json.loads(safe_zip_read(zf, info, 262144).decode("utf-8", errors="replace"))
                    if isinstance(obj, dict):
                        if "id" in obj:
                            present.add(str(obj["id"]).lower())
                        ql = obj.get("quilt_loader", {})
                        if isinstance(ql, dict) and "id" in ql:
                            present.add(str(ql["id"]).lower())
                        for p in obj.get("provides", []) or []:
                            if isinstance(p, str):
                                present.add(p.lower())
                            elif isinstance(p, dict) and "id" in p:
                                present.add(str(p["id"]).lower())
                except Exception:
                    pass
            elif fn_low in ("meta-inf/mods.toml", "meta-inf/neoforge.mods.toml"):
                try:
                    raw = safe_zip_read(zf, info, 262144).decode("utf-8", errors="replace")
                    for m in re.finditer(r'modId\s*=\s*["\']([^"\']+)["\']', raw):
                        present.add(m.group(1).lower())
                except Exception:
                    pass
            elif fn_low == "mcmod.info":
                try:
                    obj = json.loads(safe_zip_read(zf, info, 262144).decode("utf-8", errors="replace"))
                    if isinstance(obj, list):
                        for item in obj:
                            if isinstance(item, dict) and "modid" in item:
                                present.add(str(item["modid"]).lower())
                except Exception:
                    pass
            elif fn_low.endswith(".jar") and depth < 2 and info.file_size <= 16 * 1024 * 1024:
                try:
                    nested_raw = safe_zip_read(zf, info, 16 * 1024 * 1024)
                    with zipfile.ZipFile(io.BytesIO(nested_raw)) as nzf:
                        _extract_from_zip(nzf, depth + 1)
                except Exception:
                    pass

    try:
        for entry in mods_dir.iterdir():
            if entry.is_file() and entry.suffix.lower() == ".jar":
                present.add(entry.stem.lower())
                try:
                    with zipfile.ZipFile(entry) as zf:
                        _extract_from_zip(zf, 0)
                except Exception:
                    pass
    except OSError:
        pass
    return present


def _inspect_options_txt(ctx: ScanContext, label: str, opt_file: Path) -> None:
    if not opt_file.is_file():
        return
    txt = safe_read_text(opt_file, 1024 * 1024)
    if not txt:
        return

    cheat_keybinds: list[str] = []
    for line in txt.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k_strip = k.strip()
        v_strip = v.strip()
        k_low = k_strip.lower()

        if k_low == "gamma":
            try:
                gval = float(v_strip)
                if gval > 1.05:
                    ctx.add_finding(
                        Finding(
                            rule_id="E5-OPTIONS-FULLBRIGHT",
                            engine=ENGINE_NAME,
                            severity=Severity.HIGH if gval >= 3.0 else Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            category="Fullbright Config",
                            title=f"options.txt icinde Fullbright gamma degeri ({gval}) ({label})",
                            description="Standart oyun arayuzu gamma degerini 1.0 ile sinirlar; >1.0 elle/modla degistirilmistir.",
                            evidence=[f"gamma:{v_strip}", f"Dosya: {opt_file}"],
                            path=str(opt_file),
                        )
                    )
            except ValueError:
                pass

        elif k_low.startswith("key_"):
            if k_low in (
                "key_key.debug.overlay",
                "key_key.debug.modifier",
                "key_key.debug.reloadchunks",
                "key_key.debug.showhitboxes",
                "key_key.debug.clear_chat",
                "key_key.debug.cycle_gamemode",
                "key_key.debug.copy_location",
                "key_key.debug.reload_resourcepacks",
                "key_key.debug.pause_on_lost_focus",
                "key_key.debug.advanced_tooltips",
                "key_key.debug.inspect_chunks",
                "key_key.debug.profiling",
                "key_key.debug.creative_spectator",
                "key_key.debug.highlight_chunk_borders",
                "key_key.debug.showchunkborders",
                "key_key.debug.showhitboxes",
                "key_key.debug.copy_data",
                "key_key.debug.dump_dynamic_textures",
                "key_key.debug.dump_version_info",
                "key_key.debug.fps_chart",
                "key_key.debug.tps_chart",
                "key_key.debug.network_charts",
                "key_key.debug.render_options",
            ) or k_low.startswith("key_key.debug.light"):
                continue
            strict, high_ctx, low_ctx = match_cheat_signatures(k_strip)
            if strict or high_ctx or (len(low_ctx) >= 1 and any(x in k_low for x in ("reach", "velocity", "blink", "criticals", "scaffold"))):
                cheat_keybinds.append(f"{k_strip}:{v_strip}")

        elif k_low in ("resourcepacks", "incompatibleresourcepacks"):
            v_low = v_strip.lower()
            if any(x in v_low for x in ("xray", "x-ray", "fullbright", "cavefinder", "orefinder")):
                ctx.add_finding(
                    Finding(
                        rule_id="E5-OPTIONS-XRAY-PACK",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        category="X-Ray Config Reference",
                        title=f"options.txt icinde X-Ray / Fullbright resource pack kaydi ({label})",
                        description="Paket klasorden silinmis olsa bile options.txt secili kaynak paketi adini saklar.",
                        evidence=[f"{k_strip}:{v_strip}"],
                        path=str(opt_file),
                    )
                )

        elif k_low == "lastserver" and v_strip:
            ctx.telemetry.setdefault("minecraft_last_servers", []).append(f"{label}: {v_strip}")

    if cheat_keybinds:
        kb_blob = "\n".join(cheat_keybinds)
        s_kb, h_kb, l_kb = match_cheat_signatures(kb_blob)
        only_gamma_kb = bool(s_kb or h_kb or l_kb) and all(
            x in ("gammautils", "fullbright") for x in (s_kb + h_kb + l_kb)
        )
        ctx.add_finding(
            Finding(
                rule_id="E5-OPTIONS-CHEAT-KEYBIND",
                engine=ENGINE_NAME,
                severity=Severity.MEDIUM if only_gamma_kb else Severity.CRITICAL,
                confidence=Confidence.HIGH if only_gamma_kb else Confidence.CONFIRMED,
                category="Brightness Utility Keybind" if only_gamma_kb else "Cheat Keybind Trace",
                title=(
                    f"options.txt icinde Fullbright/Gamma tus atamasi ({label})"
                    if only_gamma_kb
                    else f"options.txt icinde silinmis/aktif hile tus atamasi ({label})"
                ),
                description="Hile/mod mods/ klasorunden silinse bile tus atamasi options.txt icinde kalir.",
                evidence=cheat_keybinds[:15],
                path=str(opt_file),
            )
        )


def _inspect_configs_and_launchers(ctx: ScanContext, label: str, inst_dir: Path) -> None:
    # 1. Known cheat leftover folders in instance root or config/
    for check_base in (inst_dir, inst_dir / "config"):
        if not check_base.is_dir():
            continue
        try:
            for entry in check_base.iterdir():
                ename_low = entry.name.lower()
                strict, high_ctx, _ = match_cheat_signatures(entry.name)
                if ename_low in CHEAT_FOLDER_NAMES or strict or high_ctx:
                    ctx.add_finding(
                        Finding(
                            rule_id="E5-CHEAT-CONFIG-ARTIFACT",
                            engine=ENGINE_NAME,
                            severity=Severity.CRITICAL if (strict or ename_low in CHEAT_FOLDER_NAMES) else Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            category="Cheat Config Leftover",
                            title=f"Minecraft konfigurasyonunda hile klasoru/dosyasi ({label}): {entry.name}",
                            description="mods/ klasoru temizlense bile hileye ait config/profil klasoru duruyor.",
                            evidence=[str(entry)],
                            path=str(entry),
                        )
                    )
        except OSError:
            continue

    # 2. Launcher JVM arguments (launcher_profiles.json, instance.cfg)
    for cfg_name in ("launcher_profiles.json", "launcher_profiles_microsoft_store.json"):
        lp = inst_dir / cfg_name
        if lp.is_file():
            txt = safe_read_text(lp, 2 * 1024 * 1024)
            if any(flag in txt.lower() for flag in ("-javaagent:", "-agentpath:", "-xbootclasspath", "disableattachmechanism")):
                hits = [
                    ln.strip()[:220]
                    for ln in txt.splitlines()
                    if any(f in ln.lower() for f in ("-javaagent", "-agentpath", "-xbootclasspath", "disableattach"))
                ]
                ctx.add_finding(
                    Finding(
                        rule_id="E5-LAUNCHER-JVM-AGENT",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="Launcher JVM Injection",
                        title=f"{cfg_name} icinde -javaagent / gizli JVM parametresi ({label})",
                        description="Launcher profil ayarlarina kalici agent/enjeksiyon argumani eklenmis.",
                        evidence=hits[:8],
                        path=str(lp),
                    )
                )

    for icfg in (
        inst_dir / "instance.cfg",
        inst_dir.parent / "instance.cfg",
        inst_dir / "prismlauncher.cfg",
        inst_dir / "multimc.cfg",
    ):
        if icfg.is_file():
            txt = safe_read_text(icfg, 256 * 1024)
            if any(f in txt.lower() for f in ("-javaagent:", "-agentpath:", "-xbootclasspath", "disableattachmechanism", "perfdisablesharedmem")):
                ctx.add_finding(
                    Finding(
                        rule_id="E5-INSTANCE-JVM-AGENT",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="Prism/MultiMC JVM Injection",
                        title=f"{icfg.name} icinde enjeksiyon JVM parametresi ({label})",
                        description="Prism/MultiMC launcher/instance ayarlarinda agent/attach engeli parametresi var.",
                        evidence=[ln.strip()[:200] for ln in txt.splitlines() if any(k in ln.lower() for k in ("jvm", "agent", "attach", "bootclasspath", "perfdisable"))][:6],
                        path=str(icfg),
                    )
                )


def _read_log_file_text(lp: Path) -> str:
    if lp.suffix.lower() == ".gz":
        raw = safe_read_bytes(lp, max_bytes=4 * 1024 * 1024)
        if not raw:
            return ""
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gzf:
                dec = gzf.read(8 * 1024 * 1024)
            return dec.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return safe_read_text(lp, max_bytes=6 * 1024 * 1024)


def _inspect_logs_and_crashes(ctx: ScanContext, label: str, inst_dir: Path) -> None:
    logs_dir = inst_dir / "logs"
    crashes_dir = inst_dir / "crash-reports"
    present_mod_ids = _collect_current_mod_ids(inst_dir / "mods")

    # Log wiping / zero-byte latest.log detection
    latest = logs_dir / "latest.log"
    if logs_dir.is_dir():
        has_gz = any(logs_dir.glob("*.log.gz"))
        if not latest.exists() and has_gz:
            ctx.add_finding(
                Finding(
                    rule_id="E5-LOG-MISSING-LATEST",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Anti-Forensics / Log Wipe",
                    title=f"logs/latest.log silinmis ({label})",
                    description="Eski .log.gz dosyalari mevcutken en guncel latest.log dosyasi yok (silinmis olabilir).",
                    evidence=[f"Klasor: {logs_dir}"],
                    path=str(logs_dir),
                )
            )
        elif latest.is_file():
            ts = statx_timestamps(latest)
            if ts and ts.size == 0:
                ctx.add_finding(
                    Finding(
                        rule_id="E5-LOG-ZEROED",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        category="Anti-Forensics / Log Wipe",
                        title=f"latest.log icerigi sifirlanmis (0 byte) ({label})",
                        description="Minecraft guncel log dosyasi bosaltilmis.",
                        evidence=[str(latest)],
                        path=str(latest),
                    )
                )

    def _safe_mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    log_files: list[Path] = []
    if logs_dir.is_dir():
        for name in ("latest.log", "debug.log", "fml-client-latest.log"):
            if (logs_dir / name).is_file():
                log_files.append(logs_dir / name)
        prism_logs = sorted(
            (p for p in logs_dir.glob("PrismLauncher-*.log") if p.is_file()),
            key=_safe_mtime,
            reverse=True,
        )[:4]
        log_files.extend(prism_logs)
        # Inspect up to 8 most recent .log.gz files
        gz_files = sorted(
            (p for p in logs_dir.glob("*.log.gz") if p.is_file()),
            key=_safe_mtime,
            reverse=True,
        )[:8]
        log_files.extend(gz_files)

    if crashes_dir.is_dir():
        crash_files = sorted(
            (p for p in crashes_dir.glob("*.txt") if p.is_file()),
            key=_safe_mtime,
            reverse=True,
        )[:8]
        log_files.extend(crash_files)

    # hs_err_pid*.log files in instance root
    hs_errs = list(inst_dir.glob("hs_err_pid*.log"))
    log_files.extend(hs_errs[:6])

    forge_mod_re = re.compile(r"(?:Found mod file .*? with mod id |Loading mod id )([a-z0-9_.-]{2,64})", re.IGNORECASE)

    for lf in log_files:
        txt = _read_log_file_text(lf)
        if not txt:
            continue

        is_latest_or_debug = lf.name in ("latest.log", "debug.log", "fml-client-latest.log")
        is_hs_err = lf.name.startswith("hs_err_pid")
        is_prism_log = lf.name.startswith("PrismLauncher-")
        logged_mods: list[str] = []
        in_fabric_mod_block = False
        cheat_lines: list[str] = []
        only_gamma_hits = True

        # Fast whole-file pre-scan eliminates 15s+ line-by-line loops on clean 4MB logs
        s_all, h_all, _ = match_cheat_signatures(txt)
        quick_needles = tuple(set(s_all) | set(h_all))

        if quick_needles or is_latest_or_debug or is_hs_err or is_prism_log:
            for line in txt.splitlines():
                low = line.lower()

                # Track FabricLoader / Forge mod list block for cross-verification against mods/
                if is_latest_or_debug:
                    if "loading " in low and " mods:" in low:
                        in_fabric_mod_block = True
                        continue
                    if in_fabric_mod_block:
                        m = _FABRIC_LOG_MOD_RE.match(line)
                        if m:
                            logged_mods.append(m.group(1).lower())
                            continue
                        elif line.strip() and not line.lstrip().startswith("-"):
                            in_fabric_mod_block = False
                    fm = forge_mod_re.search(line)
                    if fm:
                        logged_mods.append(fm.group(1).lower())

                if is_prism_log and any(
                    f in low for f in ("-javaagent:", "-agentpath:", "-xbootclasspath", "disableattachmechanism", "perfdisablesharedmem")
                ):
                    cheat_lines.append(line.strip()[:220])
                    only_gamma_hits = False
                    continue

                if quick_needles and any(needle in low for needle in quick_needles):
                    # Ignore genuine Minecraft server player chat messages only (not Java <init>/<clinit> generics)
                    is_chat_line = "[chat]" in low or (
                        re.search(r"^\[\d{2}:\d{2}:\d{2}\].*?\[[^\]]*INFO\]:\s*<[A-Za-z0-9_]{2,16}>", line) is not None
                    )
                    strict, high_ctx, _ = match_cheat_signatures(line)
                    line_hits = strict + high_ctx
                    if strict:
                        cheat_lines.append(f"[{','.join(strict)}] {line.strip()[:200]}")
                        if any(x not in ("gammautils", "fullbright") for x in line_hits):
                            only_gamma_hits = False
                    elif high_ctx and not is_chat_line:
                        if len(high_ctx) >= 2 or "-javaagent" in low or "mixin" in low or "mod" in low or "loading" in low or "dynamic library" in low:
                            cheat_lines.append(f"[{','.join(high_ctx)}] {line.strip()[:200]}")
                            if any(x not in ("gammautils", "fullbright") for x in line_hits):
                                only_gamma_hits = False
                elif is_hs_err and (".so" in low or "-javaagent" in low or "-agentpath" in low):
                    if any(t in low for t in ("/tmp/", "/dev/shm/", "agent", "cheat", "hook")):
                        cheat_lines.append(line.strip()[:200])
                        only_gamma_hits = False

        if cheat_lines:
            ctx.add_finding(
                Finding(
                    rule_id="E5-LOG-CHEAT-TRACE",
                    engine=ENGINE_NAME,
                    severity=Severity.MEDIUM if only_gamma_hits else Severity.CRITICAL,
                    confidence=Confidence.HIGH if only_gamma_hits else Confidence.CONFIRMED,
                    category="Utility Brightness Mod Trace" if only_gamma_hits else "Log / Crash Forensic Hit",
                    title=(
                        f"Oyun logunda Fullbright/Gamma mod kaydi: {lf.name} ({label})"
                        if only_gamma_hits
                        else f"Oyun log/crash dosyasinda hile/enjektor izi: {lf.name} ({label})"
                    ),
                    description="Log veya crash raporunda hile modu, ajan veya supheli native kutuphane kaydi bulundu.",
                    evidence=cheat_lines[:15],
                    path=str(lf),
                )
            )

        # Cross-verify mods logged in latest.log/debug.log vs actual mods/ folder (even if mods/ was wiped)
        if is_latest_or_debug and logged_mods:
            missing_from_disk: list[str] = []
            missing_cheat_mods: list[str] = []
            for mid in sorted(set(logged_mods)):
                if mid in BUILTIN_OR_NOISE_MODIDS or mid.startswith("fabric-") or mid.startswith("quilt_"):
                    continue
                # Check if modid or normalized variant is present in mods/
                mid_norm = mid.replace("-", "").replace("_", "")
                matched_disk = any(
                    mid == p or mid_norm == p.replace("-", "").replace("_", "") or mid in p
                    for p in present_mod_ids
                )
                if not matched_disk:
                    s, h, _ = match_cheat_signatures(mid)
                    if s or h or mid in CHEAT_FOLDER_NAMES:
                        missing_cheat_mods.append(mid)
                    else:
                        missing_from_disk.append(mid)

            if missing_cheat_mods:
                ctx.add_finding(
                    Finding(
                        rule_id="E5-LOG-MISSING-CHEAT-MOD",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="Post-Launch Deleted Cheat Mod",
                        title=f"{lf.name} icinde yuklendigi gorulen HILE modu mods/ klasorunden SILINMIS ({label})",
                        description="Log dosyasi oyunun bu modla basladigini gosteriyor ancak su an diskte yok!",
                        evidence=[f"Silinen hile modlari: {', '.join(missing_cheat_mods)}"],
                        path=str(lf),
                    )
                )
            if missing_from_disk:
                ctx.add_finding(
                    Finding(
                        rule_id="E5-LOG-MODLIST-MISMATCH",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="Post-Launch Deleted Mod",
                        title=f"{lf.name} listesinde olup mods/ klasorunde bulunmayan modlar ({label})",
                        description="Son oturumda yuklenen bazi modlar su an mods/ klasorunden kaldirilmis.",
                        evidence=[f"Diskte eksik mod ID'leri: {', '.join(missing_from_disk[:15])}"],
                        path=str(lf),
                    )
                )


def _inspect_home_hs_err_logs(ctx: ScanContext) -> None:
    hs_candidates: list[Path] = []
    for base in (ctx.home_dir, ctx.sys_path("/tmp")):
        if base.is_dir():
            try:
                hs_candidates.extend(sorted(base.glob("hs_err_pid*.log"))[:6])
            except OSError:
                pass
    for hf in hs_candidates:
        txt = _read_log_file_text(hf)
        if not txt:
            continue
        s_all, h_all, _ = match_cheat_signatures(txt)
        hits: list[str] = []
        for line in txt.splitlines():
            low = line.lower()
            if s_all or h_all:
                s, h, _ = match_cheat_signatures(line)
                if s or h:
                    hits.append(line.strip()[:200])
            elif (".so" in low or "-javaagent" in low or "-agentpath" in low) and any(
                t in low for t in ("/tmp/", "/dev/shm/", "agent", "cheat", "hook")
            ):
                hits.append(line.strip()[:200])
        if hits:
            ctx.add_finding(
                Finding(
                    rule_id="E5-LOG-CHEAT-TRACE",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="JVM Crash Forensic Hit",
                    title=f"JVM crash raporunda (hs_err) hile/enjektor izi: {hf.name}",
                    description="Kullanici ev/tmp dizinindeki hs_err_pid crash dosyasinda hile veya native enjeksiyon izi goruldu.",
                    evidence=hits[:12],
                    path=str(hf),
                )
            )


def run(ctx: ScanContext) -> None:
    try:
        emit_scan_progress(ctx, 0.08, "Minecraft kurulumlari ve profil dizinleri kesfediliyor...")
        mc_roots = discover_minecraft_roots(ctx)
        instances = _expand_instance_dirs(mc_roots)
        ctx.telemetry["minecraft_instances"] = [f"{lbl} ({p})" for lbl, p in instances]
        for lbl, inst_dir in instances:
            record_scan_region(ctx, "E5", f"{lbl}: {inst_dir} (options/config/logs)")

        n_inst = max(1, len(instances))
        for idx, (label, inst_dir) in enumerate(instances):
            emit_scan_progress(
                ctx,
                0.15 + 0.72 * (idx / n_inst),
                f"Minecraft kurulumu taraniyor ({idx + 1}/{len(instances)}): {label}",
            )
            _inspect_options_txt(ctx, label, inst_dir / "options.txt")
            _inspect_options_txt(ctx, label, inst_dir / "optionsLC.txt")
            _inspect_configs_and_launchers(ctx, label, inst_dir)
            _inspect_logs_and_crashes(ctx, label, inst_dir)
        emit_scan_progress(ctx, 0.90, "JVM hs_err_pid cokme kayitlari kontrol ediliyor...")
        _inspect_home_hs_err_logs(ctx)
        record_scan_region(ctx, "E5", f"{ctx.home_dir}/hs_err_pid*.log")
        ctx.set_coverage("E5.minecraft", ScanStatus.COMPLETED, f"{len(instances)} instance(s) audited")
        emit_scan_progress(ctx, 1.0, "Minecraft config ve log dogrulamasi tamamlandi.")
    except Exception as exc:
        if exc.__class__.__name__ == "ScanCancelledError":
            raise
        ctx.set_coverage("E5.minecraft", ScanStatus.ERROR, str(exc))
        ctx.add_error(ENGINE_NAME, f"Beklenmeyen hata: {exc}")

"""Engine 3: Input Devices, /dev/uinput, Wayland/X11 Macros & Hardware Remapper Analyzer."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from .models import Confidence, Finding, ScanContext, ScanStatus, Severity
from .signatures import HARDWARE_CONFIG_APPS
from .utils import (
    emit_scan_progress,
    iter_files_safe,
    record_scan_region,
    run_trusted_cmd,
    safe_read_text,
)

ENGINE_NAME = "Engine 3: Girdi, /dev/uinput, Makro & Donanim Analizi"

VIRTUAL_INPUT_PATTERNS: tuple[str, ...] = (
    "ydotool",
    "dotool",
    "input-remapper",
    "py-evdev",
    "uinput",
    "xclicker",
    "autoclick",
    "virtual mouse",
    "virtual pointer",
)

MACRO_SCRIPT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("python-evdev/uinput", re.compile(r"\b(?:evdev|UInput|uinput|BTN_LEFT|BTN_RIGHT|EV_KEY|UI_DEV_CREATE|evemu-event)\b")),
    ("pynput/pyautogui", re.compile(r"\b(?:pynput|pyautogui|pydirectinput|mouse\.click)\b")),
    (
        "xdotool/ydotool/dotool",
        re.compile(
            r"\b(?:xdotool|ydotool|dotool|wtype)\s*(?:\s|[\"'],\s*[\"'])(?:click|mousedown|mouseup|key|keydown|keyup|type|mousemove)\b"
            r"|\|\s*(?:dotool|ydotool)\b"
            r"|(?:subprocess|os\.system|Popen)\b[^\n]*(?:xdotool|ydotool|dotool|wtype)"
        ),
    ),
    (
        "XTest-API",
        re.compile(
            r"\b(?:XTestFakeButtonEvent|XTestFakeKeyEvent|XSendEvent|xtest\.fake_input)\b"
            r"|from\s+Xlib\.ext\s+import\s+[^\n]*\bxtest\b"
        ),
    ),
    ("fast-click-loop", re.compile(r"(?:sleep|usleep|nanosleep)\s*\(?\s*0\.0[0-8]")),
)

SCRIPT_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".sh", ".bash", ".zsh", ".js", ".lua", ".c", ".cpp", ".rs", ".go", ".pl", ""}
)


def _check_virtual_input_devices(ctx: ScanContext) -> None:
    dev_file = ctx.proc_root / "bus/input/devices"
    text = safe_read_text(dev_file, 512 * 1024)
    if text:
        blocks = text.split("\n\n")
        suspicious_devs: list[str] = []
        sysfs_virtual_devs: list[str] = []
        for blk in blocks:
            name_line = ""
            phys_line = ""
            sysfs_line = ""
            handlers_line = ""
            for ln in blk.splitlines():
                if ln.startswith("N: Name="):
                    name_line = ln[8:].strip().strip('"')
                elif ln.startswith("P: Phys="):
                    phys_line = ln[8:].strip()
                elif ln.startswith("S: Sysfs="):
                    sysfs_line = ln[9:].strip()
                elif ln.startswith("H: Handlers="):
                    handlers_line = ln[12:].strip()
            low = f"{name_line} {phys_line}".lower()
            if any(p in low for p in VIRTUAL_INPUT_PATTERNS):
                suspicious_devs.append(f"{name_line} (Phys={phys_line}, Handlers={handlers_line})")
            elif "/devices/virtual/input/" in sysfs_line.lower():
                h_low = handlers_line.lower()
                n_low = name_line.lower()
                if ("mouse" in h_low or "kbd" in h_low or "event" in h_low) and not any(
                    benign in n_low
                    for benign in ("pcspkr", "thinkpad", "ideapad", "avrcp", "power button", "sleep button", "lid switch", "video bus")
                ):
                    sysfs_virtual_devs.append(
                        f"{name_line} (Sysfs={sysfs_line}, Handlers={handlers_line})"
                    )

        if suspicious_devs:
            ctx.add_finding(
                Finding(
                    rule_id="E3-VIRTUAL-UINPUT-DEVICE",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Virtual Input / Macro",
                    title="Kernelde aktif sanal uinput / makro girdi aygiti tespit edildi",
                    description="Wayland/X11 uzerinde yapay fare tiklamasi veya tus basimi ureten sanal aygit mevcut.",
                    evidence=suspicious_devs,
                    path=str(dev_file),
                )
            )
        if sysfs_virtual_devs:
            ctx.add_finding(
                Finding(
                    rule_id="E3-VIRTUAL-UINPUT-SYSFS",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Disguised Virtual Input",
                    title="Sysfs /devices/virtual/input altinda gizlenmis sanal fare/klavye aygiti",
                    description="Ismi gercek donanim gibi maskelenmis ancak Sysfs uzerinde virtual input (uinput) olan aygit bulundu.",
                    evidence=sysfs_virtual_devs,
                    path=str(dev_file),
                )
            )

    uinput_dev = ctx.sys_path("/dev/uinput")
    if uinput_dev.exists():
        try:
            st = os.stat(uinput_dev)
            mode = stat.S_IMODE(st.st_mode)
            writable = os.access(uinput_dev, os.W_OK)
            ctx.telemetry["uinput_mode"] = oct(mode)
            ctx.telemetry["uinput_user_writable"] = writable
            if writable or (mode & 0o006) == 0o006:
                ctx.add_finding(
                    Finding(
                        rule_id="E3-UINPUT-WRITABLE",
                        engine=ENGINE_NAME,
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        category="Input Surface",
                        title=f"/dev/uinput mevcut kullanici tarafindan yazilabilir ({oct(mode)})",
                        description="Root yetkisi olmadan kullanici alani uinput autoclicker calistirilabilir durumda.",
                        evidence=[f"/dev/uinput mode={oct(mode)}, writable={writable}"],
                        path=str(uinput_dev),
                    )
                )
        except OSError:
            pass

    # Check ydotoold sockets
    uid = os.getuid()
    sock_candidates = [
        ctx.sys_path("/tmp/.ydotool_socket"),
        ctx.sys_path(f"/run/user/{uid}/.ydotool_socket"),
    ]
    for sock in sock_candidates:
        if sock.exists():
            ctx.add_finding(
                Finding(
                    rule_id="E3-YDOTOOL-SOCKET",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    category="Macro Daemon",
                    title="Aktif ydotoold kontrol soketi tespit edildi",
                    description="ydotool arka plan servisi Wayland altinda otomatik fare/klavye enjeksiyonu saglar.",
                    evidence=[f"Socket: {sock}"],
                    path=str(sock),
                )
            )


def _check_input_remapper(ctx: ScanContext) -> None:
    h = ctx.home_dir
    ir_dirs = [h / ".config/input-remapper-2", h / ".config/input-remapper"]
    for ird in ir_dirs:
        if not ird.is_dir():
            continue
        presets = list(ird.rglob("*.json"))
        for pf in presets:
            txt = safe_read_text(pf, 512 * 1024)
            if not txt.strip():
                continue
            low = txt.lower()
            is_config = pf.name == "config.json"
            if is_config:
                try:
                    cfg = json.loads(txt)
                    autoload = cfg.get("autoload", {})
                    if autoload:
                        ctx.add_finding(
                            Finding(
                                rule_id="E3-INPUT-REMAPPER-AUTOLOAD",
                                engine=ENGINE_NAME,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                category="Input Remapper",
                                title="input-remapper otomatik yuklenen (autoload) profil yapilandirmasi",
                                description="Oturum acildiginda otomatik aktif edilen tus/fare haritalama profilleri var.",
                                evidence=[f"Autoload: {json.dumps(autoload)[:260]}"],
                                path=str(pf),
                            )
                        )
                except Exception:
                    pass
                continue

            macro_indicators = [
                k
                for k in ("repeat(", "hold(", "wait(", "btn_left", "mouse(", "left_click", "key(btn_left", "modify(")
                if k in low
            ]
            if macro_indicators or "minecraft" in str(pf).lower():
                ctx.add_finding(
                    Finding(
                        rule_id="E3-INPUT-REMAPPER-MACRO",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL if ("repeat(" in low or "wait(" in low or "btn_left" in low) else Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        category="Input Remapper Macro",
                        title=f"input-remapper makro/fare tekrar preset'i tespit edildi: {pf.name}",
                        description="Kayitli input-remapper preset'i otomatik tiklama veya tus makrosu iceriyor.",
                        evidence=[f"Gostergeler: {', '.join(macro_indicators)}", f"Ozet: {txt[:300]}"],
                        path=str(pf),
                    )
                )


def _check_solaar_razer_autokey_xclicker(ctx: ScanContext) -> None:
    h = ctx.home_dir

    # 1. Solaar (Logitech)
    solaar_dirs = [
        h / ".config/solaar",
        h / ".var/app/io.github.pwr_solaar.solaar/config/solaar",
    ]
    for sd in solaar_dirs:
        if not sd.is_dir():
            continue
        for fname in ("rules.yaml", "config.yaml", "config.json"):
            rf = sd / fname
            if not rf.is_file():
                continue
            txt = safe_read_text(rf, 512 * 1024)
            low = txt.lower()
            hits = [k for k in ("mouseclick", "keypress", "execute", "btn_left", "button", "repeat") if k in low]
            if fname == "rules.yaml" and hits:
                ctx.add_finding(
                    Finding(
                        rule_id="E3-SOLAAR-RULE",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="Hardware Macro (Solaar)",
                        title=f"Solaar ozel fare/tus kurali tespit edildi ({fname})",
                        description="Logitech Solaar rule motorunda ozel tus basimi / tiklama / komut tetikleyici tanimli.",
                        evidence=[f"Anahtarlar: {', '.join(hits)}", txt[:300]],
                        path=str(rf),
                    )
                )

    # 2. Polychromatic / OpenRazer (avoid RGB lighting effect delay/repeat false positives)
    for pdir in (h / ".config/polychromatic", h / ".local/share/openrazer"):
        if not pdir.is_dir():
            continue
        for mf in pdir.rglob("*"):
            if mf.is_file() and mf.suffix.lower() in (".json", ".xml", ".yml", ".yaml"):
                txt = safe_read_text(mf, 256 * 1024)
                low_txt = txt.lower()
                is_effect_only = "effects" in mf.parts and "macro" not in low_txt and "click" not in low_txt
                has_macro_sig = (
                    "macro" in low_txt
                    or "turbo" in low_txt
                    or "btn_left" in low_txt
                    or "button_press" in low_txt
                    or ("click" in low_txt and ("delay" in low_txt or "repeat" in low_txt))
                )
                if has_macro_sig and not is_effect_only:
                    ctx.add_finding(
                        Finding(
                            rule_id="E3-RAZER-MACRO",
                            engine=ENGINE_NAME,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="Hardware Macro (Razer)",
                            title=f"Polychromatic/OpenRazer makro yapilandirmasi: {mf.name}",
                            description="Razer fare/klavye profilinde makro veya tıklama tekrar tanimi bulundu.",
                            evidence=[txt[:260]],
                            path=str(mf),
                        )
                    )

    # 3. XClicker / AutoKey / xbindkeys / sxhkd / KDE shortcuts
    xclicker_cfg = h / ".config/xclicker"
    if xclicker_cfg.is_dir():
        ctx.add_finding(
            Finding(
                rule_id="E3-XCLICKER-CONFIG",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="AutoClicker Config",
                title="XClicker yapilandirma klasoru tespit edildi",
                description="Linux autoclicker programi XClicker daha once bu sistemde calistirilmis.",
                evidence=[str(xclicker_cfg)],
                path=str(xclicker_cfg),
            )
        )

    hotkey_files = [
        h / ".xbindkeysrc",
        h / ".config/sxhkd/sxhkdrc",
        h / ".config/kglobalshortcutsrc",
        h / ".config/khotkeysrc",
        h / ".config/hypr/hyprland.conf",
        h / ".config/sway/config",
    ]
    autokey_dir = h / ".config/autokey/data"
    if autokey_dir.is_dir():
        hotkey_files.extend(autokey_dir.rglob("*.py"))
        hotkey_files.extend(autokey_dir.rglob("*.json"))

    for hf in hotkey_files:
        if not hf.is_file():
            continue
        txt = safe_read_text(hf, 512 * 1024)
        low = txt.lower()
        if any(
            k in low
            for k in (
                "xdotool",
                "ydotool",
                "dotool",
                "wtype",
                "evemu-event",
                "xclicker",
                "autoclick",
                "mouse.click_relative",
                "xtest.fake_input",
            )
        ):
            lines = [
                ln.strip()[:180]
                for ln in txt.splitlines()
                if any(
                    k in ln.lower()
                    for k in ("xdotool", "ydotool", "dotool", "wtype", "evemu-event", "xclicker", "autoclick", "click", "xtest.fake_input")
                )
            ]
            ctx.add_finding(
                Finding(
                    rule_id="E3-HOTKEY-MACRO",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    category="Hotkey Macro Binding",
                    title=f"Kisayol / AutoKey dosyasinda tiklama makrosu komutu: {hf.name}",
                    description="Klavye/fare kisayoluna yapay tiklama veya makro komutu atanmis.",
                    evidence=lines[:10],
                    path=str(hf),
                )
            )


def _scan_macro_scripts(ctx: ScanContext) -> None:
    h = ctx.home_dir
    scan_dirs = [
        h / ".local/bin",
        h / "bin",
        h / "Desktop",
        h / "Downloads",
        h / "Documents",
        h / ".config/autostart",
        ctx.sys_path("/tmp"),
        ctx.sys_path("/dev/shm"),
    ]
    candidates = list(iter_files_safe(scan_dirs, max_depth=3)) + list(iter_files_safe([h], max_depth=1))
    seen_scripts: set[Path] = set()
    skip_dev_parts = {"node_modules", ".venv", "venv", "__pycache__", ".git", "site-packages"}
    for fpath in candidates:
        if fpath.suffix.lower() not in SCRIPT_EXTENSIONS:
            continue
        if any(part in skip_dev_parts for part in fpath.parts):
            continue
        try:
            rp = fpath.resolve()
            if rp in seen_scripts:
                continue
            seen_scripts.add(rp)
            if fpath.stat().st_size > 512 * 1024:
                continue
        except OSError:
            continue

        txt = safe_read_text(fpath, 512 * 1024)
        if not txt:
            continue
        matched_tags: list[str] = []
        for tag, pat in MACRO_SCRIPT_PATTERNS:
            if pat.search(txt):
                matched_tags.append(tag)
        if not matched_tags:
            continue

        low_txt = txt.lower()
        is_fast_loop = "fast-click-loop" in matched_tags
        has_api = any(t != "fast-click-loop" for t in matched_tags)
        has_click_ctx = is_fast_loop and any(
            w in low_txt for w in ("click", "button", "mouse", "btn_", "fake_input", "/dev/uinput", "ioctl")
        )
        if has_api or has_click_ctx:
            if has_api:
                sev = Severity.CRITICAL if (is_fast_loop or "uinput" in low_txt or "click" in low_txt) else Severity.HIGH
            else:
                sev = Severity.MEDIUM
            ctx.add_finding(
                Finding(
                    rule_id="E3-MACRO-SCRIPT",
                    engine=ENGINE_NAME,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    category="Custom Macro / AutoClicker Script",
                    title=f"Otomasyon / makro / autoclicker scripti tespit edildi: {fpath.name}",
                    description="Kullanici dizininde veya /tmp icinde yapay fare/klavye girdisi ureten kod bulundu.",
                    evidence=[f"Tespit edilen API'ler: {', '.join(matched_tags)}", f"Yol: {fpath}"],
                    path=str(fpath),
                )
            )


def _check_live_services_and_ratbag(ctx: ScanContext) -> None:
    if not ctx.live_mode:
        return
    # Installed / running hardware macro apps
    rc, units_out, _ = run_trusted_cmd(
        ["systemctl", "--user", "list-units", "--state=active", "--no-legend", "--no-pager"],
        timeout=3.0,
    )
    if rc == 0 and units_out:
        for ln in units_out.splitlines():
            low = ln.lower()
            if any(k in low for k in ("ydotool", "dotool", "input-remapper", "autokey")):
                ctx.add_finding(
                    Finding(
                        rule_id="E3-SYSTEMD-MACRO-SVC",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        category="Active Macro Service",
                        title="Aktif kullanici makro servisi calisiyor",
                        description="systemd user altinda aktif bir makro/uinput otomasyon servisi bulundu.",
                        evidence=[ln.strip()],
                    )
                )

    rc_rb, rb_out, _ = run_trusted_cmd(["ratbagctl", "list"], timeout=3.0)
    if rc_rb == 0 and rb_out.strip():
        ctx.telemetry["ratbag_devices"] = rb_out.strip().splitlines()
        # Inspect buttons if device exists
        for dev_ln in rb_out.splitlines():
            dev_id = dev_ln.split(":", 1)[0].strip()
            if not dev_id:
                continue
            rc_info, info_out, _ = run_trusted_cmd(["ratbagctl", dev_id, "info"], timeout=3.0)
            if rc_info == 0 and info_out:
                macro_lines = [
                    l.strip()
                    for l in info_out.splitlines()
                    if "macro" in l.lower() or "special" in l.lower()
                ]
                if macro_lines:
                    ctx.add_finding(
                        Finding(
                            rule_id="E3-RATBAG-ONBOARD-MACRO",
                            engine=ENGINE_NAME,
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            category="Hardware Onboard Macro",
                            title=f"Fare uzerinde kayitli ratbag/Piper makrosu tespit edildi ({dev_id})",
                            description="Farenin kendi hafizasinda makro tusu tanimli.",
                            evidence=macro_lines[:10],
                        )
                    )


def run(ctx: ScanContext) -> None:
    try:
        emit_scan_progress(ctx, 0.15, "/proc/bus/input/devices ve /dev/uinput kontrol ediliyor...")
        _check_virtual_input_devices(ctx)
        record_scan_region(ctx, "E3", f"{ctx.proc_root / 'bus/input/devices'} ve /dev/uinput")
        emit_scan_progress(ctx, 0.35, "input-remapper profilleri taraniyor...")
        _check_input_remapper(ctx)
        record_scan_region(ctx, "E3", f"{ctx.home_dir}/.config/input-remapper*")
        emit_scan_progress(ctx, 0.55, "Solaar, OpenRazer, AutoKey ve XClicker uygulamalari taraniyor...")
        _check_solaar_razer_autokey_xclicker(ctx)
        record_scan_region(ctx, "E3", "Solaar, OpenRazer, AutoKey, XClicker, Wayland/X11 makro ayarlari")
        emit_scan_progress(ctx, 0.78, "Kullanici makro scriptleri taraniyor...")
        _scan_macro_scripts(ctx)
        emit_scan_progress(ctx, 0.92, "Ratbag ve sistem girdi servisleri kontrol ediliyor...")
        _check_live_services_and_ratbag(ctx)
        record_scan_region(ctx, "E3", "ratbagctl / Piper, udev ve kullanici makro scriptleri")
        ctx.set_coverage("E3.input", ScanStatus.COMPLETED, "Input devices & macro configs inspected")
        emit_scan_progress(ctx, 1.0, "Girdi ve makro analizi tamamlandi.")
    except Exception as exc:
        if exc.__class__.__name__ == "ScanCancelledError":
            raise
        ctx.set_coverage("E3.input", ScanStatus.ERROR, str(exc))
        ctx.add_error(ENGINE_NAME, f"Beklenmeyen hata: {exc}")

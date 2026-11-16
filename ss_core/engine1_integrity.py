"""Engine 1: Anti-Forensic & System Integrity Auditor."""

from __future__ import annotations

import math
import os
import re
import stat
from pathlib import Path

from .distro_profiles import resolve_profile
from .models import Confidence, Finding, ScanContext, ScanStatus, Severity
from .signatures import ANTI_FORENSIC_CMD_RE
from .utils import (
    emit_scan_progress,
    fmt_ns,
    match_cheat_signatures,
    record_scan_region,
    run_trusted_cmd,
    safe_read_bytes,
    safe_read_tail_text,
    safe_read_text,
    statx_timestamps,
)

ENGINE_NAME = "Engine 1: Sistem & Anti-Adli Butunluk"

CRITICAL_SHADOW_TARGETS: frozenset[str] = frozenset(
    {
        "ps",
        "pgrep",
        "pstree",
        "top",
        "htop",
        "btop",
        "killall",
        "jps",
        "jcmd",
        "lsof",
        "ss",
        "ip",
        "ls",
        "find",
        "stat",
        "getfattr",
        "strings",
        "fd",
        "rg",
        "journalctl",
        "sudo",
        "pkexec",
        "java",
    }
)

SHELL_RC_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity, str], ...] = (
    (
        "E1-RC-LDPRELOAD",
        re.compile(r"^\s*(?:export\s+|set\s+-[a-z]*x[a-z]*\s+)?LD_PRELOAD\s*(?:=|\s+[^\s#])", re.MULTILINE),
        Severity.CRITICAL,
        "Kabuk baslangic dosyasinda LD_PRELOAD enjeksiyon tanimi",
    ),
    (
        "E1-RC-LDAUDIT",
        re.compile(r"^\s*(?:export\s+|set\s+-[a-z]*x[a-z]*\s+)?LD_AUDIT\s*(?:=|\s+[^\s#])", re.MULTILINE),
        Severity.CRITICAL,
        "Kabuk baslangic dosyasinda LD_AUDIT enjeksiyon tanimi",
    ),
    (
        "E1-RC-JAVA-TOOL-OPTS",
        re.compile(
            r"^\s*(?:export\s+|set\s+-[a-z]*x[a-z]*\s+)?(?:JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS)\s*(?:=|\s+).*(?:-javaagent|-agentpath|-Xbootclasspath|DisableAttachMechanism|PerfDisableSharedMem)",
            re.MULTILINE | re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Global Java ortam degiskeninde gizli agent / attach engeli",
    ),
    (
        "E1-RC-HIST-DISABLE",
        re.compile(
            r"^\s*(?:(?:export\s+|set\s+-[a-z]*x[a-z]*\s+)?(?:HISTSIZE=0|HISTFILESIZE=0|HISTFILE=/dev/null|unset\s+HISTFILE)|set\s+\+o\s+history\b)",
            re.MULTILINE,
        ),
        Severity.HIGH,
        "Terminal komut gecmisi devre disi birakilmis",
    ),
    (
        "E1-RC-ALIAS-HIJACK",
        re.compile(
            r"^\s*(?:(?:alias|function)\s+(?:ps|pgrep|pstree|top|htop|btop|killall|lsof|ss|ip|ls|jps|jcmd|find|stat|rg|fd|strings|getfattr|journalctl|java)\s*(?:=|\s|\()|(?:ps|pgrep|pstree|top|htop|btop|killall|lsof|ss|ip|ls|jps|jcmd|find|stat|rg|fd|strings|getfattr|journalctl|java)\s*\(\s*\))",
            re.MULTILINE,
        ),
        Severity.CRITICAL,
        "Sistem/SS komutu shell alias/fonksiyon ile manipule edilmis",
    ),
)


def _check_uptime(ctx: ScanContext) -> None:
    uptime_path = ctx.proc_root / "uptime"
    text = safe_read_text(uptime_path, max_bytes=1024).strip()
    if not text:
        return
    try:
        uptime_sec = float(text.split()[0])
    except (ValueError, IndexError):
        return

    ctx.telemetry["uptime_seconds"] = round(uptime_sec, 1)
    mins = uptime_sec / 60.0
    if uptime_sec < 900:
        ctx.add_finding(
            Finding(
                rule_id="E1-REBOOT-RECENT",
                engine=ENGINE_NAME,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category="Anti-Forensics / Reboot",
                title=f"Sistem cok yakin zamanda yeniden baslatilmis ({mins:.1f} dk)",
                description=(
                    "Bilgisayar SS kontrolunden hemen once yeniden baslatilmissa RAM icindeki "
                    "ghost client ve gecici /tmp enjeksiyon izleri silinmis olabilir."
                ),
                evidence=[f"/proc/uptime = {uptime_sec:.1f}s ({mins:.1f} dakika)"],
                path=str(uptime_path),
                recommendation="Loglar, disk, tarayici gecmisi ve coredump/journal kayitlarini sikilastirin.",
            )
        )
    elif uptime_sec < 2700:
        ctx.add_finding(
            Finding(
                rule_id="E1-REBOOT-MODERATE",
                engine=ENGINE_NAME,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category="Anti-Forensics / Reboot",
                title=f"Sistem yakin zamanda yeniden baslatilmis ({mins:.1f} dk)",
                description="45 dakikanin altinda calisma suresi tespit edildi.",
                evidence=[f"/proc/uptime = {uptime_sec:.1f}s ({mins:.1f} dakika)"],
                path=str(uptime_path),
            )
        )


def _check_clock_and_session(ctx: ScanContext) -> None:
    ptrace_path = ctx.proc_root / "sys/kernel/yama/ptrace_scope"
    if ptrace_path.is_file():
        val = safe_read_text(ptrace_path, 64).strip()
        ctx.telemetry["ptrace_scope"] = val
        if val == "0":
            ctx.telemetry["ptrace_note"] = "ptrace_scope=0 (enjektorler ve RAM okuyucular icin acik)"

    session_type = os.environ.get("XDG_SESSION_TYPE", "unknown")
    ctx.telemetry["session_type"] = session_type
    ctx.telemetry["wayland_display"] = os.environ.get("WAYLAND_DISPLAY", "")
    ctx.telemetry["x11_display"] = os.environ.get("DISPLAY", "")

    # Check connected monitors directly from sysfs DRM
    drm_dir = ctx.sys_path("/sys/class/drm")
    connected_monitors: list[str] = []
    if drm_dir.is_dir():
        try:
            for card_entry in sorted(drm_dir.iterdir()):
                status_file = card_entry / "status"
                if status_file.is_file():
                    st = safe_read_text(status_file, 64).strip().lower()
                    if st == "connected":
                        connected_monitors.append(card_entry.name)
        except OSError:
            pass
    ctx.telemetry["connected_monitors"] = connected_monitors
    if len(connected_monitors) > 1:
        ctx.add_finding(
            Finding(
                rule_id="E1-MULTI-MONITOR",
                engine=ENGINE_NAME,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category="Session Integrity",
                title=f"Birden fazla fiziksel monitor bagli ({len(connected_monitors)} adet)",
                description=(
                    "Oyuncu ikinci ekranda hile menusu, autoclicker veya tarayici gizliyor olabilir."
                ),
                evidence=[f"Bagli DRM cikislari: {', '.join(connected_monitors)}"],
                recommendation="SS sirasinda tum ekranlari paylasmasini isteyin.",
            )
        )

    # Check DMI / virtualization
    dmi_prod = ctx.sys_path("/sys/class/dmi/id/product_name")
    if dmi_prod.is_file():
        prod = safe_read_text(dmi_prod, 256).strip()
        ctx.telemetry["hardware_product"] = prod
        vm_markers = ("virtualbox", "vmware", "qemu", "kvm", "bochs", "xen", "hyper-v")
        if any(m in prod.lower() for m in vm_markers):
            ctx.add_finding(
                Finding(
                    rule_id="E1-VM-DETECTED",
                    engine=ENGINE_NAME,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="Environment Integrity",
                    title=f"Sanal makine (VM) ortami tespit edildi: {prod}",
                    description="Kontrol sanal makine icinde yapiliyor olabilir (hostta baska arac calisabilir).",
                    evidence=[f"DMI product_name: {prod}"],
                    path=str(dmi_prod),
                )
            )

    if ctx.live_mode:
        rc, out, _ = run_trusted_cmd(["timedatectl", "show"], timeout=3.0)
        if rc == 0 and out:
            kv: dict[str, str] = {}
            for line in out.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    kv[k.strip()] = v.strip()
            ctx.telemetry["timedatectl"] = kv
            ntp = kv.get("NTP", "").lower()
            synced = kv.get("NTPSynchronized", "").lower()
            if ntp == "no" or synced == "no":
                ctx.add_finding(
                    Finding(
                        rule_id="E1-NTP-UNSYNC",
                        engine=ENGINE_NAME,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="Anti-Forensics / Clock",
                        title="Sistem saati NTP senkronizasyonu kapali veya senkronize degil",
                        description=(
                            "NTP kapatilarak sistem saati geri/ileri alinmis ve dosya/log tarihleri "
                            "manipule edilmis olabilir."
                        ),
                        evidence=[f"NTP={kv.get('NTP')}", f"NTPSynchronized={kv.get('NTPSynchronized')}"],
                        recommendation="statx btime/ctime ve journalctl zaman atlamalarini kontrol edin.",
                    )
                )


def _check_shell_histories(ctx: ScanContext) -> None:
    h = ctx.home_dir
    now = ctx.current_epoch()
    window_sec = ctx.time_window_hours * 3600.0
    hist_files = [
        h / ".bash_history",
        h / ".zsh_history",
        h / ".local/share/fish/fish_history",
        h / ".python_history",
    ]
    existing_any = False
    populated_hist_count = sum(
        1
        for hf in hist_files
        if hf.exists()
        and not hf.is_symlink()
        and (st_pre := statx_timestamps(hf)) is not None
        and st_pre.size > 0
    )
    for hf in hist_files:
        if not hf.exists() and not hf.is_symlink():
            continue
        existing_any = True
        try:
            if hf.is_symlink():
                target = os.readlink(hf)
                if target == "/dev/null":
                    ctx.add_finding(
                        Finding(
                            rule_id="E1-HIST-DEVNULL",
                            engine=ENGINE_NAME,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            category="Anti-Forensics / History Wipe",
                            title=f"Kabuk gecmis dosyasi /dev/null'a baglanmis: {hf.name}",
                            description="Komut gecmisinin kaydedilmesini engellemek icin symlink yapilmis.",
                            evidence=[f"{hf} -> {target}"],
                            path=str(hf),
                        )
                    )
                continue
        except OSError:
            continue

        ts = statx_timestamps(hf)
        if ts is None:
            continue
        mtime_age = now - (ts.mtime_ns / 1e9)
        ctime_age = now - (ts.ctime_ns / 1e9)

        if ts.size == 0:
            all_wiped = populated_hist_count == 0
            ctx.add_finding(
                Finding(
                    rule_id="E1-HIST-ZERO",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH if all_wiped else Severity.LOW,
                    confidence=Confidence.HIGH if all_wiped else Confidence.MEDIUM,
                    category="Anti-Forensics / History Wipe",
                    title=f"Kabuk gecmisi tamamen sifirlanmis (0 byte): {hf.name}",
                    description=(
                        "Tum kabuk gecmis dosyalari bos (kontrol oncesi terminal temizlenmis olabilir)."
                        if all_wiped
                        else "Alternatif kabuk gecmisleri dolu ancak bu dosya 0 byte (kullanilmayan kabuk iskeleti veya tekil temizleme)."
                    ),
                    evidence=[
                        "Boyut: 0 byte",
                        f"mtime: {fmt_ns(ts.mtime_ns)}",
                        f"ctime: {fmt_ns(ts.ctime_ns)}",
                        f"dolu_gecmis_sayisi: {populated_hist_count}",
                    ],
                    path=str(hf),
                )
            )
            continue

        if ts.size < 64 and mtime_age <= window_sec:
            ctx.add_finding(
                Finding(
                    rule_id="E1-HIST-TRUNCATED",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    category="Anti-Forensics / History Wipe",
                    title=f"Kabuk gecmisi yakin zamanda kirpilmis olabilir ({ts.size} byte)",
                    description="Yakin zamanli degisiklikle birlikte gecmis dosyasi asiri kucuk.",
                    evidence=[f"Boyut: {ts.size} byte", f"mtime: {fmt_ns(ts.mtime_ns)}"],
                    path=str(hf),
                )
            )

        # Timestomp check on history file: ctime recent while mtime claims > 24h older
        if ctime_age <= window_sec and (ts.ctime_ns - ts.mtime_ns) > 86400 * 1_000_000_000:
            ctx.add_finding(
                Finding(
                    rule_id="E1-HIST-TIMESTOMP",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Timestomping",
                    title=f"Kabuk gecmisinde tarih sahteciligi (Timestomping): {hf.name}",
                    description="Dosyanin inode degisiklik saati (ctime) cok yeni olmasina ragmen mtime eski tarihe cekilmis.",
                    evidence=[f"mtime: {fmt_ns(ts.mtime_ns)}", f"ctime: {fmt_ns(ts.ctime_ns)}"],
                    path=str(hf),
                )
            )

        content = safe_read_tail_text(hf, max_bytes=2 * 1024 * 1024)
        af_hits: list[str] = []
        cheat_hits: list[str] = []
        for idx, line in enumerate(content.splitlines(), 1):
            sline = line.strip()
            if not sline:
                continue
            if ANTI_FORENSIC_CMD_RE.search(sline):
                af_hits.append(f"Satir {idx}: {sline[:180]}")
            strict, high_ctx, _ = match_cheat_signatures(sline)
            if strict or high_ctx:
                cheat_hits.append(f"Satir {idx} ({','.join(strict + high_ctx)}): {sline[:180]}")
            elif any(tok in sline.lower() for tok in ("/tmp/", "/dev/shm/")) and any(
                ext in sline.lower() for ext in (".jar", ".so", ".exe", "chmod +x", "java ", "python")
            ):
                cheat_hits.append(f"Satir {idx} (tmp/shm exec): {sline[:180]}")

        if af_hits:
            ctx.add_finding(
                Finding(
                    rule_id="E1-HIST-ANTIFORENSIC-CMD",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Anti-Forensics / Commands",
                    title=f"Gecmis dosyasinda iz silme / adli manipulasyon komutu ({hf.name})",
                    description="Terminal gecmisinde dosya yok etme, gecmis silme veya tarih degistirme komutu tespit edildi.",
                    evidence=af_hits[:15],
                    path=str(hf),
                    recommendation="Silinen dosyalari Trash, browser SQLite ve RAM icinden kontrol edin.",
                )
            )
        if cheat_hits:
            ctx.add_finding(
                Finding(
                    rule_id="E1-HIST-CHEAT-CMD",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Command History",
                    title=f"Gecmis dosyasinda supheli hile/enjeksiyon/tmp komutu ({hf.name})",
                    description="Terminal gecmisinde hile istemcisi, makro veya gecici dizinden calistirma izi bulundu.",
                    evidence=cheat_hits[:15],
                    path=str(hf),
                )
            )

    if not existing_any and (h / ".bashrc").exists():
        ctx.add_finding(
            Finding(
                rule_id="E1-HIST-MISSING",
                engine=ENGINE_NAME,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category="Anti-Forensics / History Wipe",
                title="Hicbir kabuk gecmis dosyasi (.bash_history/.zsh_history) bulunamadi",
                description="Aktif bir kullanici ev dizininde shell history dosyasinin tamamen silinmis olmasi suphelidir.",
                evidence=[f"Kontrol edilen ev dizini: {h}"],
            )
        )


def _check_recently_used_tampering(ctx: ScanContext) -> None:
    xbel = ctx.home_dir / ".local/share/recently-used.xbel"
    if xbel.is_symlink():
        try:
            target = os.readlink(xbel)
            if target == "/dev/null":
                ctx.add_finding(
                    Finding(
                        rule_id="E1-XBEL-DEVNULL",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        category="Anti-Forensics",
                        title="recently-used.xbel /dev/null'a yonlendirilmis",
                        description="Masaustu son kullanilan dosya kayitlari bilincli olarak kapatilmis.",
                        evidence=[f"{xbel} -> {target}"],
                        path=str(xbel),
                    )
                )
                return
        except OSError:
            pass
    if xbel.is_file():
        ts = statx_timestamps(xbel)
        if ts and ts.size < 80:
            ctx.add_finding(
                Finding(
                    rule_id="E1-XBEL-WIPED",
                    engine=ENGINE_NAME,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="Anti-Forensics",
                    title=f"recently-used.xbel bosaltilmis ({ts.size} byte)",
                    description="Son kullanilan dosyalar gecmisi temizlenmis olabilir.",
                    evidence=[f"Boyut: {ts.size} byte", f"mtime: {fmt_ns(ts.mtime_ns)}"],
                    path=str(xbel),
                )
            )


def _check_preload_and_rc_files(ctx: ScanContext) -> None:
    sys_preload = ctx.sys_path("/etc/ld.so.preload")
    if sys_preload.is_file():
        content = safe_read_text(sys_preload, 16384).strip()
        lines = [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if lines:
            ctx.add_finding(
                Finding(
                    rule_id="E1-ETC-LD-PRELOAD",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="System Injection",
                    title="/etc/ld.so.preload icinde global .so enjeksiyonu var",
                    description="Sistem genelinde tum sureclere otomatik olarak bir paylasimli kutuphane enjekte ediliyor.",
                    evidence=lines[:10],
                    path=str(sys_preload),
                )
            )

    if os.environ.get("LD_PRELOAD"):
        ctx.add_finding(
            Finding(
                rule_id="E1-ENV-LD-PRELOAD",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Environment Injection",
                title="Ortam degiskeninde aktif LD_PRELOAD tespit edildi",
                description="Oturum genelinde LD_PRELOAD ile kutuphane kancalama (hook) aktif.",
                evidence=[f"LD_PRELOAD={os.environ.get('LD_PRELOAD')}"],
            )
        )
    if os.environ.get("LD_AUDIT"):
        ctx.add_finding(
            Finding(
                rule_id="E1-ENV-LD-AUDIT",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Environment Injection",
                title="Ortam degiskeninde aktif LD_AUDIT tespit edildi",
                description="Oturum genelinde LD_AUDIT dinamik baglayici kancasi aktif.",
                evidence=[f"LD_AUDIT={os.environ.get('LD_AUDIT')}"],
            )
        )

    h = ctx.home_dir
    rc_candidates = [
        h / ".bashrc",
        h / ".bash_profile",
        h / ".bash_login",
        h / ".bash_aliases",
        h / ".bash_logout",
        h / ".zshrc",
        h / ".zshenv",
        h / ".zprofile",
        h / ".zlogin",
        h / ".zlogout",
        h / ".profile",
        h / ".config/fish/config.fish",
    ]
    env_d = h / ".config/environment.d"
    if env_d.is_dir():
        rc_candidates.extend(sorted(env_d.glob("*.conf")))

    for rcf in rc_candidates:
        if not rcf.is_file():
            continue
        text = safe_read_text(rcf, 512 * 1024)
        for rule_id, pat, sev, desc in SHELL_RC_PATTERNS:
            matches = pat.findall(text)
            if matches:
                ctx.add_finding(
                    Finding(
                        rule_id=rule_id,
                        engine=ENGINE_NAME,
                        severity=sev,
                        confidence=Confidence.CONFIRMED,
                        category="Persistence / Env Hijack",
                        title=f"{desc} ({rcf.name})",
                        description=f"{rcf} icinde gizli ortam manipulasyonu veya komut gizleme kurali bulundu.",
                        evidence=[m.strip()[:180] for m in matches[:5]],
                        path=str(rcf),
                    )
                )
        af_lines: list[str] = []
        for idx, line in enumerate(text.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if ANTI_FORENSIC_CMD_RE.search(line):
                af_lines.append(f"Satir {idx}: {line.strip()[:180]}")
                if len(af_lines) >= 10:
                    break
        if af_lines:
            ctx.add_finding(
                Finding(
                    rule_id="E1-RC-ANTIFORENSIC-HOOK",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Persistence / Anti-Forensic Wipe",
                    title=f"Kabuk dosyasinda otomatik iz silme / anti-adli kanca ({rcf.name})",
                    description=f"{rcf} icinde oturum acilis/kapanisinda calisan anti-adli temizlik komutu bulundu.",
                    evidence=af_lines,
                    path=str(rcf),
                )
            )


def _check_path_shadowing(ctx: ScanContext) -> None:
    h = ctx.home_dir
    shadow_dirs = [
        h / ".local/bin",
        h / "bin",
        ctx.sys_path("/tmp"),
        ctx.sys_path("/dev/shm"),
    ]
    h_str = str(h)
    seen_sdirs = {str(p) for p in shadow_dirs}
    for seg in os.environ.get("PATH", "").split(":"):
        seg = seg.strip()
        if not seg:
            continue
        if seg.startswith(h_str) or seg in ("/tmp", "/dev/shm", "/var/tmp"):
            sp = Path(seg)
            if str(sp) not in seen_sdirs:
                seen_sdirs.add(str(sp))
                shadow_dirs.append(sp)
    for sdir in shadow_dirs:
        if not sdir.is_dir():
            continue
        try:
            entries = list(sdir.iterdir())
        except OSError:
            continue
        for entry in entries:
            name = entry.name
            if name not in CRITICAL_SHADOW_TARGETS:
                continue
            try:
                is_link = entry.is_symlink()
                resolved = entry.resolve()
                if not resolved.exists():
                    continue
                if os.path.isdir(resolved):
                    continue
                if not os.access(resolved, os.X_OK):
                    continue
            except OSError:
                continue

            head = safe_read_bytes(resolved, max_bytes=256)
            is_elf = head.startswith(b"\x7fELF")
            is_script = head.startswith(b"#!")

            # Legitimate user-installed JDK in ~/.local/bin/java -> symlink to a real JDK ELF
            if name == "java" and is_link and is_elf:
                rstr = str(resolved).lower()
                if any(tok in rstr for tok in ("jdk", "jvm", "java", "openjdk", "temurin", "graal", "zulu", "corretto")):
                    continue

            if is_script or (not is_elf and b"\x00" not in head[:64]):
                snippet = safe_read_text(resolved, 2048).strip() if head else "(bos calistirilabilir dosya)"
                ctx.add_finding(
                    Finding(
                        rule_id="E1-PATH-SHADOW-SCRIPT",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="SS Tool Spoofing",
                        title=f"Kritik sistem komutu sahte script ile golgelenmis: {entry}",
                        description=(
                            f"Kullanici PATH dizininde '{name}' adli bir script/kabuk golge dosyasi bulundu. "
                            "Hileciler ps/jcmd/lsof/ls ciktilarindan hileyi filtrelemek icin sahte wrapper koyar."
                        ),
                        evidence=[f"Dosya: {entry} -> {resolved}", f"Icerik: {snippet[:300]}"],
                        path=str(entry),
                    )
                )
            elif is_elf or head:
                ctx.add_finding(
                    Finding(
                        rule_id="E1-PATH-SHADOW-ELF",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="SS Tool Spoofing",
                        title=f"Kullanici dizininde sistem komutunu golgeleyen ELF/ikili dosya: {entry}",
                        description=f"PATH icinde '{name}' sistem aracini ezebilecek ozel ELF/ikili dosya mevcut.",
                        evidence=[f"Dosya: {entry} -> {resolved}"],
                        path=str(entry),
                    )
                )


def _check_distro_and_mac_posture(ctx: ScanContext) -> None:
    profile, host = resolve_profile(target_os=getattr(ctx, "target_os", "auto"), root_prefix=ctx.root_prefix)
    ctx.telemetry["target_os"] = profile.target_id
    ctx.telemetry["target_os_name"] = profile.display_name
    ctx.telemetry["host_os"] = host.target_id
    ctx.telemetry["host_pretty_name"] = host.pretty_name
    ctx.telemetry["kernel_release"] = host.kernel_release
    ctx.telemetry["mac_framework"] = profile.mac_framework

    selinux_enf = ctx.root_prefix / "sys/fs/selinux/enforce"
    if selinux_enf.exists():
        val = safe_read_text(selinux_enf).strip()
        ctx.telemetry["selinux_enforce"] = val
        if val == "0" and profile.mac_framework == "selinux":
            ctx.add_finding(
                Finding(
                    rule_id="E1-MAC-SELINUX-PERMISSIVE",
                    engine=ENGINE_NAME,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    category="MAC / OS Posture",
                    title="SELinux Zorunlu (Enforcing) modunda degil",
                    description="SELinux enforcing=0 (Permissive) durumunda; standart guvenlik politikasi gevsetilmis.",
                    path=str(selinux_enf),
                    evidence=[f"enforce={val}", f"Target OS: {profile.display_name}"],
                )
            )

    aa_param = ctx.root_prefix / "sys/module/apparmor/parameters/enabled"
    if aa_param.exists():
        aa_val = safe_read_text(aa_param).strip()
        ctx.telemetry["apparmor_enabled"] = aa_val
        if aa_val.upper() == "N" and profile.mac_framework == "apparmor":
            ctx.add_finding(
                Finding(
                    rule_id="E1-MAC-APPARMOR-DISABLED",
                    engine=ENGINE_NAME,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    category="MAC / OS Posture",
                    title="AppArmor cekirdek koruma modulu devredisi",
                    description="Ubuntu/Debian AppArmor parametresi (N) olarak tespit edildi.",
                    path=str(aa_param),
                    evidence=[f"enabled={aa_val}", f"Target OS: {profile.display_name}"],
                )
            )

    if (profile.target_id == "steamos" or host.is_steamos) and ctx.live_mode:
        rc, out, _ = run_trusted_cmd(["steamos-readonly", "status"], timeout=2.0)
        if rc == 0 and out:
            status = out.strip().lower()
            ctx.telemetry["steamos_readonly_status"] = status
            if "disabled" in status:
                ctx.add_finding(
                    Finding(
                        rule_id="E1-STEAMOS-READONLY-DISABLED",
                        engine=ENGINE_NAME,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        category="MAC / OS Posture",
                        title="SteamOS salt-okunur dosya sistemi (steamos-readonly) kapatilmis",
                        description="SteamOS kok dosya sistemi kilidi acik; sistem dizinlerine kalici arac veya modul yazilmis olabilir.",
                        evidence=[f"steamos-readonly status: {out.strip()}"],
                    )
                )


def _check_package_logs_and_aur(ctx: ScanContext) -> None:
    """Audit APT/DPKG/Pacman/DNF logs for truncation tampering or recent suspicious installs, plus AUR build caches."""
    now = ctx.current_epoch()
    win_sec = max(60.0, float(ctx.time_window_hours) * 3600.0)

    pkg_db_pairs = [
        (ctx.root_prefix / "var/lib/dpkg/status", ctx.root_prefix / "var/log/apt/history.log"),
        (ctx.root_prefix / "var/lib/dpkg/status", ctx.root_prefix / "var/log/dpkg.log"),
        (ctx.root_prefix / "var/lib/pacman/local", ctx.root_prefix / "var/log/pacman.log"),
    ]
    for db_marker, log_path in pkg_db_pairs:
        try:
            if db_marker.exists() and log_path.is_file() and log_path.stat().st_size == 0:
                ctx.add_finding(
                    Finding(
                        rule_id="E1-PKG-LOG-TAMPERED",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="Anti-Forensics / Package Logs",
                        title="Paket yoneticisi gecmis dosyasi sifirlanmis (truncate)",
                        description="Sistem paket veritabani aktifken paket gecmis logu 0 byte bulunmustur.",
                        path=str(log_path),
                        evidence=[f"marker={db_marker}", f"size=0 bytes"],
                    )
                )
        except OSError:
            pass

    suspicious_pkg_hits: list[str] = []
    # Check Pacman recent package events (ISO timestamp at start: [2026-11-15T18:00:00+0300])
    pac_log = ctx.root_prefix / "var/log/pacman.log"
    if pac_log.is_file():
        pac_txt = safe_read_tail_text(pac_log, max_bytes=262144)
        for line in pac_txt.splitlines()[-400:]:
            low = line.lower()
            if "[alpm] installed " not in low and "[alpm] upgraded " not in low:
                continue
            strict, high_ctx, _ = match_cheat_signatures(line)
            if strict or high_ctx or any(k in low for k in ("scanmem", "gameconqueror", "pcileech", "ydotool")):
                suspicious_pkg_hits.append(f"pacman: {line.strip()[:200]}")

    # Check APT recent history
    apt_log = ctx.root_prefix / "var/log/apt/history.log"
    if apt_log.is_file():
        apt_txt = safe_read_tail_text(apt_log, max_bytes=262144)
        for line in apt_txt.splitlines()[-300:]:
            low = line.lower()
            if not low.startswith(("install:", "commandline:")):
                continue
            strict, high_ctx, _ = match_cheat_signatures(line)
            if strict or high_ctx or any(k in low for k in ("scanmem", "gameconqueror", "pcileech", "ydotool")):
                suspicious_pkg_hits.append(f"apt: {line.strip()[:200]}")

    if suspicious_pkg_hits:
        ctx.add_finding(
            Finding(
                rule_id="E1-PKG-SUSPICIOUS-INSTALL",
                engine=ENGINE_NAME,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category="Package / Tool History",
                title="Paket yoneticisi gecmisinde supheli arac/paket kaydi",
                description="APT veya Pacman gecmisinde bellek okuyucu, makro veya bilinen supheli paket adi goruldu.",
                evidence=suspicious_pkg_hits[:10],
            )
        )

    # Check recent Arch AUR helper cache builds (~/.cache/yay, ~/.cache/paru/clone)
    aur_hits: list[str] = []
    for aur_dir in (ctx.home_dir / ".cache/yay", ctx.home_dir / ".cache/paru/clone"):
        if not aur_dir.is_dir():
            continue
        try:
            for entry in aur_dir.iterdir():
                if not entry.is_dir():
                    continue
                try:
                    st = entry.stat()
                    recent = (now - st.st_mtime) <= win_sec
                except OSError:
                    recent = False
                strict, high_ctx, _ = match_cheat_signatures(entry.name)
                if strict or high_ctx or (
                    recent and any(k in entry.name.lower() for k in ("scanmem", "gameconqueror", "pcileech", "ydotool", "cheat", "clicker", "inject"))
                ):
                    aur_hits.append(f"{entry} (recent={recent})")
        except OSError:
            pass
    if aur_hits:
        ctx.add_finding(
            Finding(
                rule_id="E1-AUR-SUSPICIOUS-PACKAGE",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Package / AUR Cache",
                title="AUR derleme onbelleginde (yay/paru) supheli paket",
                description="Arch/CachyOS AUR yardimci onbelleginde supheli hile, bellek tarayici veya makro paketi derlenmis.",
                evidence=aur_hits[:10],
            )
        )


def _check_live_journal_and_coredump(ctx: ScanContext) -> None:
    if not ctx.live_mode:
        return
    # Coredumpctl recent crashes
    rc, out, _ = run_trusted_cmd(["coredumpctl", "list", "--no-pager", "-n", "25"], timeout=4.0)
    if rc == 0 and out:
        suspicious_dumps: list[str] = []
        for line in out.splitlines():
            low = line.lower()
            clean_low = re.sub(r"/tmp/\.mount_[^\s/]+", "", low)
            if any(k in clean_low for k in ("/tmp/", "/dev/shm/", "java", "wine", "clicker", "injector", ".so", "python")):
                strict, high_ctx, _ = match_cheat_signatures(line)
                if strict or high_ctx or "/tmp/" in clean_low or "/dev/shm/" in clean_low or "injector" in clean_low:
                    suspicious_dumps.append(line.strip()[:200])
        if suspicious_dumps:
            ctx.add_finding(
                Finding(
                    rule_id="E1-COREDUMP-SUSPICIOUS",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Crash / Execution Trace",
                    title="coredumpctl kayitlarinda supheli cokme izleri",
                    description="Yakin zamanda /tmp, /dev/shm veya supheli binary kaynakli surec cokmesi kaydedilmis.",
                    evidence=suspicious_dumps[:10],
                )
            )

    # Recent sudo commands in journalctl
    win_h = ctx.time_window_hours if (math.isfinite(ctx.time_window_hours) and ctx.time_window_hours > 0) else 48.0
    hours = max(1, int(round(win_h)))
    rc2, jout, _ = run_trusted_cmd(
        ["journalctl", "_COMM=sudo", "--since", f"{hours} hours ago", "--no-pager", "-n", "60"],
        timeout=4.0,
    )
    if rc2 == 0 and jout:
        sudo_hits: list[str] = []
        for line in jout.splitlines():
            if "COMMAND=" in line and (
                ANTI_FORENSIC_CMD_RE.search(line)
                or any(k in line.lower() for k in ("/tmp/", "/dev/shm/", "insmod", "modprobe", "timedatectl", "date -s"))
            ):
                sudo_hits.append(line.strip()[:220])
        if sudo_hits:
            ctx.add_finding(
                Finding(
                    rule_id="E1-JOURNAL-SUDO-SUSPICIOUS",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Privilege / Anti-Forensics",
                    title="journalctl sudo gecmisinde kritik/supheli komutlar",
                    description="Son saatlerde yetkili (sudo) iz silme, saat degisikligi veya kernel/tmp islemi yapilmis.",
                    evidence=sudo_hits[:10],
                )
            )


def run(ctx: ScanContext) -> None:
    try:
        emit_scan_progress(ctx, 0.08, "Sistem acilis suresi ve bellek korumalari kontrol ediliyor...")
        _check_uptime(ctx)
        record_scan_region(ctx, "E1", f"{ctx.proc_root / 'uptime'} ve {ctx.proc_root / 'sys/kernel/yama/ptrace_scope'}")
        _check_distro_and_mac_posture(ctx)
        _check_package_logs_and_aur(ctx)
        emit_scan_progress(ctx, 0.22, "Saat senkronizasyonu ve oturum ortamı inceleniyor...")
        _check_clock_and_session(ctx)
        record_scan_region(ctx, "E1", "DMI/Donanim kimligi, Wayland/X11 ekrani, timedatectl/NTP")
        emit_scan_progress(ctx, 0.40, "Bash/Zsh/Fish kabuk gecmisleri kontrol ediliyor...")
        _check_shell_histories(ctx)
        record_scan_region(ctx, "E1", f"{ctx.home_dir}/.bash_history, .zsh_history, .local/share/fish/fish_history")
        emit_scan_progress(ctx, 0.56, "recently-used.xbel anti-adli mudahanesi kontrol ediliyor...")
        _check_recently_used_tampering(ctx)
        emit_scan_progress(ctx, 0.72, "LD_PRELOAD ve kabuk rc dosyalari inceleniyor...")
        _check_preload_and_rc_files(ctx)
        record_scan_region(ctx, "E1", "/etc/ld.so.preload, ~/.bashrc, ~/.zshrc, ~/.profile")
        emit_scan_progress(ctx, 0.86, "PATH ikili golgeleme ve sistem kayitlari kontrol ediliyor...")
        _check_path_shadowing(ctx)
        _check_live_journal_and_coredump(ctx)
        record_scan_region(ctx, "E1", "$PATH komut golgeleme, journalctl, coredumpctl")
        ctx.set_coverage(
            "E1.system",
            ScanStatus.COMPLETED if ctx.live_mode else ScanStatus.PARTIAL,
            "System/shell/MAC checks completed" if ctx.live_mode else "Offline mode (live journal/timedatectl skipped)",
        )
        emit_scan_progress(ctx, 1.0, "Sistem butunluk analizi tamamlandi.")
    except Exception as exc:
        if exc.__class__.__name__ == "ScanCancelledError":
            raise
        ctx.set_coverage("E1.system", ScanStatus.ERROR, str(exc))
        ctx.add_error(ENGINE_NAME, f"Beklenmeyen hata: {exc}")

"""Engine 2: Live /proc, Container/Namespace, JVM & RAM Memory Injection Analyzer."""

from __future__ import annotations

import ctypes
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .models import Confidence, Finding, ScanContext, ScanStatus, Severity
from .signatures import (
    CONTEXTUAL_CHEAT_MODULES,
    HIGH_SIGNAL_MODULE_NAMES,
    LEGIT_JAVA_PREFIXES,
    LEGIT_TMP_SO_PATTERNS,
    MACRO_PROCESS_NAMES,
    STRICT_CHEAT_IDENTIFIERS,
)
from .utils import (
    emit_scan_progress,
    match_cheat_signatures,
    record_scan_region,
    run_trusted_cmd,
    safe_read_bytes,
    safe_read_text,
)

ENGINE_NAME = "Engine 2: Canli /proc, JVM, Container & RAM Analizi"

# Benign /proc/<pid>/maps deleted objects (audio/display/JIT/IPC/Flatpak/Wine caches)
BENIGN_DELETED_MAP_HINTS: tuple[str, ...] = (
    "/memfd:pulseaudio",
    "/memfd:pipewire",
    "/memfd:wayland",
    "/memfd:xwayland",
    "/memfd:xshmfence",
    "/memfd:gdk-",
    "/memfd:mozilla-ipc",
    "/memfd:wine-mapping",
    "/memfd:jitcode:qtqml",
    "/memfd:jsgcheap:qtqml",
    "/memfd:jsvmstack:qtqml",
    "/memfd:unknown-usage:qtqml",
    "/memfd:kwin-dmabuf",
    "/memfd:kwin-xkb",
    "/memfd:dbus-broker-log",
    "/memfd:shared-memory-region",
    "/memfd:mesa",
    "/etc/ld.so.cache",
    "/dev/shm/org.chromium.",
    "/dev/shm/.org.chromium.",
    "/dev/shm/.com.valvesoftware.steam.",
    "/dev/shm/valveipcshm",
    "/dev/shm/pulse-shm",
    "/dev/zero",
    "/sysv",
    "/tmp/.gl",
    "/tmp/.mount_",
    "/tmp/.org.chromium.",
    "/tmp/.com.google.chrome.",
    "/tmp/.com.valvesoftware.steam.",
    "/tmp/.org.mozilla.",
    "/tmp/rust_mozprofile",
    "/tmp/orcexec",
    "/tmp/hsperfdata_",
    "/.cache/",
    "/cache/fontconfig",
    "/cache/mesa_shader_cache",
    "/mesa_shader_cache/",
    "/mime/mime.cache",
    "/icon-theme.cache",
    "gpucache",
    "dawngraphitecache",
    "dawnwebgpucache",
    "qmlcache",
    "ksycoca",
    "gvfs-metadata",
    "browsermetrics",
    "quotamanager",
    "/run/user/",
)

# Exact benign executable memfd prefixes (never use bare substring "jit"!)
BENIGN_EXEC_MEMFD_PREFIXES: tuple[str, ...] = (
    "/memfd:jitcode:qtqml",
    "/memfd:mesa",
    "/memfd:llvm",
    "/memfd:orcexec",
    "/memfd:pipewire",
    "/memfd:lp_jit",
)

# Known benign compositor/overlay/sandbox preloads on Linux desktop
BENIGN_PRELOAD_HINTS: tuple[str, ...] = (
    "libzypak-preload",
    "extest/libextest.so",
    "libextest.so",
    "libgamemodeauto.so",
    "libmangohud",
    "gameoverlayrenderer.so",
    "libgtk3-nocsd.so",
)

REMAPPER_DAEMON_NAMES: frozenset[str] = frozenset(
    {
        "input-remapper-service",
        "input-remapper-gtk",
        "input-remapper-control",
        "input-remapper-reader-service",
        "evtest",
    }
)
_PURE_MACRO_PROCESS_NAMES: frozenset[str] = MACRO_PROCESS_NAMES - REMAPPER_DAEMON_NAMES
_TMP_MAPPED_EXT_RE = re.compile(r"(?:\.so(?:\.\d+)*|\.jar|\.dll|\.exe)$", re.IGNORECASE)

# Legitimate native GUI/Browser/IDE JIT runtimes that legitimately allocate rwxp pages
LEGIT_JIT_COMMS: frozenset[str] = frozenset(
    {
        "plasmashell",
        "kwin_wayland",
        "kwin_x11",
        "kded6",
        "kded5",
        "gnome-shell",
        "gjs",
        "firefox",
        "firefox-bin",
        "opera",
        "opera-gx",
        "chrome",
        "chromium",
        "brave",
        "vivaldi-bin",
        "discord",
        "steam",
        "steamwebhelper",
        "lunarclient",
        "electron",
        "code",
        "cursor",
        "obsidian",
        "slack",
        "pipewire",
        "wireplumber",
        "webcontent",
        "isolated web co",
        "privileged cont",
        "rdd process",
        "utility process",
    }
)

# Precompiled lowercase byte patterns for ultra-fast chunked RAM scanning (ASCII + UTF-16LE)
_RAM_STRICT_BOUNDED_TERMS: tuple[bytes, ...] = (
    b"selfdestruct",
    b"autoclicker",
    b"triggerbot",
    b"cheststealer",
    b"aimassist",
    b"killaura",
)

_RAM_STRICT_TERMS: tuple[bytes, ...] = tuple(
    sorted(
        {
            s.lower().encode("ascii")
            for s in STRICT_CHEAT_IDENTIFIERS
            if len(s) >= 5
        }
        - set(_RAM_STRICT_BOUNDED_TERMS),
        key=len,
        reverse=True,
    )
)

_RAM_STRICT_CS_RE = re.compile(
    b"|".join(re.escape(t) for t in _RAM_STRICT_TERMS),
)

_RAM_STRICT_BOUNDED_CS_RE = re.compile(
    b"|".join(re.escape(t) for t in _RAM_STRICT_BOUNDED_TERMS),
)

_RAM_STRICT_UTF16_CS_RE = re.compile(
    b"|".join(
        re.escape(t.decode("ascii").encode("utf-16le"))
        for t in (_RAM_STRICT_TERMS + _RAM_STRICT_BOUNDED_TERMS)
    ),
)

_RAM_CLUSTER_TERMS: tuple[bytes, ...] = (
    b"killaura",
    b"autoclicker",
    b"autoclick",
    b"triggerbot",
    b"aimassist",
    b"selfdestruct",
    b"cheststealer",
    b"scaffold",
    b"antivelocity",
    b"antiknockback",
    b"hitbox",
    b"reach",
    b"velocity",
    b"clickgui",
    b"fullbright",
    b"freecam",
    b"xray",
    b"nametags",
    b"tracers",
)
# Bare lowercase cluster regex (word/CamelCase boundaries verified in Python only on actual hits)
_RAM_CLUSTER_CS_RE = re.compile(
    b"(" + b"|".join(re.escape(t) for t in _RAM_CLUSTER_TERMS) + b")",
)

_HIGH_SIG_BYTES: frozenset[bytes] = frozenset(t.encode("ascii") for t in HIGH_SIGNAL_MODULE_NAMES)
_MOD_CLUSTER_PRIORITY_BYTES: frozenset[bytes] = _HIGH_SIG_BYTES | frozenset(
    {b"reach", b"velocity", b"scaffold", b"blink", b"criticals"}
)


@dataclass
class ProcInfo:
    pid: int
    comm: str = ""
    cmdline: list[str] = field(default_factory=list)
    cmdline_str: str = ""
    exe: str = ""
    cwd: str = ""
    environ: dict[str, str] = field(default_factory=dict)
    tracer_pid: int = 0
    uid: int | None = None
    namespaces: dict[str, str] = field(default_factory=dict)
    cgroup: str = ""
    is_java: bool = False
    is_minecraft: bool = False
    is_wine: bool = False
    is_suspicious: bool = False


def _read_proc_link(p: Path) -> str:
    try:
        return os.readlink(p)
    except OSError:
        return ""


def _read_proc_nul_list(p: Path, max_bytes: int = 262144) -> list[str]:
    raw = safe_read_bytes(p, max_bytes=max_bytes)
    if not raw:
        return []
    parts = [x.decode("utf-8", errors="replace") for x in raw.split(b"\x00") if x]
    return parts


def _is_minecraft_cmd(cmd_low: str, comm_low: str, exe_low: str) -> bool:
    mc_hints = (
        "net.minecraft",
        "net.fabricmc",
        "net.minecraftforge",
        "cpw.mods.bootstraplauncher",
        "org.prismlauncher",
        "org.multimc",
        "com.moonsworth.lunar",
        "lunarclient",
        "feather",
        "modrinth",
        "badlion",
        "minecraft",
        "lwjgl",
        "net.quiltmc",
        "io.github.zekerzhayard",
    )
    if any(h in cmd_low for h in mc_hints):
        return True
    if ("java" in comm_low or exe_low.endswith("/java")) and (
        "minecraft" in cmd_low or ".minecraft" in cmd_low or "prismlauncher" in cmd_low
    ):
        return True
    return False


def _is_legit_tmp_so(basename: str) -> bool:
    return any(pat.match(basename) for pat in LEGIT_TMP_SO_PATTERNS)


def _is_benign_deleted_map(path_part: str, perms: str = "") -> bool:
    low = path_part.lower()
    if any(
        low.endswith(ext) or f"{ext} " in low
        for ext in (".jar", ".so", ".dll", ".exe", ".class", ".py", ".sh", ".lua", ".zip", ".appimage")
    ):
        # Never ignore deleted executable libraries, jars, or scripts!
        if "/tmp/hsperfdata_" in low:
            return True
        return False
    if any(h in low for h in BENIGN_DELETED_MAP_HINTS):
        return True
    if "x" not in perms and (
        low.startswith(("/memfd:", "/dev/shm/")) or "/cache/" in low or "/mesa_shader_cache" in low
    ):
        strict, high_ctx, _ = match_cheat_signatures(low)
        if not strict and not high_ctx:
            return True
    return False


def _is_benign_preload(val: str, proc: ProcInfo) -> bool:
    tokens = [tok.strip() for tok in re.split(r"[:\s]+", val.strip()) if tok.strip()]
    if not tokens:
        return False
    is_target = proc.is_java or proc.is_minecraft
    for tok in tokens:
        tlow = tok.lower()
        if not any(h in tlow for h in BENIGN_PRELOAD_HINTS):
            return False
        # Require trusted system/Flatpak/pressure-vessel location (prevent fake /tmp/libgamemodeauto.so)
        in_system_loc = (
            (tlow.startswith(("/usr/", "/lib", "/app/")) and not tlow.startswith("/usr/local/"))
            or "pressure-vessel-libs" in tlow
        )
        if not in_system_loc:
            return False
        if is_target and not any(o in tlow for o in ("gameoverlayrenderer", "mangohud", "gamemodeauto")):
            return False
    return True


def _is_legit_jit_process(proc: ProcInfo) -> bool:
    if proc.is_java or proc.is_minecraft:
        return False
    exe_low = proc.exe.lower()
    if exe_low.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")) and not exe_low.startswith("/tmp/.mount_"):
        return False
    comm_low = proc.comm.lower()
    if comm_low in LEGIT_JIT_COMMS:
        return True
    return any(
        j in exe_low
        for j in (
            "/firefox",
            "/opera",
            "/chromium",
            "/chrome",
            "/discord",
            "/lunarclient",
            "/plasmashell",
            "/kwin",
            "/electron",
            "/steam",
            "/code",
        )
    )


def _parse_proc_status(status_text: str) -> tuple[int, int | None]:
    tracer = 0
    uid: int | None = None
    for line in status_text.splitlines():
        if line.startswith("TracerPid:"):
            try:
                tracer = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("Uid:"):
            try:
                uid = int(line.split(":", 1)[1].strip().split()[0])
            except (ValueError, IndexError):
                pass
    return tracer, uid


def _collect_processes(ctx: ScanContext) -> tuple[list[ProcInfo], dict[str, str]]:
    procs: list[ProcInfo] = []
    self_pid = os.getpid()
    self_pids = {self_pid}
    if getattr(sys, "frozen", False):
        self_real_exes: set[str] = set()
        for cand in (sys.executable, _read_proc_link(ctx.proc_root / str(self_pid) / "exe")):
            if cand:
                try:
                    self_real_exes.add(os.path.realpath(cand))
                except OSError:
                    pass
        ppid = os.getppid()
        if ppid > 1 and self_real_exes:
            pexe = _read_proc_link(ctx.proc_root / str(ppid) / "exe")
            try:
                if pexe and os.path.realpath(pexe) in self_real_exes:
                    self_pids.add(ppid)
            except OSError:
                pass
    init_ns: dict[str, str] = {}

    # Baseline namespaces from PID 1 or self
    for ref_pid in ("1", str(self_pid)):
        ns_dir = ctx.proc_root / ref_pid / "ns"
        if ns_dir.is_dir():
            for n in ("mnt", "pid", "net", "user"):
                link = _read_proc_link(ns_dir / n)
                if link and n not in init_ns:
                    init_ns[n] = link

    try:
        entries = list(ctx.proc_root.iterdir())
    except OSError:
        return procs, init_ns

    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in self_pids:
            continue

        comm = safe_read_text(entry / "comm", 256).strip()
        cmdline = _read_proc_nul_list(entry / "cmdline")
        cmdline_str = " ".join(cmdline)
        exe = _read_proc_link(entry / "exe")
        cwd = _read_proc_link(entry / "cwd")
        status_txt = safe_read_text(entry / "status", 8192)
        tracer_pid, uid = _parse_proc_status(status_txt)
        cgroup = safe_read_text(entry / "cgroup", 4096).strip()

        env_list = _read_proc_nul_list(entry / "environ")
        env: dict[str, str] = {}
        for item in env_list:
            if "=" in item:
                k, v = item.split("=", 1)
                env[k] = v

        ns: dict[str, str] = {}
        ns_dir = entry / "ns"
        if ns_dir.is_dir():
            for n in ("mnt", "pid", "net", "user"):
                link = _read_proc_link(ns_dir / n)
                if link:
                    ns[n] = link

        cmd_low = cmdline_str.lower()
        comm_low = comm.lower()
        exe_low = exe.lower()

        is_java = (
            comm_low in ("java", "javaw", "javaw.exe")
            or exe_low.endswith(("/java", "/javaw", "/javaw.exe"))
            or any(
                jvm_tok in cmd_low
                for jvm_tok in (
                    "-javaagent:",
                    "-agentpath:",
                    "-xbootclasspath/",
                    "+disableattachmechanism",
                    "+perfdisablesharedmem",
                )
            )
            or (
                "java" in cmd_low
                and any(
                    tok in cmd_low
                    for tok in ("-jar", "-cp", "-classpath", "xmx", " @", " -m ", "--module")
                )
            )
        )
        is_mc = _is_minecraft_cmd(cmd_low, comm_low, exe_low)
        is_wine = any(w in cmd_low or w in comm_low or w in exe_low for w in ("wine", "wineserver", "proton", ".exe"))

        procs.append(
            ProcInfo(
                pid=pid,
                comm=comm,
                cmdline=cmdline,
                cmdline_str=cmdline_str,
                exe=exe,
                cwd=cwd,
                environ=env,
                tracer_pid=tracer_pid,
                uid=uid,
                namespaces=ns,
                cgroup=cgroup,
                is_java=is_java,
                is_minecraft=is_mc,
                is_wine=is_wine,
            )
        )
    return procs, init_ns


def _inspect_process_metadata(
    ctx: ScanContext, proc: ProcInfo, by_pid: dict[int, ProcInfo], init_ns: dict[str, str]
) -> None:
    cmd_low = proc.cmdline_str.lower()
    exe_low = proc.exe.lower()
    comm_low = proc.comm.lower()

    # 1. TracerPid != 0 (active ptrace debugger / injector)
    if proc.tracer_pid > 0:
        tracer = by_pid.get(proc.tracer_pid)
        tracer_desc = f"PID {proc.tracer_pid} ({tracer.comm}: {tracer.cmdline_str[:120]})" if tracer else f"PID {proc.tracer_pid}"
        sev = Severity.CRITICAL if (proc.is_minecraft or proc.is_java) else Severity.HIGH
        ctx.add_finding(
            Finding(
                rule_id="E2-PROC-TRACERPID",
                engine=ENGINE_NAME,
                severity=sev,
                confidence=Confidence.CONFIRMED,
                category="Memory Injection / Debugging",
                title=f"Surece aktif ptrace baglantisi tespit edildi (TracerPid={proc.tracer_pid})",
                description="Baska bir surec bu surecin bellegine ptrace ile bagli (enjektor/debugger).",
                evidence=[
                    f"Hedef PID {proc.pid} ({proc.comm}): {proc.cmdline_str[:200]}",
                    f"Izleyen (Tracer): {tracer_desc}",
                ],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True

    # 2. memfd / deleted / /tmp / /dev/shm executable
    if proc.exe.startswith("/memfd:") or "memfd:" in exe_low:
        ctx.add_finding(
            Finding(
                rule_id="E2-PROC-MEMFD-EXE",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Fileless Execution",
                title=f"Dosyasiz (memfd) calisan ELF sureci: PID {proc.pid} ({proc.comm})",
                description="Diskte hic dosya birakmadan dogrudan RAM icinden ELF binary calistiriliyor.",
                evidence=[f"exe={proc.exe}", f"cmdline={proc.cmdline_str[:220]}"],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True
    elif proc.exe.endswith(" (deleted)"):
        ctx.add_finding(
            Finding(
                rule_id="E2-PROC-DELETED-EXE",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Deleted Binary Execution",
                title=f"Diskten silinmis calisan surec: PID {proc.pid} ({proc.comm})",
                description="Calisan programin diski uzerindeki binary dosyasi silinmis (self-delete veya guncelleme).",
                evidence=[f"exe={proc.exe}", f"cmdline={proc.cmdline_str[:220]}"],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True

    if any(exe_low.startswith(p) for p in ("/tmp/", "/dev/shm/", "/var/tmp/")) and not exe_low.startswith("/tmp/.mount_"):
        ctx.add_finding(
            Finding(
                rule_id="E2-PROC-TMP-EXE",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Suspicious Execution Path",
                title=f"Gecici dizinden (/tmp veya /dev/shm) calisan binary: PID {proc.pid}",
                description="Gecici RAM/tmp klasorlerinden program calistirilmasi hile/enjektor davranisidir.",
                evidence=[f"exe={proc.exe}", f"cmdline={proc.cmdline_str[:220]}"],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True

    # 3. Kernel-thread masquerading (e.g. comm looks like [kworker/0:1] but has userland exe)
    if proc.exe and (comm_low.startswith("kworker") or comm_low.startswith("ksoftirqd") or proc.comm.startswith("[")):
        ctx.add_finding(
            Finding(
                rule_id="E2-PROC-MASQUERADE",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Process Masquerading",
                title=f"Kernel sureci taklidi yapan kullanici sureci: PID {proc.pid} ({proc.comm})",
                description="Surec adini kernel thread gibi gizlemis ancak gercekte userland binary calistiriyor.",
                evidence=[f"comm={proc.comm}", f"exe={proc.exe}", f"cmdline={proc.cmdline_str[:200]}"],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True

    wp = proc.environ.get("WINEPREFIX", "").strip()
    if wp and (proc.is_wine or proc.is_minecraft):
        ctx.telemetry.setdefault("live_wine_prefixes", []).append(wp)

    # 4. Environment injection checks (including LD_AUDIT bypass vector)
    for var in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"):
        val = proc.environ.get(var, "")
        if not val:
            continue
        vlow = val.lower()
        if var == "LD_PRELOAD":
            if _is_benign_preload(val, proc):
                continue
            ctx.add_finding(
                Finding(
                    rule_id="E2-PROC-LDPRELOAD",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Library Injection",
                    title=f"PID {proc.pid} ({proc.comm}) ortaminda LD_PRELOAD aktif",
                    description="Calisan surece LD_PRELOAD ile disaridan .so kutuphanesi enjekte edilmis.",
                    evidence=[f"LD_PRELOAD={val}"],
                    pid=proc.pid,
                )
            )
            proc.is_suspicious = True
        elif var == "LD_AUDIT":
            ctx.add_finding(
                Finding(
                    rule_id="E2-PROC-LDAUDIT",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Library Injection (rtld-audit)",
                    title=f"PID {proc.pid} ({proc.comm}) ortaminda LD_AUDIT aktif",
                    description="LD_AUDIT dinamik baglayici denetim arayuzu ile LD_PRELOAD kontrolleri atlatilarak .so yukleniyor olabilir.",
                    evidence=[f"LD_AUDIT={val}"],
                    pid=proc.pid,
                )
            )
            proc.is_suspicious = True
        elif var == "LD_LIBRARY_PATH":
            bad_segs = [
                seg.strip()
                for seg in val.split(":")
                if seg.strip()
                and any(seg.strip().lower().startswith(p) for p in ("/tmp", "/dev/shm", "/var/tmp"))
                and not seg.strip().lower().startswith("/tmp/.mount_")
                and "pressure-vessel-libs" not in seg.lower()
            ]
            if bad_segs:
                ctx.add_finding(
                    Finding(
                        rule_id="E2-PROC-LDLIBPATH-TMP",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="Library Injection",
                        title=f"PID {proc.pid} ({proc.comm}) LD_LIBRARY_PATH gecici dizini gosteriyor",
                        description="Surec kutuphaneleri /tmp veya /dev/shm uzerinden yukleyecek sekilde baslatilmis.",
                        evidence=[f"LD_LIBRARY_PATH={val}", f"Supheli segmentler: {', '.join(bad_segs[:5])}"],
                        pid=proc.pid,
                    )
                )
                proc.is_suspicious = True
        elif "JAVA" in var and any(
            k in vlow
            for k in (
                "-javaagent",
                "-agentpath",
                "-xbootclasspath",
                "disableattachmechanism",
                "perfdisablesharedmem",
            )
        ):
            ctx.add_finding(
                Finding(
                    rule_id="E2-PROC-JAVA-ENV-INJECT",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="JVM Injection",
                    title=f"PID {proc.pid} Java ortam degiskeni ile gizli agent/flag enjeksiyonu",
                    description=f"{var} uzerinden gizli JVM agent veya telemetry/attach engeli verilmis.",
                    evidence=[f"{var}={val}"],
                    pid=proc.pid,
                )
            )
            proc.is_suspicious = True

    # 5. JVM command-line flags & live --gameDir / proxy extraction
    if proc.is_java or proc.is_minecraft:
        n_args = len(proc.cmdline)
        for idx, arg in enumerate(proc.cmdline):
            alow = arg.lower()
            if arg == "--gameDir" and idx + 1 < n_args:
                ctx.telemetry.setdefault("live_minecraft_roots", []).append(proc.cmdline[idx + 1])
            elif arg.startswith("--gameDir="):
                ctx.telemetry.setdefault("live_minecraft_roots", []).append(arg.split("=", 1)[1])
            elif arg.startswith("-Dminecraft.applet.TargetDirectory="):
                ctx.telemetry.setdefault("live_minecraft_roots", []).append(arg.split("=", 1)[1])
            elif alow.startswith(
                ("-dsocksproxyhost=", "-dhttp.proxyhost=", "-dhttps.proxyhost=", "-djava.net.usesystemproxies=true")
            ):
                ctx.telemetry.setdefault("java_proxy_args", []).append(f"PID {proc.pid} ({proc.comm}): {arg}")

            if alow.startswith(("-javaagent:", "-agentpath:")):
                agent_target = arg.split(":", 1)[1].split("=", 1)[0]
                is_known_lunar = ".lunarclient" in agent_target.lower() and "ichor" in agent_target.lower()
                ctx.add_finding(
                    Finding(
                        rule_id="E2-JVM-AGENT-ARG",
                        engine=ENGINE_NAME,
                        severity=Severity.INFO if is_known_lunar else Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="JVM Agent Injection",
                        title=(
                            f"Lunar Ichor agent tespit edildi (PID {proc.pid})"
                            if is_known_lunar
                            else f"Java surecinde enjeksiyon agent parametresi tespit edildi (PID {proc.pid})"
                        ),
                        description="JVM baslangicinda bytecode degistirebilen -javaagent/-agentpath kullanilmis.",
                        evidence=[f"Arguman: {arg}"],
                        path=agent_target if os.path.isabs(agent_target) else None,
                        pid=proc.pid,
                        recommendation="Belirtilen .jar/.so dosyasini Engine 4 veya JADX ile mutlaka inceleyin.",
                    )
                )
                if not is_known_lunar:
                    proc.is_suspicious = True
            elif alow.startswith(("-xbootclasspath/a:", "-xbootclasspath/p:")):
                ctx.add_finding(
                    Finding(
                        rule_id="E2-JVM-BOOTCLASSPATH",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="JVM Injection",
                        title=f"JVM BootClassPath manipulasyonu (PID {proc.pid})",
                        description="Standart Java/Minecraft siniflari -Xbootclasspath ile eziliyor olabilir.",
                        evidence=[f"Arguman: {arg}"],
                        pid=proc.pid,
                    )
                )
                proc.is_suspicious = True
            elif "+disableattachmechanism" in alow:
                ctx.add_finding(
                    Finding(
                        rule_id="E2-JVM-DISABLE-ATTACH",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="Anti-Forensics / JVM",
                        title=f"JVM Attach mekanizmasi devre disi birakilmis (PID {proc.pid})",
                        description="-XX:+DisableAttachMechanism parametresi jcmd/jstack ve SS araclarini engellemek icin kullanilir.",
                        evidence=[f"Arguman: {arg}"],
                        pid=proc.pid,
                    )
                )
                proc.is_suspicious = True
            elif "+perfdisablesharedmem" in alow:
                ctx.add_finding(
                    Finding(
                        rule_id="E2-JVM-PERF-DISABLE",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        category="Anti-Forensics / JVM",
                        title=f"JVM hsperfdata bellek paylasimi devre disi birakilmis (PID {proc.pid})",
                        description="-XX:+PerfDisableSharedMem bayragi /tmp/hsperfdata icerigini SS araclarindan gizlemek icin kullanilir.",
                        evidence=[f"Arguman: {arg}"],
                        pid=proc.pid,
                    )
                )
                proc.is_suspicious = True
            elif "+allowredefinitiontoadddeletemethods" in alow:
                ctx.add_finding(
                    Finding(
                        rule_id="E2-JVM-REDEF-METHODS",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="JVM Injection",
                        title=f"JVM sinif yeniden tanimlama bayragi aktif (PID {proc.pid})",
                        description="Calisma aninda siniflara yeni metod enjekte edilmesine izin veren JVM bayragi.",
                        evidence=[f"Arguman: {arg}"],
                        pid=proc.pid,
                    )
                )
                proc.is_suspicious = True

    # 6. Process name / cmdline cheat & macro signature check
    strict, high_ctx, _ = match_cheat_signatures(f"{proc.comm} {proc.cmdline_str}")
    exe_base = os.path.basename(proc.exe.split(" (deleted)")[0]).lower() if proc.exe else ""
    cmd_bases = [os.path.basename(tok).lower() for tok in proc.cmdline[:4] if tok and not tok.startswith("-")]
    is_pure_macro = (
        comm_low in _PURE_MACRO_PROCESS_NAMES
        or exe_base in _PURE_MACRO_PROCESS_NAMES
        or any(
            b in _PURE_MACRO_PROCESS_NAMES or any(b.startswith(f"{m}.") for m in _PURE_MACRO_PROCESS_NAMES)
            for b in cmd_bases
        )
    )
    is_remapper_daemon = not is_pure_macro and (
        comm_low in REMAPPER_DAEMON_NAMES
        or comm_low.startswith("input-remapper")
        or exe_base in REMAPPER_DAEMON_NAMES
        or any(b in REMAPPER_DAEMON_NAMES for b in cmd_bases)
    )
    if strict or high_ctx:
        ctx.add_finding(
            Finding(
                rule_id="E2-PROC-CHEAT-NAME",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL if strict else Severity.HIGH,
                confidence=Confidence.CONFIRMED if strict else Confidence.HIGH,
                category="Live Cheat / Macro Process",
                title=f"Calisan surecte hile/makro imzasi: PID {proc.pid} ({proc.comm})",
                description="Surecin adi veya komut satiri bilinen hile istemcisi/makro ile eslesti.",
                evidence=[
                    f"Eslesenler: {', '.join(strict + high_ctx)}",
                    f"cmdline: {proc.cmdline_str[:250]}",
                ],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True
    elif is_pure_macro:
        ctx.add_finding(
            Finding(
                rule_id="E2-PROC-MACRO-BIN",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="Macro / AutoClicker",
                title=f"Aktif makro / girdi otomasyon sureci: {proc.comm} (PID {proc.pid})",
                description="Linux uzerinde yapay tiklama veya tus basimi uretebilen arac aktif.",
                evidence=[f"comm={proc.comm}", f"exe={proc.exe}", f"cmdline={proc.cmdline_str[:220]}"],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True
    elif is_remapper_daemon:
        ctx.add_finding(
            Finding(
                rule_id="E2-PROC-MACRO-BIN",
                engine=ENGINE_NAME,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="Input Remapper Daemon",
                title=f"Girdi esleme / remapper sureci aktif: {proc.comm} (PID {proc.pid})",
                description=(
                    "Sistemde genel amacli tus/fare esleme servisi (input-remapper/evtest) calisiyor. "
                    "Tek basina hile kaniti degildir; Engine 3 makro profilleriyle birlikte degerlendirilir."
                ),
                evidence=[f"comm={proc.comm}", f"exe={proc.exe}", f"cmdline={proc.cmdline_str[:220]}"],
                pid=proc.pid,
                metadata={"remapper_daemon": True},
            )
        )

    # 7. Namespace / container isolation detection for Java/Minecraft/Wine
    if init_ns and (proc.is_minecraft or proc.is_java or proc.is_wine or proc.is_suspicious):
        diff_ns = [
            f"{k}: {v} != {init_ns[k]}"
            for k, v in proc.namespaces.items()
            if k in init_ns and v != init_ns[k]
        ]
        if diff_ns:
            is_flatpak = "app-" in proc.cgroup or "flatpak" in proc.cgroup.lower()
            is_container = any(
                x in proc.cgroup.lower() for x in ("libpod", "podman", "docker", "distrobox", "lxc")
            )
            label = "Flatpak" if is_flatpak else ("Container/Podman" if is_container else "Izole Namespace (bwrap/unshare)")
            ctx.add_finding(
                Finding(
                    rule_id="E2-PROC-ISOLATED-NS",
                    engine=ENGINE_NAME,
                    severity=Severity.MEDIUM if is_flatpak else Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    category="Container / Namespace Isolation",
                    title=f"Oyun/Java/Wine sureci izole bir {label} alaninda calisiyor (PID {proc.pid})",
                    description=(
                        "Surec ana sistemden farkli bir mount/pid/user namespace icinde calisiyor. "
                        "Kontrol sirasinda gizli container icinde dosya/hile saklaniyor olabilir."
                    ),
                    evidence=diff_ns + ([f"cgroup={proc.cgroup[:180]}"] if proc.cgroup else []),
                    pid=proc.pid,
                    recommendation=f"/proc/{proc.pid}/root altini ve podman/distrobox/flatpak oturumlarini kontrol edin.",
                )
            )


def _inspect_maps_and_fds(ctx: ScanContext, proc: ProcInfo) -> list[tuple[int, int, str, str]]:
    """Inspect /proc/<pid>/maps and /proc/<pid>/fd. Return readable regions for RAM scan."""
    pdir = ctx.proc_root / str(proc.pid)
    readable_regions: list[tuple[int, int, str, str]] = []

    # 1. Inspect /proc/<pid>/maps
    maps_text = safe_read_text(pdir / "maps", max_bytes=8 * 1024 * 1024)
    deleted_mapped: list[str] = []
    tmp_mapped: list[str] = []
    memfd_exec: list[str] = []
    anon_rwx: list[str] = []
    cheat_path_mapped: list[str] = []

    seen_deleted: set[str] = set()
    seen_cheat: set[str] = set()
    for line in maps_text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        addr_range, perms, _, _, inode = parts[:5]
        pathname = parts[5].strip() if len(parts) == 6 else ""

        if "-" in addr_range and perms.startswith("r"):
            try:
                s_hex, e_hex = addr_range.split("-", 1)
                start_addr = int(s_hex, 16)
                end_addr = int(e_hex, 16)
                if end_addr > start_addr:
                    readable_regions.append((start_addr, end_addr, perms, pathname))
            except ValueError:
                pass

        if pathname:
            low_p = pathname.lower()
            if "/libjvm.so" in low_p or low_p.endswith("/jvm.dll") or "\\jvm.dll" in low_p:
                proc.is_java = True
            if "liblwjgl" in low_p or "/.minecraft/" in low_p or "/.lunarclient/" in low_p:
                proc.is_minecraft = True
            if "(deleted)" in low_p and pathname not in seen_deleted:
                seen_deleted.add(pathname)
                if not _is_benign_deleted_map(pathname, perms):
                    deleted_mapped.append(pathname)

            clean_low_p = re.sub(r"\s*\(deleted\)$", "", low_p).strip()
            if (
                any(clean_low_p.startswith(t) for t in ("/tmp/", "/dev/shm/", "/var/tmp/"))
                and not clean_low_p.startswith("/tmp/.mount_")
                and _TMP_MAPPED_EXT_RE.search(clean_low_p)
                and not ("x" not in perms and any(clean_low_p.startswith(b) for b in BENIGN_DELETED_MAP_HINTS))
            ):
                bname = os.path.basename(re.sub(r"\s*\(deleted\)$", "", pathname).strip())
                if not _is_legit_tmp_so(bname):
                    if pathname not in tmp_mapped:
                        tmp_mapped.append(pathname)

            if low_p.startswith("/memfd:") and "x" in perms:
                if not any(low_p.startswith(b) for b in BENIGN_EXEC_MEMFD_PREFIXES):
                    if pathname not in memfd_exec:
                        memfd_exec.append(f"{perms} {pathname}")

            if pathname not in seen_cheat:
                seen_cheat.add(pathname)
                strict, high_ctx, _ = match_cheat_signatures(pathname)
                if strict or high_ctx:
                    cheat_path_mapped.append(f"{pathname} [{','.join(strict + high_ctx)}]")
        else:
            # Anonymous rwxp in non-JIT native process can indicate shellcode/reflective loader
            if (
                perms == "rwxp"
                and not proc.is_java
                and not proc.is_wine
                and not _is_legit_jit_process(proc)
                and inode == "0"
            ):
                anon_rwx.append(f"{addr_range} {perms}")

    if deleted_mapped:
        ctx.add_finding(
            Finding(
                rule_id="E2-MAP-DELETED-BIN",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Memory Injection / Deleted Payload",
                title=f"Diskten silinmis ama RAM'e map edilmis dosya tespit edildi (PID {proc.pid})",
                description="Surecin belleginde halen yuklu olan ancak diskten silinmis (.jar/.so/binary) dosya bulundu.",
                evidence=deleted_mapped[:15],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True
    if tmp_mapped:
        ctx.add_finding(
            Finding(
                rule_id="E2-MAP-TMP-LIB",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Suspicious Mapped Library",
                title=f"/tmp veya /dev/shm icinden yuklenmis supheli .so/.jar (PID {proc.pid})",
                description="Standart LWJGL/JNA listesi disinda kalan gecici dizin kutuphanesi bellege map edilmis.",
                evidence=tmp_mapped[:15],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True
    if memfd_exec:
        ctx.add_finding(
            Finding(
                rule_id="E2-MAP-EXEC-MEMFD",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Fileless Mapped Code",
                title=f"Calistirilabilir (executable) memfd bellek bolgesi (PID {proc.pid})",
                description="Disk destegi olmayan calistirilabilir memfd alani tespit edildi.",
                evidence=memfd_exec[:10],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True
    if cheat_path_mapped:
        ctx.add_finding(
            Finding(
                rule_id="E2-MAP-CHEAT-PATH",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Loaded Cheat Library",
                title=f"Bellekte dogrudan hile isimli dosya yuklu (PID {proc.pid})",
                description="Surecin bellek haritasinda hile imzasi tasiyan dosya yolu goruldu.",
                evidence=cheat_path_mapped[:15],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True
    if len(anon_rwx) >= 2 and not proc.is_java and not proc.is_wine and not _is_legit_jit_process(proc):
        ctx.add_finding(
            Finding(
                rule_id="E2-MAP-ANON-RWX",
                engine=ENGINE_NAME,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category="Reflective Code",
                title=f"Java disi surecte birden fazla anonim RWX bellek sayfasi (PID {proc.pid})",
                description="Okunabilir-yazilabilir-calistirilabilir anonim bellek sayfalari reflektif enjeksiyon isareti olabilir.",
                evidence=anon_rwx[:8],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True

    # 2. Inspect /proc/<pid>/fd/*
    fd_dir = pdir / "fd"
    deleted_fds: list[str] = []
    input_fds: list[str] = []
    raw_mem_fds: list[str] = []
    cheat_fds: list[str] = []
    if fd_dir.is_dir():
        try:
            for fd_entry in fd_dir.iterdir():
                target = _read_proc_link(fd_entry)
                if not target:
                    continue
                tlow = target.lower()
                if tlow.endswith(" (deleted)") and not _is_benign_deleted_map(target):
                    clean_fd_path = tlow[: -len(" (deleted)")].strip()
                    fname_only = clean_fd_path.rsplit("/", 1)[-1]
                    if (
                        clean_fd_path.endswith(
                            (".jar", ".so", ".dll", ".exe", ".class", ".json", ".py", ".sh", ".zip", ".bin", ".dat", ".appimage", ".lua")
                        )
                        or ".so." in fname_only
                        or (
                            clean_fd_path.startswith(("/tmp/", "/dev/shm/", "/var/tmp/"))
                            and not clean_fd_path.startswith("/tmp/.mount_")
                            and "/hsperfdata_" not in clean_fd_path
                        )
                    ):
                        deleted_fds.append(f"fd/{fd_entry.name} -> {target}")
                if tlow == "/dev/uinput" or tlow.startswith("/dev/input/event"):
                    # Legitimate display servers / compositors / browsers / game portals / input daemons
                    if not any(
                        d in proc.comm.lower()
                        for d in (
                            "kwin",
                            "gnome-shell",
                            "sway",
                            "hyprland",
                            "xorg",
                            "xwayland",
                            "libinput",
                            "systemd",
                            "ratbagd",
                            "steam",
                            "chrome",
                            "chromium",
                            "firefox",
                            "opera",
                            "discord",
                            "xdg-desktop",
                            "pipewire",
                            "solaar",
                        )
                    ):
                        input_fds.append(f"fd/{fd_entry.name} -> {target}")
                strict, high_ctx, _ = match_cheat_signatures(target)
                if strict or high_ctx:
                    cheat_fds.append(f"fd/{fd_entry.name} -> {target}")
                if (
                    tlow in ("/dev/mem", "/dev/kmem", "/dev/port") or tlow.startswith("/dev/uio")
                ) and proc.comm.lower() not in ("xorg", "dmidecode", "fwupd", "upowerd"):
                    raw_mem_fds.append(f"fd/{fd_entry.name} -> {target}")
        except OSError:
            pass

    if deleted_fds:
        ctx.add_finding(
            Finding(
                rule_id="E2-FD-DELETED-FILE",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Deleted Open Artifact",
                title=f"Acik dosya taniticisinda (fd) diskten silinmis kritik dosya (PID {proc.pid})",
                description="Program acikken dosya diskten silinmis ancak halen acik tutuluyor.",
                evidence=deleted_fds[:15],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True
    if input_fds:
        ctx.add_finding(
            Finding(
                rule_id="E2-FD-UINPUT-ACCESS",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category="Macro / Kernel Input Access",
                title=f"Surec dogrudan /dev/uinput veya input event cihazini acik tutuyor (PID {proc.pid})",
                description="Kullanici alani bir surecin uinput veya event aygitini acmasi yapay tiklama/makro kanitidir.",
                evidence=input_fds[:10] + [f"comm={proc.comm}", f"cmdline={proc.cmdline_str[:180]}"],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True
    if cheat_fds:
        ctx.add_finding(
            Finding(
                rule_id="E2-FD-CHEAT-PATH",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Open Cheat File",
                title=f"Surec hile isimli bir dosyayi acik tutuyor (PID {proc.pid})",
                description="Acik dosya taniticilari arasinda hile mod/konfigurasyon/binary yolu tespit edildi.",
                evidence=cheat_fds[:10],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True
    if raw_mem_fds:
        ctx.add_finding(
            Finding(
                rule_id="E2-FD-RAW-DEV-ACCESS",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Raw Memory / DMA Access",
                title=f"Surec fiziksel bellek/DMA aygitini (/dev/mem|/dev/port|/dev/uio) acik tutuyor (PID {proc.pid})",
                description="Kullanici alani bir surecin fiziksel bellek veya UIO DMA aygitini acmasi doğrudan bellek okuma/yazma belirtisidir.",
                evidence=raw_mem_fds[:10] + [f"comm={proc.comm}"],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True

    return readable_regions


def _should_scan_region(perms: str, pathname: str, size: int) -> bool:
    if "r" not in perms or size <= 0:
        return False
    # Skip non-RAM device / kernel special mappings
    if pathname in ("[vvar]", "[vsyscall]", "[vdso]"):
        return False
    low = pathname.lower()
    if low.startswith(("/dev/", "/usr/lib/locale", "/usr/share/fonts", "/usr/share/icons")):
        return False
    # Skip giant shared caches > 128 MB per single mapping unless anonymous/tmp/deleted
    if size > 128 * 1024 * 1024 and pathname and "(deleted)" not in low and "/tmp/" not in low:
        return False
    return True


def _is_ram_ident_byte(b: int) -> bool:
    return (97 <= b <= 122) or (48 <= b <= 57) or b == 95


def _scan_region_bytes(
    data: bytes,
    base_addr: int,
    pathname: str,
    strict_hits: dict[str, list[str]],
    cluster_hits: list[str],
    reflective_elf_hits: list[str],
) -> None:
    if not data:
        return
    low_data = data.lower()
    n = len(data)

    # 1. Strict ASCII & UTF-16LE signatures (case-sensitive on pre-lowered bytes -> ~20x faster than IGNORECASE)
    for m in _RAM_STRICT_CS_RE.finditer(low_data):
        term = m.group(0).decode("ascii", errors="replace")
        if len(strict_hits.get(term, [])) < 5:
            start = max(0, m.start() - 32)
            end = min(n, m.end() + 48)
            snippet = data[start:end].decode("ascii", errors="replace")
            snippet_clean = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in snippet)
            strict_hits.setdefault(term, []).append(
                f"0x{base_addr + m.start():x} ({pathname or 'anon'}): ...{snippet_clean}..."
            )
    for m in _RAM_STRICT_BOUNDED_CS_RE.finditer(low_data):
        st, en = m.span()
        ok_start = (
            st == 0
            or not _is_ram_ident_byte(low_data[st - 1])
            or (((97 <= data[st - 1] <= 122) or (48 <= data[st - 1] <= 57)) and (65 <= data[st] <= 90))
        )
        if not ok_start:
            continue
        ok_end = (
            en == n
            or not _is_ram_ident_byte(low_data[en])
            or ((65 <= data[en] <= 90) and not (65 <= data[en - 1] <= 90))
        )
        if not ok_end:
            continue
        term = m.group(0).decode("ascii", errors="replace")
        if len(strict_hits.get(term, [])) < 5:
            start = max(0, st - 32)
            end = min(n, en + 48)
            snippet = data[start:end].decode("ascii", errors="replace")
            snippet_clean = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in snippet)
            strict_hits.setdefault(term, []).append(
                f"0x{base_addr + st:x} ({pathname or 'anon'}): ...{snippet_clean}..."
            )
    if b"\x00" in low_data:
        for m in _RAM_STRICT_UTF16_CS_RE.finditer(low_data):
            term = m.group(0).decode("utf-16le", errors="replace")
            if len(strict_hits.get(term, [])) < 5:
                strict_hits.setdefault(term, []).append(
                    f"0x{base_addr + m.start():x} [UTF-16LE] ({pathname or 'anon'})"
                )

    # 2. Contextual module clustering (only in non-system mappings or anonymous heap/metaspace/memfd)
    if not pathname or "/tmp/" in pathname or "(deleted)" in pathname or "anon" in pathname or "/memfd:" in pathname:
        # Single-pass scan over chunk, bucketed into 64 KB windows with word & CamelCase boundary verification
        win = 65536
        buckets: dict[int, set[bytes]] = {}
        for m in _RAM_CLUSTER_CS_RE.finditer(low_data):
            st, en = m.span()
            ok_start = (
                st == 0
                or not _is_ram_ident_byte(low_data[st - 1])
                or (((97 <= data[st - 1] <= 122) or (48 <= data[st - 1] <= 57)) and (65 <= data[st] <= 90))
            )
            if not ok_start:
                continue
            ok_end = (
                en == n
                or not _is_ram_ident_byte(low_data[en])
                or ((65 <= data[en] <= 90) and not (65 <= data[en - 1] <= 90))
            )
            if ok_end:
                buckets.setdefault(st // win, set()).add(m.group(1))
        for bidx, found_terms in buckets.items():
            if len(found_terms) >= 3 and (found_terms & _HIGH_SIG_BYTES):
                if len(cluster_hits) < 8:
                    terms_sorted = sorted(t.decode("ascii", errors="replace") for t in found_terms)
                    cluster_hits.append(
                        f"0x{base_addr + bidx * win:x} ({pathname or 'anon'}): [{', '.join(terms_sorted)}]"
                    )

    # 3. Reflective ELF header inside anonymous memory
    if not pathname and len(reflective_elf_hits) < 5:
        pos = 0
        while len(reflective_elf_hits) < 5:
            idx = data.find(b"\x7fELF", pos)
            if idx == -1 or idx + 24 > n:
                break
            # Validate ELF class (1/2), endianness (1/2), EI_VERSION=1, zero EI_PAD, valid e_type (1/2/3)
            if (
                data[idx + 4] in (1, 2)
                and data[idx + 5] in (1, 2)
                and data[idx + 6] == 1
                and data[idx + 9 : idx + 16] == b"\x00" * 7
                and (
                    (data[idx + 5] == 1 and data[idx + 16] in (1, 2, 3) and data[idx + 17] == 0)
                    or (data[idx + 5] == 2 and data[idx + 16] == 0 and data[idx + 17] in (1, 2, 3))
                )
            ):
                hit = f"0x{base_addr + idx:x} [anon mem ELF header]"
                if hit not in reflective_elf_hits:
                    reflective_elf_hits.append(hit)
                pos = idx + 24
            else:
                pos = idx + 4


def _scan_process_memory(
    ctx: ScanContext, proc: ProcInfo, regions: list[tuple[int, int, str, str]]
) -> None:
    if not ctx.enable_memory_scan:
        return
    mem_path = ctx.proc_root / str(proc.pid) / "mem"
    if not mem_path.exists():
        return

    # Prioritize deleted/tmp/shm/memfd, then [heap]/[stack], then <=32MB writable/exec anon, before huge JVM heaps
    def _priority(reg: tuple[int, int, str, str]) -> int:
        s_addr, e_addr, perms, path = reg
        size = e_addr - s_addr
        if "(deleted)" in path or "/tmp/" in path or "/dev/shm/" in path or path.startswith("/memfd:"):
            return 0
        if path in ("[heap]", "[stack]"):
            return 1
        if not path and size <= 32 * 1024 * 1024 and ("x" in perms or "w" in perms):
            return 2
        if ".jar" in path or ".so" in path:
            return 3
        if not path and ("x" in perms or "w" in perms):
            return 4
        return 5

    ordered = sorted(regions, key=_priority)
    chunk_size = 2 * 1024 * 1024
    overlap = 256
    total_scanned = 0
    skipped_zero_bytes = 0
    max_zero_skip = 512 * 1024 * 1024
    budget = ctx.max_mem_scan_bytes_per_proc

    strict_hits: dict[str, list[str]] = {}
    cluster_hits: list[str] = []
    reflective_elf_hits: list[str] = []

    try:
        fd = os.open(mem_path, os.O_RDONLY)
    except PermissionError as exc:
        ctx.telemetry.setdefault("ram_scan_denied_pids", []).append(f"{proc.pid}: {exc}")
        if proc.is_minecraft or proc.is_java or proc.is_wine or proc.is_suspicious:
            ctx.add_finding(
                Finding(
                    rule_id="E2-RAM-ACCESS-DENIED",
                    engine=ENGINE_NAME,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    category="Memory Access Visibility",
                    title=f"Hedef surecin canli RAM alani okunamadi: {proc.comm} (PID {proc.pid})",
                    description="YAMA ptrace_scope, Flatpak/sandbox veya UID izolasyonu nedeniyle /proc/<pid>/mem incelenemedi (yetkili Ring-0 VMA modu ile okunabilir).",
                    evidence=[f"PID={proc.pid} comm={proc.comm} exe={proc.exe} err={exc}"],
                    path=str(mem_path),
                )
            )
        return
    except OSError as exc:
        ctx.telemetry.setdefault("ram_scan_denied_pids", []).append(f"{proc.pid}: {exc}")
        return

    try:
        for start, end, perms, pathname in ordered:
            if ctx.is_cancelled():
                from .orchestrator import ScanCancelledError

                raise ScanCancelledError("Tarama kullanici tarafindan iptal edildi.")
            if total_scanned >= budget:
                break
            size = end - start
            if not _should_scan_region(perms, pathname, size):
                continue

            offset = start
            prev_tail = b""
            consecutive_err = 0
            while offset < end and total_scanned < budget:
                if ctx.is_cancelled():
                    from .orchestrator import ScanCancelledError

                    raise ScanCancelledError("Tarama kullanici tarafindan iptal edildi.")
                to_read = min(chunk_size, end - offset, budget - total_scanned)
                try:
                    buf = os.pread(fd, to_read, offset)
                    consecutive_err = 0
                except OSError:
                    consecutive_err += 1
                    if consecutive_err >= 8:
                        break
                    offset += min(65536, to_read)
                    prev_tail = b""
                    continue
                if not buf:
                    break
                # Skip uncommitted/all-zero pages (e.g., unused JVM heap reservation) without allocating copies
                if buf[:64] == b"\x00" * 64 and buf.count(0) == len(buf):
                    skipped_zero_bytes += len(buf)
                    prev_tail = b""
                    offset += len(buf)
                    if skipped_zero_bytes >= max_zero_skip:
                        total_scanned += len(buf)
                    continue
                total_scanned += len(buf)
                combined = prev_tail + buf
                base_addr = offset - len(prev_tail)
                _scan_region_bytes(
                    combined,
                    base_addr,
                    pathname,
                    strict_hits,
                    cluster_hits,
                    reflective_elf_hits,
                )
                prev_tail = buf[-overlap:] if len(buf) >= overlap else buf
                offset += len(buf)
    finally:
        os.close(fd)

    ctx.telemetry.setdefault("ram_scanned_bytes", {})[str(proc.pid)] = total_scanned

    if strict_hits:
        ev = []
        for term, locs in list(strict_hits.items())[:10]:
            ev.append(f"Imza '{term}': {locs[0]}")
        ctx.add_finding(
            Finding(
                rule_id="E2-RAM-STRICT-SIG",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="RAM Memory Signature",
                title=f"Surec belleginde (RAM) hile istemcisi/modul imzasi yakalandi (PID {proc.pid})",
                description="Diskten silinse bile canli RAM icinde yasayan hile sinifi veya string imzasi bulundu.",
                evidence=ev,
                pid=proc.pid,
            )
        )
    if cluster_hits:
        ctx.add_finding(
            Finding(
                rule_id="E2-RAM-MODULE-CLUSTER",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category="RAM Cheat Module Cluster",
                title=f"RAM icinde coklu hile modulu kumesi tespit edildi (PID {proc.pid})",
                description="Ayni bellek sayfasinda birden fazla PvP/Ghost hile modulu adi bir arada bulundu.",
                evidence=cluster_hits,
                pid=proc.pid,
            )
        )
    if reflective_elf_hits:
        ctx.add_finding(
            Finding(
                rule_id="E2-RAM-REFLECTIVE-ELF",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Reflective In-Memory Binary",
                title=f"Anonim RAM bolgesinde gomulu ELF binary basligi (PID {proc.pid})",
                description="Dosya destegi olmayan bellekte reflektif yuklenmis ELF kutuphanesi olasiligi.",
                evidence=reflective_elf_hits,
                pid=proc.pid,
            )
        )


def _inspect_hsperfdata_and_jcmd(ctx: ScanContext, java_procs: list[ProcInfo]) -> None:
    # Direct binary inspection of /tmp/hsperfdata_*
    tmp_dir = ctx.sys_path("/tmp")
    if tmp_dir.is_dir():
        try:
            for d in tmp_dir.glob("hsperfdata_*"):
                if not d.is_dir():
                    continue
                for perf_file in d.iterdir():
                    if not perf_file.is_file():
                        continue
                    raw = safe_read_bytes(perf_file, max_bytes=512 * 1024)
                    if not raw:
                        continue
                    strings_found = re.findall(rb"[\x20-\x7e]{6,}", raw)
                    joined = "\n".join(s.decode("ascii", errors="replace") for s in strings_found)
                    strict, high_ctx, _ = match_cheat_signatures(joined)
                    jlow = joined.lower()
                    if strict or high_ctx or "-javaagent" in jlow or "-agentpath" in jlow:
                        ev = [
                            ln[:200]
                            for ln in joined.splitlines()
                            if any(k in ln.lower() for k in ("-javaagent", "-agentpath", *strict, *high_ctx))
                        ]
                        is_lunar_only = (
                            bool(ev)
                            and not strict
                            and not high_ctx
                            and "-agentpath" not in jlow
                            and "disableattachmechanism" not in jlow
                            and "perfdisablesharedmem" not in jlow
                            and "-xbootclasspath" not in jlow
                            and all(".lunarclient" in ln.lower() and "ichor" in ln.lower() for ln in ev)
                        )
                        ctx.add_finding(
                            Finding(
                                rule_id="E2-HSPERF-SUSPICIOUS",
                                engine=ENGINE_NAME,
                                severity=Severity.INFO if is_lunar_only else (Severity.CRITICAL if strict else Severity.HIGH),
                                confidence=Confidence.HIGH,
                                category="JVM PerfData Trace",
                                title=(
                                    f"hsperfdata Lunar Ichor agent izi: {perf_file.name}"
                                    if is_lunar_only
                                    else f"hsperfdata JVM belleginde supheli arguman/iz: {perf_file.name}"
                                ),
                                description="Java HotSpot performans verisi icinde agent veya hile parametresi bulundu.",
                                evidence=ev[:10],
                                path=str(perf_file),
                            )
                        )
        except OSError:
            pass

    if not ctx.live_mode:
        return

    for proc in java_procs:
        if not (proc.is_minecraft or proc.is_java):
            continue
        pid_s = str(proc.pid)
        rc, help_out, _ = run_trusted_cmd(["jcmd", pid_s, "help"], timeout=3.0)
        if rc != 0:
            # If Minecraft specifically refuses jcmd attach without legitimate reason, record note
            if proc.is_minecraft:
                ctx.telemetry.setdefault("jcmd_unreadable", []).append(pid_s)
            continue

        avail = set(help_out.splitlines())
        # Check VM.flags and VM.system_properties
        for cmd_name in ("VM.flags", "VM.system_properties"):
            if any(cmd_name in ln for ln in avail):
                rc2, out2, _ = run_trusted_cmd(["jcmd", pid_s, cmd_name], timeout=4.0)
                if rc2 == 0 and out2:
                    low2 = out2.lower()
                    if any(
                        f in low2
                        for f in ("-javaagent:", "-agentpath:", "disableattachmechanism", "perfdisablesharedmem", "-xbootclasspath")
                    ):
                        lines = [
                            ln.strip()[:220]
                            for ln in out2.splitlines()
                            if any(
                                f in ln.lower()
                                for f in (
                                    "-javaagent",
                                    "-agentpath",
                                    "disableattach",
                                    "perfdisablesharedmem",
                                    "-xbootclasspath",
                                    "cheat",
                                    "vape",
                                    "meteor",
                                )
                            )
                        ]
                        if lines:
                            strict2, high2, _ = match_cheat_signatures(out2)
                            is_lunar_only = (
                                not strict2
                                and not high2
                                and not any(
                                    bad in low2
                                    for bad in (
                                        "-agentpath:",
                                        "disableattachmechanism",
                                        "perfdisablesharedmem",
                                        "-xbootclasspath",
                                    )
                                )
                                and all(".lunarclient" in ln.lower() and "ichor" in ln.lower() for ln in lines)
                            )
                            ctx.add_finding(
                                Finding(
                                    rule_id="E2-JCMD-FLAGS",
                                    engine=ENGINE_NAME,
                                    severity=Severity.INFO if is_lunar_only else Severity.HIGH,
                                    confidence=Confidence.CONFIRMED,
                                    category="JVM Live Flags",
                                    title=(
                                        f"jcmd {cmd_name} icinde Lunar Ichor agent izi (PID {proc.pid})"
                                        if is_lunar_only
                                        else f"jcmd {cmd_name} icinde agent/ozel JVM bayragi (PID {proc.pid})"
                                    ),
                                    description="Canli JVM bayraklari/sistem ozelliklerinde enjeksiyon izi tespit edildi.",
                                    evidence=lines[:10],
                                    pid=proc.pid,
                                )
                            )

        # Class list inspection (supports JDK 17/21/25 VM.classes, VM.class_hierarchy, GC.class_stats)
        class_cmd = None
        for cand in ("VM.classes", "VM.class_hierarchy", "GC.class_stats"):
            if any(cand in ln for ln in avail):
                class_cmd = cand
                break
        if class_cmd:
            rc3, cout, _ = run_trusted_cmd(["jcmd", pid_s, class_cmd], timeout=6.0)
            if rc3 == 0 and cout:
                cheat_classes: list[str] = []
                attach_classes: list[str] = []
                for line in cout.splitlines():
                    low = line.lower()
                    norm = low.replace(".", "/")
                    if "com.sun.tools.attach" in low or "instrumentationimpl" in low:
                        attach_classes.append(line.strip()[:180])
                        continue
                    strict, high_ctx, _ = match_cheat_signatures(line)
                    if strict:
                        cheat_classes.append(line.strip()[:180])
                        continue
                    if any(norm.strip().startswith(p) or f" {p}" in norm for p in LEGIT_JAVA_PREFIXES):
                        continue
                    if high_ctx:
                        cheat_classes.append(line.strip()[:180])

                if cheat_classes:
                    ctx.add_finding(
                        Finding(
                            rule_id="E2-JCMD-CHEAT-CLASSES",
                            engine=ENGINE_NAME,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            category="JVM Loaded Cheat Classes",
                            title=f"Canli JVM icinde yuklu hile siniflari tespit edildi (PID {proc.pid})",
                            description=f"jcmd {class_cmd} ciktisinda hile istemcisi/modulu siniflari goruldu.",
                            evidence=cheat_classes[:20],
                            pid=proc.pid,
                        )
                    )
                if attach_classes:
                    ctx.add_finding(
                        Finding(
                            rule_id="E2-JCMD-ATTACH-LOADED",
                            engine=ENGINE_NAME,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="JVM Dynamic Attach",
                            title=f"JVM icinde Dynamic Attach / Instrumentation sinifi yuklu (PID {proc.pid})",
                            description="Calisma aninda sinif enjeksiyonu veya agent yuklenmesi gerceklesmis olabilir.",
                            evidence=attach_classes[:10],
                            pid=proc.pid,
                        )
                    )


def _check_live_containers(ctx: ScanContext) -> None:
    if not ctx.live_mode:
        return
    for label, cmd in (
        ("Podman", ["podman", "ps", "-a", "--format", "{{.ID}} {{.Image}} {{.Status}} {{.Names}}"]),
        ("Distrobox", ["distrobox", "list", "--no-color"]),
    ):
        rc, out, _ = run_trusted_cmd(cmd, timeout=4.0)
        if rc == 0 and out.strip():
            lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
            # Distrobox prints header even when empty
            non_header = [ln for ln in lines if not ln.startswith("ID ") and not ln.startswith("---")]
            if non_header:
                ctx.telemetry[f"containers_{label.lower()}"] = non_header
                # Flag running containers as informational/medium for manual review
                running = [ln for ln in non_header if "up " in ln.lower() or "running" in ln.lower()]
                if running:
                    ctx.add_finding(
                        Finding(
                            rule_id="E2-CONTAINER-RUNNING",
                            engine=ENGINE_NAME,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            category="Container Isolation",
                            title=f"Aktif {label} containeri calisiyor ({len(running)} adet)",
                            description="Oyuncu gizli bir Linux containeri icinde oyun veya makro/hile calistiriyor olabilir.",
                            evidence=running[:10],
                            recommendation=f"`{cmd[0]} exec` veya GUI ile container icerigini kontrol edin.",
                        )
                    )


_CORE_TEXT_COW_LIBS = (
    "libjvm.so",
    "libc.so",
    "liblwjgl",
    "libglfw",
    "libopenal",
    "libgl.so",
    "libx11.so",
    "libwayland",
    "libdl.so",
    "ld-linux",
)


_SMAPS_HDR_RE = re.compile(
    r"^[0-9a-fA-F]+-[0-9a-fA-F]+\s+[rwxps-]{4}\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+:[0-9a-fA-F]+\s+\d+(?:\s+.*)?$"
)


def _inspect_smaps_text_cow(ctx: ScanContext, proc: ProcInfo) -> None:
    """Detect Copy-on-Write dirty anonymous pages inside read-only file-backed .text VMAs."""
    smaps_text = safe_read_text(ctx.proc_root / str(proc.pid) / "smaps", max_bytes=12 * 1024 * 1024)
    if not smaps_text:
        return

    cur_hdr = ""
    cur_path = ""
    priv_dirty = 0
    anon_kb = 0
    cow_hits: list[str] = []
    crit_hit = False

    def _flush() -> None:
        nonlocal crit_hit
        if not cur_hdr or " r-xp " not in cur_hdr or ".so" not in cur_path.lower():
            return
        low = cur_path.lower()
        if "libffi" in low:
            return
        if priv_dirty > 0 and anon_kb > 0 and (
            any(k in low for k in _CORE_TEXT_COW_LIBS)
            or any(d in low for d in ("/tmp/", "/dev/shm/", "/.minecraft/", "/.lunarclient/"))
        ):
            cow_hits.append(f"{cur_path} (Private_Dirty={priv_dirty}kB Anonymous={anon_kb}kB)")
            if any(k in low for k in ("libjvm.so", "libc.so", "liblwjgl", "libglfw")):
                crit_hit = True

    for ln in smaps_text.splitlines():
        if _SMAPS_HDR_RE.match(ln):
            _flush()
            parts = ln.split(None, 5)
            cur_hdr = ln if len(parts) >= 5 else ""
            cur_path = parts[5].strip() if len(parts) == 6 else ""
            priv_dirty = 0
            anon_kb = 0
        elif ln.startswith("Private_Dirty:"):
            try:
                priv_dirty = int(ln.split()[1])
            except (IndexError, ValueError):
                pass
        elif ln.startswith("Anonymous:"):
            try:
                anon_kb = int(ln.split()[1])
            except (IndexError, ValueError):
                pass
    _flush()

    if cow_hits:
        ctx.add_finding(
            Finding(
                rule_id="E2-MAP-TEXT-COW-PATCH",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL if crit_hit else Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Inline Text Patch / Injection",
                title=f"Salt-okunur .text kod sayfasinda Copy-on-Write bellek yamasi tespit edildi (PID {proc.pid})",
                description="libjvm/libc/LWJGL gibi kutuphanelerin salt-okunur kod segmentinde bellek içi inline hook/yama izi (Private_Dirty > 0) bulundu.",
                evidence=cow_hits[:10] + [f"comm={proc.comm}"],
                pid=proc.pid,
            )
        )
        proc.is_suspicious = True


def _is_electron_helper(proc: ProcInfo) -> bool:
    cmd = proc.cmdline_str.lower()
    if any(t in cmd for t in ("--type=gpu-process", "--type=utility", "--type=zygote", "--type=crashpad-handler")):
        return True
    # Only skip generic Chromium/Electron renderers; keep Minecraft launcher renderers (Lunar/Feather/Modrinth) in scope
    if "--type=renderer" in cmd and not proc.is_minecraft:
        return True
    return False


def run(ctx: ScanContext) -> None:
    try:
        emit_scan_progress(ctx, 0.05, "Calisan surecler toplanıyor (/proc)...")
        procs, init_ns = _collect_processes(ctx)
        by_pid = {p.pid: p for p in procs}
        my_uid = os.getuid()
        ctx.telemetry["total_processes"] = len(procs)
        ctx.telemetry["java_pids"] = [p.pid for p in procs if p.is_java]
        ctx.telemetry["minecraft_pids"] = [p.pid for p in procs if p.is_minecraft]
        record_scan_region(ctx, "E2", f"{ctx.proc_root} ({len(procs)} aktif surec)")

        emit_scan_progress(ctx, 0.20, f"{len(procs)} surec meta verisi ve komut satirlari inceleniyor...")
        for proc in procs:
            _inspect_process_metadata(ctx, proc, by_pid, init_ns)

        # Inspect /proc/<pid>/maps and /proc/<pid>/fd across all user-owned or target processes
        # so disguised Python/C external cheats (/dev/uinput, deleted .so/.jar) cannot hide.
        emit_scan_progress(ctx, 0.35, "Bellek haritalari (/proc/*/maps) ve acik dosyalar (/proc/*/fd) taraniyor...")
        regions_by_pid: dict[int, list[tuple[int, int, str, str]]] = {}
        for proc in procs:
            if (
                proc.uid is None
                or proc.uid == my_uid
                or proc.is_minecraft
                or proc.is_java
                or proc.is_wine
                or proc.is_suspicious
            ):
                regions_by_pid[proc.pid] = _inspect_maps_and_fds(ctx, proc)
        record_scan_region(ctx, "E2", f"/proc/<pid>/maps & fd ({len(regions_by_pid)} surec)")

        ctx.telemetry["java_pids"] = [p.pid for p in procs if p.is_java]
        ctx.telemetry["minecraft_pids"] = [p.pid for p in procs if p.is_minecraft]

        # Perform deep RAM scanning on Minecraft, Java, Wine, or any flagged suspicious process
        mem_targets = [
            proc
            for proc in procs
            if proc.is_suspicious
            or ((proc.is_minecraft or proc.is_java or proc.is_wine) and not _is_electron_helper(proc))
        ]
        n_mem = max(1, len(mem_targets))
        for idx, proc in enumerate(mem_targets):
            frac = 0.55 + (0.37 * (idx / n_mem))
            emit_scan_progress(ctx, frac, f"Canli RAM bellek taramasi: {proc.comm} (PID {proc.pid})...")
            _inspect_smaps_text_cow(ctx, proc)
            regs = regions_by_pid.get(proc.pid)
            if regs:
                _scan_process_memory(ctx, proc, regs)
        record_scan_region(
            ctx,
            "E2",
            f"Canli RAM Bellek Taramasi ({len(mem_targets)} hedef surec, enabled={ctx.enable_memory_scan})",
        )

        if not ctx.enable_memory_scan:
            ctx.set_coverage("E2.proc_mem", ScanStatus.SKIPPED, "Live /proc/<pid>/mem scan disabled")
        elif ctx.telemetry.get("ram_scan_denied_pids"):
            denied_n = len(ctx.telemetry.get("ram_scan_denied_pids") or [])
            ctx.set_coverage("E2.proc_mem", ScanStatus.PERMISSION_DENIED, f"{denied_n} target PID(s) denied /proc/<pid>/mem access")
        else:
            ctx.set_coverage("E2.proc_mem", ScanStatus.COMPLETED, f"{len(mem_targets)} target process(es) inspected")

        emit_scan_progress(ctx, 0.94, "JVM hsperfdata, jcmd ve container ortamlari kontrol ediliyor...")
        _inspect_hsperfdata_and_jcmd(ctx, [p for p in procs if p.is_java or p.is_minecraft])
        _check_live_containers(ctx)
        record_scan_region(ctx, "E2", f"{ctx.sys_path('/tmp')}/hsperfdata_* ve container runtime ortamlari")
        ctx.set_coverage("E2.processes", ScanStatus.COMPLETED, f"{len(procs)} processes enumerated")
        emit_scan_progress(ctx, 1.0, "Canli surec ve RAM analizi tamamlandi.")
    except Exception as exc:
        if exc.__class__.__name__ == "ScanCancelledError":
            raise
        ctx.set_coverage("E2.processes", ScanStatus.ERROR, str(exc))
        ctx.add_error(ENGINE_NAME, f"Beklenmeyen hata: {exc}")

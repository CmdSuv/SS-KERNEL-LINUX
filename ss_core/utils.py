"""Forensic utility primitives: ctypes statx, direct xattr, entropy, discovery, safe I/O."""

from __future__ import annotations

import codecs
import ctypes
import hashlib
import math
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .models import ScanContext
from .signatures import (
    CONTEXTUAL_CHEAT_MODULES,
    HIGH_SIGNAL_MODULE_NAMES,
    RESTRICTED_UTILITY_MOD_IDENTIFIERS,
    STRICT_CHEAT_IDENTIFIERS,
)

TOOL_ROOT: Path = Path(__file__).resolve().parent.parent


def _self_tool_roots() -> list[Path]:
    roots: list[Path] = [TOOL_ROOT]
    if getattr(sys, "frozen", False):
        try:
            roots.append(Path(sys.executable).resolve())
        except OSError:
            pass
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            try:
                roots.append(Path(str(meipass)).resolve())
            except OSError:
                pass
    env_bin = os.environ.get("SS_SENTINEL_SELF_BIN", "").strip()
    if env_bin:
        try:
            roots.append(Path(env_bin).resolve())
        except OSError:
            pass
    return roots


def is_self_tool_path(p: Path) -> bool:
    try:
        rp = p.resolve()
        for root in _self_tool_roots():
            if rp == root or rp.is_relative_to(root):
                return True
        return False
    except OSError:
        return False

# ---------------------------------------------------------------------------
# Linux statx(2) ABI (verified on x86_64 glibc / kernel 7.x)
# ---------------------------------------------------------------------------
AT_FDCWD = -100
AT_SYMLINK_NOFOLLOW = 0x100
STATX_BASIC_STATS = 0x7FF
STATX_BTIME = 0x800
_STATX_SIZE = 256

try:
    _LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
    _HAS_STATX = hasattr(_LIBC, "statx")
    if _HAS_STATX:
        _LIBC.statx.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.c_void_p,
        ]
        _LIBC.statx.restype = ctypes.c_int
except Exception:
    _LIBC = None
    _HAS_STATX = False


@dataclass(frozen=True)
class FileTimestamps:
    btime_ns: int | None
    ctime_ns: int
    mtime_ns: int
    atime_ns: int
    size: int
    mode: int
    ino: int
    nlink: int
    uid: int


def _unpack_statx_ts(buf: bytes, offset: int) -> int:
    sec, nsec = struct.unpack_from("<qI", buf, offset)
    return sec * 1_000_000_000 + nsec


def statx_timestamps(path: Path) -> FileTimestamps | None:
    """Retrieve btime/ctime/mtime/atime without following symlinks."""
    try:
        st = os.lstat(path)
    except OSError:
        return None

    btime_ns: int | None = None
    if _HAS_STATX and _LIBC is not None:
        buf = ctypes.create_string_buffer(_STATX_SIZE)
        try:
            rc = _LIBC.statx(
                AT_FDCWD,
                os.fsencode(path),
                AT_SYMLINK_NOFOLLOW,
                STATX_BASIC_STATS | STATX_BTIME,
                buf,
            )
            if rc == 0:
                raw = buf.raw
                mask = struct.unpack_from("<I", raw, 0)[0]
                if mask & STATX_BTIME:
                    bt = _unpack_statx_ts(raw, 80)
                    if bt > 0:
                        btime_ns = bt
        except Exception:
            pass

    return FileTimestamps(
        btime_ns=btime_ns,
        ctime_ns=st.st_ctime_ns,
        mtime_ns=st.st_mtime_ns,
        atime_ns=st.st_atime_ns,
        size=st.st_size,
        mode=st.st_mode,
        ino=st.st_ino,
        nlink=st.st_nlink,
        uid=st.st_uid,
    )


def fmt_ns(ns: int | None) -> str:
    if ns is None or ns <= 0:
        return "N/A"
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def read_xattrs(path: Path) -> dict[str, str]:
    """Read Linux extended attributes directly via os.listxattr/getxattr."""
    attrs: dict[str, str] = {}
    if not hasattr(os, "listxattr"):
        return attrs
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError:
        return attrs
    for name in names:
        try:
            val = os.getxattr(path, name, follow_symlinks=False)
            attrs[name] = val.decode("utf-8", errors="replace").strip("\x00")
        except OSError:
            continue
    return attrs


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


TRUSTED_BIN_DIRS: tuple[str, ...] = (
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/home/linuxbrew/.linuxbrew/bin",
)


def sanitized_subproc_env(preserve_display: bool = True) -> dict[str, str]:
    """Return a clean subprocess environment free of linker/JVM injection variables."""
    env = os.environ.copy()
    for bad_var in (
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_DEBUG",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "PYTHONPATH",
        "PYTHONHOME",
    ):
        env.pop(bad_var, None)
    if "LD_LIBRARY_PATH_ORIG" in env:
        orig_lp = env.pop("LD_LIBRARY_PATH_ORIG", "")
        if orig_lp:
            env["LD_LIBRARY_PATH"] = orig_lp
        else:
            env.pop("LD_LIBRARY_PATH", None)
    elif getattr(sys, "frozen", False):
        env.pop("LD_LIBRARY_PATH", None)
    env["PATH"] = ":".join(TRUSTED_BIN_DIRS)
    env["LC_ALL"] = "C"
    if not preserve_display:
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
    return env


def trusted_which(name: str) -> str | None:
    if not name or "/" in name or "\x00" in name:
        return None
    for d in TRUSTED_BIN_DIRS:
        candidate = Path(d) / name
        try:
            if candidate.exists() and os.access(candidate, os.X_OK) and not candidate.is_dir():
                return str(candidate)
        except OSError:
            continue
    return None


def run_trusted_cmd(cmd: list[str], timeout: float = 4.0) -> tuple[int, str, str]:
    """Execute a system tool resolved from trusted directories only."""
    if not cmd:
        return -1, "", "empty command"
    exe = cmd[0]
    if not os.path.isabs(exe):
        resolved = trusted_which(exe)
        if not resolved:
            return -1, "", f"binary not found in trusted dirs: {exe}"
        cmd = [resolved, *cmd[1:]]
    env = sanitized_subproc_env()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -2, "", f"timeout after {timeout}s"
    except OSError as exc:
        return -1, "", str(exc)


def safe_read_bytes(path: Path, max_bytes: int = 32 * 1024 * 1024) -> bytes:
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return b""
        with open(path, "rb") as fh:
            return fh.read(max_bytes)
    except OSError:
        return b""


def safe_read_text(path: Path, max_bytes: int = 8 * 1024 * 1024) -> str:
    raw = safe_read_bytes(path, max_bytes=max_bytes)
    return raw.decode("utf-8", errors="replace")


def safe_read_tail_bytes(path: Path, max_bytes: int = 2 * 1024 * 1024) -> bytes:
    """Read up to the final max_bytes of a regular file (seeks cleanly without reading from byte 0)."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return b""
        with open(path, "rb") as fh:
            if st.st_size > max_bytes > 0:
                fh.seek(st.st_size - max_bytes)
            return fh.read(max_bytes)
    except OSError:
        return b""


def safe_read_tail_text(path: Path, max_bytes: int = 2 * 1024 * 1024) -> str:
    raw = safe_read_tail_bytes(path, max_bytes=max_bytes)
    return raw.decode("utf-8", errors="replace")


def sha256_file(path: Path, limit_bytes: int = 128 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    read_total = 0
    try:
        with open(path, "rb") as fh:
            while read_total < limit_bytes:
                chunk = fh.read(min(65536, limit_bytes - read_total))
                if not chunk:
                    break
                h.update(chunk)
                read_total += len(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def rot13(s: str) -> str:
    return codecs.decode(s, "rot_13")


def copy_sqlite_with_sidecars(db_path: Path, tmp_dir: Path) -> Path | None:
    """Copy a potentially locked SQLite database + WAL/SHM sidecars safely."""
    try:
        if not db_path.is_file():
            return None
        dest = tmp_dir / db_path.name
        shutil.copy2(db_path, dest)
        for suffix in ("-wal", "-shm", "-journal"):
            side = Path(str(db_path) + suffix)
            if side.is_file():
                try:
                    shutil.copy2(side, Path(str(dest) + suffix))
                except OSError:
                    pass
        return dest
    except OSError:
        return None


_CAMEL_SPLIT_RE = re.compile(r"([a-z0-9])([A-Z])")


def normalize_identifier_tokens(raw: str) -> str:
    """Split CamelCase into lowercase token-friendly string."""
    s = _CAMEL_SPLIT_RE.sub(r"\1 \2", raw)
    return s.lower()


def build_str_trie_pattern(terms: Iterable[str]) -> str:
    """Compile an iterable of literal strings into a prefix-trie regex alternation."""
    root: dict[str | None, object] = {}
    for w in sorted({t for t in terms if t}):
        node = root
        for ch in w:
            nxt = node.get(ch)
            if nxt is None:
                nxt = {}
                node[ch] = nxt
            node = nxt  # type: ignore[assignment]
        node[None] = True
    if not root:
        return r"(?!)"

    def _emit(node: dict[str | None, object]) -> str:
        has_end = None in node
        children = sorted(k for k in node if k is not None)
        if not children:
            return ""
        if len(children) == 1 and not has_end:
            c = children[0]
            return re.escape(c) + _emit(node[c])  # type: ignore[arg-type]
        alts: list[str] = []
        leaf_chars: list[str] = []
        for c in children:
            sub = node[c]  # type: ignore[assignment]
            if len(sub) == 1 and None in sub:  # type: ignore[arg-type]
                leaf_chars.append(c)
            else:
                alts.append(re.escape(c) + _emit(sub))  # type: ignore[arg-type]
        if len(leaf_chars) == 1:
            alts.append(re.escape(leaf_chars[0]))
        elif len(leaf_chars) > 1:
            alts.append("[" + "".join(re.escape(c) for c in leaf_chars) + "]")
        body = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        return f"(?:{body})?" if has_end else body

    return _emit(root)


def build_bytes_trie_pattern(terms: Iterable[bytes]) -> bytes:
    """Compile an iterable of literal byte strings into a prefix-trie regex alternation."""
    root: dict[int | None, object] = {}
    for w in sorted({t for t in terms if t}):
        node = root
        for b in w:
            nxt = node.get(b)
            if nxt is None:
                nxt = {}
                node[b] = nxt
            node = nxt  # type: ignore[assignment]
        node[None] = True
    if not root:
        return b"(?!)"

    def _emit(node: dict[int | None, object]) -> bytes:
        has_end = None in node
        children = sorted(k for k in node if k is not None)
        if not children:
            return b""
        if len(children) == 1 and not has_end:
            c = children[0]
            return re.escape(bytes([c])) + _emit(node[c])  # type: ignore[arg-type]
        alts: list[bytes] = []
        leaf_bytes: list[int] = []
        for c in children:
            sub = node[c]  # type: ignore[assignment]
            if len(sub) == 1 and None in sub:  # type: ignore[arg-type]
                leaf_bytes.append(c)
            else:
                alts.append(re.escape(bytes([c])) + _emit(sub))  # type: ignore[arg-type]
        if len(leaf_bytes) == 1:
            alts.append(re.escape(bytes([leaf_bytes[0]])))
        elif len(leaf_bytes) > 1:
            alts.append(b"[" + b"".join(re.escape(bytes([c])) for c in leaf_bytes) + b"]")
        body = alts[0] if len(alts) == 1 else b"(?:" + b"|".join(alts) + b")"
        return b"(?:" + body + b")?" if has_end else body

    return _emit(root)


_ANY_CHEAT_LITERAL_RE = re.compile(
    build_str_trie_pattern(s.lower() for s in (set(STRICT_CHEAT_IDENTIFIERS) | set(CONTEXTUAL_CHEAT_MODULES)))
)

_STRICT_CS_PATTERN = re.compile(
    build_str_trie_pattern(s.lower() for s in STRICT_CHEAT_IDENTIFIERS)
)

# Single-pass CamelCase-aware boundary alternation for contextual modules:
# - Matches `KillAura`, `AutoClicker`, `myKillAuraMod`, `showHitboxes`, `kill_aura`, `KILLAURA`
# - Still respects word boundaries so `breach` != `reach` and `timer1` != `timer`
_CTX_TRIE = build_str_trie_pattern(term.lower() for term in CONTEXTUAL_CHEAT_MODULES)
_CONTEXT_COMBINED_RE = re.compile(
    r"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z]))"
    rf"(?i:({_CTX_TRIE}))"
    r"(?:(?![A-Za-z0-9])|(?<![A-Z])(?=[A-Z]))"
)


_RESTRICTED_MOD_TRIE = build_str_trie_pattern(term.lower() for term in RESTRICTED_UTILITY_MOD_IDENTIFIERS)
_RESTRICTED_MOD_RE = re.compile(
    r"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z]))"
    rf"(?i:({_RESTRICTED_MOD_TRIE}))"
    r"(?:(?![A-Za-z0-9])|(?<![A-Z])(?=[A-Z]))"
)


def match_restricted_utility_mods(raw_text: str) -> list[str]:
    """Match text against competitive-server banned/restricted utility mod IDs."""
    if not raw_text or not RESTRICTED_UTILITY_MOD_IDENTIFIERS:
        return []
    return sorted({m.group(1).lower() for m in _RESTRICTED_MOD_RE.finditer(raw_text)})


def match_cheat_signatures(raw_text: str) -> tuple[list[str], list[str], list[str]]:
    """Match text against strict and contextual cheat signatures.

    Returns:
        (strict_hits, high_signal_module_hits, other_contextual_hits)
    """
    if not raw_text:
        return [], [], []
    low = raw_text.lower()
    if _ANY_CHEAT_LITERAL_RE.search(low) is None:
        return [], [], []
    strict_hits = sorted({m.group(0) for m in _STRICT_CS_PATTERN.finditer(low)})
    ctx_hits = {m.group(1).lower() for m in _CONTEXT_COMBINED_RE.finditer(raw_text)}
    high_ctx = sorted(t for t in ctx_hits if t in HIGH_SIGNAL_MODULE_NAMES)
    low_ctx = sorted(t for t in ctx_hits if t not in HIGH_SIGNAL_MODULE_NAMES)
    return strict_hits, high_ctx, low_ctx


def discover_minecraft_roots(ctx: ScanContext) -> list[tuple[str, Path]]:
    """Locate standard, third-party, and Flatpak Minecraft launcher directories."""
    h = ctx.home_dir
    candidates: list[tuple[str, Path]] = [
        ("Standard .minecraft", h / ".minecraft"),
        ("PrismLauncher", h / ".local/share/PrismLauncher"),
        ("MultiMC", h / ".local/share/multimc"),
        ("PolyMC", h / ".local/share/PolyMC"),
        ("Lunar Client", h / ".lunarclient"),
        ("Lunar Config", h / ".config/lunarclient"),
        ("Badlion Client", h / ".config/Badlion Client"),
        ("Modrinth App (config)", h / ".config/ModrinthApp"),
        ("Modrinth App (data)", h / ".local/share/ModrinthApp"),
        ("ATLauncher", h / ".local/share/atlauncher"),
        ("ATLauncher (home)", h / ".atlauncher"),
        ("HMCL", h / ".hmcl"),
        ("TLauncher", h / ".tlauncher"),
        ("GDLauncher", h / ".config/gdlauncher_next"),
        ("Feather Client", h / ".config/feather"),
        (
            "Flatpak PrismLauncher",
            h / ".var/app/org.prismlauncher.PrismLauncher/data/PrismLauncher",
        ),
        (
            "Flatpak Minecraft",
            h / ".var/app/com.mojang.Minecraft/.minecraft",
        ),
        (
            "Flatpak ATLauncher",
            h / ".var/app/com.atlauncher.ATLauncher/data/atlauncher",
        ),
        (
            "Flatpak Modrinth (config)",
            h / ".var/app/com.modrinth.ModrinthApp/config/ModrinthApp",
        ),
        (
            "Flatpak Modrinth (data)",
            h / ".var/app/com.modrinth.ModrinthApp/data/ModrinthApp",
        ),
        (
            "Flatpak Lunar",
            h / ".var/app/com.lunarclient.LunarClient/.lunarclient",
        ),
        (
            "Snap PrismLauncher",
            h / "snap/prismlauncher/current/.local/share/PrismLauncher",
        ),
        (
            "Snap Minecraft",
            h / "snap/mc-installer/current/.minecraft",
        ),
        (
            "Snap Modrinth",
            h / "snap/modrinth-app/current/.local/share/ModrinthApp",
        ),
    ]

    found: list[tuple[str, Path]] = []
    seen_real: set[Path] = set()
    for label, p in candidates:
        try:
            if p.exists() and p.is_dir():
                rp = p.resolve()
                if rp not in seen_real:
                    seen_real.add(rp)
                    found.append((label, p))
        except OSError:
            continue

    # Add any live --gameDir / instance roots discovered from running processes (e.g., hidden --gameDir /tmp/.mc)
    for raw_root in ctx.telemetry.get("live_minecraft_roots", []):
        try:
            p = Path(raw_root)
            if p.exists() and p.is_dir():
                rp = p.resolve()
                if rp not in seen_real:
                    seen_real.add(rp)
                    found.append((f"Live --gameDir ({p.name})", p))
        except OSError:
            pass

    # Also catch any Prism/MultiMC/Modrinth sub-directories inside .var/app
    var_app = h / ".var/app"
    if var_app.is_dir():
        try:
            for app_dir in var_app.iterdir():
                for sub in (".minecraft", "data/PrismLauncher", "data/ModrinthApp", ".local/share/PrismLauncher"):
                    cand = app_dir / sub
                    if cand.is_dir():
                        rp = cand.resolve()
                        if rp not in seen_real:
                            seen_real.add(rp)
                            found.append((f"Flatpak ({app_dir.name})", cand))
        except OSError:
            pass

    # Bounded removable / MicroSD media scan (SteamOS /run/media/mmcblk0p1 & desktop /run/media/<user>/<vol>)
    media_subpaths = (
        ".minecraft",
        "Minecraft",
        "PrismLauncher",
        "ModrinthApp",
        "MultiMC",
        "ATLauncher",
        ".local/share/PrismLauncher",
        "Games/PrismLauncher",
    )
    for media_base in (ctx.root_prefix / "run/media", ctx.root_prefix / "media"):
        if not media_base.is_dir():
            continue
        try:
            mount_roots: list[Path] = []
            for entry in media_base.iterdir():
                if not entry.is_dir() or entry.is_symlink():
                    continue
                mount_roots.append(entry)
                try:
                    for sub_entry in entry.iterdir():
                        if sub_entry.is_dir() and not sub_entry.is_symlink():
                            mount_roots.append(sub_entry)
                except OSError:
                    pass
            for mnt in mount_roots:
                for sub in media_subpaths:
                    cand = mnt / sub
                    if cand.is_dir():
                        rp = cand.resolve()
                        if rp not in seen_real:
                            seen_real.add(rp)
                            found.append((f"Media ({mnt.name}/{sub})", cand))
        except OSError:
            pass

    # Also catch Wine / Proton hosted Minecraft & PrismLauncher installations
    wine_prefixes: list[Path] = []
    seen_wp: set[Path] = set()

    def _add_wp(wp_path: Path) -> None:
        try:
            if (wp_path / "drive_c").is_dir():
                rwp = wp_path.resolve()
                if rwp not in seen_wp:
                    seen_wp.add(rwp)
                    wine_prefixes.append(wp_path)
        except OSError:
            pass

    _add_wp(h / ".wine")
    for pfx_parent in (
        h / ".local/share/wineprefixes",
        h / "Games/Heroic/Prefixes",
        h / ".local/share/bottles/bottles",
        h / ".var/app/com.usebottles.bottles/data/bottles/bottles",
    ):
        if pfx_parent.is_dir():
            try:
                for child in pfx_parent.iterdir():
                    _add_wp(child)
            except OSError:
                pass
    compat = h / ".local/share/Steam/steamapps/compatdata"
    if compat.is_dir():
        try:
            for child in compat.iterdir():
                _add_wp(child / "pfx")
        except OSError:
            pass
    for raw_wp in ctx.telemetry.get("live_wine_prefixes", []):
        _add_wp(Path(raw_wp))

    for wp in wine_prefixes:
        dc = wp / "drive_c"
        for sub in ("PrismLauncher", "MultiMC", "ATLauncher"):
            cand = dc / sub
            if cand.is_dir():
                try:
                    rp = cand.resolve()
                    if rp not in seen_real:
                        seen_real.add(rp)
                        found.append((f"Wine ({wp.name}/{sub})", cand))
                except OSError:
                    pass
        users_dir = dc / "users"
        if users_dir.is_dir():
            try:
                for udir in users_dir.iterdir():
                    roaming = udir / "AppData/Roaming"
                    for sub in (".minecraft", "PrismLauncher", ".lunarclient", ".feather", "ModrinthApp"):
                        cand = roaming / sub
                        if cand.is_dir():
                            try:
                                rp = cand.resolve()
                                if rp not in seen_real:
                                    seen_real.add(rp)
                                    found.append((f"Wine ({wp.name}/{udir.name}/{sub})", cand))
                            except OSError:
                                pass
            except OSError:
                pass
    return found


def discover_browser_databases(ctx: ScanContext) -> list[tuple[str, str, Path]]:
    """Return list of (browser_name, engine_type ['chromium'|'firefox'], db_path)."""
    h = ctx.home_dir
    results: list[tuple[str, str, Path]] = []
    seen: set[Path] = set()

    def _add(label: str, btype: str, p: Path) -> None:
        try:
            if p.is_file():
                rp = p.resolve()
                if rp not in seen:
                    seen.add(rp)
                    results.append((label, btype, p))
        except OSError:
            pass

    chromium_roots = [
        ("Google Chrome", h / ".config/google-chrome"),
        ("Google Chrome Dev", h / ".config/google-chrome-unstable"),
        ("Chromium", h / ".config/chromium"),
        ("Brave", h / ".config/BraveSoftware/Brave-Browser"),
        ("Opera", h / ".config/opera"),
        ("Opera GX", h / ".config/opera-gx"),
        ("Microsoft Edge", h / ".config/microsoft-edge"),
        ("Vivaldi", h / ".config/vivaldi"),
        ("Flatpak Chrome", h / ".var/app/com.google.Chrome/config/google-chrome"),
        ("Flatpak Chrome Dev", h / ".var/app/com.google.ChromeDev/config/google-chrome-unstable"),
        ("Flatpak Chromium", h / ".var/app/org.chromium.Chromium/config/chromium"),
        (
            "Flatpak Ungoogled Chromium",
            h / ".var/app/io.github.ungoogled_software.ungoogled_chromium/config/chromium",
        ),
        ("Flatpak Brave", h / ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"),
        ("Flatpak Opera GX", h / ".var/app/com.opera.opera-gx/config/opera"),
        ("Flatpak Opera GX (alt)", h / ".var/app/com.opera.opera-gx/config/opera-gx"),
        ("Flatpak Edge", h / ".var/app/com.microsoft.Edge/config/microsoft-edge"),
        ("Snap Chromium", h / "snap/chromium/common/chromium"),
        ("Snap Brave", h / "snap/brave/current/.config/BraveSoftware/Brave-Browser"),
        ("Snap Opera", h / "snap/opera/current/.config/opera"),
        ("Snap Vivaldi", h / "snap/vivaldi/current/.config/vivaldi"),
        ("Snap Edge", h / "snap/microsoft-edge/current/.config/microsoft-edge"),
    ]
    for label, base in chromium_roots:
        if not base.is_dir():
            continue
        for hist in base.glob("*/History"):
            _add(f"{label} ({hist.parent.name})", "chromium", hist)
        _add(label, "chromium", base / "History")

    firefox_roots = [
        ("Firefox", h / ".mozilla/firefox"),
        ("LibreWolf", h / ".librewolf"),
        ("Waterfox", h / ".waterfox"),
        ("Zen Browser", h / ".zen"),
        ("Flatpak Firefox", h / ".var/app/org.mozilla.firefox/.mozilla/firefox"),
        (
            "Flatpak LibreWolf",
            h / ".var/app/io.gitlab.librewolf-community/.librewolf",
        ),
        ("Flatpak Waterfox", h / ".var/app/net.waterfox.waterfox/.waterfox"),
        ("Flatpak Zen", h / ".var/app/app.zen_browser.zen/.zen"),
        ("Snap Firefox", h / "snap/firefox/common/.mozilla/firefox"),
        ("Snap LibreWolf", h / "snap/librewolf/current/.librewolf"),
    ]
    for label, base in firefox_roots:
        if not base.is_dir():
            continue
        for places in base.glob("*/places.sqlite"):
            _add(f"{label} ({places.parent.name})", "firefox", places)

    return results


def iter_files_safe(
    roots: Iterable[Path],
    max_depth: int = 8,
    follow_symlinks: bool = False,
    skip_dir_names: frozenset[str] | set[str] | None = None,
    skip_rel_prefixes: tuple[str, ...] = (),
) -> Iterable[Path]:
    """Safe bounded directory traversal that handles symlink loops & permissions."""
    seen_dirs: set[tuple[int, int]] = set()
    clean_prefixes = tuple(p.strip("/") for p in skip_rel_prefixes if p.strip("/"))
    for root in roots:
        if not root.exists():
            continue
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            current, depth = stack.pop()
            try:
                st = os.stat(current) if follow_symlinks else os.lstat(current)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode) and not follow_symlinks:
                continue
            if stat.S_ISREG(st.st_mode):
                yield current
                continue
            if not stat.S_ISDIR(st.st_mode) or depth > max_depth:
                continue
            if is_self_tool_path(current):
                continue
            key = (st.st_dev, st.st_ino)
            if key in seen_dirs:
                continue
            seen_dirs.add(key)
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        p = Path(entry.path)
                        try:
                            if entry.is_symlink() and not follow_symlinks:
                                continue
                            if entry.name.startswith(".mount_") and current.name == "tmp":
                                continue
                            if is_self_tool_path(p):
                                continue
                            if entry.is_dir(follow_symlinks=follow_symlinks):
                                if skip_dir_names and entry.name in skip_dir_names:
                                    continue
                                if clean_prefixes:
                                    try:
                                        rel_s = p.relative_to(root).as_posix()
                                    except ValueError:
                                        rel_s = ""
                                    if rel_s and any(
                                        rel_s == pref or rel_s.startswith(pref + "/")
                                        for pref in clean_prefixes
                                    ):
                                        continue
                                if depth + 1 <= max_depth:
                                    stack.append((p, depth + 1))
                            elif entry.is_file(follow_symlinks=follow_symlinks):
                                yield p
                        except OSError:
                            continue
            except OSError:
                continue


def safe_zip_read(zf: object, info: object, max_bytes: int) -> bytes:
    """Bounded ZIP entry read that prevents forged-header decompression bombs."""
    open_fn = getattr(zf, "open", None)
    if open_fn is None:
        return b""
    with open_fn(info) as zfh:
        data = zfh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"ZIP entry exceeds bounded size limit ({max_bytes} bytes)")
    return data


def emit_scan_progress(ctx: ScanContext, fraction: float, message: str) -> None:
    """Safely notify optional orchestrator sub-progress hook (0.0..1.0)."""
    if ctx.is_cancelled():
        from .orchestrator import ScanCancelledError

        raise ScanCancelledError("Tarama kullanici tarafindan iptal edildi.")
    cb: Callable[[float, str], None] | None = getattr(ctx, "_engine_progress_cb", None)
    if cb is not None:
        try:
            cb(max(0.0, min(1.0, float(fraction))), message)
        except Exception as exc:
            if exc.__class__.__name__ == "ScanCancelledError":
                raise


def record_scan_region(ctx: ScanContext, engine_code: str, region: str) -> None:
    """Record a scanned region or artifact scope for detailed reporting."""
    bucket: dict[str, list[str]] = ctx.telemetry.setdefault("scanned_regions", {})
    arr = bucket.setdefault(engine_code, [])
    if region not in arr:
        arr.append(region)


def resolve_desktop_dir(home_dir: Path | None = None) -> Path:
    """Resolve user Desktop directory via user-dirs.dirs, xdg-user-dir, or locale fallbacks."""
    base = home_dir if home_dir is not None else Path.home()
    user_dirs = base / ".config" / "user-dirs.dirs"
    if user_dirs.is_file():
        try:
            for line in user_dirs.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if s.startswith("XDG_DESKTOP_DIR="):
                    raw_val = s.split("=", 1)[1].strip().strip('"').strip("'")
                    raw_val = raw_val.replace("$HOME", str(base)).replace("${HOME}", str(base))
                    cand = Path(raw_val)
                    if cand.is_dir():
                        return cand
        except OSError:
            pass

    try:
        same_home = base.resolve() == Path.home().resolve()
    except OSError:
        same_home = base == Path.home()

    if same_home and trusted_which("xdg-user-dir"):
        rc, out, _ = run_trusted_cmd(["xdg-user-dir", "DESKTOP"], timeout=2.0)
        if rc == 0:
            candidate_txt = out.strip()
            if candidate_txt:
                cand = Path(candidate_txt)
                if cand.is_dir():
                    return cand

    for name in ("Desktop", "Masaüstü", "Masaustu"):
        cand = base / name
        if cand.is_dir():
            return cand

    fallback = base / "Desktop"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback

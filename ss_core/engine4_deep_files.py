"""Engine 4: Bit-Level File Analysis, Timestomping, xattr, Polyglots,
JVM .class Constant Pool Parser, ELF Parser, Resource Pack X-Ray & Shader Scanner.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import stat
import struct
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any

from .models import Confidence, Finding, ScanContext, Severity
from .signatures import (
    ANTI_FORENSIC_CMD_RE,
    CHEAT_DOMAINS,
    ELF_CHEAT_OR_INJECT_SYMBOLS,
    JVM_SUSPICIOUS_API_SYMBOLS,
    OBFUSCATOR_MARKERS,
    POPULAR_MOD_IDENTITY_MAP,
    SUSPICIOUS_UNVERIFIED_MOD_ORIGINS,
    TRUSTED_MOD_ORIGINS,
    XRAY_SENSITIVE_BLOCK_TEXTURES,
)
from .utils import (
    discover_minecraft_roots,
    emit_scan_progress,
    fmt_ns,
    iter_files_safe,
    match_cheat_signatures,
    read_xattrs,
    record_scan_region,
    safe_read_bytes,
    sha256_file,
    shannon_entropy,
    statx_timestamps,
)

ENGINE_NAME = "Engine 4: Bit-Duzeyi Dosya, .class/.jar, ELF & X-Ray Analizi"

EXECUTABLE_OR_ARCHIVE_EXTS: frozenset[str] = frozenset(
    {".jar", ".zip", ".so", ".dll", ".exe", ".appimage", ".class", ".sh", ".py"}
)

SPOOF_CHECK_TEXT_OR_MEDIA_EXTS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".webp",
        ".ico",
        ".mp3",
        ".wav",
        ".mp4",
        ".pdf",
        ".txt",
        ".md",
        ".log",
        ".json",
        ".toml",
        ".yml",
        ".yaml",
        ".properties",
        ".cfg",
        ".dat",
        ".ogg",
        ".mcmeta",
    }
)

SHADER_XRAY_RE = re.compile(
    r"(?:"
    r"if\s*\([^)]*(?:mc_Entity|blockId|entityId|isOre|diamond|chest|player|stone|deepslate|netherrack)[^)]*\)\s*\{?[^}]*(?:discard\s*;|gl_Position\s*=\s*vec4\s*\(\s*0|a\s*=\s*0\.0+\b)|"
    r"discard\s*;.*(?:ore|stone|deepslate|netherrack|mc_Entity)|"
    r"(?:lmcoord|lightmap).*(?:vec2\s*\(\s*1\.0\s*,\s*1\.0\s*\)|255\.0)|"
    r"gl_DepthRange\s*\(\s*0\.0\s*,\s*0\.0|"
    r"(?:^|\n)\s*#define\s+(?:XRAY|FULLBRIGHT|ORE_ESP|CAVE_FINDER)\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)

_OBF_CTRL_RE = re.compile(r"[\x00-\x1f\x7f\u200b-\u200d\ufeff]")
_OBF_CTRL_BYTES_RE = re.compile(rb"[\x00-\x1f\x7f]|\xe2\x80[\x8b-\x8d]|\xef\xbb\xbf")
_JDK_INTERNAL_PKG_RE = re.compile(
    r"(?:^|[\s(\[;])L?(?:java|javax|sun|jdk|it/unimi/dsi|com/google/common/collect)/[A-Za-z0-9_/$]+;?",
    re.MULTILINE,
)
_OBFUSCATOR_RE = re.compile("|".join(re.escape(x) for x in OBFUSCATOR_MARKERS))
_SUSP_API_RE = re.compile("|".join(re.escape(x) for x in JVM_SUSPICIOUS_API_SYMBOLS))
_CLASS_BYTES_PREFILTER_RE = re.compile(
    b"(?i:"
    + "|".join(
        re.escape(x)
        for x in sorted(
            {
                *(__import__("ss_core.signatures", fromlist=["STRICT_CHEAT_IDENTIFIERS"]).STRICT_CHEAT_IDENTIFIERS),
                *(__import__("ss_core.signatures", fromlist=["CONTEXTUAL_CHEAT_MODULES"]).CONTEXTUAL_CHEAT_MODULES),
            },
            key=len,
            reverse=True,
        )
    ).encode("ascii")
    + b")|"
    + _OBFUSCATOR_RE.pattern.encode("ascii")
    + b"|awt/Robot|tools/attach|Instrumentation|retransformClasses|redefineClasses"
    b"|misc/Unsafe|defineAnonymousClass|defineHiddenClass|loadLibrary|\x01\x00\x04load"
)
_SUSP_API_CLS_PREFIXES: tuple[str, ...] = (
    "java/awt/Robot",
    "com/sun/tools/attach/",
    "sun/tools/attach/",
    "java/lang/instrument/Instrumentation",
    "sun/misc/Unsafe",
    "jdk/internal/misc/Unsafe",
)
_SUSP_API_METHOD_NAMES: frozenset[str] = frozenset(
    {
        "retransformClasses",
        "redefineClasses",
        "defineAnonymousClass",
        "defineHiddenClass",
        "loadLibrary",
        "load",
    }
)
_BENIGN_MANIFEST_AGENTS: tuple[str, ...] = (
    "kotlinx.coroutines.debug.",
    "net.bytebuddy.agent.",
    "org.jacoco.agent.",
    "com.intellij.rt.",
    "org.spongepowered.tools.agent.MixinAgent",
)
_BENIGN_EMBEDDED_NATIVES: tuple[str, ...] = (
    "lwjgl",
    "sqlite",
    "jansi",
    "zstd",
    "openal",
    "opus",
    "glfw",
    "junixsocket",
    "jnidispatch",
    "netty_transport",
    "netty_tcnative",
    "flatlaf",
    "libjcocoa",
    "jcocoa",
)
_BENIGN_LIB_ONLY_NATIVES: tuple[str, ...] = (
    "libjtracy",
    "jtracy",
    "liblz4-java",
)
_BENIGN_UNSAFE_MOD_PREFIXES: tuple[str, ...] = (
    "net/caffeinemc/mods/",
    "me/jellysquid/mods/",
    "me/decce/ixeris/",
    "com/ishland/c2me/",
    "org/embeddedt/",
)
_STDLIB_NESTED_HINTS: tuple[str, ...] = (
    "kotlin-stdlib",
    "kotlinx-",
    "guava-",
    "gson-",
    "fastutil-",
    "netty-",
    "lwjgl-",
    "slf4j-",
    "log4j-",
    "jna-",
    "oshi-",
    "asm-",
    "icu4j-",
    "commons-",
    "byte-buddy",
    "sponge-mixin",
)
_STD_MAVEN_CLASS_PREFIXES: tuple[str, ...] = (
    "net/minecraft/",
    "com/mojang/",
    "com/google/",
    "io/netty/",
    "org/lwjgl/",
    "it/unimi/",
    "org/apache/",
    "org/ow2/",
    "org/slf4j/",
    "org/jetbrains/",
    "org/intellij/",
    "com/ibm/",
    "org/jline/",
    "com/github/oshi/",
    "net/java/",
    "net/sf/",
    "org/lz4/",
    "com/fasterxml/",
    "org/codehaus/",
    "org/tukaani/",
    "oshi/",
    "ca/weblite/",
    "net/bytebuddy/",
    "net/minecrell/",
    "org/spongepowered/",
    "joptsimple/",
    "org/lwjglx/",
    "io/github/classgraph/",
    "jakarta/",
    "javax/",
    "module-info",
)


# ---------------------------------------------------------------------------
# 1. Magic-byte & Polyglot Inspector
# ---------------------------------------------------------------------------
def detect_magic_type(data: bytes) -> str:
    if len(data) < 4:
        return "UNKNOWN"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "ZIP/JAR"
    if data.startswith(b"MZ"):
        return "PE/EXE/DLL"
    if data.startswith(b"\xca\xfe\xba\xbe") and len(data) >= 8:
        major = struct.unpack_from(">H", data, 6)[0]
        if 45 <= major <= 80:
            return "JAVA_CLASS"
        return "MACHO_FAT"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if data.startswith(b"SQLite format 3\x00"):
        return "SQLITE"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP"
    if data.startswith(b"#!"):
        return "SCRIPT"
    return "OTHER"


def check_polyglot_payload(data: bytes, magic: str) -> list[str]:
    notes: list[str] = []
    if magic == "PNG" and len(data) >= 16:
        pos = 8
        iend_end = -1
        while pos + 12 <= len(data):
            clen = struct.unpack_from(">I", data, pos)[0]
            ctype = data[pos + 4 : pos + 8]
            next_pos = pos + 12 + clen
            if next_pos > len(data):
                break
            if ctype == b"IEND":
                iend_end = next_pos
                break
            pos = next_pos
        if iend_end != -1 and iend_end < len(data):
            trailing = data[iend_end:]
            if len(trailing.strip(b"\x00\r\n\t ")) > 32:
                tmagic = detect_magic_type(trailing)
                ent = shannon_entropy(trailing[:4096])
                if tmagic in ("ZIP/JAR", "ELF", "PE/EXE/DLL", "JAVA_CLASS", "SCRIPT") or ent > 6.8 or b"PK\x03\x04" in trailing:
                    notes.append(
                        f"PNG IEND sonrasi {len(trailing)} byte gizli veri (tur={tmagic}, entropi={ent:.2f})"
                    )
        # Also detect embedded ELF or ZIP inside malformed/chunk-stuffed PNGs
        elf_pos = 8
        while True:
            ep = data.find(b"\x7fELF", elf_pos)
            if ep == -1 or ep + 24 > len(data):
                break
            if (
                data[ep + 4] in (1, 2)
                and data[ep + 5] in (1, 2)
                and data[ep + 6] == 1
                and data[ep + 9 : ep + 16] == b"\x00" * 7
                and data[ep + 16] in (1, 2, 3)
            ):
                notes.append(f"PNG icinde ofset 0x{ep:x} konumunda gomulu ELF payload")
                break
            elf_pos = ep + 4
        if iend_end == -1:
            pk_off = data.find(b"PK\x03\x04", 8)
            if pk_off != -1 and data.find(b"PK\x05\x06", pk_off) != -1:
                notes.append(f"Bozuk/IEND'siz PNG icinde ofset 0x{pk_off:x} konumunda gomulu ZIP/JAR")
    elif magic == "JPEG":
        eoi = data.rfind(b"\xff\xd9")
        if eoi != -1 and eoi + 2 < len(data):
            trailing = data[eoi + 2 :]
            if len(trailing.strip(b"\x00\r\n\t ")) > 32:
                tmagic = detect_magic_type(trailing)
                if tmagic in ("ZIP/JAR", "ELF", "PE/EXE/DLL", "SCRIPT") or b"PK\x03\x04" in trailing:
                    notes.append(f"JPEG EOI sonrasi {len(trailing)} byte gizli veri (tur={tmagic})")
    elif magic == "ZIP/JAR":
        eocd = data.rfind(b"PK\x05\x06")
        if eocd != -1 and eocd + 22 <= len(data):
            comment_len = struct.unpack_from("<H", data, eocd + 20)[0]
            zip_end = eocd + 22 + comment_len
            if zip_end < len(data):
                trailing = data[zip_end:]
                if len(trailing.strip(b"\x00")) > 256:
                    tmagic = detect_magic_type(trailing)
                    ent = shannon_entropy(trailing[:4096])
                    notes.append(
                        f"ZIP/JAR EOCD sonrasi {len(trailing)} byte overlay verisi (tur={tmagic}, entropi={ent:.2f})"
                    )
    elif magic == "ELF":
        # Check for appended ZIP/JAR inside an ELF binary (polyglot dropper/injector)
        pk_off = data.find(b"PK\x03\x04", 64)
        if pk_off != -1:
            # Verify EOCD exists after pk_off to avoid accidental 4-byte match
            if data.find(b"PK\x05\x06", pk_off) != -1:
                notes.append(f"ELF binary icinde ofset 0x{pk_off:x} konumunda gomulu ZIP/JAR arsivi")
    elif magic == "PE/EXE/DLL":
        pk_off = data.find(b"PK\x03\x04", 64)
        if pk_off != -1 and data.find(b"PK\x05\x06", pk_off) != -1:
            tail = data[pk_off:]
            if any(m in tail for m in (b"META-INF/", b"fabric.mod.json", b"mods.toml", b"mixins.json")) or b".class" in tail:
                notes.append(f"PE/EXE icinde ofset 0x{pk_off:x} konumunda gomulu JAR/Mod arsivi")
    return notes


# ---------------------------------------------------------------------------
# 2. Pure Python JVM .class Constant Pool & Bytecode Parser
# ---------------------------------------------------------------------------
def parse_java_class(data: bytes) -> dict[str, Any] | None:
    if len(data) < 16 or not data.startswith(b"\xca\xfe\xba\xbe"):
        return None
    major = struct.unpack_from(">H", data, 6)[0]
    if not (45 <= major <= 80):
        return None

    cp_count = struct.unpack_from(">H", data, 8)[0]
    pos = 10
    cp: dict[int, tuple[int, Any]] = {}
    idx = 1
    try:
        while idx < cp_count:
            if pos >= len(data):
                return None
            tag = data[pos]
            pos += 1
            if tag == 1:  # CONSTANT_Utf8
                ln = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                raw_s = data[pos : pos + ln]
                pos += ln
                cp[idx] = (tag, raw_s.decode("utf-8", errors="replace"))
            elif tag in (3, 4):  # Integer / Float
                pos += 4
                cp[idx] = (tag, None)
            elif tag in (5, 6):  # Long / Double -> takes 2 CP slots!
                pos += 8
                cp[idx] = (tag, None)
                idx += 1
            elif tag in (7, 8, 16, 19, 20):  # Class, String, MethodType, Module, Package
                ref = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                cp[idx] = (tag, ref)
            elif tag in (9, 10, 11, 12, 17, 18):  # Fieldref, Methodref, InterfaceMethodref, NameAndType, Dynamic, InvokeDynamic
                a, b = struct.unpack_from(">HH", data, pos)
                pos += 4
                cp[idx] = (tag, (a, b))
            elif tag == 15:  # MethodHandle
                kind = data[pos]
                ref = struct.unpack_from(">H", data, pos + 1)[0]
                pos += 3
                cp[idx] = (tag, (kind, ref))
            else:
                return None
            idx += 1
    except struct.error:
        return None

    def _utf8(i: int) -> str:
        ent = cp.get(i)
        if ent and ent[0] == 1:
            return ent[1]
        return ""

    def _class_name(i: int) -> str:
        ent = cp.get(i)
        if ent and ent[0] == 7:
            return _utf8(ent[1])
        return ""

    this_class = ""
    super_class = ""
    if pos + 6 <= len(data):
        _, this_idx, super_idx = struct.unpack_from(">HHH", data, pos)
        this_class = _class_name(this_idx)
        super_class = _class_name(super_idx)

    utf8_strings: list[str] = []
    class_refs: list[str] = []
    method_refs: list[str] = []
    indy_count = 0
    control_char_names = 0

    def _has_obf_ctrl_chars(sym: str) -> bool:
        return _OBF_CTRL_RE.search(sym) is not None

    for _, (tag, val) in cp.items():
        if tag == 1 and isinstance(val, str):
            utf8_strings.append(val)
        elif tag == 7:
            cname = _utf8(val)
            if cname:
                class_refs.append(cname)
                if _has_obf_ctrl_chars(cname):
                    control_char_names += 1
        elif tag == 12 and isinstance(val, tuple):
            mname = _utf8(val[0])
            if mname and _has_obf_ctrl_chars(mname):
                control_char_names += 1
        elif tag in (10, 11) and isinstance(val, tuple):
            cls_name = _class_name(val[0])
            nat = cp.get(val[1])
            if nat and nat[0] == 12:
                mname = _utf8(nat[1][0])
                if mname in _SUSP_API_METHOD_NAMES or cls_name.startswith(_SUSP_API_CLS_PREFIXES):
                    method_refs.append(f"{cls_name}.{mname}")
        elif tag == 18:
            indy_count += 1

    return {
        "major_version": major,
        "this_class": this_class,
        "super_class": super_class,
        "utf8_strings": utf8_strings,
        "class_refs": class_refs,
        "method_refs": method_refs,
        "indy_count": indy_count,
        "control_char_names": control_char_names,
    }


def _fast_cp_obf_stats(data: bytes) -> tuple[int, int]:
    """Fast constant-pool walker for control-char obfuscated symbols & indy count without UTF-8 decoding."""
    if len(data) < 16 or not data.startswith(b"\xca\xfe\xba\xbe"):
        return 0, 0
    major = struct.unpack_from(">H", data, 6)[0]
    if not (45 <= major <= 80):
        return 0, 0
    cp_count = struct.unpack_from(">H", data, 8)[0]
    pos = 10
    utf8_ctrl: set[int] = set()
    class_refs: list[int] = []
    nat_refs: list[int] = []
    indy_count = 0
    idx = 1
    n = len(data)
    try:
        while idx < cp_count:
            if pos >= n:
                return 0, 0
            tag = data[pos]
            pos += 1
            if tag == 1:
                ln = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                raw_s = data[pos : pos + ln]
                pos += ln
                if _OBF_CTRL_BYTES_RE.search(raw_s):
                    utf8_ctrl.add(idx)
            elif tag in (3, 4):
                pos += 4
            elif tag in (5, 6):
                pos += 8
                idx += 1
            elif tag == 7:
                class_refs.append(struct.unpack_from(">H", data, pos)[0])
                pos += 2
            elif tag in (8, 16, 19, 20):
                pos += 2
            elif tag == 12:
                nat_refs.append(struct.unpack_from(">HH", data, pos)[0])
                pos += 4
            elif tag in (9, 10, 11, 17):
                pos += 4
            elif tag == 18:
                indy_count += 1
                pos += 4
            elif tag == 15:
                pos += 3
            else:
                return 0, 0
            idx += 1
    except struct.error:
        return 0, 0

    ctrl_cnt = 0
    if utf8_ctrl:
        for r in class_refs:
            if r in utf8_ctrl:
                ctrl_cnt += 1
        for r in nat_refs:
            if r in utf8_ctrl:
                ctrl_cnt += 1
    return ctrl_cnt, indy_count


# ---------------------------------------------------------------------------
# 3. Pure Python PNG Decoder & Alpha Transparency Analyzer (No Pillow Needed!)
# ---------------------------------------------------------------------------
def _paeth_predictor(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def analyze_png_transparency(data: bytes) -> dict[str, Any] | None:
    """Decode PNG IHDR/PLTE/tRNS/IDAT and compute transparent pixel ratio & whiteness."""
    if len(data) < 33 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    pos = 8
    width = height = bit_depth = color_type = interlace = 0
    idat_parts: list[bytes] = []
    plte: bytes = b""
    trns: bytes = b""

    while pos + 12 <= len(data):
        clen = struct.unpack_from(">I", data, pos)[0]
        ctype = data[pos + 4 : pos + 8]
        cdata_start = pos + 8
        cdata_end = cdata_start + clen
        if cdata_end + 4 > len(data):
            break
        cdata = data[cdata_start:cdata_end]
        if ctype == b"IHDR" and clen >= 13:
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack_from(">IIBBBBB", cdata, 0)
            if interlace not in (0, 1) or width == 0 or height == 0 or width > 4096 or height > 4096:
                return None
        elif ctype == b"PLTE":
            plte = cdata
        elif ctype == b"tRNS":
            trns = cdata
        elif ctype == b"IDAT":
            idat_parts.append(cdata)
        elif ctype == b"IEND":
            break
        pos = cdata_end + 4

    if width == 0 or height == 0 or not idat_parts:
        return None
    if bit_depth not in (1, 2, 4, 8, 16):
        return None
    if bit_depth < 8 and color_type not in (0, 3):
        return None
    if bit_depth == 16 and color_type == 3:
        return None

    channels_map = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
    ch = channels_map.get(color_type)
    if ch is None:
        return None

    try:
        raw_pixels = zlib.decompress(b"".join(idat_parts), bufsize=width * height * max(1, ch * (2 if bit_depth == 16 else 1)) + height * 8)
    except zlib.error:
        return None

    adam7_passes: tuple[tuple[int, int, int, int], ...] = (
        ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))
        if interlace == 1
        else ((0, 0, 1, 1),)
    )

    bits_pp = ch * bit_depth
    bpp = max(1, (bits_pp + 7) // 8)
    bps = 2 if bit_depth == 16 else 1
    trns_gray_val = struct.unpack_from(">H", trns, 0)[0] if len(trns) >= 2 else None
    trns_rgb_val = struct.unpack_from(">HHH", trns, 0) if len(trns) >= 6 else None

    transparent_count = 0
    total_pixels = width * height
    luma_sum = 0
    raw_pos = 0

    for xs, ys, xstep, ystep in adam7_passes:
        pass_w = (width - xs + xstep - 1) // xstep if width > xs else 0
        pass_h = (height - ys + ystep - 1) // ystep if height > ys else 0
        if pass_w == 0 or pass_h == 0:
            continue
        stride = (pass_w * bits_pp + 7) // 8
        if raw_pos + (stride + 1) * pass_h > len(raw_pixels):
            return None
        prev_row = bytearray(stride)

        for _ in range(pass_h):
            ftype = raw_pixels[raw_pos]
            src = raw_pixels[raw_pos + 1 : raw_pos + 1 + stride]
            raw_pos += 1 + stride
            recon = bytearray(stride)

            if ftype == 0:
                recon[:] = src
            elif ftype == 1:
                for i in range(stride):
                    left = recon[i - bpp] if i >= bpp else 0
                    recon[i] = (src[i] + left) & 0xFF
            elif ftype == 2:
                for i in range(stride):
                    recon[i] = (src[i] + prev_row[i]) & 0xFF
            elif ftype == 3:
                for i in range(stride):
                    left = recon[i - bpp] if i >= bpp else 0
                    up = prev_row[i]
                    recon[i] = (src[i] + ((left + up) >> 1)) & 0xFF
            elif ftype == 4:
                for i in range(stride):
                    left = recon[i - bpp] if i >= bpp else 0
                    up = prev_row[i]
                    up_left = prev_row[i - bpp] if i >= bpp else 0
                    recon[i] = (src[i] + _paeth_predictor(left, up, up_left)) & 0xFF
            else:
                return None

            for px in range(pass_w):
                if color_type == 6:  # RGBA
                    off = px * bpp
                    r = recon[off]
                    g = recon[off + bps]
                    b = recon[off + 2 * bps]
                    a = recon[off + 3 * bps]
                    if a < 250:
                        transparent_count += 1
                    luma_sum += (r + g + b) // 3
                elif color_type == 4:  # Gray + Alpha
                    off = px * bpp
                    g = recon[off]
                    a = recon[off + bps]
                    if a < 250:
                        transparent_count += 1
                    luma_sum += g
                elif color_type == 3:  # Indexed (1/2/4/8-bit)
                    if bit_depth == 8:
                        idx = recon[px]
                    elif bit_depth == 4:
                        idx = (recon[px >> 1] >> (4 - 4 * (px & 1))) & 0xF
                    elif bit_depth == 2:
                        idx = (recon[px >> 2] >> (6 - 2 * (px & 3))) & 0x3
                    else:
                        idx = (recon[px >> 3] >> (7 - (px & 7))) & 0x1
                    if idx < len(trns) and trns[idx] < 250:
                        transparent_count += 1
                    if idx * 3 + 2 < len(plte):
                        luma_sum += (plte[idx * 3] + plte[idx * 3 + 1] + plte[idx * 3 + 2]) // 3
                elif color_type == 2:  # RGB
                    off = px * bpp
                    r, g, b = recon[off], recon[off + bps], recon[off + 2 * bps]
                    if trns_rgb_val is not None:
                        if bps == 1 and (r, g, b) == (
                            trns_rgb_val[0] & 0xFF,
                            trns_rgb_val[1] & 0xFF,
                            trns_rgb_val[2] & 0xFF,
                        ):
                            transparent_count += 1
                        elif bps == 2:
                            r16 = struct.unpack_from(">H", recon, off)[0]
                            g16 = struct.unpack_from(">H", recon, off + 2)[0]
                            b16 = struct.unpack_from(">H", recon, off + 4)[0]
                            if (r16, g16, b16) == trns_rgb_val:
                                transparent_count += 1
                    luma_sum += (r + g + b) // 3
                elif color_type == 0:  # Grayscale (1/2/4/8/16-bit)
                    if bit_depth == 16:
                        v16 = struct.unpack_from(">H", recon, px * 2)[0]
                        if trns_gray_val is not None and v16 == trns_gray_val:
                            transparent_count += 1
                        luma_sum += v16 >> 8
                    elif bit_depth == 8:
                        v8 = recon[px]
                        if trns_gray_val is not None and v8 == (trns_gray_val & 0xFF):
                            transparent_count += 1
                        luma_sum += v8
                    else:
                        if bit_depth == 4:
                            gv = (recon[px >> 1] >> (4 - 4 * (px & 1))) & 0xF
                            luma_sum += gv * 17
                        elif bit_depth == 2:
                            gv = (recon[px >> 2] >> (6 - 2 * (px & 3))) & 0x3
                            luma_sum += gv * 85
                        else:
                            gv = (recon[px >> 3] >> (7 - (px & 7))) & 0x1
                            luma_sum += gv * 255
                        if trns_gray_val is not None and gv == trns_gray_val:
                            transparent_count += 1

            prev_row = recon

    has_alpha = color_type in (4, 6) or bool(trns)
    return {
        "width": width,
        "height": height,
        "transparent_ratio": round(transparent_count / max(1, total_pixels), 4),
        "transparent_pixels": transparent_count,
        "total_pixels": total_pixels,
        "has_alpha": has_alpha,
        "mean_luma": round(luma_sum / max(1, total_pixels), 2),
    }


# ---------------------------------------------------------------------------
# 4. Pure Python ELF Binary Symbol/String Analyzer
# ---------------------------------------------------------------------------
def _extract_ascii_strings(data: bytes, min_len: int = 5) -> list[str]:
    return [
        m.group(0).decode("ascii", errors="replace")
        for m in re.finditer(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)
    ]


def analyze_elf_binary(ctx: ScanContext, path: Path, data: bytes) -> None:
    if len(data) < 64 or not data.startswith(b"\x7fELF"):
        return
    strings = _extract_ascii_strings(data, min_len=5)
    joined = "\n".join(strings)

    sym_hits: list[str] = []
    highest_sev = Severity.LOW
    for sym, (sev_s, desc) in ELF_CHEAT_OR_INJECT_SYMBOLS.items():
        if sym in joined:
            sym_hits.append(f"{sym} ({desc})")
            s = Severity[sev_s]
            if s.rank > highest_sev.rank:
                highest_sev = s

    jni_exports = [s for s in strings if s.startswith("Java_") or s == "JNI_OnLoad"][:8]
    strict, high_ctx, _ = match_cheat_signatures(joined)

    # Check if this ELF sits in an abnormal user directory or carries cheat/injector markers
    p_low = str(path).lower()
    in_suspicious_dir = any(
        d in p_low for d in ("/tmp/", "/dev/shm/", "/var/tmp/", "/downloads/", "/desktop/", "/.minecraft/", "/mods/")
    )

    if (
        path.name in ("chrome-sandbox", "chrome_crashpad_handler", "nacl_helper", "webm_encoder", "crashpad_handler", "electron")
        and not strict
        and not jni_exports
        and len(sym_hits) == 1
        and sym_hits[0].startswith("ptrace ")
    ):
        return

    # Standard GNU C Library runtime copies inside Flatpak/Wine/container staging
    # export libc syscall wrappers (ptrace, process_vm_writev/readv) legitimately.
    if (
        (path.name == "libc.so" or path.name.startswith("libc.so."))
        and "GNU C Library" in joined
        and not strict
        and not high_ctx
        and not jni_exports
        and not any(
            s.startswith(("Agent_OnLoad ", "Agent_OnAttach ", "XTestFakeButtonEvent ", "XTestFakeKeyEvent ", "uinput "))
            for s in sym_hits
        )
    ):
        return

    if strict or (sym_hits and highest_sev in (Severity.CRITICAL, Severity.HIGH)) or (jni_exports and in_suspicious_dir):
        sev = Severity.CRITICAL if (strict or highest_sev == Severity.CRITICAL) else Severity.HIGH
        ev: list[str] = []
        if strict or high_ctx:
            ev.append(f"Imzalar: {', '.join(strict + high_ctx)}")
        if sym_hits:
            ev.append(f"Kritik ELF sembolleri: {', '.join(sym_hits[:8])}")
        if jni_exports:
            ev.append(f"JNI exportlari: {', '.join(jni_exports[:5])}")
        ctx.add_finding(
            Finding(
                rule_id="E4-ELF-SUSPICIOUS",
                engine=ENGINE_NAME,
                severity=sev,
                confidence=Confidence.CONFIRMED if strict else Confidence.HIGH,
                category="Native Binary / JNI / Injector",
                title=f"Supheli ELF native kutuphane/binary tespit edildi: {path.name}",
                description="Native ELF dosyasi icinde JVM/input enjeksiyon sembolleri, JNI kancasi veya hile imzasi bulundu.",
                evidence=ev,
                path=str(path),
                metadata={"sha256": sha256_file(path)},
            )
        )


_PE_INJECT_APIS: tuple[tuple[str, str], ...] = (
    ("VirtualAllocEx", "Remote memory allocation"),
    ("WriteProcessMemory", "Cross-process memory injection"),
    ("CreateRemoteThread", "Remote DLL/shellcode execution"),
    ("NtCreateThreadEx", "Native remote thread creation"),
    ("SetWindowsHookEx", "Global Windows keyboard/mouse hook"),
    ("GetAsyncKeyState", "Global key state polling (autoclicker/trigger)"),
    ("SendInput", "Synthetic mouse/keystroke injection"),
    ("mouse_event", "Legacy synthetic mouse click"),
)


def _extract_utf16le_strings(data: bytes, min_len: int = 6) -> list[str]:
    out: list[str] = []
    pat = rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}"
    for m in re.finditer(pat, data):
        try:
            out.append(m.group(0).decode("utf-16le", errors="replace"))
        except Exception:
            continue
    return out


def analyze_pe_binary(ctx: ScanContext, path: Path, data: bytes) -> None:
    if len(data) < 64 or not data.startswith(b"MZ"):
        return
    p_low = str(path).lower()
    # Skip standard Wine/Windows OS runtime DLLs to avoid false positives
    if any(w in p_low for w in ("/drive_c/windows/system32/", "/drive_c/windows/syswow64/", "/drive_c/windows/winsxs/", "/lib/wine/")):
        return

    strings = _extract_ascii_strings(data, min_len=5)
    if b"\x00" in data:
        strings.extend(_extract_utf16le_strings(data, min_len=6))
    joined = "\n".join(strings)

    strict, high_ctx, _ = match_cheat_signatures(joined)
    api_hits = [f"{api} ({desc})" for api, desc in _PE_INJECT_APIS if api in joined]
    has_jni = "JNI_OnLoad" in joined or any(s.startswith("Java_") for s in strings[:5000])
    in_suspicious_dir = any(
        d in p_low for d in ("/tmp/", "/dev/shm/", "/var/tmp/", "/downloads/", "/desktop/", "/.minecraft/", "/mods/")
    )

    is_injector_combo = (
        "VirtualAllocEx" in joined and "WriteProcessMemory" in joined
        and ("CreateRemoteThread" in joined or "NtCreateThreadEx" in joined)
    )

    if strict or (has_jni and (high_ctx or in_suspicious_dir)) or (in_suspicious_dir and (is_injector_combo or (api_hits and high_ctx))):
        sev = Severity.CRITICAL if (strict or is_injector_combo or (has_jni and in_suspicious_dir)) else Severity.HIGH
        ev: list[str] = []
        if strict or high_ctx:
            ev.append(f"Imzalar: {', '.join(strict + high_ctx)}")
        if api_hits:
            ev.append(f"Win32 enjeksiyon/makro API: {', '.join(api_hits[:8])}")
        if has_jni:
            ev.append("JNI export / Java_ girisi mevcut")
        ctx.add_finding(
            Finding(
                rule_id="E4-PE-CHEAT-OR-INJECTOR",
                engine=ENGINE_NAME,
                severity=sev,
                confidence=Confidence.CONFIRMED if strict or is_injector_combo else Confidence.HIGH,
                category="Windows PE Cheat / Wine Injector",
                title=f"Supheli Windows PE binary (.exe/.dll) tespit edildi: {path.name}",
                description="PE dosyasi icinde bilinen hile imzasi, DLL/JNI enjektoru veya yapay girdi API'si bulundu.",
                evidence=ev,
                path=str(path),
                metadata={"sha256": sha256_file(path)},
            )
        )


def _inspect_script_for_cheat_or_antiforensics(ctx: ScanContext, path: Path, data: bytes) -> None:
    if path.suffix.lower() == ".py" and data:
        from ._self_manifest import SELF_PY_SHA256S

        if SELF_PY_SHA256S and hashlib.sha256(data).hexdigest() in SELF_PY_SHA256S:
            return
    txt = data.decode("utf-8", errors="replace")
    if not txt:
        return
    strict, high_ctx, _ = match_cheat_signatures(txt)
    anti_hits = sorted({m.group(0).strip()[:80] for m in ANTI_FORENSIC_CMD_RE.finditer(txt)})
    domain_hits = [d for d in CHEAT_DOMAINS if d in txt.lower()]
    if strict or anti_hits or domain_hits or len(high_ctx) >= 2:
        sev = Severity.CRITICAL if (strict or domain_hits or len(anti_hits) >= 2) else Severity.HIGH
        ev: list[str] = []
        if strict or high_ctx:
            ev.append(f"Imzalar: {', '.join(strict + high_ctx)}")
        if domain_hits:
            ev.append(f"Hile domainleri: {', '.join(domain_hits[:5])}")
        if anti_hits:
            ev.append(f"Anti-forensik komutlar: {', '.join(anti_hits[:5])}")
        ctx.add_finding(
            Finding(
                rule_id="E4-SCRIPT-CHEAT-OR-ANTIFORENSIC",
                engine=ENGINE_NAME,
                severity=sev,
                confidence=Confidence.HIGH,
                category="Suspicious Dropper / Cleanup Script",
                title=f"Script dosyasinda hile veya iz silme (anti-forensics) kodu: {path.name}",
                description="Shell/Python scripti icinde gecmis/log temizleme, timestomp veya hile referansi bulundu.",
                evidence=ev,
                path=str(path),
            )
        )


# ---------------------------------------------------------------------------
# 5. Deep JAR / ZIP Inspector (Metadata, Constant Pool, Mixins, JiJ, Resource/Shader Packs)
# ---------------------------------------------------------------------------
def _check_spoofed_mod_name(
    ctx: ScanContext,
    display_path: str,
    mod_ids: list[str],
    mod_names: list[str],
    mod_entrypoints: list[str],
) -> None:
    if not (mod_ids or mod_names or mod_entrypoints):
        return
    base_low = os.path.basename(display_path).lower()
    all_identity = f"{' '.join(mod_ids)} {' '.join(mod_names)} {' '.join(mod_entrypoints)}".lower()
    for brand, expected_tokens in POPULAR_MOD_IDENTITY_MAP.items():
        if brand in base_low and not any(tok in all_identity for tok in expected_tokens):
            ctx.add_finding(
                Finding(
                    rule_id="E4-JAR-SPOOFED-MOD-NAME",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Renamed / Spoofed Mod",
                    title=f"Sahte isimli mod tespit edildi: '{os.path.basename(display_path)}' aslinda '{', '.join(mod_ids or mod_names)}'",
                    description=(
                        f"Dosya adi '{brand}' gibi mesru bir mod adi kullaniyor ancak icindeki metadata/paket "
                        "baska bir mod veya hile oldugunu gosteriyor."
                    ),
                    evidence=[
                        f"Dosya adi: {os.path.basename(display_path)}",
                        f"Gercek Mod ID: {', '.join(mod_ids)}",
                        f"Gercek Mod Adi: {', '.join(mod_names)}",
                        f"Entrypoint: {', '.join(mod_entrypoints[:5])}",
                    ],
                    path=display_path,
                )
            )
            break


def _check_jar_cache(
    ctx: ScanContext,
    display_path: str,
    jar_digest: bytes,
    clean_jar_digests: set[bytes] | dict[bytes, tuple[list[str], list[str], list[str]]] | None,
) -> bool:
    if clean_jar_digests is None:
        return False
    if isinstance(clean_jar_digests, dict):
        cached = clean_jar_digests.get(jar_digest)
        if cached is not None:
            _check_spoofed_mod_name(ctx, display_path, *cached)
            return True
        return False
    base_low_pre = os.path.basename(display_path).lower()
    if jar_digest in clean_jar_digests and not any(b in base_low_pre for b in POPULAR_MOD_IDENTITY_MAP):
        return True
    return False


def _analyze_jar_path(
    ctx: ScanContext,
    path: Path,
    file_size: int,
    clean_jar_digests: set[bytes] | dict[bytes, tuple[list[str], list[str], list[str]]] | None = None,
) -> None:
    """Analyze an on-disk JAR/ZIP up to 256MB without loading the entire archive into RAM."""
    display_path = str(path)
    try:
        # 1. Stream polyglot EOCD overlay check from the tail of the file (handles >32MB padded JARs)
        tail_len = min(file_size, 4 * 1024 * 1024)
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1048576)
                if not chunk:
                    break
                h.update(chunk)
            if tail_len > 0:
                fh.seek(max(0, file_size - tail_len))
                tail = fh.read(tail_len)
                eocd = tail.rfind(b"PK\x05\x06")
                if eocd != -1 and eocd + 22 <= len(tail):
                    comment_len = struct.unpack_from("<H", tail, eocd + 20)[0]
                    zip_end = eocd + 22 + comment_len
                    if zip_end < len(tail):
                        trailing = tail[zip_end:]
                        if len(trailing.strip(b"\x00")) > 256:
                            tmagic = detect_magic_type(trailing)
                            ent = shannon_entropy(trailing[:4096])
                            ctx.add_finding(
                                Finding(
                                    rule_id="E4-POLYGLOT-PAYLOAD",
                                    engine=ENGINE_NAME,
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.CONFIRMED,
                                    category="Polyglot / Hidden Payload",
                                    title=f"Dosya icine gizlenmis ek veri / polyglot tespit edildi: {path.name}",
                                    description="Bir ZIP/JAR dosyasinin sonuna gizli ikinci bir dosya veya overlay eklenmis.",
                                    evidence=[f"ZIP/JAR EOCD sonrasi {len(trailing)} byte overlay verisi (tur={tmagic}, entropi={ent:.2f})"],
                                    path=display_path,
                                )
                            )
        jar_digest = h.digest()
    except OSError:
        return

    if _check_jar_cache(ctx, display_path, jar_digest, clean_jar_digests):
        return

    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return

    _analyze_jar_zip(
        ctx,
        display_path,
        zf,
        depth=0,
        actual_file_path=path,
        jar_digest=jar_digest,
        clean_jar_digests=clean_jar_digests,
    )


def _analyze_jar_bytes(
    ctx: ScanContext,
    display_path: str,
    raw_bytes: bytes,
    depth: int = 0,
    actual_file_path: Path | None = None,
    clean_jar_digests: set[bytes] | dict[bytes, tuple[list[str], list[str], list[str]]] | None = None,
) -> None:
    if depth > 2 or not raw_bytes:
        return

    jar_digest: bytes | None = None
    if clean_jar_digests is not None:
        jar_digest = hashlib.sha256(raw_bytes).digest()
        if _check_jar_cache(ctx, display_path, jar_digest, clean_jar_digests):
            return

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes))
    except (zipfile.BadZipFile, OSError):
        return

    _analyze_jar_zip(
        ctx,
        display_path,
        zf,
        depth=depth,
        actual_file_path=actual_file_path,
        jar_digest=jar_digest,
        clean_jar_digests=clean_jar_digests,
    )


def _analyze_jar_zip(
    ctx: ScanContext,
    display_path: str,
    zf: zipfile.ZipFile,
    depth: int = 0,
    actual_file_path: Path | None = None,
    jar_digest: bytes | None = None,
    clean_jar_digests: set[bytes] | dict[bytes, tuple[list[str], list[str], list[str]]] | None = None,
) -> None:
    pre_finding_cnt = len(ctx.findings)

    with zf:
        infos = zf.infolist()
        if not infos:
            return

        encrypted_entries = [i.filename for i in infos if i.flag_bits & 0x1]
        if encrypted_entries:
            ctx.add_finding(
                Finding(
                    rule_id="E4-ZIP-ENCRYPTED",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    category="Encrypted Archive",
                    title=f"Parola korumali/sifreli arsiv (.jar/.zip): {os.path.basename(display_path)}",
                    description="Sifreli arsivler SS araclarindan hile veya enjektor gizlemek icin kullanilir.",
                    evidence=[f"Sifreli dosyalar ({len(encrypted_entries)} adet): {', '.join(encrypted_entries[:8])}"],
                    path=display_path,
                )
            )
            return

        names = [i.filename for i in infos]
        names_lower = {n.lower(): n for n in names}

        is_resource_pack = any(
            "assets/minecraft/textures/block/" in n
            or "assets/minecraft/textures/blocks/" in n
            or "assets/minecraft/models/block/" in n
            or "assets/minecraft/blockstates/" in n
            or "optifine/lightmap/" in n
            or ("pack.mcmeta" in names_lower and "assets/minecraft/textures/" in n)
            for n in names_lower
        )
        is_shader_pack = any(
            (n.startswith("shaders/") or "/shaders/" in n) and n.endswith((".fsh", ".vsh", ".glsl"))
            for n in names_lower
        )

        # Dispatch resource/shader pack analysis if applicable
        if is_resource_pack:
            _analyze_zip_resource_pack(ctx, display_path, zf, infos)
        if is_shader_pack:
            _analyze_zip_shader_pack(ctx, display_path, zf, infos)

        # Mod / Java Archive Inspection
        mod_ids: list[str] = []
        mod_names: list[str] = []
        mod_entrypoints: list[str] = []
        manifest_agents: list[str] = []
        embedded_natives: list[str] = []
        mixin_suspects: list[str] = []
        class_cheat_hits: list[str] = []
        class_api_hits: list[str] = []
        obfuscator_hits: set[str] = set()
        high_indy_classes = 0
        control_char_classes = 0

        # 5a. Manifest
        if "meta-inf/manifest.mf" in names_lower:
            try:
                mf_raw = zf.read(names_lower["meta-inf/manifest.mf"])[:65536]
                mf_txt = mf_raw.decode("utf-8", errors="replace")
                raw_agents: list[str] = []
                agent_entry_classes: list[str] = []
                for key in ("Premain-Class", "Agent-Class", "Can-Redefine-Classes", "Can-Retransform-Classes"):
                    m = re.search(rf"^{key}\s*:\s*(.+)$", mf_txt, re.MULTILINE | re.IGNORECASE)
                    if m:
                        val = m.group(1).strip()
                        raw_agents.append(f"{key}: {val}")
                        if key in ("Premain-Class", "Agent-Class"):
                            agent_entry_classes.append(val)
                if raw_agents and not (
                    agent_entry_classes
                    and all(ac.startswith(_BENIGN_MANIFEST_AGENTS) for ac in agent_entry_classes)
                ):
                    manifest_agents.extend(raw_agents)
            except Exception:
                pass

        # 5b. Mod Metadata (Fabric/Quilt/Forge/NeoForge)
        for meta_name in ("fabric.mod.json", "quilt.mod.json", "mcmod.info"):
            if meta_name in names_lower:
                try:
                    raw = zf.read(names_lower[meta_name])[:262144].decode("utf-8", errors="replace")
                    obj = json.loads(raw)
                    if isinstance(obj, dict):
                        if "id" in obj:
                            mod_ids.append(str(obj["id"]))
                        if "name" in obj:
                            mod_names.append(str(obj["name"]))
                        eps = obj.get("entrypoints", {})
                        if isinstance(eps, dict):
                            for v in eps.values():
                                if isinstance(v, list):
                                    mod_entrypoints.extend(str(x) for x in v)
                        # Check quilt loader wrapper
                        ql = obj.get("quilt_loader", {})
                        if isinstance(ql, dict) and "id" in ql:
                            mod_ids.append(str(ql["id"]))
                    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
                        if "modid" in obj[0]:
                            mod_ids.append(str(obj[0]["modid"]))
                        if "name" in obj[0]:
                            mod_names.append(str(obj[0]["name"]))
                except Exception:
                    pass

        for toml_name in ("meta-inf/mods.toml", "meta-inf/neoforge.mods.toml"):
            if toml_name in names_lower:
                try:
                    raw = zf.read(names_lower[toml_name])[:262144].decode("utf-8", errors="replace")
                    for m in re.finditer(r'modId\s*=\s*["\']([^"\']+)["\']', raw):
                        mod_ids.append(m.group(1))
                    for m in re.finditer(r'displayName\s*=\s*["\']([^"\']+)["\']', raw):
                        mod_names.append(m.group(1))
                except Exception:
                    pass

        meta_joined = " ".join(mod_ids + mod_names + mod_entrypoints)
        strict_m, high_m, _ = match_cheat_signatures(meta_joined)
        if strict_m or high_m:
            ctx.add_finding(
                Finding(
                    rule_id="E4-JAR-CHEAT-METADATA",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Cheat Mod Metadata",
                    title=f".jar mod metadatasi icinde hile imzasi: {os.path.basename(display_path)}",
                    description="Dosya adi gizlenmis olsa bile fabric.mod.json/mods.toml icinde gercek hile kimligi tespit edildi.",
                    evidence=[
                        f"Mod ID: {', '.join(mod_ids) or 'N/A'}",
                        f"Mod Adi: {', '.join(mod_names) or 'N/A'}",
                        f"Eslesenler: {', '.join(strict_m + high_m)}",
                    ],
                    path=display_path,
                )
            )

        # Spoofed popular mod filename check
        base_low = os.path.basename(display_path).lower()
        if mod_ids or mod_names or mod_entrypoints:
            all_identity = f"{' '.join(mod_ids)} {' '.join(mod_names)} {' '.join(mod_entrypoints)}".lower()
            for brand, expected_tokens in POPULAR_MOD_IDENTITY_MAP.items():
                if brand in base_low and not any(tok in all_identity for tok in expected_tokens):
                    ctx.add_finding(
                        Finding(
                            rule_id="E4-JAR-SPOOFED-MOD-NAME",
                            engine=ENGINE_NAME,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            category="Renamed / Spoofed Mod",
                            title=f"Sahte isimli mod tespit edildi: '{os.path.basename(display_path)}' aslinda '{', '.join(mod_ids or mod_names)}'",
                            description=(
                                f"Dosya adi '{brand}' gibi mesru bir mod adi kullaniyor ancak icindeki metadata/paket "
                                "baska bir mod veya hile oldugunu gosteriyor."
                            ),
                            evidence=[
                                f"Dosya adi: {os.path.basename(display_path)}",
                                f"Gercek Mod ID: {', '.join(mod_ids)}",
                                f"Gercek Mod Adi: {', '.join(mod_names)}",
                                f"Entrypoint: {', '.join(mod_entrypoints[:5])}",
                            ],
                            path=display_path,
                        )
                    )
                    break

        if manifest_agents:
            ctx.add_finding(
                Finding(
                    rule_id="E4-JAR-AGENT-MANIFEST",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    category="Java Agent JAR",
                    title=f"JVM Agent Manifest ozelligi tasiyan .jar: {os.path.basename(display_path)}",
                    description="Premain-Class/Agent-Class iceren JAR dosyasi calisan Minecraft JVM siniflarini degistirebilir.",
                    evidence=manifest_agents,
                    path=display_path,
                )
            )

        # 5c. Iterate entries for Mixins, embedded natives, .class constant pools, nested JARs
        class_infos: list[zipfile.ZipInfo] = []
        for info in infos:
            if info.is_dir() or info.file_size > 16 * 1024 * 1024:
                continue
            fn = info.filename
            fn_low = fn.lower()

            if fn_low.endswith((".so", ".dll", ".dylib", ".exe")):
                embedded_natives.append(f"{fn} ({info.file_size} byte)")
                continue

            if fn_low.endswith(".jar") and depth < 2 and info.file_size <= 16 * 1024 * 1024:
                try:
                    nested_bytes = zf.read(info)
                    _analyze_jar_bytes(
                        ctx,
                        f"{display_path}!/{fn}",
                        nested_bytes,
                        depth=depth + 1,
                        clean_jar_digests=clean_jar_digests,
                    )
                except Exception:
                    pass
                continue

            if "mixin" in fn_low and fn_low.endswith(".json") and info.file_size <= 512 * 1024:
                try:
                    mtxt = zf.read(info).decode("utf-8", errors="replace")
                    s_m, h_m, _ = match_cheat_signatures(mtxt)
                    if s_m or h_m:
                        mixin_suspects.append(f"{fn}: {', '.join(s_m + h_m)}")
                except Exception:
                    pass
                continue

            if fn_low.endswith(".class") and info.file_size <= 2 * 1024 * 1024:
                class_infos.append(info)

        if class_infos:
            all_cfns = "\n".join(ci.filename for ci in class_infos)
            if _OBF_CTRL_RE.search(all_cfns):
                control_char_classes += sum(1 for ci in class_infos if _OBF_CTRL_RE.search(ci.filename))
            s_all, h_all, _ = match_cheat_signatures(all_cfns)
            if s_all or any(x not in ("hitbox", "hitboxes") for x in h_all) or len(h_all) >= 2:
                for ci in class_infos:
                    s_fn, h_fn, _ = match_cheat_signatures(ci.filename)
                    non_ui_fn_h = [x for x in h_fn if x not in ("hitbox", "hitboxes")]
                    if s_fn or non_ui_fn_h or len(h_fn) >= 2:
                        class_cheat_hits.append(f"Sinif '{ci.filename}' [{','.join(s_fn + h_fn)}]")
                        if len(class_cheat_hits) >= 12:
                            break

        dp_norm = display_path.replace("\\", "/").lower()
        is_stdlib_jar = (
            "/libraries/" in dp_norm
            or (
                actual_file_path is not None
                and actual_file_path.parent.parent.name == "versions"
                and actual_file_path.stem == actual_file_path.parent.name
            )
            or any(h in dp_norm for h in _STDLIB_NESTED_HINTS)
        )
        recent_or_stomped = False
        if depth == 0 and actual_file_path is not None:
            try:
                st_jar = os.lstat(actual_file_path)
                age_limit = max(ctx.time_window_hours * 3600.0, 24 * 3600.0)
                recent_or_stomped = (
                    (ctx.current_epoch() - max(st_jar.st_mtime, st_jar.st_ctime)) <= age_limit
                    or (st_jar.st_ctime - st_jar.st_mtime) > 10.0
                )
            except OSError:
                recent_or_stomped = True

        benign_reflect_hits: list[str] = []
        is_unilib_mod = any(m.lower() == "unilib" for m in mod_ids)

        for info in class_infos:
            fn = info.filename
            try:
                cdata = zf.read(info)
            except Exception:
                continue

            if _CLASS_BYTES_PREFILTER_RE.search(cdata) is None:
                if (not is_stdlib_jar) or recent_or_stomped:
                    ctrl_cnt, indy_cnt = _fast_cp_obf_stats(cdata)
                    if ctrl_cnt > 0:
                        control_char_classes += 1
                    if indy_cnt >= 60:
                        high_indy_classes += 1
                continue

            parsed = parse_java_class(cdata)
            if not parsed:
                continue

            if parsed["control_char_names"] > 0:
                control_char_classes += 1
            if parsed["indy_count"] >= 60:
                high_indy_classes += 1

            # Check strict & unambiguous high-signal signatures BEFORE stripping JDK package prefixes
            # so fake java/lang/KillAura cheats cannot hide behind JDK package spoofing.
            _ambig_single_high = frozenset(
                {"hitbox", "hitboxes", "gammautils", "fullbright", "freecam", "xray", "x-ray", "baritone"}
            )
            cp_blob_raw = "\n".join(parsed["utf8_strings"])
            s_raw, h_raw, _ = match_cheat_signatures(cp_blob_raw)
            cp_blob_clean = _JDK_INTERNAL_PKG_RE.sub(" ", cp_blob_raw)
            s_cp, h_cp, l_cp = match_cheat_signatures(cp_blob_clean)
            if s_raw:
                s_cp = sorted(set(s_cp) | set(s_raw))
            blatant_h_raw = [x for x in h_raw if x not in _ambig_single_high]
            if blatant_h_raw:
                h_cp = sorted(set(h_cp) | set(blatant_h_raw))
            non_ui_cp_h = [x for x in h_cp if x not in ("hitbox", "hitboxes")]
            blatant_h_cp = [x for x in h_cp if x not in _ambig_single_high]
            is_benign_entity_cfg = (
                not s_cp
                and len(h_cp) == 1
                and h_cp[0] in ("hitbox", "hitboxes")
                and set(l_cp) <= {"nametags", "tracers", "reach"}
            )
            if (
                s_cp
                or blatant_h_cp
                or len(non_ui_cp_h) >= 2
                or (non_ui_cp_h and len(h_cp) >= 2)
                or (h_cp and l_cp)
            ) and not is_benign_entity_cfg:
                if len(class_cheat_hits) < 15:
                    class_cheat_hits.append(
                        f"{fn} ConstantPool [{', '.join((s_cp + h_cp + l_cp)[:6])}]"
                    )

            if not is_stdlib_jar and _OBFUSCATOR_RE.search(cp_blob_raw):
                obfuscator_hits.update(_OBFUSCATOR_RE.findall(cp_blob_raw))

            if (len(class_api_hits) < 12 or len(benign_reflect_hits) < 4) and not fn.startswith("kotlinx/coroutines/debug/"):
                cls_joined = "\n".join(parsed["class_refs"])
                if parsed["method_refs"] or (cls_joined and _SUSP_API_RE.search(cls_joined)):
                    joined_mrefs = "\n".join(parsed["method_refs"]) + "\n" + cls_joined
                    is_junixsocket = fn.startswith("org/newsclub/net/unix/")
                    is_benign_unsafe = fn.startswith(_BENIGN_UNSAFE_MOD_PREFIXES)
                    is_unilib_reflect = is_unilib_mod and fn.startswith("unilib/external/net/lenni0451/reflect/")
                    for api_sym, (sev_s, desc) in JVM_SUSPICIOUS_API_SYMBOLS.items():
                        if api_sym in joined_mrefs:
                            if (is_stdlib_jar or is_junixsocket) and api_sym in (
                                "sun/misc/Unsafe",
                                "jdk/internal/misc/Unsafe",
                                "java/lang/System.load",
                                "java/lang/System.loadLibrary",
                            ):
                                continue
                            if (
                                is_stdlib_jar
                                and fn.startswith("org/spongepowered/tools/agent/MixinAgent")
                                and api_sym in ("java/lang/instrument/Instrumentation", "redefineClasses")
                            ):
                                continue
                            if is_benign_unsafe and api_sym in ("sun/misc/Unsafe", "jdk/internal/misc/Unsafe"):
                                continue
                            if fn.startswith("me/decce/ixeris/") and api_sym == "defineHiddenClass":
                                continue
                            if fn.startswith("net/lostluma/battery/impl/util/Natives") and api_sym == "java/lang/System.load":
                                continue
                            if is_unilib_reflect:
                                if len(benign_reflect_hits) < 4:
                                    benign_reflect_hits.append(f"[{sev_s}] {fn} -> {api_sym} ({desc})")
                                continue
                            if len(class_api_hits) < 12:
                                class_api_hits.append(f"[{sev_s}] {fn} -> {api_sym} ({desc})")

        if embedded_natives:
            suspicious_natives = [
                n
                for n in embedded_natives
                if not any(ok in n.lower() for ok in _BENIGN_EMBEDDED_NATIVES)
                and not (
                    ("/libraries/" in dp_norm or ("/.lunarclient/" in dp_norm and "/mods/" not in dp_norm))
                    and any(ok in n.lower() for ok in _BENIGN_LIB_ONLY_NATIVES)
                )
            ]
            if suspicious_natives:
                ctx.add_finding(
                    Finding(
                        rule_id="E4-JAR-EMBEDDED-NATIVE",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="Embedded Native Binary in JAR",
                        title=f".jar icinde gomulu native kutuphane (.so/.dll/.exe): {os.path.basename(display_path)}",
                        description="Standart LWJGL/ses disinda bir .jar arsivinin icinde derlenmis C/C++ kutuphanesi tasiyor.",
                        evidence=suspicious_natives[:10],
                        path=display_path,
                    )
                )

        if mixin_suspects:
            ctx.add_finding(
                Finding(
                    rule_id="E4-JAR-SUSPICIOUS-MIXIN",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Cheat Mixin Config",
                    title=f"Mixin konfigurasyonunda hile sinifi tespit edildi: {os.path.basename(display_path)}",
                    description="Minecraft bytecode kancalama (Mixin) dosyasinda hile sinif/paket adi bulundu.",
                    evidence=mixin_suspects[:10],
                    path=display_path,
                )
            )

        if class_cheat_hits:
            ctx.add_finding(
                Finding(
                    rule_id="E4-JAR-CLASS-CONSTANT-POOL",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="JVM Bytecode / Constant Pool",
                    title=f".class Constant Pool icinde hile sinifi/string imzasi: {os.path.basename(display_path)}",
                    description="Sikistirilmis .jar icindeki derlenmis .class bytecode havuzunda dogrudan hile imzasi tespit edildi.",
                    evidence=class_cheat_hits[:12],
                    path=display_path,
                )
            )

        if class_api_hits:
            has_crit = any(x.startswith("[CRITICAL]") for x in class_api_hits)
            has_high = any(x.startswith("[HIGH]") for x in class_api_hits)
            ctx.add_finding(
                Finding(
                    rule_id="E4-JAR-DANGEROUS-API",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL if has_crit else (Severity.HIGH if has_high else Severity.MEDIUM),
                    confidence=Confidence.HIGH,
                    category="JVM Dangerous Bytecode API",
                    title=f".class bytecode icinde tehlikeli/enjektor Java API cagrisi: {os.path.basename(display_path)}",
                    description="Mod/JAR icinde Robot tiklama, Attach, Instrumentation veya gizli native yukleme cagrisi mevcut.",
                    evidence=class_api_hits[:12],
                    path=display_path,
                )
            )
        elif benign_reflect_hits and (mixin_suspects or obfuscator_hits or control_char_classes >= 3):
            ctx.add_finding(
                Finding(
                    rule_id="E4-JAR-DANGEROUS-API",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    category="JVM Dangerous Bytecode API",
                    title=f"Yansima/Instrumentation kutuphanesi supheli mod icinde: {os.path.basename(display_path)}",
                    evidence=benign_reflect_hits,
                    path=display_path,
                )
            )

        if obfuscator_hits or control_char_classes >= 3 or (high_indy_classes >= 15 and not is_stdlib_jar):
            ctx.add_finding(
                Finding(
                    rule_id="E4-JAR-OBFUSCATION",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Heavy Java Obfuscation",
                    title=f"Agir ticari obfuscator / decompiler bozucu tespit edildi: {os.path.basename(display_path)}",
                    description="Mesru acik kaynak modlarda bulunmayan agir karartma (obfuscation) izleri goruldu.",
                    evidence=[
                        f"Obfuscator imzalari: {', '.join(sorted(obfuscator_hits)) or 'N/A'}",
                        f"Kontrol karakterli siniflar: {control_char_classes}",
                        f"Yogun InvokeDynamic siniflari: {high_indy_classes}",
                    ],
                    path=display_path,
                )
            )

        if clean_jar_digests is not None and jar_digest is not None and len(ctx.findings) == pre_finding_cnt:
            if isinstance(clean_jar_digests, dict):
                clean_jar_digests[jar_digest] = (mod_ids, mod_names, mod_entrypoints)
            else:
                clean_jar_digests.add(jar_digest)


# ---------------------------------------------------------------------------
# 6. Resource Pack X-Ray & Shader X-Ray Scanners
# ---------------------------------------------------------------------------
def _inspect_png_for_xray_or_fullbright(
    ctx: ScanContext, display_path: str, filename_low: str, png_bytes: bytes
) -> None:
    bname = os.path.basename(filename_low)
    is_solid_block = bname in XRAY_SENSITIVE_BLOCK_TEXTURES and (
        "textures/block/" in filename_low or "textures/blocks/" in filename_low
    )
    is_lightmap = "lightmap" in filename_low

    if not is_solid_block and not is_lightmap:
        return

    res = analyze_png_transparency(png_bytes)
    if not res:
        return

    if is_solid_block and res["transparent_ratio"] >= 0.05:
        ctx.add_finding(
            Finding(
                rule_id="E4-RP-XRAY-TEXTURE",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="X-Ray Resource Pack",
                title=f"X-Ray seffaf blok dokusu tespit edildi: {bname}",
                description=(
                    f"Kati olmasi gereken '{bname}' dokusunun %{res['transparent_ratio'] * 100:.1f} kismi "
                    "seffaf (alfa kanali acilmis) — yeralti madenlerini gosteren X-Ray paketi!"
                ),
                evidence=[
                    f"Dosya: {display_path}",
                    f"Boyut: {res['width']}x{res['height']}",
                    f"Seffaf piksel orani: %{res['transparent_ratio'] * 100:.2f}",
                ],
                path=display_path,
            )
        )
    elif is_lightmap and res["mean_luma"] is not None and res["mean_luma"] >= 242:
        ctx.add_finding(
            Finding(
                rule_id="E4-RP-FULLBRIGHT-LIGHTMAP",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Fullbright Resource Pack",
                title=f"Tam aydinlik (Fullbright) lightmap dokusu: {bname}",
                description="Karanlik magaralari tamamen aydinlik gosteren beyaz/yuksek parlaklikli lightmap.",
                evidence=[f"Dosya: {display_path}", f"Ortalama parlaklik: {res['mean_luma']}/255"],
                path=display_path,
            )
        )


def _inspect_block_model_json_for_xray(ctx: ScanContext, display_path: str, fname: str, raw_txt: str) -> None:
    bname = os.path.basename(fname.lower())
    solid_names = {x.replace(".png", ".json") for x in XRAY_SENSITIVE_BLOCK_TEXTURES}
    template_models = {
        "cube_all.json",
        "cube.json",
        "cube_column.json",
        "cube_bottom_top.json",
        "cube_top.json",
        "orientable.json",
        "block.json",
    }
    target_models = solid_names | template_models
    if bname in target_models and "models/block/" in fname.lower():
        try:
            obj = json.loads(raw_txt)
        except Exception:
            return
        if isinstance(obj, dict):
            parent_low = str(obj.get("parent", "")).lower()
            is_empty_elements = "elements" in obj and isinstance(obj["elements"], list) and len(obj["elements"]) == 0
            is_invisible_parent = parent_low in (
                "minecraft:block/air",
                "block/air",
                "minecraft:block/glass",
                "block/glass",
                "minecraft:block/barrier",
                "block/barrier",
            )
            if is_empty_elements or is_invisible_parent:
                ctx.add_finding(
                    Finding(
                        rule_id="E4-RP-XRAY-EMPTY-MODEL",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="X-Ray Block Model",
                        title=f"Gorunmez blok modeli (X-Ray model hilesi): {bname}",
                        description="Kati blok modelinin 'elements: []' veya 'parent: air/glass' ile gorunmez yapildigi X-Ray paketi.",
                        evidence=[f"Dosya: {display_path}", f"Model JSON: {raw_txt[:200]}"],
                        path=display_path,
                    )
                )
    elif bname in solid_names and "blockstates/" in fname.lower():
        low = raw_txt.lower()
        if any(
            k in low
            for k in (
                '"minecraft:block/air"',
                '"block/air"',
                '"minecraft:block/glass"',
                '"block/glass"',
                '"minecraft:block/barrier"',
                '"block/barrier"',
            )
        ):
            ctx.add_finding(
                Finding(
                    rule_id="E4-RP-XRAY-BLOCKSTATE",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="X-Ray Blockstate",
                    title=f"Blok durumu (blockstate) hava/cam olarak yonlendirilmis: {bname}",
                    description="Katı bloklar blockstate uzerinden air/glass modeline cevrilerek X-Ray yapilmis.",
                    evidence=[f"Dosya: {display_path}", raw_txt[:220]],
                    path=display_path,
                )
            )


def _analyze_zip_resource_pack(
    ctx: ScanContext, display_path: str, zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo]
) -> None:
    for info in infos:
        if info.is_dir() or info.file_size > 8 * 1024 * 1024:
            continue
        fn_low = info.filename.lower()
        if fn_low.endswith(".png"):
            bname = os.path.basename(fn_low)
            if (
                bname in XRAY_SENSITIVE_BLOCK_TEXTURES
                and ("textures/block/" in fn_low or "textures/blocks/" in fn_low)
            ) or "lightmap" in fn_low:
                try:
                    _inspect_png_for_xray_or_fullbright(ctx, f"{display_path}!/{info.filename}", fn_low, zf.read(info))
                except Exception:
                    pass
        elif fn_low.endswith(".json") and ("models/block/" in fn_low or "blockstates/" in fn_low):
            try:
                _inspect_block_model_json_for_xray(
                    ctx, f"{display_path}!/{info.filename}", fn_low, zf.read(info).decode("utf-8", errors="replace")
                )
            except Exception:
                pass


def _analyze_zip_shader_pack(
    ctx: ScanContext, display_path: str, zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo]
) -> None:
    for info in infos:
        if info.is_dir() or info.file_size > 2 * 1024 * 1024:
            continue
        fn_low = info.filename.lower()
        if fn_low.endswith((".fsh", ".vsh", ".glsl")):
            try:
                txt = zf.read(info).decode("utf-8", errors="replace")
            except Exception:
                continue
            m = SHADER_XRAY_RE.search(txt)
            if m:
                ctx.add_finding(
                    Finding(
                        rule_id="E4-SHADER-XRAY",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category="X-Ray / Fullbright Shader",
                        title=f"Shader icinde X-Ray / Fullbright GLSL kodu tespit edildi: {os.path.basename(display_path)}",
                        description="GLSL shader kodu icinde blok gizleme (discard) veya tam aydinlik zorlamasi bulundu.",
                        evidence=[f"Dosya: {display_path}!/{info.filename}", f"Eslesen kod: {m.group(0)[:200]}"],
                        path=display_path,
                    )
                )


def _analyze_folder_resource_or_shader_pack(ctx: ScanContext, pack_dir: Path) -> None:
    for fp in iter_files_safe([pack_dir], max_depth=8):
        rel = str(fp).lower()
        if rel.endswith(".png"):
            bname = fp.name.lower()
            if (
                bname in XRAY_SENSITIVE_BLOCK_TEXTURES
                and ("textures/block/" in rel or "textures/blocks/" in rel)
            ) or "lightmap" in rel:
                _inspect_png_for_xray_or_fullbright(ctx, str(fp), rel, safe_read_bytes(fp, 8 * 1024 * 1024))
        elif rel.endswith(".json") and ("models/block/" in rel or "blockstates/" in rel):
            _inspect_block_model_json_for_xray(ctx, str(fp), rel, safe_read_bytes(fp, 512 * 1024).decode("utf-8", errors="replace"))
        elif rel.endswith((".fsh", ".vsh", ".glsl")):
            txt = safe_read_bytes(fp, 2 * 1024 * 1024).decode("utf-8", errors="replace")
            m = SHADER_XRAY_RE.search(txt)
            if m:
                ctx.add_finding(
                    Finding(
                        rule_id="E4-SHADER-XRAY",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category="X-Ray / Fullbright Shader",
                        title=f"Klasor shader paketinde X-Ray/Fullbright kodu: {fp.name}",
                        description="GLSL shader dosyasinda blok gizleme veya fullbright manipulasyonu bulundu.",
                        evidence=[m.group(0)[:200]],
                        path=str(fp),
                    )
                )


# ---------------------------------------------------------------------------
# 7. Per-File Orchestration: Symlinks, Timestomping, xattr, Magic, Binary Deep Scan
# ---------------------------------------------------------------------------
def _inspect_xattr_and_timestamps(ctx: ScanContext, path: Path, is_mc_dir: bool) -> None:
    now = ctx.current_epoch()
    window_sec = ctx.time_window_hours * 3600.0
    ts = statx_timestamps(path)
    if ts is None:
        return

    mtime_s = ts.mtime_ns / 1e9
    ctime_s = ts.ctime_ns / 1e9
    btime_s = ts.btime_ns / 1e9 if ts.btime_ns else None

    future_ref = now if ctx.now_epoch is not None else max(now, time.time())

    # 1. Future timestamp (> 120s ahead)
    if mtime_s > future_ref + 120 or ctime_s > future_ref + 120:
        ctx.add_finding(
            Finding(
                rule_id="E4-TIME-FUTURE",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="Clock / Timestamp Anomaly",
                title=f"Gelecek tarihli dosya tespit edildi: {path.name}",
                description="Dosyanin tarihi sistem saatinden ileride (sistem saati geri alinmis veya touch yapilmis).",
                evidence=[f"mtime: {fmt_ns(ts.mtime_ns)}", f"ctime: {fmt_ns(ts.ctime_ns)}"],
                path=str(path),
            )
        )

    # 2. Timestomping (touch -d / utimensat)
    # Detect when inode ctime is within recent window while mtime was pushed > 7 days back,
    # OR btime > mtime + 3600s alongside recent ctime on executable/archive files.
    ext = path.suffix.lower()
    if ext in EXECUTABLE_OR_ARCHIVE_EXTS or is_mc_dir:
        ctime_age = now - ctime_s
        diff_ctime_mtime = ctime_s - mtime_s
        if ctime_age <= window_sec and diff_ctime_mtime > 7 * 86400:
            # Check btime too if available
            btime_str = fmt_ns(ts.btime_ns)
            is_strong_timestomp = (btime_s is not None) and ((now - btime_s) <= window_sec or (btime_s - mtime_s) > 7 * 86400)
            ctx.add_finding(
                Finding(
                    rule_id="E4-TIMESTOMP-ANOMALY",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH if is_strong_timestomp else Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED if is_strong_timestomp else Confidence.MEDIUM,
                    category="Timestomping",
                    title=f"Dosya tarih sahteciligi / yeni eklenip eski gosterilmis olabilir: {path.name}",
                    description=(
                        "Dosyanin inode degisiklik zamani (ctime) / dogum zamani (btime) cok yeni olmasina ragmen "
                        "icerik degisiklik zamani (mtime) gunler/aylar oncesini gosteriyor."
                    ),
                    evidence=[
                        f"mtime: {fmt_ns(ts.mtime_ns)}",
                        f"ctime: {fmt_ns(ts.ctime_ns)}",
                        f"btime: {btime_str}",
                    ],
                    path=str(path),
                )
            )

    # 3. xattr Origin URL inspection
    xattrs = read_xattrs(path)
    origin_url = xattrs.get("user.xdg.origin.url") or xattrs.get("user.xdg.referrer.url") or ""
    if origin_url:
        olow = origin_url.lower()
        if any(dom in olow for dom in CHEAT_DOMAINS):
            ctx.add_finding(
                Finding(
                    rule_id="E4-XATTR-CHEAT-URL",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="xattr Download Origin",
                    title=f"Dosya bilinen bir HILE sitesinden indirilmis (xattr): {path.name}",
                    description="Dosya adi degistirilmis olsa bile Linux xattr verisi gercek indirme URL'sini saklamis.",
                    evidence=[f"user.xdg.origin.url = {origin_url}", f"Dosya: {path}"],
                    path=str(path),
                )
            )
        elif ext in (".jar", ".so", ".dll", ".exe", ".zip") and any(
            u in olow for u in SUSPICIOUS_UNVERIFIED_MOD_ORIGINS
        ):
            is_popular_spoof = any(brand in path.name.lower() for brand in POPULAR_MOD_IDENTITY_MAP)
            is_trusted = any(t in olow for t in TRUSTED_MOD_ORIGINS)
            if not is_trusted:
                ctx.add_finding(
                    Finding(
                        rule_id="E4-XATTR-UNVERIFIED-URL",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH if is_popular_spoof else Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        category="xattr Unverified Origin",
                        title=f"Mod/Dosya Discord veya bilinmeyen kaynaktan indirilmis: {path.name}",
                        description=(
                            "Modrinth/CurseForge/OptiFine disinda bir filehost veya Discord CDN uzerinden indirilmis."
                        ),
                        evidence=[f"user.xdg.origin.url = {origin_url}", f"Dosya: {path}"],
                        path=str(path),
                    )
                )


def inspect_single_file(
    ctx: ScanContext,
    path: Path,
    is_mc_dir: bool = False,
    clean_jar_digests: set[bytes] | dict[bytes, tuple[list[str], list[str], list[str]]] | None = None,
) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        return
    if not stat.S_ISREG(st.st_mode):
        return

    _inspect_xattr_and_timestamps(ctx, path, is_mc_dir=is_mc_dir)

    # Filename signature check
    strict_n, high_n, _ = match_cheat_signatures(path.name)
    if strict_n or high_n:
        ctx.add_finding(
            Finding(
                rule_id="E4-FILE-CHEAT-NAME",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL if strict_n else Severity.HIGH,
                confidence=Confidence.CONFIRMED if strict_n else Confidence.HIGH,
                category="Cheat Filename",
                title=f"Hile/Makro isimli dosya tespit edildi: {path.name}",
                description="Dosya adi bilinen hile istemcisi veya modulu ile eslesiyor.",
                evidence=[f"Eslesenler: {', '.join(strict_n + high_n)}", f"Yol: {path}"],
                path=str(path),
            )
        )

    # Hidden dotfile check inside Minecraft mods/resourcepacks/shaderpacks
    if is_mc_dir and path.name.startswith(".") and path.suffix.lower() in (".jar", ".zip", ".so", ".exe"):
        ctx.add_finding(
            Finding(
                rule_id="E4-HIDDEN-MC-ARTIFACT",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Hidden File",
                title=f"Minecraft klasorunde gizli (nokta ile baslayan) dosya: {path.name}",
                description="Linux dosya yoneticilerinde gizlenen dosya bulundu.",
                evidence=[str(path)],
                path=str(path),
            )
        )

    if st.st_size == 0:
        return

    # Read header first before enforcing max_file_scan_bytes so spoofed or >32MB padded JARs are caught
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return

    magic = detect_magic_type(head)
    ext = path.suffix.lower()

    # Extension spoofing check
    if ext in SPOOF_CHECK_TEXT_OR_MEDIA_EXTS and magic in ("ZIP/JAR", "ELF", "PE/EXE/DLL", "JAVA_CLASS"):
        ctx.add_finding(
            Finding(
                rule_id="E4-EXT-SPOOF",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Extension Spoofing",
                title=f"Uzanti sahteciligi tespit edildi: {path.name} aslinda {magic}",
                description=f"Dosya uzantisi '{ext}' olmasina ragmen bit basligi '{magic}' biciminde!",
                evidence=[f"Dosya: {path}", f"Gorunen uzanti: {ext}", f"Gercek Magic Tur: {magic}"],
                path=str(path),
            )
        )

    # Stream large ZIP/JARs up to 256MB directly from disk (defeats >32MB JAR padding bypass & inspects lunar.jar)
    if magic == "ZIP/JAR" and st.st_size > ctx.max_file_scan_bytes and st.st_size <= 256 * 1024 * 1024:
        _analyze_jar_path(ctx, path, st.st_size, clean_jar_digests=clean_jar_digests)
        return

    if st.st_size > ctx.max_file_scan_bytes:
        return

    # Read full bytes for deep binary/archive/PNG/ELF/PE/script inspection when relevant
    is_hot_script = ext in (".sh", ".py", ".bash", ".zsh", ".lua") or magic == "SCRIPT"
    should_deep_read = (
        magic in ("ZIP/JAR", "ELF", "JAVA_CLASS", "PE/EXE/DLL")
        or ext in (".jar", ".zip", ".so", ".exe", ".dll", ".class")
        or (is_mc_dir and ext in (".png", ".json"))
        or (ext in SPOOF_CHECK_TEXT_OR_MEDIA_EXTS and magic in ("PNG", "JPEG"))
        or (is_hot_script and st.st_size <= 512 * 1024)
    )
    if not should_deep_read:
        return

    data = safe_read_bytes(path, max_bytes=ctx.max_file_scan_bytes)
    if not data:
        return

    # Polyglot detection
    poly_notes = check_polyglot_payload(data, magic)
    if poly_notes:
        ctx.add_finding(
            Finding(
                rule_id="E4-POLYGLOT-PAYLOAD",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Polyglot / Hidden Payload",
                title=f"Dosya icine gizlenmis ek veri / polyglot tespit edildi: {path.name}",
                description="Bir resim/ELF/ZIP dosyasinin sonuna gizli ikinci bir dosya veya sifreli yuk eklenmis.",
                evidence=poly_notes,
                path=str(path),
            )
        )

    if magic == "ZIP/JAR":
        _analyze_jar_bytes(
            ctx,
            str(path),
            data,
            depth=0,
            actual_file_path=path,
            clean_jar_digests=clean_jar_digests,
        )
    elif magic == "ELF":
        analyze_elf_binary(ctx, path, data)
    elif magic == "PE/EXE/DLL":
        analyze_pe_binary(ctx, path, data)
    elif magic == "JAVA_CLASS":
        parsed = parse_java_class(data)
        if parsed:
            blob = "\n".join(parsed["utf8_strings"] + parsed["method_refs"])
            s, h_ctx, _ = match_cheat_signatures(blob)
            if s or h_ctx:
                ctx.add_finding(
                    Finding(
                        rule_id="E4-STANDALONE-CLASS-CHEAT",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="Java Class Artifact",
                        title=f"Tekil .class dosyasinda hile bytecode imzasi: {path.name}",
                        description="Diskte tekil olarak duran .class dosyasinda hile sinif/metot referanslari bulundu.",
                        evidence=[f"this_class={parsed['this_class']}", f"Eslesenler={', '.join(s + h_ctx)}"],
                        path=str(path),
                    )
                )
    elif magic == "PNG" and is_mc_dir:
        _inspect_png_for_xray_or_fullbright(ctx, str(path), str(path).lower(), data)
    elif is_hot_script:
        _inspect_script_for_cheat_or_antiforensics(ctx, path, data)


def _check_symlinks_in_mc_dirs(ctx: ScanContext, mc_dirs: list[Path]) -> None:
    for base in mc_dirs:
        if not base.is_dir():
            continue
        for sub in ("mods", "resourcepacks", "shaderpacks", "config"):
            target_dir = base / sub
            if not target_dir.is_dir():
                continue
            try:
                for entry in target_dir.iterdir():
                    if entry.is_symlink():
                        try:
                            dest = os.readlink(entry)
                            resolved = entry.resolve()
                        except OSError:
                            dest = "?"
                            resolved = Path("?")
                        rstr = str(resolved).lower()
                        if any(k in rstr for k in ("/tmp/", "/dev/shm/", "/var/tmp/", "/.")) or not str(resolved).startswith(str(base)):
                            ctx.add_finding(
                                Finding(
                                    rule_id="E4-MC-SUSPICIOUS-SYMLINK",
                                    engine=ENGINE_NAME,
                                    severity=Severity.HIGH,
                                    confidence=Confidence.CONFIRMED,
                                    category="Symlink Redirect",
                                    title=f"Minecraft '{sub}' icinde disari yonlenen sembolik bag: {entry.name}",
                                    description="Dosya oyun klasoru icinde gibi gorunup baska bir dizindeki dosyaya baglanmis.",
                                    evidence=[f"{entry} -> {dest} (cozumlenen: {resolved})"],
                                    path=str(entry),
                                )
                            )
            except OSError:
                continue


def run(ctx: ScanContext) -> None:
    try:
        emit_scan_progress(ctx, 0.02, "Minecraft kok dizinleri kesfediliyor...")
        mc_roots = discover_minecraft_roots(ctx)
        mc_paths = [p for _, p in mc_roots]

        # Expand Prism / MultiMC / Modrinth / Lunar instance subfolders so we recognize them as MC dirs
        expanded_mc_dirs: list[Path] = []
        seen_mc: set[Path] = set()

        def _add_mc_dir(d: Path) -> None:
            try:
                rd = d.resolve()
            except OSError:
                rd = d
            if rd not in seen_mc:
                seen_mc.add(rd)
                expanded_mc_dirs.append(d)

        for p in mc_paths:
            _add_mc_dir(p)
            if (p / "offline").is_dir():
                try:
                    for child in (p / "offline").iterdir():
                        if child.is_dir():
                            _add_mc_dir(child)
                except OSError:
                    pass
            for inst_sub in ("instances", "profiles"):
                if (p / inst_sub).is_dir():
                    try:
                        for child in (p / inst_sub).iterdir():
                            if (child / ".minecraft").is_dir():
                                _add_mc_dir(child / ".minecraft")
                            elif (child / "minecraft").is_dir():
                                _add_mc_dir(child / "minecraft")
                            elif child.is_dir():
                                _add_mc_dir(child)
                            if inst_sub == "profiles" and (child / "versions").is_dir():
                                for vchild in (child / "versions").iterdir():
                                    if vchild.is_dir():
                                        _add_mc_dir(vchild)
                    except OSError:
                        pass

        _check_symlinks_in_mc_dirs(ctx, expanded_mc_dirs)
        ctx.telemetry["engine4_mc_dirs_scanned"] = [str(p) for p in expanded_mc_dirs]
        for mdir in expanded_mc_dirs:
            record_scan_region(ctx, "E4", f"Minecraft Dizini (mods/packs/libs/versions): {mdir}")

        scanned_real: set[Path] = set()
        clean_jar_digests: dict[bytes, tuple[list[str], list[str], list[str]]] = {}
        last_prog_ts = time.monotonic()

        # 1. Deep scan all Minecraft roots (mods, resourcepacks, shaderpacks, versions, libraries)
        mc_subdirs: list[Path] = []
        for mdir in expanded_mc_dirs:
            for sub_name in ("mods", "resourcepacks", "shaderpacks", "libraries", "versions"):
                sub = mdir / sub_name
                if not sub.is_dir():
                    continue
                if sub_name in ("resourcepacks", "shaderpacks"):
                    try:
                        for child in sub.iterdir():
                            if child.is_dir():
                                _analyze_folder_resource_or_shader_pack(ctx, child)
                    except OSError:
                        pass
                mc_subdirs.append(sub)

        mc_files = list(iter_files_safe(mc_subdirs, max_depth=5)) if mc_subdirs else []
        n_mc = max(1, len(mc_files))
        emit_scan_progress(ctx, 0.05, f"Minecraft mod ve paketleri taraniyor ({len(mc_files)} dosya)...")
        for idx, fp in enumerate(mc_files):
            try:
                rp = fp.resolve()
            except OSError:
                rp = fp
            if rp not in scanned_real:
                scanned_real.add(rp)
                inspect_single_file(ctx, fp, is_mc_dir=True, clean_jar_digests=clean_jar_digests)
            now_mono = time.monotonic()
            if (idx % 20 == 0 or now_mono - last_prog_ts >= 0.12):
                last_prog_ts = now_mono
                emit_scan_progress(
                    ctx,
                    0.05 + 0.35 * ((idx + 1) / n_mc),
                    f"Minecraft dosya/JAR analizi ({idx + 1}/{len(mc_files)}): {fp.name}",
                )

        # 2. Scan hot user drop/execution zones (Downloads, Desktop, Documents, /tmp, /dev/shm, /var/tmp, ~/.local/bin)
        h = ctx.home_dir
        hot_dirs = [
            h / "Downloads",
            h / "Desktop",
            h / "Documents",
            h / ".local/bin",
            h / "bin",
            ctx.sys_path("/tmp"),
            ctx.sys_path("/dev/shm"),
            ctx.sys_path("/var/tmp"),
        ]
        existing_hot = [str(d) for d in hot_dirs if d.exists()]
        ctx.telemetry["engine4_hot_dirs_scanned"] = existing_hot
        for d in existing_hot:
            record_scan_region(ctx, "E4", f"Sicak Klasor: {d}")

        hot_files = list(iter_files_safe(hot_dirs, max_depth=4))
        n_hot = max(1, len(hot_files))
        emit_scan_progress(ctx, 0.40, f"Downloads, Desktop, /tmp ve /dev/shm taraniyor ({len(hot_files)} dosya)...")
        for idx, fp in enumerate(hot_files):
            try:
                rp = fp.resolve()
            except OSError:
                rp = fp
            if rp not in scanned_real:
                scanned_real.add(rp)
                inspect_single_file(ctx, fp, is_mc_dir=False, clean_jar_digests=clean_jar_digests)
            now_mono = time.monotonic()
            if (idx % 25 == 0 or now_mono - last_prog_ts >= 0.12):
                last_prog_ts = now_mono
                emit_scan_progress(
                    ctx,
                    0.40 + 0.22 * ((idx + 1) / n_hot),
                    f"Sicak bolge taramasi ({idx + 1}/{len(hot_files)}): {fp.name}",
                )

        # 3. Recently modified executables/archives anywhere under home within time window
        if ctx.deep_home_scan:
            record_scan_region(
                ctx,
                "E4",
                f"Derin Ev Dizini Taramasi ({h}, derinlik<=5, pencere={ctx.time_window_hours} saat)",
            )
            emit_scan_progress(ctx, 0.62, f"Ev dizini derin imza ve timestomp taramasi ({h})...")
            now = ctx.current_epoch()
            win_sec = ctx.time_window_hours * 3600.0
            skip_dir_names = {
                ".cache",
                "Steam",
                "containers",
                ".nv",
                ".cargo",
                ".rustup",
                ".npm",
                "__pycache__",
                "node_modules",
                ".git",
            }
            skip_rel_prefixes = (
                ".cache",
                ".local/share/Steam",
                ".local/share/containers",
                ".var/app/com.valvesoftware.Steam",
                ".nv",
                ".cargo",
                ".rustup",
                ".npm",
            )
            checked_home = 0
            for fp in iter_files_safe(
                [h],
                max_depth=5,
                skip_dir_names=skip_dir_names,
                skip_rel_prefixes=skip_rel_prefixes,
            ):
                checked_home += 1
                now_mono = time.monotonic()
                if now_mono - last_prog_ts >= 0.12:
                    last_prog_ts = now_mono
                    curve = 0.62 + 0.37 * (1.0 - math.exp(-checked_home / 2000.0))
                    emit_scan_progress(
                        ctx,
                        min(0.99, curve),
                        f"Ev dizini taranıyor ({checked_home} dosya kontrol edildi, {len(scanned_real)} derin analiz)...",
                    )
                try:
                    st = os.lstat(fp)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if (now - st.st_ctime) <= win_sec or (now - st.st_mtime) <= win_sec:
                    ext = fp.suffix.lower()
                    if ext in EXECUTABLE_OR_ARCHIVE_EXTS or ext in SPOOF_CHECK_TEXT_OR_MEDIA_EXTS or ext == "":
                        try:
                            rp = fp.resolve()
                        except OSError:
                            rp = fp
                        if rp not in scanned_real:
                            scanned_real.add(rp)
                            inspect_single_file(ctx, fp, is_mc_dir=False, clean_jar_digests=clean_jar_digests)

        ctx.telemetry["engine4_files_deep_scanned"] = len(scanned_real)
        emit_scan_progress(ctx, 1.0, f"Derin dosya taramasi tamamlandi ({len(scanned_real)} dosya).")
    except Exception as exc:
        ctx.add_error(ENGINE_NAME, f"Beklenmeyen hata: {exc}")

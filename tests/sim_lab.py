"""Adversarial simulation helpers generating clean & compromised Linux/Minecraft artifacts."""

from __future__ import annotations

import codecs
import gzip
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import time
import zipfile
import zlib
from pathlib import Path


def make_minimal_png(
    width: int,
    height: int,
    rgba: tuple[int, int, int, int] = (128, 128, 128, 255),
    transparent_pixels: int = 0,
    color_type: int = 6,
) -> bytes:
    """Create a valid PNG image with controllable alpha transparency."""
    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    raw_rows = bytearray()
    rem_trans = transparent_pixels
    r, g, b, a = rgba
    for y in range(height):
        # Alternate PNG filters (0, 1, 2, 3, 4) to exercise all unfilter paths
        ftype = y % 5 if color_type == 6 else 0
        raw_rows.append(0)  # keep filter 0 for clean exact pixel packing when generating
        row_pixels = bytearray()
        for _ in range(width):
            cur_a = 0 if rem_trans > 0 else a
            if rem_trans > 0:
                rem_trans -= 1
            if color_type == 6:
                row_pixels.extend((r, g, b, cur_a))
            elif color_type == 2:
                row_pixels.extend((r, g, b))
        raw_rows.extend(row_pixels)

    idat = zlib.compress(bytes(raw_rows))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )


def make_paeth_filtered_png(width: int, height: int, alpha_zero_count: int) -> bytes:
    """Create an RGBA PNG using PNG Sub/Up/Paeth filters to test unfiltering code."""
    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    plain_rows = []
    rem = alpha_zero_count
    for y in range(height):
        row = bytearray()
        for x in range(width):
            a = 0 if rem > 0 else 255
            if rem > 0:
                rem -= 1
            row.extend(((x * 17) & 0xFF, (y * 31) & 0xFF, 90, a))
        plain_rows.append(row)

    encoded = bytearray()
    stride = width * 4
    prev = bytearray(stride)
    for y, row in enumerate(plain_rows):
        ftype = (y % 4) + 1  # cycle through Sub(1), Up(2), Avg(3), Paeth(4)
        encoded.append(ftype)
        for i in range(stride):
            left = row[i - 4] if i >= 4 else 0
            up = prev[i]
            up_left = prev[i - 4] if i >= 4 else 0
            if ftype == 1:
                pred = left
            elif ftype == 2:
                pred = up
            elif ftype == 3:
                pred = (left + up) >> 1
            else:
                p = left + up - up_left
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - up_left)
                pred = left if (pa <= pb and pa <= pc) else (up if pb <= pc else up_left)
            encoded.append((row[i] - pred) & 0xFF)
        prev = row

    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", zlib.compress(bytes(encoded)))
        + _chunk(b"IEND", b"")
    )


def make_jar(path: Path, entries: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


def compile_java_to_class_bytes(tmp_dir: Path, pkg_rel: str, class_name: str, source: str) -> tuple[str, bytes]:
    """Compile real Java source via javac into actual .class bytecode."""
    src_file = tmp_dir / pkg_rel / f"{class_name}.java"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    src_file.write_text(source, encoding="utf-8")
    out_dir = tmp_dir / "classes"
    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.check_call(["javac", "-d", str(out_dir), str(src_file)])
    class_rel = f"{pkg_rel}/{class_name}.class" if pkg_rel else f"{class_name}.class"
    return class_rel, (out_dir / class_rel).read_bytes()


def compile_c_shared_so(tmp_dir: Path, name: str, c_source: str) -> Path:
    src = tmp_dir / f"{name}.c"
    out = tmp_dir / f"{name}.so"
    src.write_text(c_source, encoding="utf-8")
    subprocess.check_call(["gcc", "-shared", "-fPIC", str(src), "-o", str(out)])
    return out


def build_clean_baseline(base: Path) -> tuple[Path, Path, Path]:
    """Create a realistic clean Linux Minecraft environment (home, root, proc)."""
    home = base / "home"
    root = base / "sysroot"
    proc = base / "proc"
    for d in (home, root, proc):
        d.mkdir(parents=True, exist_ok=True)

    # 1. System files
    (proc / "uptime").write_text("18420.55 72000.00\n", encoding="utf-8")
    (proc / "bus/input").mkdir(parents=True, exist_ok=True)
    (proc / "bus/input/devices").write_text(
        'I: Bus=0003 Vendor=046d Product=c077 Version=0111\n'
        'N: Name="Logitech USB Optical Mouse"\n'
        'P: Phys=usb-0000:00:14.0-1/input0\n'
        'H: Handlers=mouse0 event2\n\n',
        encoding="utf-8",
    )
    (proc / "net").mkdir(parents=True, exist_ok=True)
    (proc / "net/tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:1770 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1001\n",
        encoding="utf-8",
    )
    (proc / "net/tcp6").write_text(
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        encoding="utf-8",
    )

    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n::1 localhost\n", encoding="utf-8")
    (root / "sys/class/drm/card0-DP-1").mkdir(parents=True, exist_ok=True)
    (root / "sys/class/drm/card0-DP-1/status").write_text("connected\n", encoding="utf-8")
    (root / "sys/class/net/eth0").mkdir(parents=True, exist_ok=True)
    (root / "sys/class/net/eth0/operstate").write_text("up\n", encoding="utf-8")

    # 2. Clean user history & xbel
    (home / ".bashrc").write_text("export PATH=$HOME/.local/bin:$PATH\n", encoding="utf-8")
    (home / ".bash_history").write_text(
        "ls -la\n"
        "python3 --version\n"
        "flatpak list\n"
        "git status\n"
        "uname -a\n"
        "java -version\n"
        "cat /etc/os-release\n"
        "df -h\n"
        "uptime\n"
        "ls -lh ~/.minecraft/mods\n",
        encoding="utf-8",
    )
    (home / ".local/share").mkdir(parents=True, exist_ok=True)
    existing_doc = home / "Downloads/notes.txt"
    existing_doc.parent.mkdir(parents=True, exist_ok=True)
    existing_doc.write_text("Minecraft server IP\n", encoding="utf-8")
    (home / ".local/share/recently-used.xbel").write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n<xbel version="1.0">\n'
        f'  <bookmark href="file://{existing_doc}" added="2026-11-15T10:00:00Z" modified="2026-11-15T10:00:00Z"/>\n'
        f'</xbel>\n',
        encoding="utf-8",
    )

    # 3. Clean Minecraft instance with genuine Sodium mod + opaque stone.png + matching latest.log
    mc = home / ".minecraft"
    (mc / "mods").mkdir(parents=True, exist_ok=True)
    (mc / "logs").mkdir(parents=True, exist_ok=True)
    (mc / "resourcepacks").mkdir(parents=True, exist_ok=True)

    sodium_meta = json.dumps(
        {
            "schemaVersion": 1,
            "id": "sodium",
            "version": "0.5.8",
            "name": "Sodium",
            "entrypoints": {"client": ["me.jellysquid.mods.sodium.client.SodiumClientMod"]},
        }
    ).encode("utf-8")
    make_jar(
        mc / "mods/sodium-fabric-0.5.8.jar",
        {"fabric.mod.json": sodium_meta, "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"},
    )
    (mc / "options.txt").write_text(
        "gamma:1.0\nfov:0.5\nkey_key.attack:key.mouse.left\nlastServer:play.example.net\n",
        encoding="utf-8",
    )
    (mc / "logs/latest.log").write_text(
        "[12:00:01] [main/INFO]: Loading Minecraft 1.21 with Fabric Loader 0.16.0\n"
        "[12:00:01] [main/INFO]: Loading 2 mods:\n"
        "\t- minecraft 1.21\n"
        "\t- sodium 0.5.8\n"
        "[12:00:05] [Render thread/INFO]: Sound engine started\n",
        encoding="utf-8",
    )

    clean_pack = mc / "resourcepacks/CleanPack.zip"
    make_jar(
        clean_pack,
        {
            "pack.mcmeta": b'{"pack":{"pack_format":34,"description":"Clean"}}',
            "assets/minecraft/textures/block/stone.png": make_minimal_png(16, 16, (120, 120, 120, 255), 0),
        },
    )

    # 4. Clean Chrome SQLite DB with regular websites
    chrome_dir = home / ".config/google-chrome/Default"
    chrome_dir.mkdir(parents=True, exist_ok=True)
    db_path = chrome_dir / "History"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
    conn.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, tab_url TEXT, target_path TEXT, start_time INTEGER)")
    now_wk = int((time.time() + 11644473600) * 1_000_000)
    for i in range(25):
        conn.execute(
            "INSERT INTO urls VALUES (?, ?, ?, 1, ?)",
            (i + 1, f"https://modrinth.com/mod/sodium/{i}", "Modrinth", now_wk - i * 1000000),
        )
    conn.commit()
    conn.close()

    # 5. Clean simulated Java Minecraft PID in proc
    p1 = proc / "1"
    (p1 / "ns").mkdir(parents=True, exist_ok=True)
    for n in ("mnt", "pid", "net", "user"):
        os.symlink(f"{n}:[4026531840]", p1 / "ns" / n)

    pmc = proc / "4242"
    (pmc / "ns").mkdir(parents=True, exist_ok=True)
    (pmc / "fd").mkdir(parents=True, exist_ok=True)
    for n in ("mnt", "pid", "net", "user"):
        os.symlink(f"{n}:[4026531840]", pmc / "ns" / n)
    (pmc / "comm").write_text("java\n", encoding="utf-8")
    os.symlink("/usr/lib/jvm/java-21/bin/java", pmc / "exe")
    (pmc / "cmdline").write_bytes(
        b"/usr/lib/jvm/java-21/bin/java\x00-Xmx4G\x00net.minecraft.client.main.Main\x00"
    )
    (pmc / "status").write_text("Name:\tjava\nUid:\t1000\t1000\nTracerPid:\t0\n", encoding="utf-8")
    (pmc / "environ").write_bytes(b"HOME=/home/player\x00DISPLAY=:0\x00")
    (pmc / "maps").write_text(
        "7f0000000000-7f0000100000 r-xp 00000000 08:01 101 /tmp/liblwjgl64.so\n"
        "7f0000200000-7f0000300000 r--p 00000000 08:01 102 /home/player/.minecraft/mods/sodium-fabric-0.5.8.jar\n",
        encoding="utf-8",
    )

    return home, root, proc


def write_simulated_proc_entry(
    proc_root: Path,
    pid: int,
    comm: str,
    cmdline: list[str],
    exe_target: str = "/usr/bin/java",
    tracer_pid: int = 0,
    environ: dict[str, str] | None = None,
    maps_lines: list[str] | None = None,
    fds: dict[str, str] | None = None,
    ns: dict[str, str] | None = None,
    cgroup: str = "0::/user.slice",
    mem_bytes: bytes | None = None,
) -> Path:
    pdir = proc_root / str(pid)
    (pdir / "ns").mkdir(parents=True, exist_ok=True)
    (pdir / "fd").mkdir(parents=True, exist_ok=True)
    (pdir / "comm").write_text(comm + "\n", encoding="utf-8")
    (pdir / "cmdline").write_bytes(b"\x00".join(a.encode() for a in cmdline) + b"\x00")
    exe_link = pdir / "exe"
    if exe_link.is_symlink() or exe_link.exists():
        exe_link.unlink()
    os.symlink(exe_target, exe_link)
    (pdir / "status").write_text(f"Name:\t{comm}\nUid:\t1000\nTracerPid:\t{tracer_pid}\n", encoding="utf-8")
    (pdir / "cgroup").write_text(cgroup + "\n", encoding="utf-8")
    env_bytes = b"\x00".join(f"{k}={v}".encode() for k, v in (environ or {}).items())
    (pdir / "environ").write_bytes(env_bytes)

    ns_vals = ns or {
        "mnt": "mnt:[4026531840]",
        "pid": "pid:[4026531840]",
        "net": "net:[4026531840]",
        "user": "user:[4026531840]",
    }
    for k, v in ns_vals.items():
        lk = pdir / "ns" / k
        if lk.is_symlink() or lk.exists():
            lk.unlink()
        os.symlink(v, lk)

    if fds:
        for fd_num, target in fds.items():
            fl = pdir / "fd" / fd_num
            if fl.is_symlink() or fl.exists():
                fl.unlink()
            os.symlink(target, fl)

    if maps_lines is not None:
        (pdir / "maps").write_text("\n".join(maps_lines) + "\n", encoding="utf-8")
    if mem_bytes is not None:
        (pdir / "mem").write_bytes(mem_bytes)

    return pdir

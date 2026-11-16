"""Engine 6: Desktop Artifacts (recently-used.xbel, Clipboard, Trash),
Browser SQLite (+ WAL & Freelist Carving), Wine/Proton Registry (+ UserAssist ROT13),
Java UserPrefs & Persistence/Autostart.
"""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from .models import Confidence, Finding, ScanContext, Severity
from .signatures import CHEAT_DOMAINS, SUSPICIOUS_UNVERIFIED_MOD_ORIGINS
from .utils import (
    copy_sqlite_with_sidecars,
    discover_browser_databases,
    emit_scan_progress,
    match_cheat_signatures,
    record_scan_region,
    rot13,
    run_trusted_cmd,
    safe_read_bytes,
    safe_read_text,
    statx_timestamps,
)

ENGINE_NAME = "Engine 6: Masaustu, Cop Kutusu, Tarayici SQLite & Wine/Proton"

WEBKIT_EPOCH_OFFSET_SEC = 11644473600

WINDOWS_CHEAT_KEYWORDS: tuple[str, ...] = (
    "vape",
    "drip",
    "driplite",
    "entropy",
    "slinky",
    "whiteout",
    "icetea",
    "krypton",
    "itami",
    "opautoclicker",
    "gsautoclicker",
    "speedautoclicker",
    "autoclicker",
    "tinytask",
    "cheatengine",
    "cheat engine",
    "processhacker",
    "x64dbg",
    "extremeinjector",
    "xenos",
)

_WIN_CHEAT_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"vape(?:v4|lite)?|driplite|slinky|whiteout|krypton|itami|icetea|"
    r"opautoclicker|gsautoclicker|speedautoclicker|autoclicker|tinytask|"
    r"cheat\s*engine|process\s*hacker|x64dbg|extreme\s*injector|xenos\s*injector"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)
_WIN_EXE_CTX_RE = re.compile(
    r"(?<![a-z0-9])(?:drip|entropy|xenos)(?:\.exe|\.dll)?(?![a-z0-9])",
    re.IGNORECASE,
)


def _fmt_epoch(ts_sec: float) -> str:
    try:
        return datetime.fromtimestamp(ts_sec, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts_sec)


def _check_recently_used(ctx: ScanContext) -> None:
    xbel = ctx.home_dir / ".local/share/recently-used.xbel"
    if not xbel.is_file():
        return
    txt = safe_read_text(xbel, 4 * 1024 * 1024)
    if not txt.strip():
        return

    try:
        root = ET.fromstring(txt)
    except ET.ParseError:
        return

    deleted_suspicious: list[str] = []
    active_suspicious: list[str] = []

    for bm in root.findall(".//bookmark"):
        href = bm.attrib.get("href", "")
        modified = bm.attrib.get("modified", "")
        if not href.startswith("file://"):
            continue
        parsed = urllib.parse.urlparse(href)
        fpath_str = urllib.parse.unquote(parsed.path)
        fpath = Path(fpath_str)
        exists = fpath.exists()
        low = fpath_str.lower()
        strict, high_ctx, _ = match_cheat_signatures(fpath_str)
        is_suspect_ext = low.endswith((".jar", ".so", ".dll", ".exe", ".appimage", ".class"))
        in_tmp = any(t in low for t in ("/tmp/", "/dev/shm/", "/var/tmp/"))

        if strict or high_ctx:
            msg = f"{fpath_str} (modified={modified}, diskte={'VAR' if exists else 'SILINMIS'})"
            (active_suspicious if exists else deleted_suspicious).append(msg)
        elif not exists and (is_suspect_ext or in_tmp):
            deleted_suspicious.append(f"{fpath_str} (modified={modified}, diskten SILINMIS)")

    if deleted_suspicious:
        ctx.add_finding(
            Finding(
                rule_id="E6-XBEL-DELETED-ARTIFACT",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Desktop Recent Deleted File",
                title="recently-used.xbel icinde sonradan diskten silinmis kritik dosya izi",
                description="Kullanici bu .jar/.so/.exe veya hile dosyasini acmis/kullanmis ancak dosya su an diskte yok!",
                evidence=deleted_suspicious[:15],
                path=str(xbel),
            )
        )
    if active_suspicious:
        ctx.add_finding(
            Finding(
                rule_id="E6-XBEL-CHEAT-FILE",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="Desktop Recent Trace",
                title="recently-used.xbel icinde hile dosyasi kaydi",
                description="Son kullanilan dosyalar gecmisinde hile imzali dosya goruldu.",
                evidence=active_suspicious[:12],
                path=str(xbel),
            )
        )


def _check_clipboard_and_klipper(ctx: ScanContext) -> None:
    h = ctx.home_dir
    klipper_file = h / ".local/share/klipper/history2.lst"
    clip_blobs: list[tuple[str, str]] = []

    if klipper_file.is_file():
        raw = safe_read_bytes(klipper_file, 4 * 1024 * 1024)
        # Qt QDataStream stores UTF-16BE / UTF-8 strings; extract both
        ascii_runs = [
            m.group(0).decode("utf-8", errors="replace")
            for m in re.finditer(rb"[\x20-\x7e]{5,}", raw)
        ]
        # UTF-16BE ASCII strings (common in Qt QString serialization)
        utf16be_runs = [
            m.group(0).decode("utf-16be", errors="replace")
            for m in re.finditer(rb"(?:\x00[\x20-\x7e]){5,}", raw)
        ]
        clip_blobs.append((str(klipper_file), "\n".join(ascii_runs + utf16be_runs)))

    for extra_clip in (
        h / ".cache/cliphist/db",
        h / ".local/share/copyq/copyq_tab_JmNsaXBib2FyZA==.dat",
    ):
        if extra_clip.is_file():
            raw = safe_read_bytes(extra_clip, 4 * 1024 * 1024)
            runs = [m.group(0).decode("utf-8", errors="replace") for m in re.finditer(rb"[\x20-\x7e]{5,}", raw)]
            clip_blobs.append((str(extra_clip), "\n".join(runs)))

    if ctx.live_mode:
        for cmd in (["wl-paste", "--no-newline"], ["xclip", "-o", "-selection", "clipboard"]):
            rc, out, _ = run_trusted_cmd(cmd, timeout=1.5)
            if rc == 0 and out.strip():
                clip_blobs.append((f"Live ({cmd[0]})", out[:8192]))
                break

    for src, text in clip_blobs:
        hits: list[str] = []
        for line in text.splitlines():
            s, h_ctx, _ = match_cheat_signatures(line)
            low = line.lower()
            if s or h_ctx or any(dom in low for dom in CHEAT_DOMAINS):
                hits.append(line.strip()[:180])
            elif any(k in low for k in ("shred ", "rm -rf", "setfattr", "history -c", "/dev/shm/", "java -javaagent")):
                hits.append(line.strip()[:180])
        if hits:
            ctx.add_finding(
                Finding(
                    rule_id="E6-CLIPBOARD-HIT",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Clipboard Forensics",
                    title=f"Pano (Clipboard/Klipper) gecmisinde supheli komut veya link",
                    description="Panoda hile sitesi, agent parametresi veya iz silme komutu bulundu.",
                    evidence=hits[:12],
                    path=src if src.startswith("/") else None,
                )
            )


def _check_trash(ctx: ScanContext) -> None:
    trash_info = ctx.home_dir / ".local/share/Trash/info"
    trash_files = ctx.home_dir / ".local/share/Trash/files"
    if not trash_info.is_dir() and not trash_files.is_dir():
        return

    now = ctx.current_epoch()
    win_sec = ctx.time_window_hours * 3600.0
    suspicious_trashed: list[str] = []

    try:
        seen_trash_targets: set[str] = set()
        if trash_info.is_dir():
            for tif in trash_info.glob("*.trashinfo"):
                txt = safe_read_text(tif, 16384)
                orig_path = ""
                del_date = ""
                for ln in txt.splitlines():
                    if ln.startswith("Path="):
                        orig_path = urllib.parse.unquote(ln[5:].strip())
                    elif ln.startswith("DeletionDate="):
                        del_date = ln[13:].strip()
                if orig_path:
                    seen_trash_targets.add(os.path.basename(orig_path))
                seen_trash_targets.add(tif.stem)
                is_recent = False
                if del_date:
                    try:
                        dt = datetime.fromisoformat(del_date)
                        if dt.tzinfo is None:
                            delta = (datetime.fromtimestamp(now) - dt).total_seconds()
                        else:
                            delta = now - dt.timestamp()
                        if -300.0 <= delta <= win_sec:
                            is_recent = True
                    except Exception:
                        pass
                ts = statx_timestamps(tif)
                if ts and (now - ts.mtime_ns / 1e9) <= win_sec:
                    is_recent = True

                strict, high_ctx, _ = match_cheat_signatures(orig_path)
                low_p = orig_path.lower()
                is_mod_or_bin = low_p.endswith((".jar", ".so", ".dll", ".exe", ".appimage", ".zip", ".sh", ".py"))
                if strict or high_ctx or (is_recent and (is_mod_or_bin or ".minecraft" in low_p or "prism" in low_p)):
                    suspicious_trashed.append(
                        f"{orig_path} (Silinme={del_date or 'N/A'}, Yakin={'EVET' if is_recent else 'Hayir'})"
                    )
        if trash_files.is_dir():
            for tf in trash_files.iterdir():
                if tf.name in seen_trash_targets:
                    continue
                low_tf = tf.name.lower()
                s_tf, h_tf, _ = match_cheat_signatures(tf.name)
                if s_tf or h_tf or low_tf.endswith((".jar", ".so", ".dll", ".exe", ".appimage")):
                    ts_tf = statx_timestamps(tf)
                    rec_tf = bool(ts_tf and (now - ts_tf.mtime_ns / 1e9) <= win_sec)
                    if s_tf or h_tf or rec_tf:
                        suspicious_trashed.append(
                            f"{tf} [orphan Trash/files] (Yakin={'EVET' if rec_tf else 'Hayir'})"
                        )
    except OSError:
        pass

    if suspicious_trashed:
        ctx.add_finding(
            Finding(
                rule_id="E6-TRASH-SUSPICIOUS",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL if any("EVET" in x for x in suspicious_trashed) else Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="Trash Bin Forensics",
                title="Cop Kutusunda silinmis mod/binary/hile izleri bulundu",
                description="Oyuncu yakin saatlerde Cop Kutusuna .jar, .so, .exe veya Minecraft dosyasi atmis.",
                evidence=suspicious_trashed[:15],
                path=str(trash_files),
            )
        )


def _carve_raw_sqlite_urls(db_and_wal_paths: list[Path]) -> list[str]:
    """Carve deleted URLs directly from raw SQLite pages & WAL frames (chunked up to 128MB)."""
    hits: set[str] = set()
    url_re = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{8,220}")
    chunk_size = 16 * 1024 * 1024
    max_file = 128 * 1024 * 1024
    for p in db_and_wal_paths:
        if not p.is_file():
            continue
        try:
            read_total = 0
            tail = b""
            with open(p, "rb") as fh:
                while read_total < max_file:
                    chunk = fh.read(min(chunk_size, max_file - read_total))
                    if not chunk:
                        break
                    read_total += len(chunk)
                    buf = tail + chunk
                    for m in url_re.finditer(buf):
                        u = m.group(0).decode("ascii", errors="replace")
                        ulow = u.lower()
                        s, h_ctx, _ = match_cheat_signatures(u)
                        if any(dom in ulow for dom in CHEAT_DOMAINS) or s or len(h_ctx) >= 2:
                            hits.add(u)
                        elif ("minecraft" in ulow and bool(h_ctx)) or (
                            any(uhost in ulow for uhost in SUSPICIOUS_UNVERIFIED_MOD_ORIGINS)
                            and any(ext in ulow for ext in (".jar", ".so", ".exe", ".dll", "cheat", "click", "xray"))
                        ):
                            hits.add(u)
                    tail = buf[-512:] if len(buf) >= 512 else buf
        except OSError:
            continue
    return sorted(hits)


def _check_browsers(ctx: ScanContext) -> None:
    dbs = discover_browser_databases(ctx)
    ctx.telemetry["browser_dbs_found"] = [f"{lbl}: {p}" for lbl, _, p in dbs]
    if not dbs:
        return

    now = ctx.current_epoch()
    win_sec = ctx.time_window_hours * 3600.0

    with tempfile.TemporaryDirectory(prefix="ss_browser_") as tmp:
        tmp_dir = Path(tmp)
        for idx, (label, btype, db_path) in enumerate(dbs):
            sub_tmp = tmp_dir / str(idx)
            sub_tmp.mkdir(parents=True, exist_ok=True)
            snap = copy_sqlite_with_sidecars(db_path, sub_tmp)
            if not snap:
                continue

            ts = statx_timestamps(db_path)
            db_size = ts.size if ts else 0
            sidecar_paths = [
                snap,
                Path(str(snap) + "-wal"),
                Path(str(snap) + "-journal"),
            ]

            conn: sqlite3.Connection | None = None
            url_hits: list[str] = []
            dl_hits: list[str] = []
            total_urls = 0
            recent_count = 0

            try:
                conn = sqlite3.connect(f"file:{snap}?mode=ro", uri=True)
                cur = conn.cursor()
                if btype == "chromium":
                    cur.execute("SELECT COUNT(*) FROM urls")
                    total_urls = cur.fetchone()[0]
                    cutoff_wk = int((now - win_sec + WEBKIT_EPOCH_OFFSET_SEC) * 1_000_000)
                    cur.execute("SELECT COUNT(*) FROM urls WHERE last_visit_time >= ?", (cutoff_wk,))
                    recent_count = cur.fetchone()[0]

                    cur.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC")
                    rows_checked = 0
                    while rows_checked < 100000:
                        batch = cur.fetchmany(5000)
                        if not batch:
                            break
                        rows_checked += len(batch)
                        for url, title, lvt in batch:
                            u_s = f"{url or ''} {title or ''}"
                            ulow = u_s.lower()
                            s, h_ctx, _ = match_cheat_signatures(u_s)
                            if (
                                any(dom in ulow for dom in CHEAT_DOMAINS)
                                or s
                                or len(h_ctx) >= 2
                                or ("minecraft" in ulow and bool(h_ctx))
                            ):
                                t_unix = (lvt / 1_000_000) - WEBKIT_EPOCH_OFFSET_SEC if lvt else 0
                                url_hits.append(f"[{_fmt_epoch(t_unix)}] {url} ({title})")

                    try:
                        cur.execute("SELECT term FROM keyword_search_terms LIMIT 10000")
                        for (term,) in cur.fetchall():
                            s, h_ctx, _ = match_cheat_signatures(term or "")
                            if s or len(h_ctx) >= 2 or ("minecraft" in (term or "").lower() and bool(h_ctx)):
                                url_hits.append(f"[Arama] {term}")
                    except sqlite3.Error:
                        pass

                    try:
                        cur.execute(
                            "SELECT d.tab_url, COALESCE(c.url, ''), d.target_path, d.start_time "
                            "FROM downloads d LEFT JOIN downloads_url_chains c ON d.id = c.id "
                            "ORDER BY d.start_time DESC LIMIT 5000"
                        )
                    except sqlite3.Error:
                        cur.execute(
                            "SELECT tab_url, '', target_path, start_time FROM downloads "
                            "ORDER BY start_time DESC LIMIT 5000"
                        )
                    for tab_url, chain_url, target_path, st_time in cur.fetchall():
                        combo = f"{tab_url or ''} {chain_url or ''} {target_path or ''}"
                        clow = combo.lower()
                        s, h_ctx, _ = match_cheat_signatures(combo)
                        is_susp_dl = any(dom in clow for dom in CHEAT_DOMAINS) or s or h_ctx or (
                            any(h in clow for h in SUSPICIOUS_UNVERIFIED_MOD_ORIGINS)
                            and any(ext in clow for ext in (".jar", ".so", ".exe", ".dll"))
                        )
                        if is_susp_dl:
                            t_unix = (st_time / 1_000_000) - WEBKIT_EPOCH_OFFSET_SEC if st_time else 0
                            src_url = chain_url or tab_url
                            dl_hits.append(f"[{_fmt_epoch(t_unix)}] {target_path} <- {src_url}")

                elif btype == "firefox":
                    cur.execute("SELECT COUNT(*) FROM moz_places")
                    total_urls = cur.fetchone()[0]
                    cutoff_pr = int((now - win_sec) * 1_000_000)
                    cur.execute("SELECT COUNT(*) FROM moz_places WHERE last_visit_date >= ?", (cutoff_pr,))
                    recent_count = cur.fetchone()[0]

                    cur.execute("SELECT url, title, last_visit_date FROM moz_places ORDER BY last_visit_date DESC")
                    rows_checked = 0
                    while rows_checked < 100000:
                        batch = cur.fetchmany(5000)
                        if not batch:
                            break
                        rows_checked += len(batch)
                        for url, title, lvd in batch:
                            u_s = f"{url or ''} {title or ''}"
                            ulow = u_s.lower()
                            s, h_ctx, _ = match_cheat_signatures(u_s)
                            if (
                                any(dom in ulow for dom in CHEAT_DOMAINS)
                                or s
                                or len(h_ctx) >= 2
                                or ("minecraft" in ulow and bool(h_ctx))
                            ):
                                t_unix = (lvd / 1_000_000) if lvd else 0
                                url_hits.append(f"[{_fmt_epoch(t_unix)}] {url} ({title})")

                    # Firefox downloads are stored in moz_annos (content) joined with moz_places
                    try:
                        cur.execute(
                            "SELECT p.url, a.content, a.dateAdded FROM moz_annos a "
                            "JOIN moz_places p ON a.place_id = p.id ORDER BY a.dateAdded DESC LIMIT 5000"
                        )
                        for purl, content, dadd in cur.fetchall():
                            combo = f"{purl or ''} {content or ''}"
                            clow = combo.lower()
                            s, h_ctx, _ = match_cheat_signatures(combo)
                            if any(dom in clow for dom in CHEAT_DOMAINS) or s or h_ctx or (
                                any(ext in clow for ext in (".jar", ".so", ".exe"))
                                and any(h in clow for h in SUSPICIOUS_UNVERIFIED_MOD_ORIGINS)
                            ):
                                t_unix = (dadd / 1_000_000) if dadd else 0
                                dl_hits.append(f"[{_fmt_epoch(t_unix)}] {content} <- {purl}")
                    except sqlite3.Error:
                        pass
            except sqlite3.Error as exc:
                ctx.add_error(ENGINE_NAME, f"{label} SQLite okuma hatasi: {exc}")
            finally:
                if conn is not None:
                    conn.close()

            if url_hits:
                ctx.add_finding(
                    Finding(
                        rule_id="E6-BROWSER-CHEAT-URL",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="Browser History",
                        title=f"Tarayici gecmisinde hile sitesi/aramasi ({label})",
                        description="Ziyaret edilen URL veya basliklar arasinda hile sitesi tespit edildi.",
                        evidence=url_hits[:15],
                        path=str(db_path),
                    )
                )
            if dl_hits:
                ctx.add_finding(
                    Finding(
                        rule_id="E6-BROWSER-CHEAT-DOWNLOAD",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="Browser Download",
                        title=f"Tarayici indirmelerinde hile/supheli .jar/.exe kaydi ({label})",
                        description="Dosya diskten silinmis olsa bile tarayici indirme kaydi duruyor.",
                        evidence=dl_hits[:15],
                        path=str(db_path),
                    )
                )

            # History wipe detection: flag only if recently modified within scan window (avoids unused browser profiles)
            db_recent = ts is not None and (now - (ts.mtime_ns / 1e9)) <= win_sec
            if db_recent and (total_urls <= 3 or (db_size < 102400 and total_urls < 15)):
                ctx.add_finding(
                    Finding(
                        rule_id="E6-BROWSER-HISTORY-WIPED",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="Anti-Forensics / Browser Wipe",
                        title=f"Tarayici gecmisi yakin zamanda temizlenmis / sifirlanmis ({label})",
                        description=f"Veritabani yakin saatte degismis olmasina ragmen sadece {total_urls} kayit iceriyor (boyut={db_size} byte).",
                        evidence=[f"Dosya: {db_path}", f"Kayit sayisi: {total_urls}", f"Son {ctx.time_window_hours}h icinde: {recent_count}"],
                        path=str(db_path),
                    )
                )

            # Raw SQLite freelist & WAL carving (catches deleted records before VACUUM!)
            carved = _carve_raw_sqlite_urls(sidecar_paths)
            # Report any carved URL not already surfaced in active SQL hits
            existing_blob = "\n".join(url_hits + dl_hits)
            deleted_only_carved = [u for u in carved if u not in existing_blob]
            if deleted_only_carved:
                ctx.add_finding(
                    Finding(
                        rule_id="E6-BROWSER-SQLITE-FREELIST-CARVE",
                        engine=ENGINE_NAME,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="Deleted Browser History Carving",
                        title=f"Silinmis tarayici gecmisi ham SQLite sayfalarindan kurtarildi ({label})",
                        description=(
                            "Kullanici tarayici gecmisini temizlemis olsa bile SQLite serbest/WAL sayfalarindan "
                            "silinen hile/indirme URL'leri dogrudan kurtarildi!"
                        ),
                        evidence=deleted_only_carved[:15],
                        path=str(db_path),
                    )
                )

            if btype == "chromium":
                bm_file = db_path.parent / "Bookmarks"
                if bm_file.is_file():
                    bm_txt = safe_read_text(bm_file, 2 * 1024 * 1024)
                    bm_hits: list[str] = []
                    if bm_txt:
                        for bm_ln in bm_txt.splitlines():
                            low_b = bm_ln.lower()
                            if '"url"' in low_b or '"name"' in low_b:
                                s_bm, h_bm, _ = match_cheat_signatures(bm_ln)
                                if s_bm or any(dom in low_b for dom in CHEAT_DOMAINS) or len(h_bm) >= 2:
                                    bm_hits.append(bm_ln.strip()[:180])
                    if bm_hits:
                        ctx.add_finding(
                            Finding(
                                rule_id="E6-BROWSER-BOOKMARK-CHEAT",
                                engine=ENGINE_NAME,
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                category="Browser Bookmark",
                                title=f"Tarayici yer imlerinde (Bookmarks) hile kaydi ({label})",
                                description="Gecmis temizlense bile tarayici yer imlerinde hile sitesi veya indirici kaydi duruyor.",
                                evidence=bm_hits[:12],
                                path=str(bm_file),
                            )
                        )


def _check_wine_and_proton(ctx: ScanContext) -> None:
    h = ctx.home_dir
    reg_files: list[Path] = []
    wine_dir = h / ".wine"
    if wine_dir.is_dir():
        reg_files.extend(wine_dir.glob("*.reg"))
    wine_pfx_dir = h / ".local/share/wineprefixes"
    if wine_pfx_dir.is_dir():
        reg_files.extend(wine_pfx_dir.glob("*/*.reg"))
    compat = h / ".local/share/Steam/steamapps/compatdata"
    if compat.is_dir():
        reg_files.extend(compat.glob("*/pfx/*.reg"))
    heroic_pfx = h / "Games/Heroic/Prefixes"
    if heroic_pfx.is_dir():
        reg_files.extend(heroic_pfx.glob("*/*.reg"))
    for live_wp in ctx.telemetry.get("live_wine_prefixes", []):
        lwp = Path(live_wp)
        if lwp.is_dir():
            reg_files.extend(lwp.glob("*.reg"))

    seen_reg: set[Path] = set()
    for rf in reg_files:
        try:
            rrf = rf.resolve()
        except OSError:
            rrf = rf
        if rrf in seen_reg or not rf.is_file():
            continue
        seen_reg.add(rrf)
        txt = safe_read_text(rf, 8 * 1024 * 1024)
        if not txt:
            continue

        direct_hits: list[str] = []
        rot13_hits: list[str] = []
        in_userassist = False

        for line in txt.splitlines():
            sline = line.strip()
            low = sline.lower()
            if sline.startswith("["):
                in_userassist = "\\userassist\\" in low
                continue

            s_dir, h_dir, _ = match_cheat_signatures(sline)
            if (
                _WIN_CHEAT_RE.search(low)
                or s_dir
                or ((_WIN_EXE_CTX_RE.search(low) or bool(h_dir)) and (".exe" in low or ".dll" in low or "\\" in low))
            ):
                direct_hits.append(sline[:200])

            if in_userassist and sline.startswith('"'):
                # Format: "E:\Path\Incr.rkr"=hex:...
                key_part = sline.split('"', 2)[1] if sline.count('"') >= 2 else ""
                if key_part:
                    decoded = rot13(key_part)
                    dlow = decoded.lower()
                    s_dec, h_dec, _ = match_cheat_signatures(decoded)
                    if (
                        _WIN_CHEAT_RE.search(dlow)
                        or _WIN_EXE_CTX_RE.search(dlow)
                        or s_dec
                        or (bool(h_dec) and (".exe" in dlow or ".dll" in dlow or "\\" in dlow))
                    ):
                        rot13_hits.append(f"ROT13('{key_part}') -> '{decoded}'")

        if rot13_hits:
            ctx.add_finding(
                Finding(
                    rule_id="E6-WINE-USERASSIST-ROT13",
                    engine=ENGINE_NAME,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="Wine UserAssist Execution Proof",
                    title=f"Wine UserAssist icinde ROT13 gizli Windows .exe hile calistirma kaniti ({rf.name})",
                    description="Windows/Wine UserAssist kaydi bu hile/autoclicker .exe dosyasinin calistirildigini kanitliyor.",
                    evidence=rot13_hits[:12],
                    path=str(rf),
                )
            )
        elif direct_hits:
            ctx.add_finding(
                Finding(
                    rule_id="E6-WINE-REG-CHEAT",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Wine Registry Trace",
                    title=f"Wine/Proton kayit defterinde Windows hile/makro izi ({rf.name})",
                    description="Wine registry icinde Windows hile istemcisi veya clicker kaydi bulundu.",
                    evidence=direct_hits[:12],
                    path=str(rf),
                )
            )


def _check_java_userprefs_and_autostart(ctx: ScanContext) -> None:
    h = ctx.home_dir
    uprefs = h / ".java/.userPrefs"
    if uprefs.is_dir():
        hits: list[str] = []
        for xf in uprefs.rglob("*.xml"):
            txt = safe_read_text(xf, 128 * 1024)
            s, h_ctx, _ = match_cheat_signatures(f"{xf} {txt}")
            if s or h_ctx:
                hits.append(f"{xf}: {', '.join(s + h_ctx)}")
        if hits:
            ctx.add_finding(
                Finding(
                    rule_id="E6-JAVA-USERPREFS-CHEAT",
                    engine=ENGINE_NAME,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    category="Java UserPrefs Trace",
                    title="~/.java/.userPrefs icinde hile ayar izi bulundu",
                    description="Java uygulamalarinin kalici preference kayitlarinda hile anahtarlari mevcut.",
                    evidence=hits[:10],
                    path=str(uprefs),
                )
            )

    # Autostart desktop entries & user systemd units
    for adir in (h / ".config/autostart", h / ".config/systemd/user"):
        if not adir.is_dir():
            continue
        for f in adir.rglob("*"):
            if not f.is_file():
                continue
            txt = safe_read_text(f, 65536)
            low = txt.lower()
            if any(k in low for k in ("xdotool", "ydotool", "dotool", "xclicker", "/tmp/", "/dev/shm/")) or any(
                match_cheat_signatures(txt)[0]
            ):
                ctx.add_finding(
                    Finding(
                        rule_id="E6-PERSISTENCE-AUTOSTART",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="Startup Persistence",
                        title=f"Otomatik baslatma dosyasinda supheli komut/makro: {f.name}",
                        description="Oturum acilisinda calisan gizli makro veya tmp/shm komutu bulundu.",
                        evidence=[txt.strip()[:260]],
                        path=str(f),
                    )
                )


def run(ctx: ScanContext) -> None:
    try:
        emit_scan_progress(ctx, 0.12, "Masaustu son kullanilanlar (recently-used.xbel) inceleniyor...")
        _check_recently_used(ctx)
        record_scan_region(ctx, "E6", f"{ctx.home_dir}/.local/share/recently-used.xbel")
        emit_scan_progress(ctx, 0.28, "Pano (clipboard / Klipper) gecmisi inceleniyor...")
        _check_clipboard_and_klipper(ctx)
        record_scan_region(ctx, "E6", "Wayland/X11 Pano ve KDE Klipper verileri")
        emit_scan_progress(ctx, 0.44, "Cop kutusu (Trash) kayitlari taraniyor...")
        _check_trash(ctx)
        record_scan_region(ctx, "E6", f"{ctx.home_dir}/.local/share/Trash")
        emit_scan_progress(ctx, 0.65, "Tarayici SQLite gecmisi, WAL ve freelist taraniyor...")
        _check_browsers(ctx)
        for item in ctx.telemetry.get("browser_dbs_found", []):
            record_scan_region(ctx, "E6", f"Tarayici DB: {item}")
        emit_scan_progress(ctx, 0.84, "Wine/Proton UserAssist ve kayit defteri taraniyor...")
        _check_wine_and_proton(ctx)
        record_scan_region(ctx, "E6", f"{ctx.home_dir}/.wine ve Steam Proton prefix kayit defterleri")
        emit_scan_progress(ctx, 0.94, "Java UserPrefs ve autostart kayitlari kontrol ediliyor...")
        _check_java_userprefs_and_autostart(ctx)
        record_scan_region(ctx, "E6", f"{ctx.home_dir}/.java/.userPrefs ve .config/autostart")
        emit_scan_progress(ctx, 1.0, "Masaustu ve tarayici izleri tamamlandi.")
    except Exception as exc:
        ctx.add_error(ENGINE_NAME, f"Beklenmeyen hata: {exc}")

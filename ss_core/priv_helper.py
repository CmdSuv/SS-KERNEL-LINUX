"""Privilege elevation bridge, ephemeral Ring-0 LKM lifecycle, and opt-in IOMMU hardening."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from .distro_profiles import (
    format_kernel_headers_install_hint,
    resolve_profile,
)


def _bundle_root() -> Path:
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(str(meipass))
    return Path(__file__).resolve().parent.parent


def _invoker_uid() -> int:
    for env_k in ("PKEXEC_UID", "SUDO_UID"):
        raw = os.environ.get(env_k, "").strip()
        if raw.isdigit():
            return int(raw)
    return os.getuid()


def _invoker_home() -> Path:
    uid = _invoker_uid()
    try:
        return Path(pwd.getpwuid(uid).pw_dir)
    except KeyError:
        return Path.home()


def _is_trusted_artifact(candidate: Path, require_exec: bool = False) -> bool:
    """Verify binary/.ko ownership and directory safety before root execution/insmod."""
    try:
        resolved = candidate.resolve(strict=True)
        st = os.stat(resolved)
        parent_st = os.stat(resolved.parent)
    except OSError:
        return False

    if not stat.S_ISREG(st.st_mode):
        return False
    if require_exec and not os.access(resolved, os.X_OK):
        return False

    trusted_uids = {0, os.geteuid(), os.getuid(), _invoker_uid()}
    if st.st_uid not in trusted_uids or parent_st.st_uid not in trusted_uids:
        return False
    # Block world-writable artifacts or world-writable parent directories (e.g. /tmp)
    if (st.st_mode & stat.S_IWOTH) != 0 or (parent_st.st_mode & stat.S_IWOTH) != 0:
        return False

    # Optional pinned SHA-256 sidecar verification when packaged
    sidecar = Path(str(resolved) + ".sha256")
    if sidecar.is_file():
        try:
            expected = sidecar.read_text(encoding="utf-8", errors="ignore").strip().split()[0].lower()
            if len(expected) == 64:
                actual = hashlib.sha256(resolved.read_bytes()).hexdigest().lower()
                if not secrets.compare_digest(expected, actual):
                    return False
        except (OSError, IndexError):
            return False
    return True


def _modinfo_vermagic(ko_path: Path) -> str:
    if not shutil.which("modinfo"):
        return ""
    try:
        cp = subprocess.run(
            ["modinfo", "-F", "vermagic", str(ko_path)],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return (cp.stdout or "").strip()
    except OSError:
        return ""


def _vermagic_matches(vermagic: str, kernel_release: str) -> bool:
    return bool(vermagic) and (vermagic.startswith(kernel_release + " ") or vermagic == kernel_release)


def find_lkm_object(root: Path | None = None, kernel_release: str | None = None) -> Path | None:
    """Locate trusted mc_ss_kmod.ko, preferring exact running kernel vermagic & versioned caches."""
    rel = kernel_release or os.uname().release
    base = root if root is not None else _bundle_root()
    if root is not None:
        candidates = [
            base / "kernel" / "prebuilt" / rel / "mc_ss_kmod.ko",
            base / "kernel" / "mc_ss_kmod.ko",
        ]
    else:
        repo_root = Path(__file__).resolve().parent.parent
        inv_share = _invoker_home() / ".local" / "share" / "mc-ss-sentinel"
        sys_share = Path("/usr/local/share/mc-ss-sentinel")
        candidates = [
            base / "kernel" / "prebuilt" / rel / "mc_ss_kmod.ko",
            repo_root / "kernel" / "prebuilt" / rel / "mc_ss_kmod.ko",
            inv_share / "kmods" / rel / "mc_ss_kmod.ko",
            sys_share / "kmods" / rel / "mc_ss_kmod.ko",
            base / "kernel" / "mc_ss_kmod.ko",
            repo_root / "kernel" / "mc_ss_kmod.ko",
            inv_share / "mc_ss_kmod.ko",
            sys_share / "mc_ss_kmod.ko",
        ]
    trusted: list[Path] = []
    seen_real: set[Path] = set()
    for c in candidates:
        try:
            rp = c.resolve(strict=True)
        except OSError:
            continue
        if rp in seen_real:
            continue
        seen_real.add(rp)
        if _is_trusted_artifact(c, require_exec=False):
            trusted.append(c)

    if not trusted:
        return None
    for c in trusted:
        if _vermagic_matches(_modinfo_vermagic(c), rel):
            return c
    return trusted[0]


def _kdir_uses_clang(kdir: Path) -> bool:
    cfg = kdir / ".config"
    txt = _read_text_safe(cfg)
    if not txt:
        return False
    return any(
        line.strip() in ("CONFIG_CC_IS_CLANG=y", "CONFIG_LTO_CLANG_THIN=y", "CONFIG_LTO_CLANG_FULL=y")
        for line in txt.splitlines()
    )


def verify_kernel_sources(ksrc_dir: Path) -> tuple[bool, str]:
    """Verify integrity of kernel module sources against pinned kernel_sources.sha256."""
    manifest = ksrc_dir / "kernel_sources.sha256"
    if not manifest.is_file() or not _is_trusted_artifact(manifest, require_exec=False):
        return False, "Missing or untrusted kernel_sources.sha256 manifest."
    expected: dict[str, str] = {}
    for line in _read_text_safe(manifest).splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and len(parts[0]) == 64:
            expected[Path(parts[1]).name] = parts[0].lower()
    required = ("mc_ss_kmod.c", "mc_ss_kmod.h", "Makefile")
    for fname in required:
        if fname not in expected:
            return False, f"Incomplete kernel_sources.sha256 (missing {fname})."
        fpath = ksrc_dir / fname
        if not fpath.is_file() or not _is_trusted_artifact(fpath, require_exec=False):
            return False, f"Untrusted or missing kernel source file: {fname}"
        try:
            actual = hashlib.sha256(fpath.read_bytes()).hexdigest().lower()
        except OSError as exc:
            return False, f"Failed reading {fname}: {exc}"
        if not secrets.compare_digest(expected[fname], actual):
            return False, f"SHA-256 mismatch on kernel source {fname}."
    return True, "ok"


def ensure_or_build_lkm_for_running_kernel(
    root: Path | None = None,
    kernel_release: str | None = None,
    root_prefix: Path = Path("/"),
    target_os: str = "auto",
) -> dict[str, Any]:
    """Return vermagic-matched mc_ss_kmod.ko or compile & cache it cleanly from verified sources."""
    rel = kernel_release or os.uname().release
    profile, _ = resolve_profile(target_os=target_os, root_prefix=root_prefix)
    existing = find_lkm_object(root=root, kernel_release=rel)
    if existing and _vermagic_matches(_modinfo_vermagic(existing), rel):
        return {"ok": True, "built": False, "lkm_path": str(existing), "needs_llvm": False, "reason": "matched"}

    kdir = root_prefix / "lib" / "modules" / rel / "build"
    needs_llvm = _kdir_uses_clang(kdir)
    hint = format_kernel_headers_install_hint(profile.target_id, rel, needs_llvm=needs_llvm)
    if not kdir.is_dir() or not (kdir / "Makefile").exists():
        return {
            "ok": False,
            "built": False,
            "lkm_path": None,
            "needs_llvm": needs_llvm,
            "reason": f"Kernel build headers missing at {kdir}",
            "headers_hint": hint,
        }

    base = root if root is not None else _bundle_root()
    repo_ksrc = Path(__file__).resolve().parent.parent / "kernel"
    ksrc_dir = next((d for d in (base / "kernel", repo_ksrc) if (d / "mc_ss_kmod.c").is_file()), None)
    if ksrc_dir is None:
        return {"ok": False, "built": False, "lkm_path": None, "needs_llvm": needs_llvm, "reason": "Kernel C sources not found.", "headers_hint": hint}

    ok_src, src_msg = verify_kernel_sources(ksrc_dir)
    if not ok_src:
        return {"ok": False, "built": False, "lkm_path": None, "needs_llvm": needs_llvm, "reason": src_msg, "headers_hint": hint}

    if not shutil.which("make"):
        return {"ok": False, "built": False, "lkm_path": None, "needs_llvm": needs_llvm, "reason": "'make' tool missing.", "headers_hint": hint}
    if needs_llvm and not shutil.which("clang"):
        return {"ok": False, "built": False, "lkm_path": None, "needs_llvm": True, "reason": "Kernel requires Clang/LLVM (LLVM=1) but 'clang' is not installed.", "headers_hint": hint}
    if not needs_llvm and not (shutil.which("gcc") or shutil.which("cc")):
        return {"ok": False, "built": False, "lkm_path": None, "needs_llvm": False, "reason": "'gcc' compiler missing.", "headers_hint": hint}

    tmp_dir = Path(tempfile.mkdtemp(prefix="mc_ss_kbuild_"))
    try:
        os.chmod(tmp_dir, 0o700)
        for fname in ("mc_ss_kmod.c", "mc_ss_kmod.h", "Makefile"):
            shutil.copy2(ksrc_dir / fname, tmp_dir / fname)
        make_cmd = ["make", "-C", str(kdir), f"M={tmp_dir}"]
        if needs_llvm:
            make_cmd.append("LLVM=1")
        make_cmd.append("modules")
        cp = subprocess.run(make_cmd, capture_output=True, text=True, timeout=120, check=False)
        built_ko = tmp_dir / "mc_ss_kmod.ko"
        if cp.returncode != 0 or not built_ko.is_file():
            err = (cp.stderr or cp.stdout or f"make rc={cp.returncode}").strip()
            comp_m = re.search(r"\b(gcc-\d+|clang-\d+|clang)\s*:\s*not found\b", err)
            if comp_m:
                missing_cc = comp_m.group(1)
                if profile.pkg_family == "deb":
                    hint = f"{hint} && sudo apt-get install -y {missing_cc}"
                else:
                    hint = f"{hint} (eksik derleyici: {missing_cc})"
            return {"ok": False, "built": False, "lkm_path": None, "needs_llvm": needs_llvm, "reason": f"Kbuild compile failed: {err[-400:]}", "headers_hint": hint}

        cache_dir = _invoker_home() / ".local" / "share" / "mc-ss-sentinel" / "kmods" / rel
        cache_dir.mkdir(parents=True, exist_ok=True)
        dest_ko = cache_dir / "mc_ss_kmod.ko"
        shutil.copy2(built_ko, dest_ko)
        os.chmod(dest_ko, 0o644)
        digest = hashlib.sha256(dest_ko.read_bytes()).hexdigest()
        dest_sha = cache_dir / "mc_ss_kmod.ko.sha256"
        dest_sha.write_text(f"{digest}\n", encoding="utf-8")
        os.chmod(dest_sha, 0o644)
        return {
            "ok": True,
            "built": True,
            "lkm_path": str(dest_ko),
            "needs_llvm": needs_llvm,
            "vermagic": _modinfo_vermagic(dest_ko),
            "reason": "compiled_and_cached",
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "built": False, "lkm_path": None, "needs_llvm": needs_llvm, "reason": str(exc), "headers_hint": hint}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def find_native_probe(root: Path | None = None) -> Path | None:
    """Locate compiled C ss_kernel_probe binary cleanly."""
    base = root if root is not None else _bundle_root()
    candidates = [
        base / "native" / "ss_kernel_probe",
        Path(__file__).resolve().parent.parent / "native" / "ss_kernel_probe",
        _invoker_home() / ".local" / "share" / "mc-ss-sentinel" / "ss_kernel_probe",
        Path("/usr/local/share/mc-ss-sentinel/ss_kernel_probe"),
    ]
    for c in candidates:
        if c.is_file() and _is_trusted_artifact(c, require_exec=True):
            return c
    return None


def _read_text_safe(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return ""


def detect_cpu_vendor(root_prefix: Path = Path("/"), proc_root: Path | None = None) -> str:
    pr = proc_root if proc_root is not None else (root_prefix / "proc")
    txt = _read_text_safe(pr / "cpuinfo")
    if "AuthenticAMD" in txt:
        return "AMD"
    if "GenuineIntel" in txt:
        return "Intel"
    return "Unknown"


def inspect_iommu_compliance(
    root_prefix: Path = Path("/"),
    proc_root: Path | None = None,
) -> dict[str, Any]:
    """Inspect real hardware ACPI DMAR/IVRS tables, active IOMMU groups, and cmdline posture."""
    pr = proc_root if proc_root is not None else (root_prefix / "proc")
    cmdline = _read_text_safe(pr / "cmdline")
    cpu_vendor = detect_cpu_vendor(root_prefix=root_prefix, proc_root=pr)
    acpi_dir = root_prefix / "sys" / "firmware" / "acpi" / "tables"
    class_iommu = root_prefix / "sys" / "class" / "iommu"
    groups_dir = root_prefix / "sys" / "kernel" / "iommu_groups"

    dmar_present = (acpi_dir / "DMAR").exists()
    ivrs_present = (acpi_dir / "IVRS").exists()

    try:
        iommu_hw_units = [p.name for p in class_iommu.iterdir()] if class_iommu.is_dir() else []
    except OSError:
        iommu_hw_units = []
    try:
        iommu_groups = [p.name for p in groups_dir.iterdir()] if groups_dir.is_dir() else []
    except OSError:
        iommu_groups = []

    tokens = set(cmdline.split())
    passthrough_on = any(
        t.startswith("iommu.passthrough=1") or t in ("iommu=pt", "iommu.passthrough=on")
        for t in tokens
    )
    forced_off = any(
        t in (
            "iommu=off",
            "intel_iommu=off",
            "amd_iommu=off",
            "intel_iommu=0",
            "amd_iommu=0",
            "iommu=nopt",
        )
        for t in tokens
    )
    acs_override = any("pcie_acs_override" in t for t in tokens)
    strict_disabled = "iommu.strict=0" in tokens
    strict_enabled = ("iommu.strict=1" in tokens) and not strict_disabled

    recommended_args: list[str] = []
    if cpu_vendor == "Intel" and "intel_iommu=on" not in tokens:
        recommended_args.append("intel_iommu=on")
    elif cpu_vendor == "AMD" and "amd_iommu=on" not in tokens:
        recommended_args.append("amd_iommu=on")
    if "iommu=force" not in tokens:
        recommended_args.append("iommu=force")
    if not strict_enabled:
        recommended_args.append("iommu.strict=1")
    if "iommu.passthrough=0" not in tokens:
        recommended_args.append("iommu.passthrough=0")

    is_ostree = "ostree=" in cmdline or (root_prefix / "run" / "ostree-booted").exists()

    return {
        "cpu_vendor": cpu_vendor,
        "cmdline": cmdline,
        "acpi_dmar_present": dmar_present,
        "acpi_ivrs_present": ivrs_present,
        "iommu_hw_units": iommu_hw_units,
        "iommu_group_count": len(iommu_groups),
        "iommu_active": bool(iommu_hw_units or iommu_groups),
        "passthrough_enabled": passthrough_on,
        "forced_off": forced_off,
        "acs_override": acs_override,
        "strict_disabled": strict_disabled,
        "strict_enabled": strict_enabled,
        "is_ostree": is_ostree,
        "recommended_kargs": recommended_args,
    }


def check_kernel_prereqs(
    root_prefix: Path = Path("/"),
    proc_root: Path | None = None,
    target_os: str = "auto",
) -> dict[str, Any]:
    """Evaluate host kernel & header capability for Ring-0 LKM audit cleanly (zero mutations)."""
    rel = os.uname().release
    profile, host = resolve_profile(target_os=target_os, root_prefix=root_prefix)
    pr = proc_root if proc_root is not None else (root_prefix / "proc")
    lockdown_raw = _read_text_safe(root_prefix / "sys" / "kernel" / "security" / "lockdown")
    modules_disabled = _read_text_safe(pr / "sys" / "kernel" / "modules_disabled")
    unpriv_bpf = _read_text_safe(pr / "sys" / "kernel" / "unprivileged_bpf_disabled")
    kptr_restrict = _read_text_safe(pr / "sys" / "kernel" / "kptr_restrict")

    lockdown_mode = "unknown"
    m = re.search(r"\[([^\]]+)\]", lockdown_raw)
    if m:
        lockdown_mode = m.group(1)

    ko_path = find_lkm_object(kernel_release=rel)
    probe_path = find_native_probe()

    ko_vermagic = _modinfo_vermagic(ko_path) if ko_path else ""
    ko_vermagic_ok = _vermagic_matches(ko_vermagic, rel)
    kdir = root_prefix / "lib" / "modules" / rel / "build"
    headers_present = kdir.is_dir() and (kdir / "Makefile").exists()
    needs_llvm = _kdir_uses_clang(kdir)
    headers_hint = format_kernel_headers_install_hint(profile.target_id, rel, needs_llvm=needs_llvm)

    return {
        "kernel_release": rel,
        "target_os": profile.target_id,
        "target_display_name": profile.display_name,
        "host_os": host.target_id,
        "host_pretty_name": host.pretty_name,
        "is_immutable": profile.is_immutable,
        "headers_present": headers_present,
        "needs_llvm": needs_llvm,
        "headers_install_hint": headers_hint,
        "clang_available": shutil.which("clang") is not None,
        "gcc_available": shutil.which("gcc") is not None or shutil.which("cc") is not None,
        "lockdown_mode": lockdown_mode,
        "modules_disabled": modules_disabled or "unknown",
        "unprivileged_bpf_disabled": unpriv_bpf or "unknown",
        "kptr_restrict": kptr_restrict or "unknown",
        "lkm_path": str(ko_path) if ko_path else None,
        "lkm_vermagic": ko_vermagic,
        "lkm_vermagic_match": ko_vermagic_ok,
        "native_probe_path": str(probe_path) if probe_path else None,
        "pkexec_available": shutil.which("pkexec") is not None,
        "is_root": os.geteuid() == 0,
    }


def _collect_root_extras(probe_bin: Path | None) -> dict[str, Any]:
    """Collect root-level eBPF, ftrace, kprobe, auditd, PCI config, and dmesg telemetry."""
    out: dict[str, Any] = {}

    if probe_bin and probe_bin.is_file():
        try:
            cp = subprocess.run(
                [str(probe_bin), "all"],
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
            if cp.stdout.strip():
                out["native_probe"] = json.loads(cp.stdout)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            out["native_probe_error"] = str(exc)

    for key, p in (
        ("kprobes_list", Path("/sys/kernel/debug/kprobes/list")),
        ("ftrace_enabled_functions", Path("/sys/kernel/tracing/enabled_functions")),
        ("ftrace_filter", Path("/sys/kernel/tracing/set_ftrace_filter")),
    ):
        try:
            if p.is_file():
                lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                out[key] = lines[:400]
        except OSError:
            pass

    if shutil.which("dmesg"):
        try:
            cp = subprocess.run(
                ["dmesg", "-T", "--color=never"],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            if cp.returncode == 0 and cp.stdout:
                out["dmesg_tail"] = cp.stdout.splitlines()[-500:]
        except (OSError, subprocess.SubprocessError):
            pass

    if shutil.which("ausearch"):
        try:
            cp = subprocess.run(
                ["ausearch", "-m", "SYSCALL", "-ts", "today", "-i"],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            if cp.stdout:
                out["audit_syscalls_tail"] = cp.stdout.splitlines()[-300:]
        except (OSError, subprocess.SubprocessError):
            pass

    bpf_fs = Path("/sys/fs/bpf")
    if bpf_fs.is_dir():
        try:
            pinned: list[str] = []
            for entry in sorted(bpf_fs.rglob("*")):
                pinned.append(str(entry))
                if len(pinned) >= 300:
                    break
            out["bpf_pinned"] = pinned
        except OSError:
            pass

    return out


def _rmmod_cleanly(mod_name: str = "mc_ss_kmod") -> bool:
    """Deterministic rmmod with brief refcount drain retry."""
    if not Path(f"/sys/module/{mod_name}").exists():
        return True
    rmmod_bin = shutil.which("rmmod") or "/usr/sbin/rmmod"
    for _ in range(10):
        try:
            cp = subprocess.run(
                [rmmod_bin, mod_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if cp.returncode == 0 or not Path(f"/sys/module/{mod_name}").exists():
                return True
        except (OSError, subprocess.SubprocessError):
            pass
        time.sleep(0.08)
    return not Path(f"/sys/module/{mod_name}").exists()


def execute_kernel_snapshot_helper(
    trace_window_ms: int = 1500,
    lkm_override: Path | None = None,
    probe_override: Path | None = None,
    target_os: str = "auto",
) -> dict[str, Any]:
    """
    Runs with root privileges:
      1. Cleans up any stale leftover mc_ss_kmod
      2. Resolves matching mc_ss_kmod.ko or compiles & caches it cleanly on-target
      3. Loads mc_ss_kmod.ko with ephemeral nonce + trace window
      4. Collects /proc/mc_ss_sentinel/{status,integrity,tasks_vma,pci_iommu,events}
      5. Collects native eBPF/kprobe/ftrace/audit/dmesg data
      6. Guaranteed `finally:` rmmod + unload verification
    """
    if os.geteuid() != 0:
        return {"ok": False, "error": "Helper requires root privileges (euid != 0)."}

    prereqs = check_kernel_prereqs(target_os=target_os)
    ko_path = lkm_override if lkm_override is not None else find_lkm_object()
    probe_path = probe_override if probe_override is not None else find_native_probe()
    if ko_path is not None and not _is_trusted_artifact(ko_path, require_exec=False):
        ko_path = None
    if probe_path is not None and not _is_trusted_artifact(probe_path, require_exec=True):
        probe_path = None

    build_attempt: dict[str, Any] | None = None
    if lkm_override is None and prereqs["modules_disabled"] != "1" and (ko_path is None or not prereqs["lkm_vermagic_match"]):
        build_attempt = ensure_or_build_lkm_for_running_kernel(target_os=target_os)
        if build_attempt.get("ok") and build_attempt.get("lkm_path"):
            cand = Path(build_attempt["lkm_path"])
            if _is_trusted_artifact(cand, require_exec=False):
                ko_path = cand
                prereqs["lkm_path"] = str(cand)
                prereqs["lkm_vermagic"] = build_attempt.get("vermagic") or _modinfo_vermagic(cand)
                prereqs["lkm_vermagic_match"] = _vermagic_matches(prereqs["lkm_vermagic"], prereqs["kernel_release"])

    result: dict[str, Any] = {
        "ok": True,
        "prereqs": prereqs,
        "lkm_attempted": False,
        "lkm_loaded": False,
        "lkm_unloaded_cleanly": True,
        "lkm_error": "",
        "lkm_build_attempt": build_attempt,
        "session_nonce": "",
        "proc_snapshots": {},
        "root_extras": {},
    }

    # Pre-clean any stray module from previous interrupted session
    _rmmod_cleanly("mc_ss_kmod")

    # Handle termination signals so driver still unloads cleanly on cancel
    def _on_sig(_signum: int, _frame: Any) -> None:
        _rmmod_cleanly("mc_ss_kmod")
        raise KeyboardInterrupt("Kernel helper interrupted")

    is_main_thread = threading.current_thread() is threading.main_thread()
    prev_int: Any = None
    prev_term: Any = None
    if is_main_thread:
        prev_int = signal.signal(signal.SIGINT, _on_sig)
        prev_term = signal.signal(signal.SIGTERM, _on_sig)

    try:
        # Always collect root-level eBPF / audit / kprobe / PCI even if .ko cannot load
        result["root_extras"] = _collect_root_extras(probe_path)

        if ko_path and ko_path.is_file():
            result["lkm_attempted"] = True
            ko_vermagic = prereqs["lkm_vermagic"]
            ko_vermagic_ok = prereqs["lkm_vermagic_match"]
            if lkm_override is not None and shutil.which("modinfo"):
                try:
                    cp_mi = subprocess.run(
                        ["modinfo", "-F", "vermagic", str(ko_path)],
                        capture_output=True,
                        text=True,
                        timeout=3,
                        check=False,
                    )
                    ko_vermagic = (cp_mi.stdout or "").strip()
                    rel_k = prereqs["kernel_release"]
                    ko_vermagic_ok = ko_vermagic.startswith(rel_k + " ") or ko_vermagic == rel_k
                except OSError:
                    ko_vermagic_ok = False
            if prereqs["modules_disabled"] == "1":
                result["lkm_error"] = "kernel.modules_disabled=1 (modül yükleme kilitli)."
            elif not ko_vermagic_ok:
                result["lkm_error"] = (
                    f"Kernel vermagic uyumsuz: running={prereqs['kernel_release']}, "
                    f"ko={ko_vermagic}"
                )
            else:
                nonce = secrets.token_hex(8)
                result["session_nonce"] = nonce
                insmod_bin = shutil.which("insmod") or "/usr/sbin/insmod"
                clamped_ms = max(100, min(5000, int(trace_window_ms)))
                try:
                    cp = subprocess.run(
                        [
                            insmod_bin,
                            str(ko_path),
                            f"session_nonce={nonce}",
                            "enable_live_probes=1",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=8,
                        check=False,
                    )
                    if cp.returncode != 0:
                        result["lkm_error"] = (cp.stderr or cp.stdout or f"insmod rc={cp.returncode}").strip()
                    else:
                        result["lkm_loaded"] = True
                        time.sleep(clamped_ms / 1000.0)
                        proc_base = Path("/proc/mc_ss_sentinel")
                        pids_before = {
                            int(p.name)
                            for p in Path("/proc").iterdir()
                            if p.name.isdigit()
                        }
                        for node in ("status", "integrity", "tasks_vma", "pci_iommu", "events"):
                            np = proc_base / node
                            try:
                                result["proc_snapshots"][node] = np.read_text(
                                    encoding="utf-8", errors="ignore"
                                )
                            except OSError as exc:
                                result["proc_snapshots"][node] = f"READ_ERR|{exc}"
                        pids_after = {
                            int(p.name)
                            for p in Path("/proc").iterdir()
                            if p.name.isdigit()
                        }
                        if isinstance(result.get("root_extras"), dict):
                            result["root_extras"]["proc_pids_at_lkm"] = sorted(
                                pids_before | pids_after
                            )
                finally:
                    unloaded = _rmmod_cleanly("mc_ss_kmod")
                    result["lkm_unloaded_cleanly"] = unloaded
                    if not unloaded:
                        result["lkm_error"] = (result["lkm_error"] + " | rmmod verification failed").strip(" |")
        else:
            hint = ""
            if isinstance(build_attempt, dict):
                reason = build_attempt.get("reason", "")
                hdr_hint = build_attempt.get("headers_hint", "")
                hint = f" ({reason}; kurulum: {hdr_hint})" if hdr_hint else f" ({reason})"
            result["lkm_error"] = f"Derlenmis mc_ss_kmod.ko bulunamadi{hint}."
    finally:
        if is_main_thread:
            signal.signal(signal.SIGINT, prev_int)
            signal.signal(signal.SIGTERM, prev_term)

    return result


def collect_privileged_kernel_snapshot(
    trace_window_ms: int = 1500,
    allow_pkexec: bool = True,
    target_os: str = "auto",
) -> dict[str, Any]:
    """
    Acquire full Ring-0 + eBPF + root forensic snapshot from either current root context
    or a single sanctioned pkexec elevation invocation. Always cleans up kernel driver on return.
    """
    if os.geteuid() == 0:
        return execute_kernel_snapshot_helper(trace_window_ms=trace_window_ms, target_os=target_os)

    if not allow_pkexec:
        return {"ok": False, "declined": True, "error": "Elevated Ring-0 scan disabled by caller."}

    pkexec_bin = shutil.which("pkexec")
    if not pkexec_bin:
        return {"ok": False, "declined": True, "error": "pkexec bulunamadi; root yetkisi alinamadi."}

    clamped_ms = max(100, min(5000, int(trace_window_ms)))
    if getattr(sys, "frozen", False):
        cmd = [pkexec_bin, sys.executable, "--kernel-snapshot-helper", "--trace-ms", str(clamped_ms)]
    else:
        entry = Path(__file__).resolve().parent.parent / "ss_sentinel.py"
        cmd = [
            pkexec_bin,
            sys.executable,
            str(entry),
            "--kernel-snapshot-helper",
            "--trace-ms",
            str(clamped_ms),
        ]
    if target_os and target_os != "auto":
        cmd.extend(["--target-os", target_os])

    try:
        cp = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if cp.returncode == 126 or cp.returncode == 127:
            return {
                "ok": False,
                "declined": True,
                "error": f"Kullanici Polkit (pkexec) yetki onayini iptal etti (rc={cp.returncode}).",
            }
        if cp.returncode != 0:
            err_txt = (cp.stderr or "").strip() or f"pkexec helper rc={cp.returncode}"
            return {"ok": False, "declined": True, "error": err_txt}
        data = json.loads(cp.stdout)
        if isinstance(data, dict):
            return data
        return {"ok": False, "error": "Gecersiz helper JSON ciktisi."}
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": f"Yetkili helper hatasi: {exc}"}


def _merge_cmdline_tokens(existing: str, add_args: list[str], remove_args: list[str]) -> str:
    rm = set(remove_args)
    kept = [tok for tok in existing.split() if tok not in rm]
    seen = set(kept)
    for arg in add_args:
        if arg not in seen:
            kept.append(arg)
            seen.add(arg)
    return " ".join(kept)


def update_grub_default_content(text: str, add_args: list[str], remove_args: list[str]) -> str:
    pattern = re.compile(r'^([ \t]*GRUB_CMDLINE_LINUX_DEFAULT=)(["\'])(.*?)\2([ \t]*(?:#.*)?)$', re.MULTILINE)
    m = pattern.search(text)
    if m:
        merged = _merge_cmdline_tokens(m.group(3), add_args, remove_args)
        replacement = f'{m.group(1)}"{merged}"{m.group(4)}'
        return text[: m.start()] + replacement + text[m.end() :]
    merged = _merge_cmdline_tokens("", add_args, remove_args)
    suffix = "\n" if text and not text.endswith("\n") else ""
    return f'{text}{suffix}GRUB_CMDLINE_LINUX_DEFAULT="{merged}"\n'


def update_systemd_boot_entry_content(text: str, add_args: list[str], remove_args: list[str]) -> str:
    lines = text.splitlines(keepends=True)
    updated = False
    out_lines: list[str] = []
    for ln in lines:
        m = re.match(r'^([ \t]*options[ \t]+)(.*?)(\r?\n?)$', ln)
        if m:
            merged = _merge_cmdline_tokens(m.group(2), add_args, remove_args)
            out_lines.append(f"{m.group(1)}{merged}{m.group(3)}")
            updated = True
        else:
            out_lines.append(ln)
    if not updated:
        merged = _merge_cmdline_tokens("", add_args, remove_args)
        if out_lines and not out_lines[-1].endswith("\n"):
            out_lines.append("\n")
        out_lines.append(f"options {merged}\n")
    return "".join(out_lines)


def update_sdboot_manage_content(text: str, add_args: list[str], remove_args: list[str]) -> str:
    pattern = re.compile(r'^([ \t]*LINUX_OPTIONS=)(["\'])(.*?)\2([ \t]*(?:#.*)?)$', re.MULTILINE)
    m = pattern.search(text)
    if m:
        merged = _merge_cmdline_tokens(m.group(3), add_args, remove_args)
        replacement = f'{m.group(1)}"{merged}"{m.group(4)}'
        return text[: m.start()] + replacement + text[m.end() :]
    merged = _merge_cmdline_tokens("", add_args, remove_args)
    suffix = "\n" if text and not text.endswith("\n") else ""
    return f'{text}{suffix}LINUX_OPTIONS="{merged}"\n'


def update_limine_default_content(text: str, add_args: list[str], remove_args: list[str]) -> str:
    pattern = re.compile(r'^([ \t]*KERNEL_CMDLINE\[default\]\+?=[ \t]*)(["\'])(.*?)\2([ \t]*(?:#.*)?)$', re.MULTILINE)
    m = pattern.search(text)
    if m:
        merged = _merge_cmdline_tokens(m.group(3), add_args, remove_args)
        replacement = f'{m.group(1)}"{merged}"{m.group(4)}'
        return text[: m.start()] + replacement + text[m.end() :]
    merged = _merge_cmdline_tokens("", add_args, remove_args)
    suffix = "\n" if text and not text.endswith("\n") else ""
    return f'{text}{suffix}KERNEL_CMDLINE[default]+="{merged}"\n'


def detect_bootloader_strategy(
    root_prefix: Path = Path("/"),
    target_os: str = "auto",
    is_ostree: bool = False,
) -> tuple[str, dict[str, Any]]:
    """Identify the active Linux bootloader & config file layout for IOMMU enforcement."""
    profile, host = resolve_profile(target_os=target_os, root_prefix=root_prefix)
    explicit = bool(target_os and target_os not in ("auto", "host"))
    if profile.target_id == "bazzite" or (is_ostree and not explicit):
        return "rpm_ostree", {"profile": profile.target_id, "can_auto_apply": True}
    if profile.target_id == "steamos" or (host.is_steamos and not explicit):
        return "steamos_readonly", {
            "profile": profile.target_id,
            "can_auto_apply": False,
            "reason": "SteamOS 3 uses an immutable Valve A/B rootfs; verify VT-d / AMD-Vi / IOMMU in UEFI Setup instead of modifying A/B GRUB.",
        }
    if (root_prefix / "usr/bin/kernelstub").exists() or (
        root_prefix == Path("/") and shutil.which("kernelstub") is not None and host.os_id == "pop"
    ):
        return "kernelstub", {"profile": profile.target_id, "can_auto_apply": True}

    if profile.target_id == "fedora_nobara":
        return "grubby", {"profile": profile.target_id, "can_auto_apply": True}

    if profile.family == "debian_ubuntu":
        return "grub_update", {
            "profile": profile.target_id,
            "grub_default": str(root_prefix / "etc/default/grub"),
            "can_auto_apply": True,
        }

    limine_default = root_prefix / "etc/default/limine"
    limine_conf = next(
        (p for p in (root_prefix / "boot/limine.conf", root_prefix / "boot/limine/limine.conf") if p.is_file()),
        None,
    )
    if limine_default.is_file() or limine_conf is not None:
        return "limine", {
            "profile": profile.target_id,
            "limine_default": str(limine_default) if limine_default.is_file() else "",
            "limine_conf": str(limine_conf) if limine_conf else "",
            "can_auto_apply": limine_default.is_file(),
        }

    for esp in (root_prefix / "boot", root_prefix / "efi", root_prefix / "boot/efi"):
        if (esp / "loader/loader.conf").is_file():
            entries_dir = esp / "loader/entries"
            entries = sorted(p for p in entries_dir.glob("*.conf") if not p.name.endswith("-fallback.conf")) if entries_dir.is_dir() else []
            if not entries and entries_dir.is_dir():
                entries = sorted(entries_dir.glob("*.conf"))
            sdboot_manage = root_prefix / "etc/sdboot-manage.conf"
            return "systemd_boot", {
                "profile": profile.target_id,
                "esp_root": str(esp),
                "entries": [str(p) for p in entries],
                "sdboot_manage": str(sdboot_manage) if sdboot_manage.is_file() else "",
                "can_auto_apply": bool(entries or sdboot_manage.is_file()),
            }

    if profile.target_id == "arch_cachyos":
        grub_cfg = (
            "/boot/grub2/grub.cfg"
            if (root_prefix / "boot/grub2/grub.cfg").is_file() and not (root_prefix / "boot/grub/grub.cfg").is_file()
            else "/boot/grub/grub.cfg"
        )
        return "grub_mkconfig", {
            "profile": profile.target_id,
            "grub_default": str(root_prefix / "etc/default/grub"),
            "grub_cfg": grub_cfg,
            "can_auto_apply": True,
        }

    return "grub_update", {
        "profile": profile.target_id,
        "grub_default": str(root_prefix / "etc/default/grub"),
        "can_auto_apply": True,
    }


def build_iommu_hardening_plan(
    root_prefix: Path = Path("/"),
    proc_root: Path | None = None,
    target_os: str = "auto",
) -> dict[str, Any]:
    """Generate an explicit, reversible, user-approved distro-aware IOMMU enforcement plan."""
    comp = inspect_iommu_compliance(root_prefix=root_prefix, proc_root=proc_root)
    profile, _ = resolve_profile(target_os=target_os, root_prefix=root_prefix)
    args = comp["recommended_kargs"]
    if (
        not args
        and comp["iommu_active"]
        and not comp["passthrough_enabled"]
        and not comp["forced_off"]
        and not comp.get("strict_disabled")
    ):
        return {
            "needed": False,
            "bootloader": "none",
            "target_os": profile.target_id,
            "can_auto_apply": False,
            "summary": "IOMMU ve katı DMA izolasyonu halihazırda etkin.",
            "commands": [],
            "compliance": comp,
        }

    bad_flags = [
        f
        for f in (
            "iommu=off",
            "intel_iommu=off",
            "amd_iommu=off",
            "intel_iommu=0",
            "amd_iommu=0",
            "iommu=pt",
            "iommu=nopt",
            "iommu.passthrough=1",
            "iommu.passthrough=on",
            "iommu.strict=0",
        )
        if f in comp["cmdline"].split()
    ]

    strategy, meta = detect_bootloader_strategy(
        root_prefix=root_prefix,
        target_os=target_os,
        is_ostree=bool(comp["is_ostree"]),
    )
    commands: list[list[str]] = []
    if strategy == "rpm_ostree":
        cmd = ["rpm-ostree", "kargs"]
        for bf in bad_flags:
            cmd.append(f"--delete-if-present={bf}")
        for ka in args:
            cmd.append(f"--append-if-missing={ka}")
        commands = [cmd]
    elif strategy == "grubby":
        cmd = ["grubby", "--update-kernel=ALL"]
        if bad_flags:
            cmd.append(f"--remove-args={' '.join(bad_flags)}")
        if args:
            cmd.append(f"--args={' '.join(args)}")
        commands = [cmd]
    elif strategy == "kernelstub":
        for bf in bad_flags:
            commands.append(["kernelstub", "-d", bf])
        if args:
            commands.append(["kernelstub", "-a", " ".join(args)])
    elif strategy == "grub_update":
        commands = [
            ["grub-default-edit", meta["grub_default"], f"ADD={' '.join(args)}"],
            ["update-grub"],
        ]
    elif strategy == "grub_mkconfig":
        commands = [
            ["grub-default-edit", meta["grub_default"], f"ADD={' '.join(args)}"],
            ["grub-mkconfig", "-o", meta["grub_cfg"]],
        ]
    elif strategy == "systemd_boot":
        if meta.get("sdboot_manage"):
            commands = [
                ["sdboot-manage-edit", meta["sdboot_manage"], f"ADD={' '.join(args)}"],
                ["sdboot-manage", "update"],
            ]
        elif meta.get("entries"):
            for ent in meta["entries"]:
                commands.append(["systemd-boot-entry-edit", ent, f"ADD={' '.join(args)}"])
    elif strategy == "limine":
        if meta.get("limine_default"):
            commands = [
                ["limine-default-edit", meta["limine_default"], f"ADD={' '.join(args)}"],
                ["limine-update"],
            ]

    hw_lbl = "DMAR (VT-d)" if comp["acpi_dmar_present"] else "AMD-Vi / IOMMU"
    extra_note = f"\nNot: {meta['reason']}" if meta.get("reason") else ""
    return {
        "needed": True,
        "bootloader": strategy,
        "bootloader_meta": meta,
        "target_os": profile.target_id,
        "target_display_name": profile.display_name,
        "can_auto_apply": bool(meta.get("can_auto_apply", True)),
        "recommended_args": args,
        "remove_args": bad_flags,
        "summary": (
            f"[{profile.display_name} / {strategy}] Donanımda {hw_lbl} tespit edildi; "
            f"DMA saldırılarına karşı çekirdek parametreleriyle katı IOMMU zorlaması eklenebilir "
            f"(Değişiklik yeniden başlatma sonrası aktif olur).{extra_note}"
        ),
        "commands": commands,
        "compliance": comp,
    }


def _write_with_backup(path: Path, new_content: str) -> None:
    if path.exists():
        backup = Path(str(path) + ".mc_ss_sentinel.bak")
        if not backup.exists():
            shutil.copy2(path, backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new_content, encoding="utf-8")


def execute_iommu_hardening_as_root(
    target_os: str = "auto",
    root_prefix: Path = Path("/"),
    proc_root: Path | None = None,
) -> dict[str, Any]:
    """Perform distro-appropriate root bootloader mutation & rebuild when needed."""
    if os.geteuid() != 0 and root_prefix == Path("/"):
        return {"ok": False, "changed": False, "message": "Root yetkisi gerekli."}

    plan = build_iommu_hardening_plan(root_prefix=root_prefix, proc_root=proc_root, target_os=target_os)
    if not plan["needed"]:
        return {"ok": True, "changed": False, "message": plan["summary"], "plan": plan}
    if not plan.get("can_auto_apply"):
        return {
            "ok": False,
            "changed": False,
            "message": plan["summary"],
            "plan": plan,
        }

    strategy = plan["bootloader"]
    args: list[str] = plan.get("recommended_args", [])
    bad_flags: list[str] = plan.get("remove_args", [])
    meta: dict[str, Any] = plan.get("bootloader_meta", {})

    try:
        if strategy in {"rpm_ostree", "grubby", "kernelstub"}:
            outputs: list[str] = []
            for cmd in plan["commands"]:
                if shutil.which(cmd[0]) is None:
                    return {"ok": False, "changed": False, "message": f"Komut bulunamadi: {cmd[0]}"}
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
                if cp.returncode != 0:
                    return {
                        "ok": False,
                        "changed": False,
                        "message": (cp.stderr or cp.stdout or f"{cmd[0]} rc={cp.returncode}").strip(),
                    }
                if cp.stdout.strip():
                    outputs.append(cp.stdout.strip())
            return {
                "ok": True,
                "changed": True,
                "message": "IOMMU DMA koruma parametreleri uygulandı. Etkinleşmesi için bilgisayarı yeniden başlatın.",
                "stdout": "\n".join(outputs),
            }

        if strategy in {"grub_update", "grub_mkconfig"}:
            grub_default = Path(meta.get("grub_default") or (root_prefix / "etc/default/grub"))
            old_txt = _read_text_safe(grub_default)
            new_txt = update_grub_default_content(old_txt, args, bad_flags)
            _write_with_backup(grub_default, new_txt)
            if root_prefix != Path("/"):
                return {"ok": True, "changed": True, "message": f"Dry-root GRUB guncellendi: {grub_default}"}
            if strategy == "grub_update":
                upd = shutil.which("update-grub") or shutil.which("update-grub2")
                if upd:
                    cp = subprocess.run([upd], capture_output=True, text=True, timeout=120, check=False)
                elif shutil.which("grub-mkconfig"):
                    cp = subprocess.run(["grub-mkconfig", "-o", "/boot/grub/grub.cfg"], capture_output=True, text=True, timeout=120, check=False)
                else:
                    return {"ok": False, "changed": False, "message": "update-grub / grub-mkconfig bulunamadi."}
            else:
                mkcfg = shutil.which("grub-mkconfig") or shutil.which("grub2-mkconfig")
                if not mkcfg:
                    return {"ok": False, "changed": False, "message": "grub-mkconfig bulunamadi."}
                cp = subprocess.run([mkcfg, "-o", meta.get("grub_cfg", "/boot/grub/grub.cfg")], capture_output=True, text=True, timeout=120, check=False)
            if cp.returncode != 0:
                return {"ok": False, "changed": False, "message": (cp.stderr or cp.stdout or f"rc={cp.returncode}").strip()}
            return {
                "ok": True,
                "changed": True,
                "message": "GRUB IOMMU DMA koruma parametreleri uygulandı ve yapılandırma yeniden üretildi. Yeniden başlatın.",
                "stdout": cp.stdout.strip(),
            }

        if strategy == "systemd_boot":
            if meta.get("sdboot_manage"):
                cfg = Path(meta["sdboot_manage"])
                _write_with_backup(cfg, update_sdboot_manage_content(_read_text_safe(cfg), args, bad_flags))
                if root_prefix == Path("/") and shutil.which("sdboot-manage"):
                    cp = subprocess.run(["sdboot-manage", "update"], capture_output=True, text=True, timeout=120, check=False)
                    if cp.returncode != 0:
                        return {"ok": False, "changed": False, "message": (cp.stderr or cp.stdout or f"sdboot-manage rc={cp.returncode}").strip()}
            for ent_str in meta.get("entries", []):
                ent = Path(ent_str)
                _write_with_backup(ent, update_systemd_boot_entry_content(_read_text_safe(ent), args, bad_flags))
            return {
                "ok": True,
                "changed": True,
                "message": "systemd-boot IOMMU parametreleri uygulandı. Etkinleşmesi için bilgisayarı yeniden başlatın.",
            }

        if strategy == "limine":
            cfg_str = meta.get("limine_default")
            if not cfg_str:
                return {"ok": False, "changed": False, "message": "Limine varsayilan konfigurasyonu (/etc/default/limine) bulunamadi; manuel ekleyin."}
            cfg = Path(cfg_str)
            _write_with_backup(cfg, update_limine_default_content(_read_text_safe(cfg), args, bad_flags))
            if root_prefix == Path("/") and shutil.which("limine-update"):
                cp = subprocess.run(["limine-update"], capture_output=True, text=True, timeout=120, check=False)
                if cp.returncode != 0:
                    return {"ok": False, "changed": False, "message": (cp.stderr or cp.stdout or f"limine-update rc={cp.returncode}").strip()}
            return {
                "ok": True,
                "changed": True,
                "message": "Limine IOMMU parametreleri uygulandı. Etkinleşmesi için bilgisayarı yeniden başlatın.",
            }

        return {"ok": False, "changed": False, "message": f"Otomatik uygulama desteklenmeyen bootloader: {strategy}"}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "changed": False, "message": str(exc)}


def apply_iommu_hardening(target_os: str = "auto") -> dict[str, Any]:
    """Execute user-confirmed opt-in IOMMU kernel parameter hardening via pkexec (if needed)."""
    plan = build_iommu_hardening_plan(target_os=target_os)
    if not plan["needed"] or (not plan["commands"] and plan.get("can_auto_apply")):
        return {"ok": True, "changed": False, "message": plan["summary"]}
    if not plan.get("can_auto_apply"):
        return {"ok": False, "changed": False, "message": plan["summary"]}

    if os.geteuid() == 0:
        return execute_iommu_hardening_as_root(target_os=target_os)

    pkexec_bin = shutil.which("pkexec")
    if not pkexec_bin:
        return {"ok": False, "changed": False, "message": "Komut bulunamadi: pkexec"}

    strategy = plan["bootloader"]
    if strategy in {"rpm_ostree", "grubby"}:
        cmd = plan["commands"][0]
        if shutil.which(cmd[0]) is None:
            return {"ok": False, "changed": False, "message": f"Komut bulunamadi: {cmd[0]}"}
        exec_cmd = [pkexec_bin] + cmd
    else:
        if getattr(sys, "frozen", False):
            exec_cmd = [pkexec_bin, sys.executable, "--apply-iommu-helper", "--target-os", plan["target_os"]]
        else:
            entry = Path(__file__).resolve().parent.parent / "ss_sentinel.py"
            exec_cmd = [pkexec_bin, sys.executable, str(entry), "--apply-iommu-helper", "--target-os", plan["target_os"]]

    try:
        cp = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=180, check=False)
        if strategy not in {"rpm_ostree", "grubby"} and cp.stdout.strip():
            try:
                parsed = json.loads(cp.stdout)
                if isinstance(parsed, dict) and "ok" in parsed:
                    return parsed
            except json.JSONDecodeError:
                pass
        if cp.returncode == 0:
            return {
                "ok": True,
                "changed": True,
                "message": "IOMMU DMA koruma parametreleri uygulandı. Etkinleşmesi için bilgisayarı yeniden başlatın.",
                "stdout": cp.stdout.strip(),
            }
        return {
            "ok": False,
            "changed": False,
            "message": (cp.stderr or cp.stdout or f"rc={cp.returncode}").strip(),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "changed": False, "message": str(exc)}

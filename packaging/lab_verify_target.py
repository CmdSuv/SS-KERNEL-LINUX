#!/usr/bin/env python3
"""In-container real-time target verification (prebuilt LKM, live C probe, ELF headless scan & IOMMU)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 4:
        print("Usage: lab_verify_target.py <target_id> <work_dir> <out_bin>", file=sys.stderr)
        return 2

    target_id = sys.argv[1]
    work_dir = Path(sys.argv[2]).resolve()
    out_bin = Path(sys.argv[3]).resolve()
    sys.path.insert(0, str(work_dir))

    from ss_core import distro_profiles, priv_helper

    # 1. Verify native C probe execution
    probe = work_dir / "native/ss_kernel_probe"
    cp_probe = subprocess.run([str(probe), "pid_cross"], capture_output=True, text=True, check=False)
    if cp_probe.returncode != 0:
        print(f"[LAB-ERR] ss_kernel_probe failed: rc={cp_probe.returncode} err={cp_probe.stderr}", file=sys.stderr)
        return 1
    pdata = json.loads(cp_probe.stdout)
    assert "pid_cross" in pdata, f"Missing pid_cross in {pdata}"
    print(f"[lab-verify] ss_kernel_probe OK (readdir={pdata['pid_cross']['readdir_count']})")

    # 2. Verify real Kbuild compilation & dynamic ensure_or_build_lkm_for_running_kernel against container /lib/modules/*/build
    built_dirs = sorted(Path("/lib/modules").glob("*/build")) if Path("/lib/modules").is_dir() else []
    kbuilt_checked = 0
    for bdir in built_dirs:
        if not (bdir / "Makefile").is_file():
            continue
        krel = bdir.parent.name
        prebuilt_ko = work_dir / "kernel/prebuilt" / krel / "mc_ss_kmod.ko"
        assert prebuilt_ko.is_file(), f"Missing prebuilt .ko for {krel}"
        cp_mi = subprocess.run(["modinfo", "-F", "vermagic", str(prebuilt_ko)], capture_output=True, text=True, check=False)
        assert cp_mi.returncode == 0 and krel in cp_mi.stdout, f"Bad vermagic for {krel}: {cp_mi.stdout}"

        # Now clear cache and verify on-target dynamic builder works end-to-end on clean tree
        cache_ko = Path.home() / ".local/share/mc-ss-sentinel/kmods" / krel / "mc_ss_kmod.ko"
        if cache_ko.exists():
            shutil.rmtree(cache_ko.parent, ignore_errors=True)
        # Hide prebuilt temporarily by copying work/kernel without prebuilt
        with tempfile.TemporaryDirectory() as td_k:
            fake_root = Path(td_k)
            shutil.copytree(work_dir / "kernel", fake_root / "kernel", ignore=shutil.ignore_patterns("prebuilt", "*.ko"))
            res = priv_helper.ensure_or_build_lkm_for_running_kernel(
                root=fake_root,
                kernel_release=krel,
                root_prefix=Path("/"),
                target_os=target_id,
            )
            assert res.get("ok"), f"Dynamic Kbuild failed for {krel}: {res}"
            print(f"[lab-verify] Dynamic Kbuild OK for {krel}: vermagic={res.get('vermagic')}")
            kbuilt_checked += 1

    assert kbuilt_checked >= 1, f"No container /lib/modules/*/build Kbuild trees verified for {target_id}!"
    print(f"[lab-verify] Verified {kbuilt_checked} container kernel trees with real Kbuild.")

    # 3. Inspect OS detection inside container
    prof, host = distro_profiles.resolve_profile(target_os="auto")
    print(f"[lab-verify] Inside-container OS detection: host={host.target_id} ({host.pretty_name}) profile={prof.target_id}")

    # 4. Run BUILT single-file ELF on realistic adversarial home + Desktop report validation
    with tempfile.TemporaryDirectory() as td_h:
        home = Path(td_h)
        desk = home / "Desktop"
        desk.mkdir(parents=True)
        mods = home / ".minecraft/mods"
        mods.mkdir(parents=True)
        (mods / "wurst-killaura-1.21.jar").write_bytes(b"PK\x03\x04fakejar-wurst-killaura")

        if target_id in {"ubuntu_24_04", "ubuntu_22_04"}:
            snap_ff = home / "snap/firefox/common/.mozilla/firefox/test.default"
            snap_ff.mkdir(parents=True)
            (snap_ff / "places.sqlite").write_bytes(b"SQLite format 3\x00")

        env = os.environ.copy()
        env["QT_QPA_PLATFORM"] = "offscreen"
        env["HOME"] = str(home)
        cp_elf = subprocess.run(
            [
                str(out_bin),
                "--headless-scan",
                "--home-dir",
                str(home),
                "--desktop-dir",
                str(desk),
                "--target-os",
                target_id,
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            check=False,
        )
        if cp_elf.returncode != 0:
            print(f"[LAB-ERR] ELF headless scan failed rc={cp_elf.returncode}\nSTDOUT:\n{cp_elf.stdout}\nSTDERR:\n{cp_elf.stderr}", file=sys.stderr)
            return 1
        txts = list(desk.glob("MC_SS_Raporu_*.txt"))
        assert len(txts) == 1, f"Expected 1 Desktop txt, found {txts}"
        txt = txts[0].read_text(encoding="utf-8")
        assert "wurst-killaura-1.21.jar" in txt, "Built ELF missed cheat jar in Desktop report!"
        assert prof.display_name in txt or distro_profiles.DISTRO_PROFILES[target_id].display_name in txt, "Missing Target OS profile in report!"
        print(f"[lab-verify] Built ELF Desktop report OK ({txts[0].name}, {len(txt)} chars)")

        # 5. Also verify ELF --kernel-snapshot-helper JSON handling cleanly inside container
        cp_kh = subprocess.run(
            [str(out_bin), "--kernel-snapshot-helper", "--trace-ms", "150", "--target-os", target_id],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            check=False,
        )
        kh_json = json.loads(cp_kh.stdout.strip())
        assert isinstance(kh_json, dict) and kh_json.get("ok") is True, f"Helper JSON bad: {kh_json}"
        assert "native_probe" in (kh_json.get("root_extras") or {}), "ELF helper failed to run bundled native probe!"
        print(f"[lab-verify] Built ELF kernel-snapshot-helper OK (native_probe collected, lkm_error={kh_json.get('lkm_error')!r})")

        # 6. Verify real Qt6 / PySide6 GUI dialogs + icons + fonts inside compiled single-file ELF
        cp_gui = subprocess.run(
            [str(out_bin), "--smoke-gui-offscreen", "--target-os", target_id],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )
        if cp_gui.returncode != 0 or "GUI_SMOKE_OK" not in cp_gui.stdout:
            print(
                f"[LAB-ERR] ELF GUI smoke test failed rc={cp_gui.returncode}\n"
                f"STDOUT:\n{cp_gui.stdout}\nSTDERR:\n{cp_gui.stderr}",
                file=sys.stderr,
            )
            return 1
        print(f"[lab-verify] Built ELF Qt6/PySide6 GUI smoke OK ({cp_gui.stdout.strip()})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

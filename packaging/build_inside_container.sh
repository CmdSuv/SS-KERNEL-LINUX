#!/usr/bin/env bash
set -euo pipefail

TARGET_ID="${1:?Usage: build_inside_container.sh <target_id>}"
SRC_DIR="${SRC_DIR:-/src}"
OUT_DIR="${OUT_DIR:-/out/${TARGET_ID}}"
WORK_DIR="/tmp/mc_ss_work_${TARGET_ID}"
PYI_WORK="/tmp/mc_ss_pyi_${TARGET_ID}"

echo "[build] Target OS: ${TARGET_ID}"
rm -rf "${WORK_DIR}" "${PYI_WORK}"
mkdir -p "${WORK_DIR}" "${OUT_DIR}" "${PYI_WORK}"

# Copy project cleanly excluding VCS/build artifacts & target outputs
tar -C "${SRC_DIR}" \
    --exclude="./.git" \
    --exclude="./reports" \
    --exclude="./dist" \
    --exclude="./build" \
    --exclude="./targets" \
    --exclude="./.pytest_cache" \
    --exclude="./__pycache__" \
    --exclude="*/__pycache__" \
    --exclude="*.pyc" \
    --exclude="*.ko" \
    --exclude="*.mod" \
    --exclude="*.mod.c" \
    --exclude="*.o" \
    --exclude=".*.cmd" \
    --exclude="Module.symvers" \
    --exclude="modules.order" \
    -cf - . | tar -C "${WORK_DIR}" -xf -

cd "${WORK_DIR}"

echo "[build] Compiling native/ss_kernel_probe inside ${TARGET_ID} environment..."
make -C native clean
make -C native
sha256sum native/ss_kernel_probe | awk '{print $1}' > native/ss_kernel_probe.sha256

echo "[build] Refreshing kernel_sources.sha256..."
(cd kernel && sha256sum mc_ss_kmod.c mc_ss_kmod.h Makefile > kernel_sources.sha256)

# If matching /lib/modules/*/build exists inside the build container, compile prebuilt versioned .ko modules
PREBUILT_COUNT=0
if [ -d /lib/modules ]; then
    for kbuild in /lib/modules/*/build; do
        if [ -f "${kbuild}/Makefile" ]; then
            krel="$(basename "$(dirname "${kbuild}")")"
            echo "[build] Building prebuilt LKM for container kernel: ${krel}"
            tmp_k="/tmp/kbuild_${krel}"
            rm -rf "${tmp_k}"
            cp -a "${WORK_DIR}/kernel" "${tmp_k}"
            make -C "${tmp_k}" KDIR="${kbuild}"
            mkdir -p "${WORK_DIR}/kernel/prebuilt/${krel}"
            cp "${tmp_k}/mc_ss_kmod.ko" "${WORK_DIR}/kernel/prebuilt/${krel}/mc_ss_kmod.ko"
            sha256sum "${WORK_DIR}/kernel/prebuilt/${krel}/mc_ss_kmod.ko" | awk '{print $1}' \
                > "${WORK_DIR}/kernel/prebuilt/${krel}/mc_ss_kmod.ko.sha256"
            PREBUILT_COUNT=$((PREBUILT_COUNT + 1))
            rm -rf "${tmp_k}"
        fi
    done
fi

echo "${TARGET_ID}" > "${WORK_DIR}/TARGET_OS"

echo "[build] Updating ss_core/_self_manifest.py..."
python3 - <<'PYEOF'
import hashlib
from pathlib import Path

root = Path(".")
py_files = [root / "ss_gui.py", root / "ss_sentinel.py"] + sorted((root / "ss_core").glob("*.py"))
hashes = sorted(
    hashlib.sha256(p.read_bytes()).hexdigest()
    for p in py_files
    if p.name != "_self_manifest.py"
)
probe_sha = (root / "native" / "ss_kernel_probe.sha256").read_text(encoding="utf-8").strip().split()[0].lower()
ksrc_hashes: dict[str, str] = {}
for fn in ("mc_ss_kmod.c", "mc_ss_kmod.h", "Makefile"):
    kp = root / "kernel" / fn
    if kp.is_file():
        ksrc_hashes[fn] = hashlib.sha256(kp.read_bytes()).hexdigest()

lines = [
    '"""SHA-256 manifest of verified MC SS Sentinel Python, C probe, and kernel source files (populated at build time)."""',
    "",
    "from __future__ import annotations",
    "",
    "SELF_PY_SHA256S: frozenset[str] = frozenset({",
]
for h in hashes:
    lines.append(f'    "{h}",')
lines.append("})")
lines.append("")
lines.append(f'NATIVE_PROBE_SHA256: str = "{probe_sha}"')
lines.append("KERNEL_SOURCES_SHA256: dict[str, str] = {")
for k in sorted(ksrc_hashes.keys()):
    lines.append(f'    "{k}": "{ksrc_hashes[k]}",')
lines.append("}")
(root / "ss_core" / "_self_manifest.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
PYEOF

echo "[build] Running unit test suite inside ${TARGET_ID} container..."
QT_QPA_PLATFORM=offscreen PYTHONPATH="${WORK_DIR}" python3 -m unittest discover -s tests

PYI_ADD_DATA=(
    "--add-data" "${WORK_DIR}/assets:assets"
    "--add-data" "${WORK_DIR}/TARGET_OS:."
    "--add-data" "${WORK_DIR}/kernel/mc_ss_kmod.c:kernel"
    "--add-data" "${WORK_DIR}/kernel/mc_ss_kmod.h:kernel"
    "--add-data" "${WORK_DIR}/kernel/Makefile:kernel"
    "--add-data" "${WORK_DIR}/kernel/kernel_sources.sha256:kernel"
    "--add-data" "${WORK_DIR}/native/ss_kernel_probe.sha256:native"
)
if [ -d "${WORK_DIR}/kernel/prebuilt" ]; then
    PYI_ADD_DATA+=("--add-data" "${WORK_DIR}/kernel/prebuilt:kernel/prebuilt")
fi

HIDDEN_IMPORTS=(
    "--hidden-import" "ss_core.distro_profiles"
    "--hidden-import" "ss_core.priv_helper"
    "--hidden-import" "ss_core.models"
    "--hidden-import" "ss_core.orchestrator"
    "--hidden-import" "ss_core.signatures"
    "--hidden-import" "ss_core.utils"
    "--hidden-import" "ss_core._self_manifest"
    "--hidden-import" "ss_core.engine1_integrity"
    "--hidden-import" "ss_core.engine2_live_proc"
    "--hidden-import" "ss_core.engine3_input_macro"
    "--hidden-import" "ss_core.engine4_deep_files"
    "--hidden-import" "ss_core.engine5_minecraft"
    "--hidden-import" "ss_core.engine6_desktop_traces"
    "--hidden-import" "ss_core.engine7_network_usb"
    "--hidden-import" "ss_core.engine8_reporter"
    "--hidden-import" "ss_core.engine9_kernel"
)

EXCLUDE_QT=(
    "--exclude-module" "PySide6.QtWebEngineCore"
    "--exclude-module" "PySide6.QtWebEngineWidgets"
    "--exclude-module" "PySide6.QtWebEngineQuick"
    "--exclude-module" "PySide6.QtPdf"
    "--exclude-module" "PySide6.QtPdfWidgets"
    "--exclude-module" "PySide6.QtQuick"
    "--exclude-module" "PySide6.QtQml"
    "--exclude-module" "PySide6.QtMultimedia"
    "--exclude-module" "PySide6.Qt3DCore"
)

echo "[build] Packaging PyInstaller single-file ELF into ${OUT_DIR}/MC-SS-Sentinel..."
python3 -m PyInstaller \
    --noconfirm \
    --clean \
    --onefile \
    --windowed \
    --name MC-SS-Sentinel \
    --distpath "${OUT_DIR}" \
    --workpath "${PYI_WORK}/build" \
    --specpath "${PYI_WORK}/spec" \
    "${EXCLUDE_QT[@]}" \
    "${PYI_ADD_DATA[@]}" \
    --add-binary "${WORK_DIR}/native/ss_kernel_probe:native" \
    "${HIDDEN_IMPORTS[@]}" \
    "${WORK_DIR}/ss_gui.py"

chmod 0755 "${OUT_DIR}/MC-SS-Sentinel"
sha256sum "${OUT_DIR}/MC-SS-Sentinel" | awk '{print $1}' > "${OUT_DIR}/MC-SS-Sentinel.sha256"

echo "[build] Verifying compiled ELF in real-time lab checks..."
QT_QPA_PLATFORM=offscreen PYTHONPATH="${WORK_DIR}" python3 "${WORK_DIR}/packaging/lab_verify_target.py" \
    "${TARGET_ID}" "${WORK_DIR}" "${OUT_DIR}/MC-SS-Sentinel"

cp "${WORK_DIR}/assets/mc_ss_sentinel.png" "${OUT_DIR}/mc_ss_sentinel.png"
cat > "${OUT_DIR}/MC-SS-Sentinel.desktop" <<'DESK'
[Desktop Entry]
Type=Application
Name=MC SS Sentinel
Comment=Linux Derin Adli Hile Kontrol Aracı (Ring-0 + 9 Katman)
Exec=%h/.local/bin/MC-SS-Sentinel
Icon=mc-ss-sentinel
Terminal=false
Categories=System;Security;Utility;
StartupWMClass=MC-SS-Sentinel
DESK

cat > "${OUT_DIR}/install_target.sh" <<'INST'
#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${HOME}/.local/bin" "${HOME}/.local/share/applications" "${HOME}/.local/share/icons/hicolor/256x256/apps"
install -m 0755 "${HERE}/MC-SS-Sentinel" "${HOME}/.local/bin/MC-SS-Sentinel"
install -m 0644 "${HERE}/mc_ss_sentinel.png" "${HOME}/.local/share/icons/hicolor/256x256/apps/mc-ss-sentinel.png"
install -m 0644 "${HERE}/MC-SS-Sentinel.desktop" "${HOME}/.local/share/applications/MC-SS-Sentinel.desktop"
update-desktop-database "${HOME}/.local/share/applications" >/dev/null 2>&1 || true
echo "Kuruldu: ${HOME}/.local/bin/MC-SS-Sentinel"
INST
chmod 0755 "${OUT_DIR}/install_target.sh"

python3 - <<PYEOF
import json, platform, re, subprocess, sysconfig
from pathlib import Path

out_dir = Path("${OUT_DIR}")
bin_path = out_dir / "MC-SS-Sentinel"
probe_path = Path("${WORK_DIR}/native/ss_kernel_probe")

def max_glibc(path: Path) -> str:
    if not path.is_file():
        return "missing"
    try:
        out = subprocess.check_output(["objdump", "-T", str(path)], text=True, stderr=subprocess.DEVNULL)
        vers = sorted(
            {f"GLIBC_{m}" for m in re.findall(r"GLIBC_(\d+(?:\.\d+)*)", out)},
            key=lambda s: [int(x) for x in s.split("_", 1)[1].split(".") if x.isdigit()],
        )
        return vers[-1] if vers else "unknown"
    except Exception:
        return "unknown"

libdir = sysconfig.get_config_var("LIBDIR") or ""
libpy_candidates = []
for var_name in ("INSTSONAME", "LDLIBRARY"):
    val = sysconfig.get_config_var(var_name) or ""
    if libdir and val:
        libpy_candidates.append(Path(libdir) / val)
libpy_path = next((p for p in libpy_candidates if p.is_file()), Path("/nonexistent"))
if not libpy_path.is_file():
    for base_lib in (Path("/usr/lib64"), Path("/usr/lib"), Path("/lib64"), Path("/lib")):
        if base_lib.is_dir():
            for cand in sorted(base_lib.rglob("libpython3*.so*")):
                if cand.is_file():
                    libpy_path = cand
                    break
        if libpy_path.is_file():
            break

uapi = Path("/usr/include/linux/version.h").read_text(errors="ignore") if Path("/usr/include/linux/version.h").is_file() else ""
meta = {
    "target_id": "${TARGET_ID}",
    "python_version": platform.python_version(),
    "ldd_version": subprocess.getoutput("ldd --version | head -n 1"),
    "binary_max_glibc": max_glibc(bin_path),
    "libpython_max_glibc": max_glibc(libpy_path),
    "native_probe_max_glibc": max_glibc(probe_path),
    "prebuilt_kmods": ${PREBUILT_COUNT},
    "linux_uapi_header": [ln.strip() for ln in uapi.splitlines() if "LINUX_VERSION" in ln],
    "binary_sha256": (out_dir / "MC-SS-Sentinel.sha256").read_text().strip(),
    "native_probe_sha256": Path("${WORK_DIR}/native/ss_kernel_probe.sha256").read_text().strip(),
}
(out_dir / "build_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
PYEOF

rm -rf "${WORK_DIR}" "${PYI_WORK}"
echo "[build] SUCCESS -> ${OUT_DIR}/MC-SS-Sentinel"

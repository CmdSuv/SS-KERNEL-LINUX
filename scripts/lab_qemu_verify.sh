#!/usr/bin/env bash
# Isolated QEMU/KVM Virtual Kernel Laboratory Verification Harness for MC SS Sentinel
# IMPORTANT:
#   - Does NOT touch or load any LKM into the live host Bazzite kernel!
#   - Builds mc_ss_kmod.ko + ss_kernel_probe cleanly against kernel headers, then boots
#     a completely disposable QEMU/KVM guest kernel with an isolated initramfs to verify:
#     insmod -> /proc/mc_ss_sentinel/* snapshots -> ss_kernel_probe -> rmmod -> zero-oops dmesg.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
KVER="${KVER:-$(uname -r)}"
KDIR="${KDIR:-/lib/modules/${KVER}/build}"

echo "[LAB] Host kernel release target : ${KVER}"
echo "[LAB] Kernel build tree          : ${KDIR}"

if [ "${LAB_SKIP_BUILD:-0}" != "1" ]; then
    if [ ! -d "${KDIR}" ]; then
        echo "[ERROR] Kernel headers not found at ${KDIR}" >&2
        exit 1
    fi

    echo "[LAB 1/4] Compiling native C userspace probe (ss_kernel_probe)..."
    make -C "${REPO_ROOT}/native" clean
    make -C "${REPO_ROOT}/native"

    echo "[LAB 2/4] Compiling Ring-0 LKM (mc_ss_kmod.ko) against ${KDIR}..."
    make -C "${REPO_ROOT}/kernel" KDIR="${KDIR}" clean
    make -C "${REPO_ROOT}/kernel" KDIR="${KDIR}"
    modinfo "${REPO_ROOT}/kernel/mc_ss_kmod.ko" | grep -E 'filename|version|vermagic|license|depends'
else
    echo "[LAB 1-2/4] Skipping compile (using prebuilt artifacts)..."
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "[ERROR] qemu-system-x86_64 is not installed; install qemu-system-x86 before live guest lab run." >&2
    exit 2
fi

VMLINUZ="${VMLINUZ:-}"
if [ -z "${VMLINUZ}" ] || [ ! -r "${VMLINUZ}" ]; then
    for cand in "/boot/vmlinuz-${KVER}" "/lib/modules/${KVER}/vmlinuz"; do
        if [ -r "${cand}" ]; then
            VMLINUZ="${cand}"
            break
        fi
    done
fi
if [ -z "${VMLINUZ}" ]; then
    echo "[WARN] Readable host vmlinuz not found for direct guest boot (set VMLINUZ=/path/to/bzImage)." >&2
    exit 3
fi

BUSYBOX_BIN="${BUSYBOX_BIN:-}"
if [ -z "${BUSYBOX_BIN}" ]; then
    for cand in busybox.static busybox; do
        if command -v "${cand}" >/dev/null 2>&1; then
            BUSYBOX_BIN="$(command -v "${cand}")"
            break
        fi
    done
fi
if [ -z "${BUSYBOX_BIN}" ]; then
    echo "[WARN] busybox binary not found; install busybox for minimal QEMU initramfs test." >&2
    exit 4
fi

LAB_TMP="$(mktemp -d /tmp/mc_ss_qemu_lab_XXXXXX)"
trap 'rm -rf "${LAB_TMP}"' EXIT

INITRAMFS_DIR="${LAB_TMP}/rootfs"
mkdir -p "${INITRAMFS_DIR}"/{bin,sbin,proc,sys,dev,etc,tmp,var,lib,lib64,usr/lib64}
cp "${BUSYBOX_BIN}" "${INITRAMFS_DIR}/bin/busybox"
chmod +x "${INITRAMFS_DIR}/bin/busybox"
for applet in sh mount umount mkdir cat dmesg sleep insmod rmmod lsmod grep poweroff head tail wc tr ls uname kill; do
    ln -s busybox "${INITRAMFS_DIR}/bin/${applet}"
done

cat > "${INITRAMFS_DIR}/etc/lab.env" << ENVEOF
LAB_HEAD_LINES=${LAB_HEAD_LINES:-20}
LAB_PROBE_LINES=${LAB_PROBE_LINES:-30}
ENVEOF

cp "${REPO_ROOT}/kernel/mc_ss_kmod.ko" "${INITRAMFS_DIR}/mc_ss_kmod.ko"
cp "${REPO_ROOT}/native/ss_kernel_probe" "${INITRAMFS_DIR}/ss_kernel_probe"
chmod +x "${INITRAMFS_DIR}/ss_kernel_probe"
# Copy dynamic loader / libc dependencies of ss_kernel_probe into initramfs when not statically linked
while IFS= read -r libpath; do
    if [ -n "${libpath}" ] && [ -f "${libpath}" ]; then
        dest_dir="${INITRAMFS_DIR}$(dirname "${libpath}")"
        mkdir -p "${dest_dir}"
        cp -L "${libpath}" "${INITRAMFS_DIR}${libpath}"
    fi
done < <(ldd "${REPO_ROOT}/native/ss_kernel_probe" 2>/dev/null | grep -oE '/[^ ]+' || true)
if [ -n "${LAB_EXTRA_DIR:-}" ] && [ -d "${LAB_EXTRA_DIR}" ]; then
    cp -a "${LAB_EXTRA_DIR}/." "${INITRAMFS_DIR}/"
fi

cat > "${INITRAMFS_DIR}/init" << 'EOF'
#!/bin/sh
[ -f /etc/lab.env ] && . /etc/lab.env
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev || true

echo "=== GUEST_KERNEL_START $(/bin/uname -r) ==="
echo "CMDLINE=$(/bin/cat /proc/cmdline 2>/dev/null || true)"
/bin/insmod /mc_ss_kmod.ko session_nonce=qemu_lab_nonce enable_live_probes=1
RC_INS=$?
echo "INSMOD_RC=${RC_INS}"

if [ -x /lab_adversarial ]; then
    echo "=== ADVERSARIAL_PROBE_START ==="
    /lab_adversarial &
    ADV_PID=$!
    echo "ADV_PID=${ADV_PID}"
fi

/bin/sleep 1
for node in status integrity tasks_vma pci_iommu events; do
    LINES=$(/bin/wc -l < "/proc/mc_ss_sentinel/${node}" 2>/dev/null || echo 0)
    echo "PROC_${node}_LINES=${LINES}"
    echo "=== BEGIN_NODE_${node} ==="
    /bin/cat "/proc/mc_ss_sentinel/${node}" 2>/dev/null | /bin/head -n "${LAB_HEAD_LINES:-20}" || true
    echo "=== END_NODE_${node} ==="
done

echo "=== NATIVE_PROBE_START ==="
if [ -f /lib_hide_pid.so ] && [ -n "${ADV_PID:-}" ]; then
    LD_PRELOAD=/lib_hide_pid.so HIDE_PID="${ADV_PID}" /ss_kernel_probe all > /tmp/probe_out.json
else
    /ss_kernel_probe all > /tmp/probe_out.json
fi
PROBE_RC=$?
echo "PROBE_RC=${PROBE_RC}"
echo "=== BEGIN_NATIVE_PROBE ==="
/bin/head -n "${LAB_PROBE_LINES:-30}" /tmp/probe_out.json || true
echo "=== END_NATIVE_PROBE ==="

if [ -n "${ADV_PID:-}" ]; then
    /bin/kill "${ADV_PID}" 2>/dev/null || true
    wait "${ADV_PID}" 2>/dev/null || true
fi

/bin/rmmod mc_ss_kmod
RC_RM=$?
echo "RMMOD_RC=${RC_RM}"

# Second rapid reload/unload cycle verifies probe & procfs teardown left no dangling state
/bin/insmod /mc_ss_kmod.ko session_nonce=qemu_lab_nonce_2 enable_live_probes=1
RC_INS2=$?
/bin/cat /proc/mc_ss_sentinel/status >/dev/null 2>&1 || true
/bin/rmmod mc_ss_kmod
RC_RM2=$?
echo "RELOAD_CYCLE_RC=${RC_INS2}:${RC_RM2}"

if [ -d /sys/module/mc_ss_kmod ]; then
    echo "UNLOAD_STATUS=FAIL_STILL_PRESENT"
else
    echo "UNLOAD_STATUS=CLEANLY_REMOVED"
fi

echo "=== GUEST_DMESG_CHECK ==="
/bin/dmesg | /bin/grep -iE 'mc_ss_kmod|BUG:|Oops:|PANIC|WARNING:' | /bin/tail -n 30 || true
echo "=== GUEST_KERNEL_DONE ==="
/bin/poweroff -f
EOF
chmod +x "${INITRAMFS_DIR}/init"

(cd "${INITRAMFS_DIR}" && find . | cpio -H newc -o --quiet | gzip -1 > "${LAB_TMP}/initramfs.cpio.gz")

KVM_FLAG=""
CPU_FLAG=""
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
    CPU_FLAG="-cpu host"
fi

echo "[LAB 3/4] Booting isolated QEMU guest kernel for Ring-0 validation..."
qemu-system-x86_64 \
    ${KVM_FLAG} \
    ${CPU_FLAG} \
    ${QEMU_EXTRA_ARGS:-} \
    -m 1024M \
    -nographic \
    -no-reboot \
    -kernel "${VMLINUZ}" \
    -initrd "${LAB_TMP}/initramfs.cpio.gz" \
    -append "console=ttyS0 nokaslr quiet panic=-1 ${QEMU_APPEND:-}" \
    | tee "${LAB_TMP}/qemu_console.log"

if [ -n "${LAB_OUT_LOG:-}" ]; then
    cp "${LAB_TMP}/qemu_console.log" "${LAB_OUT_LOG}"
fi

echo "[LAB 4/4] Verifying QEMU guest output..."
grep -q "INSMOD_RC=0" "${LAB_TMP}/qemu_console.log"
grep -q "RMMOD_RC=0" "${LAB_TMP}/qemu_console.log"
grep -q "RELOAD_CYCLE_RC=0:0" "${LAB_TMP}/qemu_console.log"
grep -q "PROBE_RC=0" "${LAB_TMP}/qemu_console.log"
grep -q "UNLOAD_STATUS=CLEANLY_REMOVED" "${LAB_TMP}/qemu_console.log"
if grep -qE "PROC_(status|integrity)_LINES=0" "${LAB_TMP}/qemu_console.log"; then
    echo "[FAIL] /proc/mc_ss_sentinel snapshot returned empty output in QEMU guest!" >&2
    exit 4
fi
if grep -qiE "BUG:|Oops:|kernel panic|Call Trace:|WARNING:.*mc_ss_kmod" "${LAB_TMP}/qemu_console.log"; then
    echo "[FAIL] Kernel anomaly detected inside QEMU guest log!" >&2
    exit 5
fi
echo "[PASS] Isolated QEMU laboratory verification succeeded with clean load & unload!"

"""OS / Distro profile registry, host detection, kernel header & bootloader helpers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import platform
import re
import sys


@dataclass(frozen=True)
class DistroProfile:
    target_id: str
    display_name: str
    short_name: str
    subtitle: str
    family: str
    is_immutable: bool
    pkg_manager: str
    mac_framework: str
    default_bootloader: str
    kernel_notes: str
    userspace_notes: str
    iommu_notes: str
    has_snap: bool = False
    has_aur: bool = False
    has_steamos_readonly: bool = False
    clang_lto_possible: bool = False
    glibc_baseline: str = ""


@dataclass(frozen=True)
class DistroDetection:
    target_id: str
    pretty_name: str
    os_id: str
    version_id: str
    codename: str
    is_ostree: bool
    is_steamos: bool
    kernel_release: str
    confidence: str  # "exact" | "family" | "fallback"


TARGET_ORDER: tuple[str, ...] = (
    "bazzite",
    "fedora_nobara",
    "ubuntu_24_04",
    "ubuntu_22_04",
    "debian",
    "arch_cachyos",
    "steamos",
)

TARGET_ALIASES: dict[str, str] = {
    "bazzite": "bazzite",
    "silverblue": "bazzite",
    "kinoite": "bazzite",
    "fedora_atomic": "bazzite",
    "fedora": "fedora_nobara",
    "nobara": "fedora_nobara",
    "fedora_nobara": "fedora_nobara",
    "ubuntu": "ubuntu_24_04",
    "ubuntu24": "ubuntu_24_04",
    "ubuntu_24_04": "ubuntu_24_04",
    "noble": "ubuntu_24_04",
    "ubuntu22": "ubuntu_22_04",
    "ubuntu_22_04": "ubuntu_22_04",
    "jammy": "ubuntu_22_04",
    "debian": "debian",
    "bookworm": "debian",
    "trixie": "debian",
    "debian12": "debian",
    "debian13": "debian",
    "arch": "arch_cachyos",
    "cachyos": "arch_cachyos",
    "arch_cachyos": "arch_cachyos",
    "endeavouros": "arch_cachyos",
    "garuda": "arch_cachyos",
    "manjaro": "arch_cachyos",
    "steamos": "steamos",
    "steamdeck": "steamos",
    "holo": "steamos",
}


DISTRO_PROFILES: dict[str, DistroProfile] = {
    "bazzite": DistroProfile(
        target_id="bazzite",
        display_name="Bazzite / Fedora Atomic",
        short_name="Bazzite",
        subtitle="Silverblue / Kinoite / Universal Blue (Immutable ostree + SELinux)",
        family="fedora_atomic",
        is_immutable=True,
        pkg_manager="rpm-ostree",
        mac_framework="selinux",
        default_bootloader="rpm_ostree",
        kernel_notes=(
            "Immutable ostree image: Ring-0 LKM uses bundled vermagic-matched .ko or "
            "layered kernel-devel headers; falls back cleanly to Native C BTF/eBPF probe."
        ),
        userspace_notes="Flatpak-first desktop & launchers (~/.var/app), SELinux enforcing checks.",
        iommu_notes="rpm-ostree kargs --append=iommu=force (+ intel_iommu=on / amd_iommu=on)",
        glibc_baseline="2.43+",
    ),
    "fedora_nobara": DistroProfile(
        target_id="fedora_nobara",
        display_name="Fedora Workstation & Nobara",
        short_name="Fedora/Nobara",
        subtitle="Fedora 43-45, Nobara, RHEL/Alma/Rocky (DNF + grubby + SELinux)",
        family="fedora",
        is_immutable=False,
        pkg_manager="dnf",
        mac_framework="selinux",
        default_bootloader="grubby",
        kernel_notes=(
            "Mutable kernel-devel DKMS/Kbuild path: auto-compiles mc_ss_kmod.ko against "
            "/lib/modules/$(uname -r)/build when matching kernel-devel is installed."
        ),
        userspace_notes="DNF package audit (/var/log/dnf*.log), Flatpak & native launchers, SELinux.",
        iommu_notes="grubby --update-kernel=ALL --args=...",
        glibc_baseline="2.41+",
    ),
    "ubuntu_24_04": DistroProfile(
        target_id="ubuntu_24_04",
        display_name="Ubuntu 24.04 LTS",
        short_name="Ubuntu 24.04",
        subtitle="Ubuntu 24.04 Noble, Pop!_OS 24.04 (Kernel 6.8/6.11 + AppArmor + Snap)",
        family="debian_ubuntu",
        is_immutable=False,
        pkg_manager="apt",
        mac_framework="apparmor",
        default_bootloader="grub_update",
        kernel_notes=(
            "Auto-compiles Ring-0 LKM against linux-headers-$(uname -r); compatible with GA 6.8 and HWE 6.11+."
        ),
        userspace_notes="Audits Snap browsers (~/snap/firefox|chromium|brave), Flatpak, apt/dpkg logs & AppArmor.",
        iommu_notes="/etc/default/grub (GRUB_CMDLINE_LINUX_DEFAULT) + update-grub (or kernelstub on Pop!_OS)",
        has_snap=True,
        glibc_baseline="2.39",
    ),
    "ubuntu_22_04": DistroProfile(
        target_id="ubuntu_22_04",
        display_name="Ubuntu 22.04 LTS",
        short_name="Ubuntu 22.04",
        subtitle="Ubuntu 22.04 Jammy, Pop!_OS 22.04 (Kernel 5.15 GA / 6.8 HWE + Snap)",
        family="debian_ubuntu",
        is_immutable=False,
        pkg_manager="apt",
        mac_framework="apparmor",
        default_bootloader="grub_update",
        kernel_notes=(
            "Built for glibc 2.35 & Linux 5.15+ LKM/UAPI compatibility (core_layout & 6.x HWE guards)."
        ),
        userspace_notes="Audits Snap & native browsers, apt/dpkg.log tampering & AppArmor posture.",
        iommu_notes="/etc/default/grub + update-grub (or kernelstub on Pop!_OS)",
        has_snap=True,
        glibc_baseline="2.35",
    ),
    "debian": DistroProfile(
        target_id="debian",
        display_name="Debian 12 / 13",
        short_name="Debian",
        subtitle="Bookworm (12) / Trixie (13), MX Linux (Kernel 6.1 / 6.12 + AppArmor)",
        family="debian_ubuntu",
        is_immutable=False,
        pkg_manager="apt",
        mac_framework="apparmor",
        default_bootloader="grub_update",
        kernel_notes=(
            "Built for glibc 2.36 & Kernel 6.1+/6.12+ (with pre-6.4 module_layout & VMA_ITERATOR guards)."
        ),
        userspace_notes="Audits /var/log/apt/history.log, dpkg.log, native/Flatpak apps & AppArmor.",
        iommu_notes="/etc/default/grub + update-grub",
        glibc_baseline="2.36",
    ),
    "arch_cachyos": DistroProfile(
        target_id="arch_cachyos",
        display_name="Arch Linux & CachyOS",
        short_name="Arch/CachyOS",
        subtitle="Arch, CachyOS, EndeavourOS, Garuda (GCC & Clang/ThinLTO LLVM=1 + AUR)",
        family="arch",
        is_immutable=False,
        pkg_manager="pacman",
        mac_framework="apparmor_or_none",
        default_bootloader="systemd_boot_or_grub",
        kernel_notes=(
            "Auto-detects CONFIG_CC_IS_CLANG / ThinLTO and passes LLVM=1 during LKM compilation; "
            "maps linux/zen/lts/cachyos headers dynamically."
        ),
        userspace_notes="Audits /var/log/pacman.log & AUR caches (~/.cache/yay, ~/.cache/paru).",
        iommu_notes="systemd-boot (/boot/loader/entries/*.conf), GRUB (/etc/default/grub + grub-mkconfig), or Limine",
        has_aur=True,
        clang_lto_possible=True,
        glibc_baseline="2.40+",
    ),
    "steamos": DistroProfile(
        target_id="steamos",
        display_name="SteamOS 3 (Steam Deck)",
        short_name="SteamOS 3",
        subtitle="Valve Holo / Neptune Immutable (SD Card /run/media + steamos-readonly)",
        family="steamos",
        is_immutable=True,
        pkg_manager="pacman_readonly",
        mac_framework="readonly",
        default_bootloader="steamos_grub",
        kernel_notes=(
            "Immutable Neptune rootfs: checks steamos-readonly status, loads matching .ko or "
            "operates via Native C BTF/eBPF & Ring-3 engines without breaking Valve updates."
        ),
        userspace_notes="Scans MicroSD /run/media/* & Flatpak (~/.var/app) launchers and Steam Deck shortcuts.",
        iommu_notes="SteamOS immutable EFI GRUB; inspect-only guidance (avoid breaking A/B partition updates)",
        has_steamos_readonly=True,
        glibc_baseline="2.39+",
    ),
}


def get_baked_target_os() -> str | None:
    """Read optional per-distro build target baked beside executable/repo."""
    candidates: list[Path] = [
        Path(__file__).resolve().parent.parent / "TARGET_OS",
    ]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.insert(0, Path(meipass) / "TARGET_OS")
    try:
        candidates.insert(0, Path(sys.executable).resolve().parent / "TARGET_OS")
    except OSError:
        pass
    for path in candidates:
        try:
            if path.is_file():
                val = path.read_text(encoding="utf-8", errors="ignore").strip().lower()
                if val in TARGET_ALIASES:
                    return TARGET_ALIASES[val]
        except OSError:
            continue
    return None


def normalize_target_os(target_os: str | None) -> str | None:
    if not target_os:
        return None
    raw = str(target_os).strip().lower()
    if raw in ("auto", "host", ""):
        return None
    return TARGET_ALIASES.get(raw)


def _parse_os_release(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip().strip('"').strip("'")
        parsed[k.strip().upper()] = v
    return parsed


def detect_host_distro(
    root_prefix: Path = Path("/"),
    os_release_text: str | None = None,
    kernel_release: str | None = None,
) -> DistroDetection:
    """Identify the running Linux distribution accurately across Tier 1 & Tier 2 targets."""
    krel = kernel_release or platform.release()
    if os_release_text is None:
        for rel in (root_prefix / "etc" / "os-release", root_prefix / "usr" / "lib" / "os-release"):
            try:
                if rel.is_file():
                    os_release_text = rel.read_text(encoding="utf-8", errors="ignore")
                    break
            except OSError:
                continue
    kv = _parse_os_release(os_release_text or "")
    os_id = kv.get("ID", "").lower()
    variant_id = kv.get("VARIANT_ID", "").lower()
    version_id = kv.get("VERSION_ID", "").lower()
    codename = (kv.get("UBUNTU_CODENAME") or kv.get("VERSION_CODENAME") or "").lower()
    pretty = kv.get("PRETTY_NAME") or kv.get("NAME") or (os_id or "Linux")
    id_like = [tok.lower() for tok in re.split(r"[\s,]+", kv.get("ID_LIKE", "")) if tok]

    is_ostree = (
        (root_prefix / "run" / "ostree-booted").exists()
        or (root_prefix / "ostree").is_dir()
        or os_id in {"bazzite", "silverblue", "kinoite", "bluefin", "aurora"}
        or variant_id in {"bazzite", "silverblue", "kinoite", "sericea", "onyx", "sway-atomic", "budgie-atomic"}
    )
    is_steamos = (
        os_id == "steamos"
        or (root_prefix / "etc" / "steamos-release").is_file()
        or "steamos" in pretty.lower()
        or "neptune" in krel.lower()
    )

    if is_steamos:
        return DistroDetection("steamos", pretty, os_id or "steamos", version_id, codename, False, True, krel, "exact")

    if os_id == "bazzite" or (os_id == "fedora" and is_ostree) or variant_id in {"bazzite", "silverblue", "kinoite"}:
        conf = "exact" if os_id == "bazzite" or variant_id == "bazzite" else "family"
        return DistroDetection("bazzite", pretty, os_id or "bazzite", version_id, codename, True, False, krel, conf)

    if os_id in {"nobara", "fedora", "rhel", "almalinux", "rocky", "centos"} or (
        "fedora" in id_like and not is_ostree
    ):
        conf = "exact" if os_id in {"fedora", "nobara"} else "family"
        return DistroDetection("fedora_nobara", pretty, os_id, version_id, codename, False, False, krel, conf)

    if os_id in {"arch", "cachyos", "endeavouros", "garuda", "manjaro", "arcolinux", "artix"} or "arch" in id_like:
        conf = "exact" if os_id in {"arch", "cachyos"} else "family"
        return DistroDetection("arch_cachyos", pretty, os_id, version_id, codename, False, False, krel, conf)

    if os_id == "ubuntu" or "ubuntu" in id_like or os_id in {"pop", "zorin", "elementary", "neon"}:
        is_22 = (
            codename in {"jammy", "focal"}
            or version_id.startswith("22.")
            or version_id.startswith("20.")
        )
        tid = "ubuntu_22_04" if is_22 else "ubuntu_24_04"
        conf = "exact" if os_id == "ubuntu" else "family"
        return DistroDetection(tid, pretty, os_id, version_id, codename, False, False, krel, conf)

    if os_id in {"debian", "mx", "kali", "devuan", "parrot"} or "debian" in id_like:
        conf = "exact" if os_id == "debian" else "family"
        return DistroDetection("debian", pretty, os_id, version_id, codename, False, False, krel, conf)

    # Heuristic fallback from kernel release string if os-release missing in stripped test fixture
    kl = krel.lower()
    if "bazzite" in kl or ".fc" in kl:
        return DistroDetection("bazzite" if is_ostree else "fedora_nobara", pretty, os_id, version_id, codename, is_ostree, False, krel, "family")
    if "cachyos" in kl or "arch" in kl:
        return DistroDetection("arch_cachyos", pretty, os_id, version_id, codename, False, False, krel, "family")
    return DistroDetection("debian", pretty, os_id or "unknown", version_id, codename, is_ostree, False, krel, "fallback")


def resolve_profile(
    target_os: str | None = None,
    root_prefix: Path = Path("/"),
    os_release_text: str | None = None,
    kernel_release: str | None = None,
) -> tuple[DistroProfile, DistroDetection]:
    """Return active DistroProfile (explicit selection -> baked TARGET_OS -> host auto-detect) + host info."""
    host = detect_host_distro(root_prefix=root_prefix, os_release_text=os_release_text, kernel_release=kernel_release)
    explicit = normalize_target_os(target_os)
    if explicit and explicit in DISTRO_PROFILES:
        return DISTRO_PROFILES[explicit], host
    baked = get_baked_target_os()
    if baked and baked in DISTRO_PROFILES:
        return DISTRO_PROFILES[baked], host
    return DISTRO_PROFILES[host.target_id], host


def arch_headers_package_for_release(kernel_release: str) -> str:
    """Map an Arch/CachyOS/Manjaro uname -r string to its exact pacman kernel headers package."""
    kl = kernel_release.lower()
    manjaro_m = re.match(r"^(\d+)\.(\d+)\.\d+.*-manjaro", kl)
    if manjaro_m:
        return f"linux{manjaro_m.group(1)}{manjaro_m.group(2)}-headers"

    cachy_flavors = (
        ("-cachyos-rt-bore", "linux-cachyos-rt-bore-headers"),
        ("-cachyos-lto", "linux-cachyos-lto-headers"),
        ("-cachyos-bore", "linux-cachyos-bore-headers"),
        ("-cachyos-bmq", "linux-cachyos-bmq-headers"),
        ("-cachyos-eevdf", "linux-cachyos-eevdf-headers"),
        ("-cachyos-server", "linux-cachyos-server-headers"),
        ("-cachyos-lts", "linux-cachyos-lts-headers"),
        ("-cachyos-rc", "linux-cachyos-rc-headers"),
        ("-cachyos", "linux-cachyos-headers"),
    )
    for token, pkg in cachy_flavors:
        if token in kl:
            return pkg

    generic_flavors = (
        ("-hardened", "linux-hardened-headers"),
        ("-zen", "linux-zen-headers"),
        ("-lts", "linux-lts-headers"),
        ("-xanmod", "linux-xanmod-headers"),
        ("-lqx", "linux-lqx-headers"),
        ("-liquorix", "linux-lqx-headers"),
    )
    for token, pkg in generic_flavors:
        if token in kl:
            return pkg
    return "linux-headers"


def format_kernel_headers_install_hint(target_id: str, kernel_release: str = "", needs_llvm: bool = False) -> str:
    """Return copy-pasteable distro-accurate command to install matching kernel headers."""
    krel = kernel_release or platform.release()
    if target_id == "bazzite":
        return "rpm-ostree install kernel-devel kernel-headers (Bazzite is immutable; reboot or use bundled .ko)"
    if target_id == "fedora_nobara":
        return f"sudo dnf install -y kernel-devel-{krel} kernel-headers gcc make"
    if target_id in {"ubuntu_24_04", "ubuntu_22_04", "debian"}:
        return f"sudo apt-get update && sudo apt-get install -y linux-headers-{krel} build-essential"
    if target_id == "arch_cachyos":
        hdr_pkg = arch_headers_package_for_release(krel)
        llvm_pkgs = " clang lld llvm" if (needs_llvm or "cachyos" in krel.lower() or "lto" in krel.lower()) else ""
        return f"sudo pacman -S --needed {hdr_pkg} base-devel{llvm_pkgs}"
    if target_id == "steamos":
        return "SteamOS 3 is immutable (steamos-readonly): use matching Neptune .ko or Native BTF/eBPF mode"
    return f"Install matching kernel headers for {krel}"

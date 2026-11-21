"""Engine 7: Network Sockets (/proc/net), Proxies, VPNs, /etc/hosts & USB/Device History."""

from __future__ import annotations

import os
import re
import socket
import struct
from pathlib import Path

from .models import Confidence, Finding, ScanContext, ScanStatus, Severity
from .signatures import CHEAT_DOMAINS
from .utils import emit_scan_progress, record_scan_region, run_trusted_cmd, safe_read_text

ENGINE_NAME = "Engine 7: Ag, Proxy, VPN, Hosts & USB Analizi"

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

SUSPICIOUS_PROXY_PORTS: dict[int, str] = {
    1080: "SOCKS Proxy (1080)",
    1081: "SOCKS Proxy (1081)",
    7890: "Clash/Proxy (7890)",
    7891: "Clash SOCKS (7891)",
    9050: "Tor SOCKS (9050)",
    9051: "Tor Control (9051)",
    10808: "v2ray/xray SOCKS (10808)",
    10809: "v2ray/xray HTTP (10809)",
    3128: "HTTP Proxy (3128)",
    8118: "Privoxy (8118)",
}

CHEAT_WEBGUI_PORTS: frozenset[int] = frozenset({1337, 6969, 42069, 31337})

VPN_IFACE_PREFIXES: tuple[str, ...] = (
    "tun",
    "tap",
    "wg",
    "nord",
    "proton",
    "mullvad",
    "tailscale",
    "zt",
    "ppp",
    "ipsec",
    "warp",
)


def _decode_proc_ip(hex_ip: str, ipv6: bool) -> str:
    try:
        if not ipv6 and len(hex_ip) == 8:
            packed = struct.pack("=I", int(hex_ip, 16))
            return socket.inet_ntop(socket.AF_INET, packed)
        if ipv6 and len(hex_ip) == 32:
            words = [int(hex_ip[i : i + 8], 16) for i in range(0, 32, 8)]
            packed = struct.pack("=4I", *words)
            return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        pass
    return hex_ip


def _build_inode_to_proc_map(ctx: ScanContext) -> dict[str, tuple[int, str]]:
    mapping: dict[str, tuple[int, str]] = {}
    try:
        for entry in ctx.proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            comm = safe_read_text(entry / "comm", 128).strip()
            fd_dir = entry / "fd"
            if not fd_dir.is_dir():
                continue
            try:
                for fde in fd_dir.iterdir():
                    try:
                        target = os.readlink(fde)
                    except OSError:
                        continue
                    if target.startswith("socket:[") and target.endswith("]"):
                        inode = target[8:-1]
                        mapping[inode] = (pid, comm)
            except OSError:
                continue
    except OSError:
        pass
    return mapping


_DPI_BYPASS_PROCS: tuple[str, ...] = (
    "ciadpi",
    "byedpi",
    "goodbyedpi",
    "zapret",
    "tpws",
    "nfqws",
    "spoofdpi",
)


def _check_proc_net_sockets(ctx: ScanContext) -> None:
    inode_map = _build_inode_to_proc_map(ctx)
    proxy_hits: list[str] = []
    dpi_only_hits: list[str] = []
    game_on_proxy = False
    dpi_ports: set[int] = set()
    cheat_gui_hits: list[str] = []
    java_conns: list[str] = []

    parsed_rows: list[tuple[str, int, str, int, str, tuple[int, str] | None]] = []
    for fname, ipv6 in (("net/tcp", False), ("net/tcp6", True)):
        txt = safe_read_text(ctx.proc_root / fname, 2 * 1024 * 1024)
        if not txt:
            continue
        lines = txt.splitlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            loc, rem, st_hex = parts[1], parts[2], parts[3]
            inode = parts[9]
            if ":" not in loc or ":" not in rem:
                continue
            l_ip_hex, l_port_hex = loc.split(":", 1)
            r_ip_hex, r_port_hex = rem.split(":", 1)
            try:
                l_port = int(l_port_hex, 16)
                r_port = int(r_port_hex, 16)
            except ValueError:
                continue
            l_ip = _decode_proc_ip(l_ip_hex, ipv6)
            r_ip = _decode_proc_ip(r_ip_hex, ipv6)
            state = TCP_STATES.get(st_hex.upper(), st_hex)
            owner = inode_map.get(inode)
            parsed_rows.append((l_ip, l_port, r_ip, r_port, state, owner))
            if state == "LISTEN" and l_port in SUSPICIOUS_PROXY_PORTS and owner:
                if any(d in owner[1].lower() for d in _DPI_BYPASS_PROCS):
                    dpi_ports.add(l_port)

    for l_ip, l_port, r_ip, r_port, state, owner in parsed_rows:
        owner_str = f"PID {owner[0]} ({owner[1]})" if owner else "bilinmeyen PID"
        owner_low = owner[1].lower() if owner else ""

        if state == "LISTEN" and l_port in SUSPICIOUS_PROXY_PORTS:
            rec = f"{l_ip}:{l_port} [{SUSPICIOUS_PROXY_PORTS[l_port]}] -> {owner_str}"
            if l_port in dpi_ports:
                dpi_only_hits.append(rec)
            else:
                proxy_hits.append(rec)

        if state == "LISTEN" and l_port in CHEAT_WEBGUI_PORTS:
            cheat_gui_hits.append(f"{l_ip}:{l_port} (LISTEN) -> {owner_str}")

        if state == "ESTABLISHED":
            is_java_or_game = any(t in owner_low for t in ("java", "javaw", "wine", "proton", "minecraft", "lunar", "prism"))
            if is_java_or_game:
                java_conns.append(f"{owner_str}: {l_ip}:{l_port} -> {r_ip}:{r_port}")
            if r_port in SUSPICIOUS_PROXY_PORTS:
                is_browser_or_chat = any(
                    b in owner_low for b in ("opera", "firefox", "chrome", "chromium", "brave", "vivaldi", "edge", "discord", "vesktop", "telegram")
                )
                if is_java_or_game:
                    game_on_proxy = True
                    proxy_hits.append(f"Oyun/Java sureci yerel proxy portuna bagli: {r_ip}:{r_port} ({owner_str})")
                elif r_ip in ("127.0.0.1", "::1") and not is_browser_or_chat:
                    proxy_hits.append(f"Surec yerel/supheli proxy portuna bagli: {r_ip}:{r_port} ({owner_str})")
                elif r_port in dpi_ports and is_browser_or_chat:
                    dpi_only_hits.append(f"Sohbet/Tarayici DPI proxy baglantisi: {r_ip}:{r_port} ({owner_str})")

    ctx.telemetry["java_established_sockets"] = java_conns[:30]

    if proxy_hits or game_on_proxy:
        ctx.add_finding(
            Finding(
                rule_id="E7-LOCAL-PROXY-ACTIVE",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Proxy / Tunnel",
                title="Yerel SOCKS/HTTP proxy veya tunel portu aktif",
                description="Oyun veya sistem trafigi yerel proxy/tunel uzerinden yonlendiriliyor olabilir.",
                evidence=(proxy_hits + dpi_only_hits)[:12],
            )
        )
    elif dpi_only_hits:
        ctx.add_finding(
            Finding(
                rule_id="E7-LOCAL-PROXY-ACTIVE",
                engine=ENGINE_NAME,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="DPI Bypass Proxy (Discord/Browser)",
                title="Yerel DPI/sansur asma proxy'si aktif (yalnizca sohbet/tarayici bagli)",
                description="ciadpi/byedpi benzeri yerel DPI araci aktif ancak Java/Minecraft sureci bu proxy'ye bagli degil.",
                evidence=dpi_only_hits[:12],
            )
        )
    if cheat_gui_hits:
        ctx.add_finding(
            Finding(
                rule_id="E7-CHEAT-PORT-LISTEN",
                engine=ENGINE_NAME,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category="Suspicious Local Server",
                title="Bilinen hile WebGUI/kontrol portu dinlemede",
                description="1337/6969/42069/31337 gibi yaygin web-panel/IRC portlarindan biri dinleniyor.",
                evidence=cheat_gui_hits[:8],
            )
        )


def _check_vpn_and_proxy_configs(ctx: ScanContext) -> None:
    net_dir = ctx.sys_path("/sys/class/net")
    vpn_ifaces: list[str] = []
    if net_dir.is_dir():
        try:
            for iface in net_dir.iterdir():
                iname = iface.name.lower()
                # Skip Linux IPIP kernel dummy tunl0 and container/VM tap bridges when down
                if iname.startswith(("tunl", "virbr", "docker", "podman", "veth", "br-")):
                    continue
                if any(iname.startswith(p) for p in VPN_IFACE_PREFIXES):
                    oper = safe_read_text(iface / "operstate", 32).strip().lower()
                    if iname.startswith("tap") and oper == "down":
                        continue
                    vpn_ifaces.append(f"{iface.name} (state={oper or 'unknown'})")
        except OSError:
            pass

    if ctx.live_mode:
        rc, nm_out, _ = run_trusted_cmd(["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"], timeout=3.0)
        if rc == 0 and nm_out:
            for ln in nm_out.splitlines():
                low = ln.lower()
                if any(c in low for c in ("bridge", "virbr", "docker", "podman", "veth", "loopback", ":tap")):
                    continue
                if any(k in low for k in ("vpn", "wireguard", "tun", "openvpn", "mullvad", "proton", "nord")):
                    vpn_ifaces.append(f"nmcli: {ln}")

    if vpn_ifaces:
        ctx.add_finding(
            Finding(
                rule_id="E7-VPN-ACTIVE",
                engine=ENGINE_NAME,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category="VPN / Tunnel",
                title="Aktif VPN / WireGuard / Tunel ag arayuzu tespit edildi",
                description="VPN kullanimi IP ban atlatma (ban evade) veya multi-hesap suphesi olusturur.",
                evidence=sorted(set(vpn_ifaces)),
            )
        )

    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SOCKS_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        if os.environ.get(var):
            ctx.add_finding(
                Finding(
                    rule_id="E7-PROXY-ENV",
                    engine=ENGINE_NAME,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    category="Proxy Environment",
                    title=f"Oturumda proxy ortam degiskeni ayarli: {var}",
                    description="Ag istekleri proxy sunucusu uzerinden geciriliyor.",
                    evidence=[f"{var}={os.environ.get(var)}"],
                )
            )
            break

    for pc in (ctx.home_dir / ".proxychains/proxychains.conf", ctx.sys_path("/etc/proxychains.conf"), ctx.sys_path("/etc/proxychains4.conf")):
        if pc.is_file():
            ctx.add_finding(
                Finding(
                    rule_id="E7-PROXYCHAINS-CFG",
                    engine=ENGINE_NAME,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="Proxy Tooling",
                    title=f"proxychains yapilandirmasi mevcut: {pc.name}",
                    description="Uygulamalari SOCKS/HTTP proxy icinden baslatmak icin proxychains kurulu/yapilandirilmis.",
                    evidence=[str(pc)],
                    path=str(pc),
                )
            )

    java_proxies = ctx.telemetry.get("java_proxy_args", [])
    if java_proxies:
        ctx.add_finding(
            Finding(
                rule_id="E7-JVM-PROXY-FLAG",
                engine=ENGINE_NAME,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category="JVM Proxy Tunnel",
                title="Calisan Java/Minecraft sureci SOCKS/HTTP proxy argumani kullaniyor",
                description="JVM baslatma parametrelerinde -DsocksProxyHost veya -Dhttp.proxyHost tanimi bulundu.",
                evidence=list(dict.fromkeys(java_proxies))[:10],
            )
        )


def _check_etc_hosts(ctx: ScanContext) -> None:
    hosts_path = ctx.sys_path("/etc/hosts")
    if not hosts_path.is_file():
        return
    txt = safe_read_text(hosts_path, 512 * 1024)
    suspicious_lines: list[str] = []
    for line in txt.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        low = s.lower()
        parts = low.split()[1:]
        if not parts:
            continue
        _std_loopback_names = {
            "localhost",
            "localhost.localdomain",
            "localhost4",
            "localhost4.localdomain4",
            "localhost6",
            "localhost6.localdomain6",
            "ip6-localhost",
            "ip6-loopback",
        }
        if all(tok in _std_loopback_names for tok in parts):
            continue
        if any(dom in low for dom in CHEAT_DOMAINS) or any(
            k in low for k in ("mojang.com", "minecraftservices.com", "authserver", "anticheat", "lunarclient")
        ):
            suspicious_lines.append(s[:200])

    if suspicious_lines:
        ctx.add_finding(
            Finding(
                rule_id="E7-HOSTS-SPOOF",
                engine=ENGINE_NAME,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="Hosts / Auth Spoofing",
                title="/etc/hosts icinde supheli domain yonlendirmesi (Auth crack / blok)",
                description="Hile lisans sunucusu taklidi veya Mojang/anti-cheat domain engellemesi yapilmis.",
                evidence=suspicious_lines,
                path=str(hosts_path),
            )
        )


def _check_usb_devices_and_history(ctx: ScanContext) -> None:
    usb_dir = ctx.sys_path("/sys/bus/usb/devices")
    storage_devs: list[str] = []
    macro_hw_devs: list[str] = []

    # Vendors known for onboard-macro mice / rapid-trigger / programmable firmware
    macro_vendors = {
        "09da": "A4Tech/Bloody (Onboard Auto-Fire/Macro riski)",
        "1532": "Razer",
        "046d": "Logitech",
        "1038": "SteelSeries",
        "258a": "Glorious/Sinowealth",
        "31e3": "Wooting",
    }

    if usb_dir.is_dir():
        try:
            for dev in usb_dir.iterdir():
                if not dev.is_dir():
                    continue
                vid = safe_read_text(dev / "idVendor", 32).strip().lower()
                pid = safe_read_text(dev / "idProduct", 32).strip().lower()
                prod = safe_read_text(dev / "product", 128).strip()
                manu = safe_read_text(dev / "manufacturer", 128).strip()
                bclass = safe_read_text(dev / "bDeviceClass", 16).strip()
                # Check interface class 08 (Mass Storage)
                iface_classes = [
                    safe_read_text(ic_file, 16).strip()
                    for ic_file in dev.glob("*:*/bInterfaceClass")
                ]
                if bclass == "08" or "08" in iface_classes:
                    storage_devs.append(f"USB Mass Storage: {manu} {prod} ({vid}:{pid})")
                if vid == "09da":  # Bloody mice specifically notorious for hardware recoil/autoclick macros
                    macro_hw_devs.append(f"{macro_vendors[vid]}: {manu} {prod} ({vid}:{pid})")
        except OSError:
            pass

    if storage_devs:
        ctx.add_finding(
            Finding(
                rule_id="E7-USB-STORAGE-CONNECTED",
                engine=ENGINE_NAME,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category="External USB Storage",
                title="Bilgisayara harici USB depolama aygiti bagli",
                description="Harici USB bellek icinden tasinabilir hile calistirilmis olabilir.",
                evidence=storage_devs,
                recommendation="USB bellek icerigini kontrol edin veya cikarilip cikarilmadigini sorun.",
            )
        )
    if macro_hw_devs:
        ctx.add_finding(
            Finding(
                rule_id="E7-USB-BLOODY-MOUSE",
                engine=ENGINE_NAME,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category="Hardware Macro Mouse",
                title="Donanim dahili makro bellekli fare bagli (A4Tech/Bloody)",
                description="Bloody fareler kendi dahili hafizasinda yazilimsiz autoclick/makro calistirabilir.",
                evidence=macro_hw_devs,
            )
        )

    if ctx.live_mode:
        hours = max(1, int(round(ctx.time_window_hours)))
        rc, jout, _ = run_trusted_cmd(
            ["journalctl", "-k", "--since", f"{hours} hours ago", "--no-pager", "-n", "200"],
            timeout=3.5,
        )
        if rc == 0 and jout:
            usb_events: list[str] = []
            for ln in jout.splitlines():
                low = ln.lower()
                if any(k in low for k in ("usb-storage", "usb mass storage", "attached scsi removable disk")):
                    usb_events.append(ln.strip()[:200])
            if usb_events:
                ctx.add_finding(
                    Finding(
                        rule_id="E7-USB-RECENT-KERNEL-EVENT",
                        engine=ENGINE_NAME,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="Recent USB Connect/Disconnect",
                        title=f"Son {hours} saat icinde USB depolama tak-cikar olayi",
                        description="Kontrol oncesi USB bellek takilip hile calistirildiktan sonra cikarilmis olabilir.",
                        evidence=usb_events[:12],
                    )
                )


def run(ctx: ScanContext) -> None:
    try:
        emit_scan_progress(ctx, 0.20, "/proc/net aktif ag soketleri inceleniyor...")
        _check_proc_net_sockets(ctx)
        record_scan_region(ctx, "E7", f"{ctx.proc_root}/net/tcp, tcp6, udp")
        emit_scan_progress(ctx, 0.45, "VPN tunelleri ve proxy ortamlari kontrol ediliyor...")
        _check_vpn_and_proxy_configs(ctx)
        record_scan_region(ctx, "E7", f"{ctx.sys_path('/sys/class/net')} ve proxy ortamlari")
        emit_scan_progress(ctx, 0.70, "/etc/hosts DNS yonlendirmeleri inceleniyor...")
        _check_etc_hosts(ctx)
        record_scan_region(ctx, "E7", f"{ctx.sys_path('/etc/hosts')}")
        emit_scan_progress(ctx, 0.90, "USB aygitlari ve tak-cikar gecmisi kontrol ediliyor...")
        _check_usb_devices_and_history(ctx)
        record_scan_region(ctx, "E7", f"{ctx.sys_path('/sys/bus/usb/devices')} ve USB kayitlari")
        ctx.set_coverage("E7.network_usb", ScanStatus.COMPLETED, "Sockets, proxies, hosts, USB audited")
        emit_scan_progress(ctx, 1.0, "Ag ve USB analizi tamamlandi.")
    except Exception as exc:
        if exc.__class__.__name__ == "ScanCancelledError":
            raise
        ctx.set_coverage("E7.network_usb", ScanStatus.ERROR, str(exc))
        ctx.add_error(ENGINE_NAME, f"Beklenmeyen hata: {exc}")

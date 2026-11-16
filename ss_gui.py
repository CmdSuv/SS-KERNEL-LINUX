#!/usr/bin/env python3
"""MC SS Sentinel - Classic Pitch-Black Minimal Desktop GUI with Consent Gate."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


def _run_kernel_helper_cli(argv: list[str]) -> int:
    import argparse
    import json
    from ss_core import priv_helper as _priv_helper

    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--kernel-snapshot-helper", action="store_true")
    ap.add_argument("--trace-ms", type=int, default=1500)
    ap.add_argument("--target-os", type=str, default="auto")
    ns, _unknown = ap.parse_known_args(argv)
    snap = _priv_helper.execute_kernel_snapshot_helper(
        trace_window_ms=ns.trace_ms,
        target_os=ns.target_os,
    )
    print(json.dumps(snap, ensure_ascii=False), flush=True)
    return 0 if snap.get("ok") else 1


def _run_iommu_helper_cli(argv: list[str]) -> int:
    import argparse
    import json
    from ss_core import priv_helper as _priv_helper

    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--apply-iommu-helper", action="store_true")
    ap.add_argument("--target-os", type=str, default="auto")
    ns, _unknown = ap.parse_known_args(argv)
    res = _priv_helper.execute_iommu_hardening_as_root(target_os=ns.target_os)
    print(json.dumps(res, ensure_ascii=False), flush=True)
    return 0 if res.get("ok") else 1


def _run_headless_scan(argv: list[str]) -> int:
    import argparse
    from ss_core import engine8_reporter as _e8, orchestrator as _orch
    from ss_core.models import ScanContext as _ScanCtx

    ap = argparse.ArgumentParser(description="MC SS Sentinel Headless Scan")
    ap.add_argument("--headless-scan", action="store_true")
    ap.add_argument("--home-dir", type=Path, default=None)
    ap.add_argument("--desktop-dir", type=Path, default=None)
    ap.add_argument("--kernel-lkm", action="store_true")
    ap.add_argument("--trace-ms", type=int, default=1500)
    ap.add_argument("--target-os", type=str, default="auto")
    args = ap.parse_args(argv)

    ctx = _ScanCtx(
        home_dir=args.home_dir if args.home_dir is not None else Path.home(),
        live_mode=True,
        enable_memory_scan=True,
        enable_kernel_lkm=bool(args.kernel_lkm),
        kernel_trace_ms=args.trace_ms,
        target_os=args.target_os,
        deep_home_scan=True,
    )
    _orch.run_all_engines(
        ctx,
        progress_pct_cb=lambda pct, msg: print(f"[%{pct:3d}] {msg}", flush=True),
    )
    txt_path, payload = _e8.write_desktop_txt_report(
        ctx, desktop_dir=args.desktop_dir
    )
    ass = payload["assessment"]
    print(
        f"TAMAMLANDI | KARAR={ass['verdict']} | RISK={ass['risk_score']}/100 | RAPOR={txt_path}",
        flush=True,
    )
    return 0


# Short-circuit privileged/headless CLI paths BEFORE importing Qt so root/TTY calls never touch Wayland/X11
if __name__ == "__main__" and "--kernel-snapshot-helper" in sys.argv[1:]:
    raise SystemExit(_run_kernel_helper_cli(sys.argv[1:]))
if __name__ == "__main__" and "--apply-iommu-helper" in sys.argv[1:]:
    raise SystemExit(_run_iommu_helper_cli(sys.argv[1:]))
if __name__ == "__main__" and "--headless-scan" in sys.argv[1:]:
    raise SystemExit(_run_headless_scan(sys.argv[1:]))

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QCloseEvent, QFont, QIcon, QPalette, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ss_core import distro_profiles, engine8_reporter, orchestrator, priv_helper
from ss_core.models import ScanContext

DEVELOPER_GITHUB_URL = "https://github.com/CmdSuv"
UI_FONT_FAMILY = "Cantarell"
UI_FONT_STACK = '"Cantarell", "Adwaita Sans", "Noto Sans", sans-serif'


def _make_ui_font(point_size: float, weight: QFont.Weight = QFont.Weight.Normal) -> QFont:
    font = QFont(UI_FONT_FAMILY)
    font.setPointSizeF(point_size)
    font.setWeight(weight)
    return font


def _asset_path(filename: str) -> Path | None:
    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(str(meipass)) / "assets" / filename)
    candidates.append(Path(__file__).resolve().parent / "assets" / filename)
    for c in candidates:
        if c.is_file():
            return c
    return None

CONSENT_CONTRACT_HTML = """
<div style="color:#e2e8f0; font-size:12.5px; line-height:1.55;">
  <h3 style="color:#ffffff; margin-top:0;">MC SS SENTINEL — AÇIK RIZA, AYDINLATMA VE KULLANIM SÖZLEŞMESİ</h3>
  <p>
    Bu uygulamayı başlatarak aşağıdaki tüm koşulları okuduğunuzu, anladığınızı ve
    bilgisayarınız üzerinde <b>tamamen kendi özgür iradeniz ve açık izninizle</b>
    adli kontrol (ScreenShare / SS) taraması yapılmasına onay verdiğinizi beyan etmiş olursunuz.
  </p>

  <h4 style="color:#60a5fa; margin-bottom:4px;">1. Gönüllü Kullanım ve Açık İzin</h4>
  <p>
    <b>MC SS Sentinel</b>, yalnızca kullanıcının kendi rızası ve onayıyla çalıştırılmak üzere
    tasarlanmış bir Linux masaüstü adli kontrol aracıdır. Aracı açmanız ve
    <b>"Tamam"</b> butonuna basmanız; kendi cihazınızda belirtilen sistem, dosya, süreç ve
    uygulama izlerinin yerel olarak incelenmesine açıkça izin verdiğiniz anlamına gelir.
    İzin vermiyorsanız pencereyi kapatabilir veya <b>"Reddet / Çıkış"</b> butonuna basarak
    hiçbir tarama yapılmadan programdan çıkabilirsiniz.
  </p>

  <h4 style="color:#60a5fa; margin-bottom:4px;">2. Tarama Kapsamı (İncelenecek Tüm Alanlar)</h4>
  <p>Tarama başlatıldığında araç cihazınız üzerinde salt-okunur (değişiklik yapmayan) olarak şu katmanları denetler:</p>
  <ul>
    <li><b>Çalışan Süreçler ve Bellek (RAM):</b> <code>/proc</code> süreç ağacı, ham <code>getdents64</code> / <code>readdir</code> gizli PID kıyası, bellek haritaları (<code>maps</code>), <code>smaps</code> <code>.text</code> CoW yama bütünlüğü, açık dosya tanıtıcıları (<code>fd</code>, <code>/dev/mem</code> / <code>/dev/uio*</code> erişimleri), Java / Minecraft / Wine süreçlerinin okunabilir RAM sayfaları, JVM <code>hsperfdata</code> ve aktif container ortamları.</li>
    <li><b>Minecraft ve Başlatıcı Kurulumları:</b> <code>.minecraft</code>, PrismLauncher, Lunar Client, HMCL ve Wine/Proton profilleri altındaki <code>mods/</code>, <code>resourcepacks/</code>, <code>shaderpacks/</code>, <code>libraries/</code>, <code>versions/</code>, <code>options.txt</code>, yapılandırma dosyaları ve oyun/çökme logları.</li>
    <li><b>Dosya Sistemi ve Derin İkili Analiz:</b> <code>Downloads</code>, <code>Desktop</code>, <code>Documents</code>, <code>.local/bin</code>, <code>/tmp</code>, <code>/dev/shm</code>, <code>/var/tmp</code> ve son saatlerde değiştirilen arşiv/çalıştırılabilir dosyalar; <code>statx</code> zaman damgaları, <code>xattr</code> nitelikleri, <code>.jar/.class</code> sabit havuzu ve ELF/PE imzaları.</li>
    <li><b>Sistem Bütünlüğü ve Kabuk İzleri:</b> Sistem çalışma süresi (<code>uptime</code>), <code>ptrace_scope</code>, saat/NTP durumu, kabuk geçmişleri (<code>.bash_history</code>, <code>.zsh_history</code>, <code>fish_history</code>), <code>LD_PRELOAD</code>, <code>$PATH</code> gölgeleme ve sistem/coredump kayıtları.</li>
    <li><b>Girdi ve Makro Katmanı:</b> <code>/dev/uinput</code>, <code>/proc/bus/input/devices</code>, <code>input-remapper</code>, Solaar, Piper/ratbag, OpenRazer, AutoKey, XClicker ve kullanıcı makro scriptleri.</li>
    <li><b>Masaüstü ve Tarayıcı İzleri:</b> <code>recently-used.xbel</code>, pano (Clipboard/Klipper) kayıtları, Çöp Kutusu (<code>Trash</code>), tarayıcı SQLite geçmiş/indirme kayıtları, Wine/Proton <code>user.reg</code> (UserAssist), <code>.java/.userPrefs</code> ve başlangıç kayıtları.</li>
    <li><b>Ağ ve Donanım İzleri:</b> <code>/proc/net</code> aktif soket bağlantıları, VPN/proxy yapılandırmaları, <code>/etc/hosts</code> ve USB aygıt geçmişi.</li>
    <li><b>Ring-0 Çekirdek, DMA/IOMMU ve eBPF Bütünlüğü (Yetkili Mod):</b> Kullanıcı onayıyla Polkit (<code>pkexec</code>) üzerinden geçici <code>mc_ss_kmod</code> çekirdek modülü yalnızca tarama süresince yüklenebilir; çekirdek fonksiyon prologları/kancaları, <code>CR3</code> sayfa izinleri, <code>MODXSCAN</code> yetim çekirdek sayfaları, <code>init_task</code> VMA RAM baytları (reflektif ELF, JNI ve <code>UPX!</code>/<code>.vmp</code> imzaları), geçici <code>sys_enter</code> tarama penceresi olayları (<code>ptrace</code>, <code>process_vm_writev</code>/<code>readv</code>, <code>memfd_create</code>, <code>execveat</code>, <code>uinput</code> <code>UI_DEV_CREATE</code>, <code>bpf</code>, modül yükleme, ham G/Ç portu), 4KB PCIe <code>DSN</code>/DMA/FPGA config uzayı, <code>/dev/mem</code>–<code>/dev/uio*</code> düğümleri, donanım IOMMU grupları, <code>/sys/kernel/btf/vmlinux</code> üzerinden eBPF <code>fentry</code>/<code>LSM</code> hedefleri ve <code>/sys/fs/bpf</code> pinlenmiş nesneleri salt-okunur denetlenir. Tarama bittiği anda sürücü <code>rmmod</code> ile çekirdekten tamamen çıkartılır.</li>
  </ul>

  <h4 style="color:#60a5fa; margin-bottom:4px;">3. Gizlilik, Yerel Çalışma ve Raporlama</h4>
  <p>
    Bu yazılım <b>%100 yerel (offline)</b> olarak çalışır. Tarama sırasında hiçbir dosyanızı,
    kişisel verinizi, tarayıcı geçmişinizi veya sistem bilginizi dış bir sunucuya göndermez,
    uzak bir yere yüklemez veya üçüncü taraflarla otomatik olarak paylaşmaz.
    Tarama tamamlandığında yalnızca kendi bilgisayarınızın <b>Masaüstüne (.txt)</b>
    detaylı bir rapor dosyası oluşturulur; bu raporu incelemek veya bir yetkiliyle paylaşıp
    paylaşmamak tamamen sizin kendi kontrolünüzdedir.
  </p>

  <h4 style="color:#60a5fa; margin-bottom:4px;">4. Salt-Okunur Tarama, Opsiyonel IOMMU Sertleştirme ve Sorumluluk Beyanı</h4>
  <p>
    MC SS Sentinel tarama sırasında sisteminizden veya oyun klasörlerinizden herhangi bir
    dosya silmez, değiştirmez ya da ayarlarınızı bozmaz; yalnızca okuma ve analiz işlemi yapar.
    Yalnızca kullanıcının ana penceredeki <b>"IOMMU / DMA Koruma"</b> butonundan
    <b>"IOMMU Korumasını Uygula (Yetkili)"</b> seçeneğine ayrıca basıp Polkit yönetici şifresiyle
    onay vermesi halinde çekirdek önyükleme parametreleri (<code>rpm-ostree kargs</code>,
    <code>grubby</code>, <code>GRUB</code>, <code>kernelstub</code>, <code>systemd-boot</code> veya <code>Limine</code>) donanımsal DMA izolasyonunu açmak üzere güncellenir ve yeniden başlatma
    sonrası etkinleşir. Derin dosya/bytecode taraması kurulu mod ve arşiv sayısına bağlı olarak birkaç dakika sürebilir.
  </p>

  <h4 style="color:#22c55e; margin-bottom:4px;">5. Onay Beyanı</h4>
  <p style="color:#ffffff;">
    <b>Yukarıdaki tüm maddeleri ve taranacak alanların kapsamını sonuna kadar okuduğumu,
    anladığımı; bu programı ve adli kontrol taramasını tamamen kendi rızam ve açık iznimle
    başlattığımı kabul, beyan ve onaylarım.</b>
  </p>
</div>
"""

DARK_SCROLLBAR_QSS = """
QScrollBar:vertical {
    background: #0a0a0a;
    width: 11px;
    margin: 0px;
    border-left: 1px solid #1f2937;
}
QScrollBar::handle:vertical {
    background: #334155;
    min-height: 28px;
    border-radius: 4px;
    margin: 2px;
}
QScrollBar::handle:vertical:hover {
    background: #475569;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: #050505;
}
"""


_PRIMARY_BTN_QSS = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3b82f6, stop:1 #1d4ed8);
    color: #ffffff;
    border: 1px solid #60a5fa;
    border-radius: 9px;
    padding: 8px 18px;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #60a5fa, stop:1 #2563eb);
}
QPushButton:pressed {
    background: #1e40af;
}
QPushButton:disabled {
    background: #0d1118;
    border-color: #1e293b;
    color: #4b5563;
}
"""

_SECONDARY_BTN_QSS = """
QPushButton {
    background-color: #0b0f17;
    color: #cbd5e1;
    border: 1px solid #253042;
    border-radius: 9px;
    padding: 8px 18px;
}
QPushButton:hover {
    background-color: #151c28;
    border-color: #3b4b63;
    color: #ffffff;
}
QPushButton:pressed {
    background-color: #090d14;
}
"""


class _ClickableOSCard(QFrame):
    """OS selection card that activates its radio button when clicked anywhere."""

    def __init__(self, radio: QRadioButton | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._radio = radio

    def bind_radio(self, radio: QRadioButton) -> None:
        self._radio = radio

    def mousePressEvent(self, event) -> None:  # type: ignore[override]
        if self._radio is not None:
            self._radio.setChecked(True)
        super().mousePressEvent(event)


def _load_app_icon() -> QIcon:
    p = _asset_path("mc_ss_sentinel.png")
    if p is None:
        fallback = Path.home() / ".local/share/icons/hicolor/256x256/apps/mc-ss-sentinel.png"
        if fallback.is_file():
            p = fallback
    if p is not None:
        ico = QIcon(str(p))
        if not ico.isNull():
            return ico
    return QIcon()


class ConsentDialog(QDialog):
    """Mandatory consent agreement dialog: user must scroll to the very bottom to enable 'Tamam'."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("MC SS Sentinel — Açık Rıza ve İzin Sözleşmesi")
        ico = _load_app_icon()
        if not ico.isNull():
            self.setWindowIcon(ico)
        self.setFixedSize(680, 560)
        self.setStyleSheet(
            f"QDialog {{ background-color: #000000; color: #f1f5f9; font-family: {UI_FONT_STACK}; }}"
            + DARK_SCROLLBAR_QSS
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 20)
        layout.setSpacing(12)

        hdr_card = QFrame(self)
        hdr_card.setObjectName("ConsentHdrCard")
        hdr_card.setStyleSheet(
            "#ConsentHdrCard { background-color: #080b11; border: 1px solid #1b2432; border-radius: 10px; }"
        )
        hdr_row = QHBoxLayout(hdr_card)
        hdr_row.setContentsMargins(16, 12, 16, 12)
        hdr_row.setSpacing(12)
        hdr_row.addStretch(1)

        logo_p = _asset_path("mc_ss_sentinel.png")
        if logo_p is not None:
            pix = QPixmap(str(logo_p)).scaled(
                34,
                34,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            badge = QLabel(hdr_card)
            badge.setPixmap(pix)
            badge.setFixedSize(34, 34)
            badge.setStyleSheet("background: transparent;")
            hdr_row.addWidget(badge)

        hdr_text = QVBoxLayout()
        hdr_text.setSpacing(2)
        header = QLabel("Kullanıcı İzni ve Adli Tarama Sözleşmesi", hdr_card)
        header.setFont(_make_ui_font(13.5, QFont.Weight.DemiBold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("color: #f8fafc; background: transparent;")
        hdr_text.addWidget(header)

        sub = QLabel(
            "Onaylamak ve işletim sistemi seçimine geçmek için metni en alta kaydırın.",
            hdr_card,
        )
        sub.setFont(_make_ui_font(9.2))
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("color: #8b9bb4; background: transparent;")
        hdr_text.addWidget(sub)
        hdr_row.addLayout(hdr_text)
        hdr_row.addStretch(1)
        layout.addWidget(hdr_card)

        self.contract_view = QTextEdit(self)
        self.contract_view.setReadOnly(True)
        self.contract_view.setFont(_make_ui_font(10))
        self.contract_view.setHtml(
            f"<div style=\"font-family:{UI_FONT_STACK};\">{CONSENT_CONTRACT_HTML}</div>"
        )
        self.contract_view.setStyleSheet(
            """
            QTextEdit {
                background-color: #070a0f;
                color: #dbe2ea;
                border: 1px solid #1b2432;
                border-radius: 10px;
                padding: 14px 16px;
            }
            """
        )
        layout.addWidget(self.contract_view, stretch=1)

        self.scroll_hint_label = QLabel(
            "Devam etmek için sözleşme metnini en alta kadar kaydırın.",
            self,
        )
        self.scroll_hint_label.setFont(_make_ui_font(9.3, QFont.Weight.DemiBold))
        self.scroll_hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll_hint_label.setStyleSheet(
            "color: #fbbf24; background-color: #0c0f16; border: 1px solid #262e3d; border-radius: 8px; padding: 6px 12px;"
        )
        layout.addWidget(self.scroll_hint_label)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(14)

        self.reject_button = QPushButton("Reddet / Çıkış", self)
        self.reject_button.setFixedHeight(40)
        self.reject_button.setFont(_make_ui_font(10, QFont.Weight.Medium))
        self.reject_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.reject_button.setStyleSheet(_SECONDARY_BTN_QSS)
        self.reject_button.clicked.connect(self.reject)
        btn_row.addWidget(self.reject_button, stretch=1)

        self.ok_button = QPushButton("Tamam", self)
        self.ok_button.setFixedHeight(40)
        self.ok_button.setEnabled(False)
        self.ok_button.setFont(_make_ui_font(10.2, QFont.Weight.DemiBold))
        self.ok_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ok_button.setStyleSheet(_PRIMARY_BTN_QSS)
        self.ok_button.clicked.connect(self.accept)
        btn_row.addWidget(self.ok_button, stretch=1)
        layout.addLayout(btn_row)

        self._reached_bottom = False
        sb = self.contract_view.verticalScrollBar()
        sb.valueChanged.connect(self._on_scroll_changed)
        sb.rangeChanged.connect(self._on_range_changed)
        QTimer.singleShot(0, self._sync_initial_scroll_state)

    def _sync_initial_scroll_state(self) -> None:
        sb = self.contract_view.verticalScrollBar()
        if sb.maximum() <= 0:
            self._unlock_accept()

    def _on_range_changed(self, _min_v: int, max_v: int) -> None:
        if max_v <= 0 and not self._reached_bottom and self.isVisible():
            self._unlock_accept()

    def _on_scroll_changed(self, value: int) -> None:
        if self._reached_bottom:
            return
        sb = self.contract_view.verticalScrollBar()
        if sb.maximum() > 0 and value >= sb.maximum() - 4:
            self._unlock_accept()

    def _unlock_accept(self) -> None:
        self._reached_bottom = True
        self.ok_button.setEnabled(True)
        self.scroll_hint_label.setStyleSheet(
            "color: #4ade80; background-color: #07150e; border: 1px solid #166534; border-radius: 8px; padding: 6px 12px;"
        )
        self.scroll_hint_label.setText(
            'Sözleşme sonuna kadar okundu. Onaylamak için "Tamam" butonuna basın.'
        )


class TargetOSDialog(QDialog):
    """Post-consent OS profile selector shown cleanly on #000000 black theme."""

    def __init__(
        self,
        default_target_os: str | None = None,
        root_prefix: Path = Path("/"),
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("MC SS Sentinel — İşletim Sistemi Seçimi")
        ico = _load_app_icon()
        if not ico.isNull():
            self.setWindowIcon(ico)
        self.setModal(True)
        self.setFixedSize(680, 610)
        self.setStyleSheet(
            f"QDialog {{ background-color: #000000; color: #f8fafc; font-family: {UI_FONT_STACK}; }}"
            f"{DARK_SCROLLBAR_QSS}"
        )

        initial_profile, host_det = distro_profiles.resolve_profile(
            target_os=default_target_os, root_prefix=root_prefix
        )
        baked = distro_profiles.get_baked_target_os()
        self.detected_host = host_det
        self.selected_target_os = initial_profile.target_id
        self.option_buttons: dict[str, QRadioButton] = {}
        self._option_cards: dict[str, QFrame] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 20, 26, 20)
        layout.setSpacing(12)

        hdr_box = QVBoxLayout()
        hdr_box.setSpacing(6)
        header = QLabel("Hangi İşletim Sistemi İçin Tarama Yapılsın?", self)
        header.setFont(_make_ui_font(13.5, QFont.Weight.DemiBold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("color: #f8fafc; background: transparent;")
        hdr_box.addWidget(header)

        host_pill_row = QHBoxLayout()
        host_pill_row.addStretch(1)
        host_lbl = QLabel(
            f"Algılanan Sistem: {host_det.pretty_name}  •  Çekirdek: {host_det.kernel_release}",
            self,
        )
        host_lbl.setFont(_make_ui_font(9.0, QFont.Weight.Medium))
        host_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        host_lbl.setStyleSheet(
            "color: #93c5fd; background-color: #09111e; border: 1px solid #1e3a5f; border-radius: 7px; padding: 4px 12px;"
        )
        host_pill_row.addWidget(host_lbl)
        host_pill_row.addStretch(1)
        hdr_box.addLayout(host_pill_row)
        layout.addLayout(hdr_box)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background-color: #000000; border: none;")
        list_host = QWidget(scroll)
        list_host.setStyleSheet("background-color: #000000;")
        list_layout = QVBoxLayout(list_host)
        list_layout.setContentsMargins(0, 2, 6, 2)
        list_layout.setSpacing(8)

        self._btn_group = QButtonGroup(self)
        for tid in distro_profiles.TARGET_ORDER:
            prof = distro_profiles.DISTRO_PROFILES[tid]
            card = _ClickableOSCard(parent=list_host)
            card.setObjectName(f"OsCard_{tid}")
            card.setCursor(Qt.CursorShape.PointingHandCursor)
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(14, 10, 14, 10)
            card_layout.setSpacing(3)

            top_row = QHBoxLayout()
            top_row.setSpacing(8)

            rb = QRadioButton(prof.display_name, card)
            rb.setFont(_make_ui_font(10.2, QFont.Weight.DemiBold))
            rb.setCursor(Qt.CursorShape.PointingHandCursor)
            rb.setStyleSheet(
                "QRadioButton { color: #f8fafc; background: transparent; spacing: 8px; }"
                "QRadioButton::indicator { width: 15px; height: 15px; }"
            )
            card.bind_radio(rb)
            top_row.addWidget(rb, stretch=1)

            if tid == host_det.target_id:
                det_pill = QLabel("Algılanan", card)
                det_pill.setFont(_make_ui_font(8.2, QFont.Weight.DemiBold))
                det_pill.setStyleSheet(
                    "color: #4ade80; background-color: #062112; border: 1px solid #166534; border-radius: 6px; padding: 2px 8px;"
                )
                top_row.addWidget(det_pill)
            if baked and tid == baked:
                def_pill = QLabel("Varsayılan", card)
                def_pill.setFont(_make_ui_font(8.2, QFont.Weight.DemiBold))
                def_pill.setStyleSheet(
                    "color: #93c5fd; background-color: #0b162a; border: 1px solid #1e3a5f; border-radius: 6px; padding: 2px 8px;"
                )
                top_row.addWidget(def_pill)

            sub = QLabel(prof.subtitle, card)
            sub.setFont(_make_ui_font(8.8))
            sub.setStyleSheet("color: #94a3b8; background: transparent; padding-left: 23px;")
            sub.setWordWrap(True)

            card_layout.addLayout(top_row)
            card_layout.addWidget(sub)
            self._btn_group.addButton(rb)
            self.option_buttons[tid] = rb
            self._option_cards[tid] = card
            rb.toggled.connect(lambda checked, target_id=tid: checked and self._select_os(target_id))
            list_layout.addWidget(card)

        list_layout.addStretch(1)
        scroll.setWidget(list_host)
        layout.addWidget(scroll, stretch=1)

        self.detail_label = QLabel("", self)
        self.detail_label.setFont(_make_ui_font(9.0))
        self.detail_label.setWordWrap(True)
        self.detail_label.setStyleSheet(
            "background-color: #080b11; color: #cbd5e1; border: 1px solid #1b2432; border-radius: 9px; padding: 10px 14px;"
        )
        layout.addWidget(self.detail_label)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(14)
        self.back_button = QPushButton("Vazgeç / Çıkış", self)
        self.back_button.setFixedHeight(40)
        self.back_button.setFont(_make_ui_font(10, QFont.Weight.Medium))
        self.back_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.back_button.setStyleSheet(_SECONDARY_BTN_QSS)
        self.back_button.clicked.connect(self.reject)
        btn_row.addWidget(self.back_button, stretch=1)

        self.confirm_button = QPushButton("Seçili Sistemle Devam Et", self)
        self.confirm_button.setFixedHeight(40)
        self.confirm_button.setFont(_make_ui_font(10.0, QFont.Weight.DemiBold))
        self.confirm_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.confirm_button.setStyleSheet(_PRIMARY_BTN_QSS)
        self.confirm_button.clicked.connect(self.accept)
        btn_row.addWidget(self.confirm_button, stretch=1)
        layout.addLayout(btn_row)

        if initial_profile.target_id in self.option_buttons:
            self.option_buttons[initial_profile.target_id].setChecked(True)
        self._select_os(initial_profile.target_id)

    def _select_os(self, target_id: str) -> None:
        self.selected_target_os = target_id
        prof = distro_profiles.DISTRO_PROFILES[target_id]
        for tid, card in self._option_cards.items():
            if tid == target_id:
                card.setStyleSheet(
                    f"#{card.objectName()} {{ background-color: #0d1424; border: 1px solid #3b82f6; border-radius: 8px; }}"
                )
            else:
                card.setStyleSheet(
                    f"#{card.objectName()} {{ background-color: #080a0e; border: 1px solid #1c222d; border-radius: 8px; }}"
                )
        self.detail_label.setText(
            f"<b>Çekirdek / Ring-0:</b> {prof.kernel_notes}<br>"
            f"<b>Kullanıcı Alanı / İzler:</b> {prof.userspace_notes}<br>"
            f"<b>IOMMU Önyükleme:</b> {prof.iommu_notes}"
        )


class ScanWorker(QThread):
    """Runs the 9-engine forensic scan off the UI thread and writes Desktop .txt."""

    progress_changed = Signal(int, str)
    scan_completed = Signal(str, dict)
    scan_failed = Signal(str)

    def __init__(
        self,
        home_dir: Path | None = None,
        desktop_dir: Path | None = None,
        enable_kernel_lkm: bool = False,
        target_os: str = "auto",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._home_dir = home_dir if home_dir is not None else Path.home()
        self._desktop_dir = desktop_dir
        self._enable_kernel_lkm = enable_kernel_lkm
        self._target_os = target_os

    def run(self) -> None:
        try:
            ctx = ScanContext(
                home_dir=self._home_dir,
                live_mode=True,
                enable_memory_scan=True,
                enable_kernel_lkm=self._enable_kernel_lkm,
                target_os=self._target_os,
                deep_home_scan=True,
            )

            def _on_pct(pct: int, msg: str) -> None:
                self.progress_changed.emit(max(0, min(98, pct)), msg)

            orchestrator.run_all_engines(ctx, progress_pct_cb=_on_pct)
            self.progress_changed.emit(99, "Detayli rapor Masaustune yaziliyor...")
            txt_path, payload = engine8_reporter.write_desktop_txt_report(
                ctx, desktop_dir=self._desktop_dir
            )
            self.progress_changed.emit(100, "Tarama tamamlandi.")
            self.scan_completed.emit(str(txt_path), payload)
        except Exception as exc:
            self.scan_failed.emit(str(exc))


class IommuApplyWorker(QThread):
    """Applies opt-in IOMMU kernel parameter hardening off the UI thread."""

    finished_with_result = Signal(dict)

    def __init__(self, target_os: str = "auto", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target_os = target_os

    def run(self) -> None:
        try:
            res = priv_helper.apply_iommu_hardening(target_os=self._target_os)
            self.finished_with_result.emit(res if isinstance(res, dict) else {"ok": False, "message": str(res)})
        except Exception as exc:
            self.finished_with_result.emit({"ok": False, "message": str(exc)})


class SentinelMainWindow(QMainWindow):
    """Pitch-black classic minimal GUI window: single 'Tara' button + bottom progress bar + CmdSuv credit."""

    def __init__(
        self,
        home_dir: Path | None = None,
        desktop_dir: Path | None = None,
        enable_kernel_lkm_default: bool = False,
        target_os: str = "auto",
    ) -> None:
        super().__init__()
        self._home_dir = home_dir
        self._desktop_dir = desktop_dir
        profile, _ = distro_profiles.resolve_profile(target_os=target_os)
        self._target_os = profile.target_id
        self._distro_profile = profile
        self._worker: ScanWorker | None = None
        self._iommu_worker: IommuApplyWorker | None = None

        self.setWindowTitle("MC SS Sentinel")
        ico = _load_app_icon()
        if not ico.isNull():
            self.setWindowIcon(ico)
        self.setFixedSize(560, 468)
        self.setStyleSheet(
            f"QMainWindow {{ background-color: #000000; color: #f8fafc; font-family: {UI_FONT_STACK}; }}"
        )

        central = QWidget(self)
        central.setStyleSheet(f"background-color: #000000; font-family: {UI_FONT_STACK};")
        self.setCentralWidget(central)

        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(28, 24, 28, 18)
        root_layout.setSpacing(14)

        # Centered symmetric hero header
        hero_box = QVBoxLayout()
        hero_box.setSpacing(6)
        hero_row = QHBoxLayout()
        hero_row.setSpacing(10)
        hero_row.addStretch(1)
        logo_p = _asset_path("mc_ss_sentinel.png")
        if logo_p is not None:
            pix = QPixmap(str(logo_p)).scaled(
                36,
                36,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            logo_lbl = QLabel(central)
            logo_lbl.setPixmap(pix)
            logo_lbl.setFixedSize(36, 36)
            logo_lbl.setStyleSheet("background: transparent;")
            hero_row.addWidget(logo_lbl)

        title_lbl = QLabel("MC SS Sentinel", central)
        title_lbl.setFont(_make_ui_font(16.5, QFont.Weight.DemiBold))
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setStyleSheet("color: #f8fafc; background: transparent;")
        hero_row.addWidget(title_lbl)
        hero_row.addStretch(1)
        hero_box.addLayout(hero_row)

        sub_lbl = QLabel("Linux Derin Adli Hile Kontrol Aracı", central)
        sub_lbl.setFont(_make_ui_font(9.4))
        sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub_lbl.setStyleSheet("color: #8b9bb4; background: transparent;")
        hero_box.addWidget(sub_lbl)

        os_bar = QHBoxLayout()
        os_bar.setSpacing(8)
        os_bar.addStretch(1)
        self.os_badge_label = QLabel(f"Hedef OS: {self._distro_profile.display_name}", central)
        self.os_badge_label.setFixedHeight(28)
        self.os_badge_label.setFont(_make_ui_font(8.8, QFont.Weight.DemiBold))
        self.os_badge_label.setStyleSheet(
            "color: #93c5fd; background-color: #0b1220; border: 1px solid #1e3a5f; border-radius: 7px; padding: 0px 12px;"
        )
        os_bar.addWidget(self.os_badge_label)

        self.change_os_button = QPushButton("OS Değiştir", central)
        self.change_os_button.setFixedHeight(28)
        self.change_os_button.setFont(_make_ui_font(8.8, QFont.Weight.Medium))
        self.change_os_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.change_os_button.setStyleSheet(
            "QPushButton { background-color: #0c111b; color: #cbd5e1; border: 1px solid #283344; border-radius: 7px; padding: 0px 12px; }"
            "QPushButton:hover { border-color: #3b82f6; color: #ffffff; background-color: #131c2c; }"
        )
        self.change_os_button.clicked.connect(self.select_target_os)
        os_bar.addWidget(self.change_os_button)
        os_bar.addStretch(1)
        hero_box.addLayout(os_bar)
        root_layout.addLayout(hero_box)

        sep = QFrame(central)
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #161d28; border: none;")
        root_layout.addWidget(sep)

        # Symmetric options card (checkbox with real checkmark + matching IOMMU action button)
        opts_card = QFrame(central)
        opts_card.setObjectName("OptsCard")
        opts_card.setFixedHeight(50)
        opts_card.setStyleSheet(
            "#OptsCard { background-color: #080b11; border: 1px solid #1b2432; border-radius: 10px; }"
        )
        opts_row = QHBoxLayout(opts_card)
        opts_row.setContentsMargins(14, 8, 14, 8)
        opts_row.setSpacing(10)

        check_png = _asset_path("check_white.png")
        checked_img_qss = (
            f"image: url({check_png.as_posix()});"
            if check_png is not None
            else ""
        )
        self.kernel_lkm_checkbox = QCheckBox(
            "Ring-0 Kernel LKM + DMA/IOMMU", opts_card
        )
        self.kernel_lkm_checkbox.setToolTip(
            "Polkit yetkisiyle geçici mc_ss_kmod.ko yükler; tarama bitince otomatik kaldırır (Gir-Tara-Çık)."
        )
        self.kernel_lkm_checkbox.setFont(_make_ui_font(9.5, QFont.Weight.Medium))
        self.kernel_lkm_checkbox.setCursor(Qt.CursorShape.PointingHandCursor)
        self.kernel_lkm_checkbox.setChecked(enable_kernel_lkm_default)
        self.kernel_lkm_checkbox.setStyleSheet(
            f"""
            QCheckBox {{
                color: #dbe2ea;
                background: transparent;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 17px;
                height: 17px;
                border: 1px solid #384457;
                background-color: #0d1117;
                border-radius: 5px;
            }}
            QCheckBox::indicator:hover {{
                border-color: #f59e0b;
            }}
            QCheckBox::indicator:checked {{
                background-color: #d97706;
                border-color: #f59e0b;
                {checked_img_qss}
            }}
            """
        )
        opts_row.addWidget(self.kernel_lkm_checkbox, stretch=1)

        self.iommu_button = QPushButton("IOMMU / DMA Koruma", opts_card)
        self.iommu_button.setMinimumHeight(30)
        self.iommu_button.setFont(_make_ui_font(9.0, QFont.Weight.DemiBold))
        self.iommu_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.iommu_button.setStyleSheet(
            """
            QPushButton {
                background-color: #10151f;
                color: #fbbf24;
                border: 1px solid #2a3342;
                border-radius: 7px;
                padding: 4px 12px;
            }
            QPushButton:hover {
                background-color: #182030;
                border-color: #f59e0b;
                color: #fde68a;
            }
            QPushButton:pressed {
                background-color: #0d1119;
            }
            """
        )
        self.iommu_button.clicked.connect(self.show_iommu_dialog)
        opts_row.addWidget(self.iommu_button)
        root_layout.addWidget(opts_card)

        # Refined primary 'Tara' CTA button
        self.scan_button = QPushButton("Tara", central)
        self.scan_button.setMinimumHeight(46)
        self.scan_button.setFont(_make_ui_font(11.5, QFont.Weight.DemiBold))
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.setStyleSheet(_PRIMARY_BTN_QSS)
        self.scan_button.clicked.connect(self.start_scan)
        root_layout.addWidget(self.scan_button)

        # Balanced centered status card
        self.status_frame = QFrame(central)
        self.status_frame.setObjectName("StatusCard")
        self.status_frame.setFrameShape(QFrame.Shape.StyledPanel)
        self.status_frame.setStyleSheet(
            "#StatusCard { background-color: #080b11; border: 1px solid #1b2432; border-radius: 10px; }"
        )
        frame_layout = QVBoxLayout(self.status_frame)
        frame_layout.setContentsMargins(16, 12, 16, 12)
        frame_layout.setSpacing(2)

        self.status_label = QLabel(
            "Hazır — Taramayı başlatmak için Tara butonuna basın.",
            self.status_frame,
        )
        self.status_label.setFont(_make_ui_font(10.0))
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.status_label.setStyleSheet(
            "color: #cbd5e1; border: none; background: transparent;"
        )
        frame_layout.addWidget(self.status_label)
        root_layout.addWidget(self.status_frame, stretch=1)

        # Sleek percentage progress bar
        self.progress_bar = QProgressBar(central)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p%")
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFont(_make_ui_font(9.2, QFont.Weight.DemiBold))
        self.progress_bar.setMinimumHeight(24)
        self.progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_bar.setStyleSheet(
            """
            QProgressBar {
                border: 1px solid #1c222d;
                border-radius: 8px;
                background-color: #080a0e;
                color: #f8fafc;
                text-align: center;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #16a34a, stop:1 #22c55e);
                border-radius: 7px;
            }
            """
        )
        root_layout.addWidget(self.progress_bar)

        # Symmetric footer: left engine badge mirrors right developer credit
        footer_row = QHBoxLayout()
        footer_row.setContentsMargins(2, 2, 2, 0)
        self.ver_label = QLabel("v2.0 • 9 Motor + Ring-0", central)
        self.ver_label.setFont(_make_ui_font(8.8))
        self.ver_label.setStyleSheet("color: #64748b; background: transparent;")
        footer_row.addWidget(self.ver_label)
        footer_row.addStretch(1)
        self.dev_label = QLabel(
            f'<span style="color:#64748b;">Geliştirici:</span> '
            f'<a href="{DEVELOPER_GITHUB_URL}" style="color:#60a5fa; text-decoration:none; font-weight:600;">CmdSuv</a> '
            f'<span style="color:#475569;">•</span> '
            f'<a href="{DEVELOPER_GITHUB_URL}" style="color:#60a5fa; text-decoration:none;">github.com/CmdSuv</a>',
            central,
        )
        self.dev_label.setFont(_make_ui_font(8.8))
        self.dev_label.setTextFormat(Qt.TextFormat.RichText)
        self.dev_label.setOpenExternalLinks(True)
        self.dev_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.dev_label.setStyleSheet("background: transparent;")
        footer_row.addWidget(self.dev_label)
        root_layout.addLayout(footer_row)

    def select_target_os(self) -> None:
        dlg = TargetOSDialog(default_target_os=self._target_os, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            prof, _ = distro_profiles.resolve_profile(target_os=dlg.selected_target_os)
            self._target_os = prof.target_id
            self._distro_profile = prof
            self.os_badge_label.setText(f"Hedef OS: {prof.display_name}")
            self.status_label.setText(f"Hedef OS profili güncellendi: {prof.display_name}")

    def start_scan(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self.scan_button.setEnabled(False)
        self.kernel_lkm_checkbox.setEnabled(False)
        self.change_os_button.setEnabled(False)
        self.scan_button.setText("Taranıyor...")
        self.progress_bar.setValue(0)
        self.status_label.setFont(_make_ui_font(10.0))
        self.status_label.setStyleSheet(
            "color: #e2e8f0; border: none; background: transparent;"
        )
        self.status_label.setText(f"[{self._distro_profile.short_name}] Tarama başlatılıyor...")

        self._worker = ScanWorker(
            home_dir=self._home_dir,
            desktop_dir=self._desktop_dir,
            enable_kernel_lkm=self.kernel_lkm_checkbox.isChecked(),
            target_os=self._target_os,
            parent=self,
        )
        self._worker.progress_changed.connect(self._on_progress)
        self._worker.scan_completed.connect(self._on_completed)
        self._worker.scan_failed.connect(self._on_failed)
        self._worker.start()

    def show_iommu_dialog(self) -> None:
        plan = priv_helper.build_iommu_hardening_plan(target_os=self._target_os)
        comp = plan["compliance"]
        lines = [
            f"Hedef OS        : {self._distro_profile.display_name} ({plan.get('bootloader', 'auto')})",
            f"CPU Türü        : {comp['cpu_vendor']}",
            f"ACPI DMAR/IVRS  : DMAR={comp['acpi_dmar_present']} | IVRS={comp['acpi_ivrs_present']}",
            f"IOMMU Aktif     : {'EVET' if comp['iommu_active'] else 'HAYIR (DMA RİSKİ!)'}",
            f"IOMMU Grupları  : {comp['iommu_group_count']} | Katı Mod (strict): {comp['strict_enabled']}",
            f"Passthrough     : {comp['passthrough_enabled']} | Devredışı Bayrak: {comp['forced_off']}",
            "",
            plan["summary"],
        ]
        if plan["commands"]:
            lines.append("")
            lines.append("Önerilen Önyükleme Komutu:")
            for cmd in plan["commands"]:
                lines.append("  " + " ".join(cmd))

        box = QMessageBox(self)
        box.setWindowTitle("IOMMU & DMA Donanım Koruma Durumu")
        box.setStyleSheet(
            "QMessageBox { background-color: #000000; color: #f8fafc; }"
            "QLabel { color: #f8fafc; background-color: #000000; }"
            "QPushButton { background-color: #1e293b; color: #ffffff; border: 1px solid #475569; padding: 6px 14px; border-radius: 4px; }"
        )
        box.setText("\n".join(lines))
        if plan["needed"] and plan["commands"] and plan.get("can_auto_apply", True):
            apply_btn = box.addButton("IOMMU Korumasını Uygula (Yetkili)", QMessageBox.ButtonRole.AcceptRole)
            box.addButton("Kapat", QMessageBox.ButtonRole.RejectRole)
            box.exec()
            if box.clickedButton() == apply_btn:
                if self._iommu_worker is not None and self._iommu_worker.isRunning():
                    return
                self.iommu_button.setEnabled(False)
                self.iommu_button.setText("Uygulanıyor...")
                self.status_label.setText(
                    f"IOMMU çekirdek parametreleri uygulanıyor ({plan.get('bootloader', 'bootloader')})..."
                )
                self._iommu_worker = IommuApplyWorker(target_os=self._target_os, parent=self)
                self._iommu_worker.finished_with_result.connect(self._on_iommu_applied)
                self._iommu_worker.start()
        else:
            box.addButton("Tamam", QMessageBox.ButtonRole.AcceptRole)
            box.exec()

    def _on_iommu_applied(self, res: dict[str, Any]) -> None:
        self.iommu_button.setEnabled(True)
        self.iommu_button.setText("IOMMU / DMA Koruma")
        self.status_label.setText(res.get("message", "IOMMU işlemi tamamlandı."))
        QMessageBox.information(self, "IOMMU Sertleştirme", res.get("message", ""))

    def closeEvent(self, event: QCloseEvent) -> None:
        for th in (self._worker, self._iommu_worker):
            if th is not None and th.isRunning():
                th.wait(1500)
                if th.isRunning():
                    th.terminate()
                    th.wait(500)
        super().closeEvent(event)

    def _on_progress(self, pct: int, msg: str) -> None:
        self.progress_bar.setValue(pct)
        self.status_label.setText(f"[%{pct}] {msg}")

    def _on_completed(self, _txt_path: str, _payload: dict[str, Any]) -> None:
        self.progress_bar.setValue(100)
        self.scan_button.setEnabled(True)
        self.kernel_lkm_checkbox.setEnabled(True)
        self.change_os_button.setEnabled(True)
        self.scan_button.setText("Tara")
        self.status_label.setStyleSheet(
            "color: #4ade80; border: none; background: transparent;"
        )
        self.status_label.setFont(_make_ui_font(10.0, QFont.Weight.DemiBold))
        self.status_label.setText("Tarama tamamlandı. Rapor masaüstüne kaydedildi.")

    def _on_failed(self, err: str) -> None:
        self.scan_button.setEnabled(True)
        self.kernel_lkm_checkbox.setEnabled(True)
        self.change_os_button.setEnabled(True)
        self.scan_button.setText("Tara")
        self.status_label.setFont(_make_ui_font(10.0))
        self.status_label.setStyleSheet(
            "color: #f87171; border: none; background: transparent;"
        )
        self.status_label.setText(f"Tarama hatası: {err}")


def _apply_black_palette(app: QApplication) -> None:
    app.setStyle("Fusion")
    app.setFont(_make_ui_font(10.0))
    pal = QPalette()
    black = QColor("#000000")
    near_black = QColor("#070707")
    white = QColor("#f8fafc")
    pal.setColor(QPalette.ColorRole.Window, black)
    pal.setColor(QPalette.ColorRole.WindowText, white)
    pal.setColor(QPalette.ColorRole.Base, near_black)
    pal.setColor(QPalette.ColorRole.AlternateBase, black)
    pal.setColor(QPalette.ColorRole.Text, white)
    pal.setColor(QPalette.ColorRole.Button, QColor("#111111"))
    pal.setColor(QPalette.ColorRole.ButtonText, white)
    pal.setColor(QPalette.ColorRole.Highlight, QColor("#2563eb"))
    pal.setColor(QPalette.ColorRole.HighlightedText, white)
    app.setPalette(pal)


def _run_smoke_gui_offscreen(argv: list[str]) -> int:
    import argparse

    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--smoke-gui-offscreen", action="store_true")
    ap.add_argument("--target-os", type=str, default="auto")
    ns, _unknown = ap.parse_known_args(argv)

    app = QApplication.instance() or QApplication([])
    _apply_black_palette(app)
    c = ConsentDialog()
    assert not c.windowIcon().isNull()
    o = TargetOSDialog(default_target_os=None if ns.target_os == "auto" else ns.target_os)
    w = SentinelMainWindow(target_os=o.selected_target_os)
    assert not w.windowIcon().isNull()
    c.close()
    o.close()
    w.close()
    print(f"GUI_SMOKE_OK target={o.selected_target_os}", flush=True)
    return 0


def main() -> int:
    if "--kernel-snapshot-helper" in sys.argv[1:]:
        return _run_kernel_helper_cli(sys.argv[1:])

    if "--apply-iommu-helper" in sys.argv[1:]:
        return _run_iommu_helper_cli(sys.argv[1:])

    if "--headless-scan" in sys.argv[1:]:
        return _run_headless_scan(sys.argv[1:])

    if "--smoke-gui-offscreen" in sys.argv[1:]:
        return _run_smoke_gui_offscreen(sys.argv[1:])

    app = QApplication(sys.argv)
    _apply_black_palette(app)
    app.setApplicationName("MC SS Sentinel")
    app.setDesktopFileName("MC-SS-Sentinel")
    ico = _load_app_icon()
    if not ico.isNull():
        app.setWindowIcon(ico)

    consent = ConsentDialog()
    if consent.exec() != QDialog.DialogCode.Accepted:
        return 0

    os_dlg = TargetOSDialog()
    if os_dlg.exec() != QDialog.DialogCode.Accepted:
        return 0
    selected_os = os_dlg.selected_target_os

    prereqs = priv_helper.check_kernel_prereqs(target_os=selected_os)
    lkm_available = bool(
        priv_helper.find_lkm_object() is not None
        or prereqs.get("lkm_vermagic_match")
        or prereqs.get("headers_present")
    )
    win = SentinelMainWindow(
        enable_kernel_lkm_default=lkm_available,
        target_os=selected_os,
    )
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

# MC SS Sentinel

**Linux için 9 Katmanlı Derin Adli Hile Kontrol (ScreenShare / SS) & Ring-0 Çekirdek Analiz Aracı**

**Geliştirici / Telif Sahibi:** Omar Yiğitcan Mengü ([GitHub: CmdSuv](https://github.com/CmdSuv))  
**Sürüm:** `2.0.0` | **Dil:** Python 3.10+ · PySide6 (Qt6) · Pure C (Linux Kernel LKM + Userspace Probe)

---

## Nedir?

**MC SS Sentinel**, Linux sistemlerde Minecraft (ve genel sistem/girdi/bellek düzeyi hileleri) için tasarlanmış, tamamen **yerel (offline)** çalışan, tarama motorları bütünüyle **salt-okunur** olan çok katmanlı adli kontrol (SS) aracıdır (yalnızca kullanıcı tarafından açıkça onaylanan *IOMMU/DMA Korumasını Aç* özelliği önyükleyici parametrelerine `.mc_ss_sentinel.bak` yedeği alarak yazar).

Klasik yalnızca dosya adına bakan araçların aksine kullanıcı izniyle çalışan **9 bağımsız analiz motorunu**, **yerel C sondasını (`ss_kernel_probe`)** ve x86_64 çekirdekler için geçici **"Gir-Tara-Çık" Ring-0 Linux Çekirdek Modülünü (`mc_ss_kmod.ko`)** bir araya getirir.

---

## Öne Çıkan Özellikler

- **%100 Yerel ve Açık Rıza Kapılı:** Dış sunucuya veri göndermez. Açılışta en alta kaydırılmadan onaylanmayan **Açık Rıza Sözleşmesi** ve ardından **İşletim Sistemi Profil Seçici** açılır.
- **Sade ve Anlaşılır Raporlama:** Tarama bitiminde Masaüstüne (`MC_SS_Raporu_*.txt`) anlaşılır Türkçe yönetici özeti, 6 ayrı risk alanı ayrımı (Hile Kanıtı, Adli Manipülasyon, Çekirdek Bütünlüğü, DMA/Donanım, Sistem Güvenliği, Tarama Kapsamı), önem derecesine göre gruplanmış kanıt kartları (`2A Kritik/Yüksek`, `2B Orta`, `2C Düşük/Bilgi`), sadeleştirilmiş Sistem/Ring-0 tablosu ve SHA-256 bütünlük doğrulaması yazar.
- **Ekran Paylaşımı (SS) Dostu Arayüz:** Tarama tamamlandığında arayüzde kırmızı risk/karar metni göstermez; yalnızca raporun masaüstüne kaydedildiğini bildirir.
- **7 Büyük Linux Dağıtımı İçin Özel Profiller ve Derleme Desteği:**
  - `bazzite` — Bazzite / Fedora Atomic (`rpm-ostree`)
  - `fedora_nobara` — Fedora Workstation & Nobara (`dnf` + `grubby`)
  - `ubuntu_24_04` — Ubuntu 24.04 LTS / Linux Mint 22 / Pop!_OS 24.04 (Snap + `AppArmor`)
  - `ubuntu_22_04` — Ubuntu 22.04 LTS / Linux Mint 21 / Pop!_OS 22.04 (`5.15 GA` & `6.8 HWE`)
  - `debian` — Debian 12 Bookworm / Debian 13 Trixie / MX Linux
  - `arch_cachyos` — Arch Linux / CachyOS / EndeavourOS / Garuda (`GCC` & `Clang/LLVM=1` Kernel)
  - `steamos` — SteamOS 3 (Steam Deck / Valve Holo + MicroSD `/run/media`)

---

## 9 Adli Analiz Katmanı

| Motor | Kapsam |
| :--- | :--- |
| **E1 — Sistem Bütünlüğü** | `uptime`, `ptrace_scope`, saat/NTP manipülasyonu, Bash/Zsh/Fish geçmiş temizliği, `LD_PRELOAD`, `$PATH` gölgeleme, `journalctl` / `coredumpctl` |
| **E2 — Canlı Süreçler & RAM** | `/proc` süreç ağacı, `/proc/<pid>/maps` ve `smaps` `.text` yama kontrolü, `memfd:` / silinmiş `.jar`/`.so`, Java/Minecraft RAM imza taraması, `hsperfdata` & container tespiti |
| **E3 — Girdi & Makro** | `/dev/uinput`, `/proc/bus/input/devices`, `input-remapper`, Solaar, Piper/`ratbagd`, OpenRazer, AutoKey, XClicker ve makro scriptleri |
| **E4 — Derin Dosya & Bytecode** | `.minecraft`/launcher kurulumları, `Downloads`, `Desktop`, `/tmp`, `/dev/shm`; `.jar`/`.class` sabit havuzu (mixin/cheat API/obfuscation), polyglot dosyalar, `statx` timestomp, `xattr` |
| **E5 — Minecraft İzleri** | Vanilla & tüm launcher profilleri (Prism, Lunar, Modrinth, HMCL, Wine/Proton), `options.txt`, oyun logları, `hs_err_pid` |
| **E6 — Masaüstü & Tarayıcı** | `recently-used.xbel`, pano/Klipper, Çöp Kutusu, tarayıcı SQLite geçmiş + WAL + freelist kalıntıları, Wine `user.reg` UserAssist, `.java/.userPrefs` |
| **E7 — Ağ & USB** | `/proc/net` soketleri, VPN tünelleri, yerel SOCKS/HTTP proxy portları, `/etc/hosts` yönlendirmeleri, USB donanım geçmişi |
| **E8 — Korelasyon & Raporlama** | Çoklu motor korelasyon kuralları (`WIPE-CHAIN`, `GHOST-RAM`, `JVM-INJECT`, `RING0-ROOTKIT`, `DMA-EXPOSURE` vb.), 6 alanlı açıklanabilir puanlama ve `.txt`/`.html`/`.json`/`.sha256` raporları |
| **E9 — Ring-0 Kernel & eBPF/DMA** | Polkit ile x86_64 çekirdeklerde geçici `mc_ss_kmod.ko` (`5.15–7.3+`), `ss_kernel_probe` (`sys_bpf` + `getdents64` gizli PID cross-view + PCIe 4KB config), `ftrace`/syscall/VFS kanca taraması, yetim kernel bellek/VMA bayt taraması ve **IOMMU / DMA** koruması |

---

## Proje Dizin Yapısı

```text
mc-ss-forensics/
├── ss_gui.py                   # Qt6 (PySide6) masaüstü arayüzü (Sözleşme -> OS Seçici -> Tarama)
├── ss_sentinel.py              # CLI giriş noktası & yardımcı modlar
├── ss_core/                    # E1–E9 analiz motorları, dağıtım profilleri ve yetki yardımcısı
├── kernel/                     # Ephemeral Ring-0 LKM (mc_ss_kmod.c, mc_ss_kmod.h, Makefile)
├── native/                     # Pure C kullanıcı-modu sondası (ss_kernel_probe.c: eBPF, pid_cross, PCIe)
├── assets/                     # Uygulama simgesi ve UI görselleri
├── packaging/                  # 7 dağıtım için Containerfile/Dockerfile, build_inside_container.sh, doğrulayıcı
├── scripts/                    # Çoklu hedef container derleme yöneticisi (build_distro_targets.py)
├── tests/                      # 81 birim ve entegrasyon testi
├── launch_ss_sentinel.sh       # Terminal tabanlı hızlı başlatıcı
├── LICENSE                     # Zorunlu Atıf, Ticari Olmayan & Değişmez Lisans (+ kernel/ GPL-2.0 notu)
└── README.md
```

---

## Kurulum ve Kaynaktan Çalıştırma

### Gereksinimler
- Python `>= 3.10`
- `PySide6` (veya dağıtım paketi `python3-pyside6` / `pyside6`)
- `gcc`, `make` (native probe derlemesi için)
- Opsiyonel Ring-0 LKM modu için: çalışan çekirdeğe uygun `kernel-devel` / `linux-headers-$(uname -r)` ve `kmod`

### 1. Native C Aracını Derle ve Testleri Çalıştır
```bash
make -C native
QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s tests
```

### 2. GUI / CLI Olarak Başlat
```bash
# Masaüstü Arayüzü (Sözleşme -> OS Seçici -> Tara)
python3 ss_gui.py

# Komut Satırı (Headless Masaüstü Raporu)
python3 ss_gui.py --headless-scan --target-os auto
```

### 3. Belirli Bir Linux Hedefi İçin Tek-Parça ELF Derleme (Podman / Container)
Her dağıtımın kendi `glibc` ve çekirdek başlıklarıyla tek dosya (`targets/<hedef>/MC-SS-Sentinel`) üretmek için:
```bash
python3 scripts/build_distro_targets.py --targets ubuntu_24_04 --cpus 6 --memory 4g --cleanup-image
```
Desteklenen hedef kimlikleri: `bazzite`, `fedora_nobara`, `ubuntu_24_04`, `ubuntu_22_04`, `debian`, `arch_cachyos`, `steamos`.

---

## Lisans ve Telif Hakkı

**Copyright (c) 2026 Omar Yiğitcan Mengü** ([CmdSuv](https://github.com/CmdSuv)). Tüm hakları saklıdır.

- Kaynak kod ve ikililer **ücretsiz olarak kopyalanabilir, paylaşılabilir, incelenebilir ve güncellenebilir**.
- **Satılamaz, ticari kazanç amacıyla kullanılamaz ve başka bir kişiye aitmiş gibi gösterilemez.**
- Herhangi bir kopyalama, paylaşım, kullanım veya güncelleme işleminde projedeki **orijinal [`LICENSE`](LICENSE) dosyası ve Omar Yiğitcan Mengü telif bildirimi eksiksiz olarak korunmak zorundadır**; lisansın değiştirilmesi veya silinmesi hukuken yasaktır.
- `kernel/` dizinindeki Linux çekirdek modülü dosyaları çekirdek uyumluluğu gereği `GPL-2.0-only` altındadır; ayrıntılar için [`LICENSE`](LICENSE) dosyasına bakın.

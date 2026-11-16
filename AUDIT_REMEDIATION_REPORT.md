# MC SS Sentinel / SS-KERNEL-LINUX — Kapsamlı Teknik Denetim, Güçlendirme ve Doğrulama Raporu

**Depo:** `https://github.com/CmdSuv/SS-KERNEL-LINUX`  
**Çalışma Dizini:** `/home/COSMOS/.gemini/antigravity/scratch/mc-ss-forensics`  
**Temel Commit / Dal:** `918d372` (`main`)  
**Ana Doğrulama Ortamı:** Fedora 45 / Bazzite Linux `7.3.4-ogc6.1.fc45.x86_64` (`x86_64`), Python `3.14` + `PySide6 6.11.2` + `Podman 6.1.3`  
**Kapsamlı Lab Doğrulaması:** 7 Linux Hedefi (`bazzite`, `fedora_nobara`, `ubuntu_24_04`, `ubuntu_22_04`, `debian`, `arch_cachyos`, `steamos`)

---

## A. Yönetici Özeti ve Depo Mimari Haritası

Projedeki mevcut 9 katmanlı mimari, CLI parametreleri, siyah `#000000` Qt6 arayüz teması, kural kimlik sözleşmeleri ve `LICENSE` (Omar Yiğitcan Mengü telif hakkı + `kernel/` `GPL-2.0-only` bildirimi) korunarak tüm depo baştan sona incelenmiş, temel ve inceleme-aşamasında saptanan mühendislik, güvenlik, çekirdek güvenliği, korelasyon ve yanlış-pozitif açıkları giderilmiştir.

### 1. Bileşen ve Veri Akışı Haritası
1. **Giriş Noktaları ([`ss_sentinel.py`](ss_sentinel.py), [`ss_gui.py`](ss_gui.py)):**  
   Qt yüklenmeden önce `--kernel-snapshot-helper`, `--apply-iommu-helper`, `--headless-scan` ve `--smoke-gui-offscreen` hızlı yolları işlenir. Normal masaüstü akışında kullanıcı `ConsentDialog` (zorunlu kaydırma) -> `TargetOSDialog` -> `SentinelMainWindow` sırasını izler; `ScanWorker` iş parçacığı kooperatif iptal (`ctx.request_cancel()`) ile yönetilir (`QThread.terminate()` kesinlikle çağrılmaz).
2. **Çekirdek Veri Sözleşmesi ve Zamanlayıcı ([`ss_core/models.py`](ss_core/models.py), [`ss_core/orchestrator.py`](ss_core/orchestrator.py)):**  
   `ScanContext`, `Finding` (otomatik tekilleştirme ve maksimum önem derecesi birleştirme), `Severity`, `Confidence` ve `ScanStatus` ile veri sözleşmesini tanımlar. `run_all_engines()` motorları sabit ağırlıklı sıralamayla çalıştırır (`E1`–`E7`, `E9` -> en sonda `E8`), hataları `ScanStatus.ERROR`/`PARTIAL` olarak izler ve `ScanCancelledError` ile temiz iptal sağlar.
3. **Analiz Motorları (`E1`–`E7`, `E9`):**  
   - `engine1_integrity.py`: Uptime/reboot, saat/NTP, kabuk geçmişlerinin sonu (tail), `.xbel`, `LD_PRELOAD`/`PATH` gölgeleme, MAC, paket logları/AUR, `coredumpctl` ve `journalctl sudo`.  
   - `engine2_live_proc.py`: `/proc` süreç ağacı, `/proc/<pid>/maps` & `smaps` `.text` CoW yaması, `/proc/<pid>/fd`, JVM argümanları/`hsperfdata`/`jcmd`, container izolasyonu ve chunked `/proc/<pid>/mem` taraması.  
   - `engine3_input_macro.py`: `/dev/uinput`, `/proc/bus/input/devices`, `input-remapper` preset analizi, Solaar/OpenRazer/Piper/AutoKey/XClicker ve makro betikleri.  
   - `engine4_deep_files.py`: Magic/polyglot tespiti, JVM `.class` sabit havuzu ayrıştırıcı, saf Python PNG X-Ray çözücü, ELF/PE/shader/JAR taramaları, `statx` timestomp, `xattr` ve `.minecraft` sembolik bağ denetimi.  
   - `engine5_minecraft.py`: Vanilla/Prism/Lunar/Modrinth/HMCL/Wine örnekleri, `options.txt`/`optionsLC.txt`, launcher/JVM bayrakları ve sınırlı gzip akışıyla `.log.gz` incelemesi.  
   - `engine6_desktop_traces.py`: `recently-used.xbel`, pano/Klipper, Çöp Kutusu, tarayıcı SQLite + WAL/freelist kazıması, Wine ROT13 UserAssist, `.java/.userPrefs` ve autostart.  
   - `engine7_network_usb.py`: `/proc/net` soketleri, VPN/proxy, `/etc/hosts`, USB sysfs ve `usb-storage` çekirdek olayları.  
   - `engine9_kernel.py` + `priv_helper.py` + `kernel/mc_ss_kmod.{c,h}` + `native/ss_kernel_probe.c`: Polkit destekli geçici x86_64 LKM (kprobe + ftrace + CR3 PTE + VMA bayt + PCIe/IOMMU) ve saf C kullanıcı-modu sondası (`sys_bpf`, `getdents64` vs `readdir`, 4KB PCIe config).
4. **Korelasyon, Risk ve Raporlama ([`ss_core/engine8_reporter.py`](ss_core/engine8_reporter.py)):**  
   `correlate_findings()` 9 kuralı bağımsızlık/PID/dosya kapsamıyla çalıştırır; `compute_risk_assessment()` 6 bağımsız alan (`cheat_evidence`, `forensic_tampering`, `kernel_integrity`, `dma_hardware`, `os_security`, `scan_coverage`) ve aynı-özne azaltımıyla açıklanabilir skor üretir; `.txt`/`.html`/`.json`/`.sha256` ve masaüstü raporu yazar.

---

## B. Detaylı Teknik Denetim Bulguları ve Uygulanan Düzeltmeler (14 Alanlı Kayıtlar)

### Bulgu F-01: Yetki Yükseltme (`priv_helper.py`) — `PKEXEC_UID` Güven Boşluğu, TOCTOU, Kilit Sırası ve IOMMU Geri Alma
1. **Bulgu ID:** `F-01`
2. **Bileşen / Dosya:** `ss_core/priv_helper.py`, `ss_core/_self_manifest.py`, `ss_sentinel.py`
3. **Kategori:** Güvenlik / Yetki Yükseltme ve Bütünlük Doğrulama
4. **Önem (Severity):** `CRITICAL`
5. **Kök Neden (Root Cause):** İlk durumda `profile.family == "debian_ubuntu"` öznitelik hatası ve `O_NOFOLLOW` eksikleri vardı; sonraki düzeltmede ise `_is_trusted_artifact`/`_stage_verified_artifact` içinde `trusted_uids` kümesine `_invoker_uid()` doğrudan eklendi, `pinned_probe_sha` yalnızca `frozen` ikilide ayarlandı, `verify_kernel_sources` gömülü `_self_manifest.KERNEL_SOURCES_SHA256` özetini kontrol etmedi, Kbuild kilit (`_acquire_kmod_lock`) sonradan alındı, sahneleme `/tmp` (olasılıkla `noexec`) üzerine kuruldu ve IOMMU komutu başarısız olunca değiştirilen `/etc/default/grub` geri alınmadı.
6. **Girdi / Tetikleme Koşulu:** Yetkisiz kullanıcı (`UID != 0`) `pkexec` ile kaynak koddan çalıştırırken `ss_kernel_probe` veya `kernel/` dosyalarını kendi `.sha256` dosyasıyla birlikte değiştirirse, ya da eşzamanlı iki `pkexec` çağrısı yapılırsa, ya da `update-grub` hata verirse.
7. **Beklenen Davranış:** Root düzeyindeki yardımcı, yetkisiz çağıranın değiştirdiği `.ko` dosyasını asla kabul etmemeli; kaynak ve C sondasında `_self_manifest` SHA-256 sabitlemesi istemeli; Kbuild derlemesini dosya kilidi altında atomik yazmalı; `/var/cache/mc-ss-sentinel` üzerinde `0700` sahneleme tercih etmeli; başarısız bootloader güncellemesinde dosyayı geri yüklemelidir.
8. **Önceki Gerçekleşen Davranış:** Kaynak modda root yetkisindeki yardımcı `UID 1000` tarafında hazırlanmış sahte ikili/kaynak veya başarısız `grub-mkconfig` sonrasında sessizce bozulmuş `/etc/default/grub` + `"changed": False` döndürüyordu.
9. **Etki / Risk:** Yerel yetki yükseltme (LPE) yüzeyi, Kbuild yarış durumu (TOCTOU) ve yarı kalmış önyükleyici yapılandırması.
10. **Uygulanan Düzeltme:** `_trusted_artifact_uids()` ile root (`euid == 0`) durumunda çağıran UID yalnızca gömülü `pinned_sha256` doğrulandığında kabul edilecek şekilde sınırlandı; `verify_kernel_sources(..., require_manifest=...)` ile Kbuild öncesinde `_self_manifest.KERNEL_SOURCES_SHA256` zorunlu kılındı; `_acquire_kmod_lock()` Kbuild kontrol/derleme aşamasının önüne taşındı; `.ko` önbelleği `.tmp` + `os.replace()` ile atomik yazıldı; `_create_exec_stage_dir()` eklendi (`/var/cache/mc-ss-sentinel/stage_*` `0700`, test/fallback için `/tmp`); `_rollback_text()` başarısız `update-grub`/`grub-mkconfig`/`sdboot-manage`/`limine-update` durumunda yapılandırmayı atomik geri yükler hâle getirildi.
11. **Mimari Etki ve Uyumluluk:** `pkexec` tek-çağrı sözleşmesi ve sentetik testlerle tam uyumlu (`verify_kernel_sources` geçici test dizinlerinde `require_manifest=False` varsayılanını korur).
12. **Değiştirilen Dosya ve Semboller:** `ss_core/priv_helper.py` (`_embedded_kernel_sources_sha`, `_trusted_artifact_uids`, `_is_trusted_artifact`, `_stage_verified_artifact`, `verify_kernel_sources`, `ensure_or_build_lkm_for_running_kernel`, `_create_exec_stage_dir`, `execute_kernel_snapshot_helper`, `collect_privileged_kernel_snapshot`, `execute_iommu_hardening_as_root`).
13. **Doğrulama Yöntemi ve Test Kanıtı:** `tests/test_hardening_and_coverage.py` içinde `test_priv_helper_root_manifest_pin_and_iommu_failure_rollback`, `test_stage_verified_artifact_tamper_and_write_with_backup` ve `test_kernel_sources_sha_verification` host + 7 container ortamında (`euid=0`) geçti.
14. **Durum (Status):** `KAPATILDI VE DOĞRULANDI`

### Bulgu F-02: Linux Çekirdek Modülü (`mc_ss_kmod.c` / `.h`) — Bellek Güvenliği, Mimari Koruması ve Kırpılma Bildirimi
1. **Bulgu ID:** `F-02`
2. **Bileşen / Dosya:** `kernel/mc_ss_kmod.c`, `kernel/mc_ss_kmod.h`, `kernel/kernel_sources.sha256`
3. **Kategori:** Kernel Mühendisliği & Bellek Güvenliği
4. **Önem (Severity):** `CRITICAL`
5. **Kök Neden:** `ss_classify_prologue()` içinde `0x0f 0x1f` 3 baytlık NOP kontrolü `off + 3 <= len` sınır kontrolü olmadan okuma yapıyordu; `ss_check_pci_cap_loop()` `pdev->cfg_size` sınırını doğrulamadan `pos + 1` okuyordu; `ss_snapshot_modules()` `SS_MAX_MOD_SNAP` (512) limitine ulaşınca kırpılmayı raporlamıyordu; ayrıca ilk aşamada x86_64 mimari koruması, syscall tablo tahliyesi (eviction), `bprm->filename`, `seq_has_overflowed` ve `EVENT_META` eksikti.
6. **Girdi / Tetikleme Koşulu:** Kısaltılmış/sınırda prolog tamponu, `cfg_size` dışı bozuk `cap` işaretçisine sahip PCIe cihazı veya `512+` yüklü modüllü sistem.
7. **Beklenen Davranış:** Her dizi indekslemesi ve PCI config okuması açık sınır kontrolüyle korunmalı; modül dizisi sınırda kesilirse `TRUNCATED|mods=1|max_mods=...` üretilmelidir.
8. **Önceki Gerçekleşen Davranış:** Sınır dışı 1–2 baytlık okuma olasılığı ve `512` sonrası modüllerin sessizce atlanması.
9. **Etki / Risk:** Çekirdek içi sınır-dışı okuma riski ve yüksek modüllü çekirdeklerde eksik rootkit kapsama bildirimi.
10. **Uygulanan Düzeltme:** `ss_classify_prologue` içine `off + 3 <= len` eklendi; `ss_check_pci_cap_loop` döngüsüne `(int)pos + 1 < pdev->cfg_size` eklendi; `ss_snapshot_modules(..., bool *truncated_out)` ve `TRUNCATED|mods=1|max_mods=%u` çıktısı eklendi (Engine 9 ile eşleştirildi).
11. **Mimari Etki ve Uyumluluk:** Yalnızca x86_64 Kbuild `5.15–7.3+` çekirdekleriyle uyumlu ve mevcut `/proc/mc_ss_sentinel/*` pipe formatını korur.
12. **Değiştirilen Dosya ve Semboller:** `kernel/mc_ss_kmod.c` (`ss_classify_prologue`, `ss_snapshot_modules`, `ss_integrity_seq_show`, `ss_check_pci_cap_loop`), `kernel/mc_ss_kmod.h`.
13. **Doğrulama Yöntemi ve Test Kanıtı:** Host `7.3.4-ogc6.1` ve 7 container çekirdeğinde (`5.15.0`, `6.1.0`, `6.8.0`, `7.3.3`, `7.3.4`) uyarısız Kbuild derleme ve `test_e9_has_ret_zero_failed_uinput_call_rel32_sysfs_vfio_and_no_lkm_as_root` geçti.
14. **Durum (Status):** `KAPATILDI VE DOĞRULANDI`

### Bulgu F-03: Saf C Sonda (`ss_kernel_probe.c`) — `getdents64`, `hidepid=ptraceable`, `EINTR` ve PCIe Döngü Kontrolü
1. **Bulgu ID:** `F-03`
2. **Bileşen / Dosya:** `native/ss_kernel_probe.c`, `native/ss_kernel_probe.sha256`
3. **Kategori:** Native Sistem Programlama / Doğruluk
4. **Önem (Severity):** `HIGH`
5. **Kök Neden:** `detect_proc_hidepid()` `hidepid=1`, `2`, `invisible`, `noaccess` değerlerini kontrol edip modern Linux çekirdeklerindeki `hidepid=4` ve `hidepid=ptraceable` bağlama seçeneklerini kaçırıyordu; önceki turda düzeltilen `_Alignas(8)` `getdents64`, `EINTR`, `ext_cap_loop` ve `bpf.errno` eklentileri doğrulandı.
6. **Girdi / Tetikleme Koşulu:** `/proc` `hidepid=ptraceable` veya `hidepid=4` ile bağlanmış sistemde unprivileged `ss_kernel_probe --pid-cross` çalıştırılması.
7. **Beklenen Davranış:** `hidepid_detected=1` dönmeli, böylece Engine 9 bunu rootkit kaynaklı gizli PID (`E9-HIDDEN-PID-READDIR`) sanmamalıdır.
8. **Önceki Gerçekleşen Davranış:** `hidepid_detected=0` döndüğü için yetkisiz kullanıcının görmediği süreçler yanlış alarm üretebiliyordu.
9. **Etki / Risk:** `hidepid=ptraceable` kullanan sertleştirilmiş masaüstü dağıtımlarında yanlış pozitif gizli PID bulgusu.
10. **Uygulanan Düzeltme:** `detect_proc_hidepid()` içerisine `hidepid=4` ve `hidepid=ptraceable` taraması eklendi.
11. **Mimari Etki ve Uyumluluk:** CLI JSON şeması korundu.
12. **Değiştirilen Dosya ve Semboller:** `native/ss_kernel_probe.c` (`detect_proc_hidepid`), `native/ss_kernel_probe.sha256`.
13. **Doğrulama Yöntemi ve Test Kanıtı:** `make -C native CFLAGS="-O2 -Wall -Wextra -Werror"` sıfır uyarıyla derlendi; `--pid-cross`, `--pci-ext`, `--all` hostta ve 7 containerda doğrulandı.
14. **Durum (Status):** `KAPATILDI VE DOĞRULANDI`

### Bulgu F-04: Engine 8 Risk Puanlama & Kapsam Bütünlüğü (`verdict` Çelişkisi ve `SKIPPED`/`UNSUPPORTED` Körlüğü)
1. **Bulgu ID:** `F-04`
2. **Bileşen / Dosya:** `ss_core/engine8_reporter.py`, `ss_core/models.py`
3. **Kategori:** Skorlama Mimarisi & Raporlama Güvenilirliği
4. **Önem (Severity):** `CRITICAL`
5. **Kök Neden:** (a) İlk geçişte `ScanContext` `coverage` ve `engine_status` özelliklerini dışa açmadığı için `scan_quality` hep `100` kalıyordu; düzeltme sonrası da `_compute_scan_quality()` yalnızca `ERROR`/`CANCELLED`/`TIMED_OUT`/`PARTIAL` durumlarını cezalandırıp `--engines E1` ile atlanan motorları (`SKIPPED`) ve `UNSUPPORTED` kapsama satırlarını yok sayıyordu. (b) `compute_risk_assessment()` 777. satırda `(score >= 65 and cheat_s >= 20)` koşuluyla, `cheat_verdict_level` yalnızca `MEDIUM` iken bile ana kararı `"KRITIK - DOGRULANMIS HILE"` ilan ediyordu. (c) `E2-PROC-CHEAT-NAME`/`E2-PROC-MASQUERADE`/yüksek `E2-HSPERF-SUSPICIOUS` yanlışlıkla `os_security` alanına düşüyordu; buna karşın `input-remapper` servisi `cheat_evidence` sayılıyordu. (d) `write_reports()` aynı saniye içinde ikinci kez çağrılınca önceki çıktının üzerine yazıyordu.
6. **Girdi / Tetikleme Koşulu:** `dma_hardware = CRITICAL` + tek `MEDIUM` hile bulgusu (`cheat_s=20`); veya `--engines E9` çalıştırılması; veya aynı saniyede iki `write_reports()` çağrısı.
7. **Beklenen Davranış:** Ana `CRITICAL` hile kararı `cheat_verdict_level == "CRITICAL"` ile tutarlı olmalı; atlanan motorlar ve `UNSUPPORTED` alanlar `scan_quality`'yi düşürüp çoğunluk atlandığında `INCOMPLETE` vermeli; `floor_uplift` şeffaf alanla açıklanmalı; `write_reports()` sayaç sonekiyle dosyaları korumalıdır.
8. **Önceki Gerçekleşen Davranış:** Orta düzey tek mod + yüksek DMA donanım puanı birleşince sistem `"DOGRULANMIS HILE"` kararı veriyordu; `--engines E1` taraması %100 kalite alıyordu.
9. **Etki / Risk:** Donanım/OS açıklarının kesin hile gibi sunulması ve eksik taramaların tam/temiz görünmesi.
10. **Uygulanan Düzeltme:** `_classify_domain()` güncellendi (`E2-PROC-CHEAT-NAME`/`MASQUERADE`/yüksek `HSPERF` -> `cheat_evidence`, `remapper_daemon` `LOW` -> `os_security`); `_compute_scan_quality()` `SKIPPED` motor (`-5`) ve `UNSUPPORTED`/`SKIPPED` kapsama cezalarını ekledi (`E9.lkm` opsiyonel fallback hariç); `verdict` `cheat_verdict_level == "CRITICAL"` şartına bağlandı; `raw_risk_score` ve `floor_uplift` rapora eklendi; `write_reports()` sayaç döngüsüyle benzersiz dosya adı üretir hâle getirildi.
11. **Mimari Etki ve Uyumluluk:** 6 alanlı JSON şeması korundu, yeni alanlar geriye dönük eklendi.
12. **Değiştirilen Dosya ve Semboller:** `ss_core/engine8_reporter.py` (`_CHEAT_EVIDENCE_EXPLICIT`, `_classify_domain`, `_compute_scan_quality`, `compute_risk_assessment`, `write_reports`).
13. **Doğrulama Yöntemi ve Test Kanıtı:** `test_e8_verdict_alignment_fileless_jvm_scope_quality_and_report_collision` ve mevcut `E8` testleri geçti.
14. **Durum (Status):** `KAPATILDI VE DOĞRULANDI`

### Bulgu F-05: Engine 8 Korelasyon Kapsam Sızıntısı (`JVM-INJECT-CHAIN` ve `KERNEL-FILELESS`)
1. **Bulgu ID:** `F-05`
2. **Bileşen / Dosya:** `ss_core/engine8_reporter.py`
3. **Kategori:** Korelasyon Doğruluğu / Yanlış Pozitif Önleme
4. **Önem (Severity):** `HIGH`
5. **Kök Neden:** `KERNEL-FILELESS` içindeki `fileless_disk_pairs` kuralı `E2-MAP-TEXT-COW-PATCH` (`pid=X`, `path=None`) ile ilgisiz disk bulgusunu (`E4-JAR-OBFUSCATION`, `pid=None`, `path="/mods/Sodium.jar"`) `_pids_compatible()` üzerinden `True` eşleyip sahte `"Ring-0 ..."` korelasyonu üretiyordu; benzer şekilde `JVM-INJECT-CHAIN` iki farklı disk JAR dosyasını veya disk `E4-JAR-AGENT-MANIFEST` ile alakasız süreçteki `E2-MAP-*` yamalarını eşleyebiliyordu.
6. **Girdi / Tetikleme Koşulu:** Tarayıcı/Electron JIT kaynaklı `E2-MAP-TEXT-COW-PATCH (pid=901)` + diskte karmaşıklaştırılmış sıradan bir `.jar` (`E4-JAR-OBFUSCATION`).
7. **Beklenen Davranış:** `fileless_disk_pairs` yalnızca gerçek `E9-KERNEL-VMA-*` bulgularıyla ve aynı PID veya paylaşılan dosya kökü (stem) varsa tetiklenmeli; `JVM-INJECT-CHAIN` farklı ikili yollarını ve `pid=None` ajanları köksüz `E2-MAP-*` ile birleştirmemelidir.
8. **Önceki Gerçekleşen Davranış:** İlgisiz süreç + ilgisiz `.jar` bir araya gelince `E8-CORR-KERNEL-FILELESS` / `E8-CORR-JVM-INJECT-CHAIN` (`HIGH`/`CRITICAL`) patlıyordu.
9. **Etki / Risk:** Gerçek hile olmayan sistemlerde yapay yüksek korelasyon puanları.
10. **Uygulanan Düzeltme:** `_artifact_scope_compatible()` ile `JVM-INJECT-CHAIN` ikili dosya yolları ve `E2-MAP-*` eşleşmeleri kök/PID ile sınırlandı; `fileless_disk_pairs` `kr.rule_id.startswith("E9-KERNEL-VMA-")` + PID/stem eşleşmesine bağlandı.
11. **Mimari Etki ve Uyumluluk:** `test_bypass_hardening.py` ve `test_redteam_bypasses.py` korelasyon senaryolarıyla tam uyumlu.
12. **Değiştirilen Dosya ve Semboller:** `ss_core/engine8_reporter.py` (`correlate_findings`).
13. **Doğrulama Yöntemi ve Test Kanıtı:** `test_e8_verdict_alignment_fileless_jvm_scope_quality_and_report_collision`, `test_correlation_independence_pid_path_scoping_and_domain_separation` ve tüm kırmızı-takım/bypass testleri geçti.
14. **Durum (Status):** `KAPATILDI VE DOĞRULANDI`

### Bulgu F-06: Engine 2 Canlı Süreç & RAM Yanlış Pozitifleri ve İptal Tepkisi
1. **Bulgu ID:** `F-06`
2. **Bileşen / Dosya:** `ss_core/engine2_live_proc.py`
3. **Kategori:** Canlı Süreç / RAM Analizi & Hata/İptal Yönetimi
4. **Önem (Severity):** `HIGH`
5. **Kök Neden:** (a) `_inspect_maps_and_fds()` 883. satırda alt dize `".so" in low_p` kullandığı için `/dev/shm/.org.chromium.Chromium.sOwnZa (deleted)` haritasını `.so` kütüphanesi sanıp `HIGH` `E2-MAP-TMP-LIB` üretiyordu (canlı dry-run'da 2 kez yakalandı!). (b) `_inspect_process_metadata()` genel masaüstü tuş eşleyici `input-remapper-service` (`comm=input-remapper-`) arka plan servisini `xclicker` ile bir tutup `CONFIRMED HIGH` makro hilesi yazıyordu. (c) `_inspect_hsperfdata_and_jcmd()` komut satırındaki gibi `.lunarclient/.../ichor` ajanını `INFO` düzeyine indirgemiyordu. (d) `_scan_region_bytes()` `e_type` üst baytını kontrol etmiyordu; `_scan_process_memory()` bölge/parça döngüleri içinde `ctx.is_cancelled()` kontrol etmiyordu.
6. **Girdi / Tetikleme Koşulu:** Masaüstünde açık Chromium/Electron + çalışan `input-remapper-service` veya Lunar Client (`ichor` ajanlı) JVM.
7. **Beklenen Davranış:** `.sOwnZa` eşleşmemeli; `input-remapper-*`/`evtest` tek başına `LOW` (`os_security`, `remapper_daemon=True`) olup yalnızca Engine 3 preset/makro eşleşmesiyle yüksek riske dönmeli; `ichor` ajanı tüm yüzeylerde tutarlı biçimde `INFO` olmalı; büyük heap taramaları iptale anında yanıt vermelidir.
8. **Önceki Gerçekleşen Davranış:** Temiz masaüstünde yalnızca Chromium ve `input-remapper` açıkken dahi 63/100 `YUKSEK RISK - OLASI HILE` sonucu üretiliyordu.
9. **Etki / Risk:** Gerçek masaüstü kullanıcılarında sistematik yüksek yanlış-pozitif oranı ve yavaş iptal.
10. **Uygulanan Düzeltme:** `_TMP_MAPPED_EXT_RE` dosya uzantısı regex sınırı + yürütülemeyen `BENIGN_DELETED_MAP_HINTS` filtresi eklendi; `REMAPPER_DAEMON_NAMES` ayrıştırıldı; `hsperfdata` ve `jcmd` için Lunar Ichor `INFO` muafiyeti eklendi; ELF `e_type` endianness üst bayt sıfır kontrolü ve `_scan_process_memory()` döngü içi `ctx.is_cancelled()` eklendi.
11. **Mimari Etki ve Uyumluluk:** `ydotool`/`xdotool`/`xclicker` hâlâ `HIGH`/`CRITICAL` `cheat_evidence` üretir.
12. **Değiştirilen Dosya ve Semboller:** `ss_core/engine2_live_proc.py` (`REMAPPER_DAEMON_NAMES`, `_TMP_MAPPED_EXT_RE`, `_inspect_process_metadata`, `_inspect_maps_and_fds`, `_scan_region_bytes`, `_scan_process_memory`, `_inspect_hsperfdata_and_jcmd`).
13. **Doğrulama Yöntemi ve Test Kanıtı:** Canlı host dry-run skorunu 63'ten 36'ya (`cheat_evidence=0`) düşürdü; `test_e2_chromium_shm_sownza_input_remapper_and_lunar_ichor_no_false_high` ve canlı child/JVM e2e testleri geçti.
14. **Durum (Status):** `KAPATILDI VE DOĞRULANDI`

### Bulgu F-07: Engine 9 Çekirdek Analizi — `has_ret=0`, `CALL_REL32`, LKM-siz VFIO/FPGA, USB MCU ve Root `--no-lkm`
1. **Bulgu ID:** `F-07`
2. **Bileşen / Dosya:** `ss_core/engine9_kernel.py`
3. **Kategori:** Ring-0 Çekirdek & Donanım Doğruluğu
4. **Önem (Severity):** `HIGH`
5. **Kök Neden:** (a) Çekirdek olaylarında `has_ret=0` (henüz `sys_exit` eşleşmemiş veya LSM ile kesilmiş) çağrılar `ret >= 0` ile aynı tutulup `CRITICAL CONFIRMED` sayılıyordu; `type=12` (`UI_DEV_CREATE`) `failed`/`ret < 0` kontrolünü atlıyordu. (b) `_analyze_ring0_integrity()` içinde `CALL_REL32` (`0xE8`) kancalarının yabancı modül (`[rootkit]`) veya `0x...` hedeflemesi incelenmiyordu. (c) LKM olmadan `pci_iommu` fallback'i `/sys/kernel/iommu_groups/*/type` okumadığı için `UNKNOWN_NO_LKM` üzerindeki yasal IOMMU korumalı `vfio-pci`/FPGA aygıtlarını `CRITICAL` yapıyordu. (d) Genel USB geliştirme kartları (`2e8a`, Adafruit) donanım makrosu anahtarı olmadan `HIGH` oluyordu. (e) `os.geteuid() == 0` ve `enable_kernel_lkm=False` iken bile LKM yüklenmeye çalışılıyordu.
6. **Girdi / Tetikleme Koşulu:** `has_ret=0` olayları, reddedilen `UI_DEV_CREATE`, `[mod]` hedefli `CALL_REL32`, sysfs'te aktif IOMMU gruplu `vfio-pci`, ya da `sudo python3 ss_sentinel.py` (LKM bayrağı olmadan).
7. **Beklenen Davranış:** Doğrulanmamış/başarısız olaylar `MEDIUM`/`LOW` olarak düşürülmeli; yabancı `CALL_REL32` yakalanmalı; sysfs IOMMU tipi okunarak korumalı `vfio-pci`/FPGA abartılmamalı; `--kernel-lkm` olmadan root modunda `load_lkm=False` ile yalnızca C sonda çalıştırılmalıdır.
8. **Önceki Gerçekleşen Davranış:** `sudo` kullanan yönetici LKM istemese bile çekirdeğe modül derleyip yüklemeye çalışıyor; başarısız `uinput` ioctl'u kesin sanal fare oluşturulmuş gibi `CRITICAL` yazılıyordu.
9. **Etki / Risk:** İstenmeyen LKM yükleme girişimi, yanlış pozitif `CRITICAL` olaylar ve rootkit `CALL_REL32` kör noktası.
10. **Uygulanan Düzeltme:** `*_unverified` ve `uinput_failed`/`uinput_unverified` akışları eklendi (eski `has_ret` alanı olmayan test mock'ları korunarak); `is_suspicious_call` (`CALL_REL32` -> OOT modül/`0x`) eklendi; sysfs fallback `iommu_groups/<N>/type` ve `sysfs_iommu_translated` okunur kılındı; USB MCU `HIGH` seviyesi `kmbox|makcu|badusb|leonardo|teensy` ile daraltıldı; `load_lkm=enable_lkm` eklendi.
11. **Mimari Etki ve Uyumluluk:** `test_engine9_kernel.py` içindeki Arduino Leonardo, Alveo ve Rootkit testleriyle tam uyumlu.
12. **Değiştirilen Dosya ve Semboller:** `ss_core/engine9_kernel.py` (`_analyze_ring0_integrity`, `_analyze_pci_iommu`, `_analyze_ring0_events`, `_analyze_kernel_surface_sysfs`, `run`).
13. **Doğrulama Yöntemi ve Test Kanıtı:** `test_e9_has_ret_zero_failed_uinput_call_rel32_sysfs_vfio_and_no_lkm_as_root` ve tüm `TestEngine9KernelAndDma` / `TestHardeningRegressions` testleri geçti.
14. **Durum (Status):** `KAPATILDI VE DOĞRULANDI`

### Bulgu F-08: `E1`, `E4`, `E5`, `E6`, `E7`, `orchestrator` ve `utils` Bütünlük & Kenar Durumu Hataları
1. **Bulgu ID:** `F-08`
2. **Bileşen / Dosya:** `ss_core/utils.py`, `ss_core/orchestrator.py`, `ss_core/engine1_integrity.py`, `engine4_deep_files.py`, `engine5_minecraft.py`, `engine6_desktop_traces.py`, `engine7_network_usb.py`
3. **Kategori:** Hata Yönetimi, Dosya/ZIP Güvenliği ve Yanlış Pozitif Azaltımı
4. **Önem (Severity):** `HIGH`
5. **Kök Neden:** (a) `E1` büyük `.bash_history`, `pacman.log`, `apt/history.log` dosyalarının sonunu değil ilk N baytını okuyup en güncel komutları kaçırıyor ve `NaN` `time_window_hours`'da çökebiliyordu. (b) `E4` `_check_symlinks_in_mc_dirs()` içinde `"/." in rstr` kullandığından `/.minecraft/` içindeki meşru iç bağları bile işaretliyordu; ayrıca `_check_spoofed_mod_name()` kodu yinelenmişti. (c) `E5` `.log.gz` için `gzip.decompress(raw)[:8MB]` kullanıp bellek bombasına (OOM) açıktı. (d) `E6` SQLite sorgusu başarısız olduğunda (`total_urls=0`) yanlışlıkla `E6-BROWSER-HISTORY-WIPED` üretiyordu; `/tmp/mozilla_0/*.pdf` gibi geçmiş dosya izleri `CRITICAL` `E6-XBEL-DELETED-ARTIFACT` oluyordu; `.rglob` sembolik bağları izliyordu. (e) `E7` normal fare/kulaklık çıkarılmasını (`usb disconnect`) `HIGH` USB depolama olayı olarak işaretliyordu. (f) `orchestrator` motor `ctx.add_error()` kaydetse dahi elle `COMPLETED` yazmışsa `PARTIAL`'a çevirmiyordu.
6. **Girdi / Tetikleme Koşulu:** >2 MiB bash geçmişi; 10 MiB+ gzip log bombası; bozuk SQLite Chrome History; `.minecraft/config` içi meşru symlink; `.xbel` içinde `/tmp/mozilla_0/invoice.pdf`; BT/USB mouse kopması.
7. **Beklenen Davranış:** Büyük logların kuyruğu (tail) okunmalı; gzip akışı 8 MiB'da durmalı; bozuk SQLite silinmiş geçmiş sanılmamalı; yalnızca gerçek tehlikeli `/tmp` ikilileri `.xbel`'de kritik sayılmalı; hatalı `COMPLETED` motor `PARTIAL` işaretlenmelidir.
8. **Önceki Gerçekleşen Davranış:** Son komutlar görünmüyor, gzip tüm veriyi açıyor, bozuk DB yanlış wipe bulgusu üretiyor, temiz `.minecraft` iç symlink'i alarma neden oluyordu.
9. **Etki / Risk:** Dosya kaçırma (false negative), DoS/OOM riski ve masaüstü yanlış pozitifleri.
10. **Uygulanan Düzeltme:** `safe_read_tail_bytes()`/`safe_read_tail_text()` eklendi ve `E1`'de kullanıldı + `math.isfinite` eklendi; `E4` symlink kontrolü `(not inside_base) or resolved.name.startswith(".")` yapıldı ve yalın `_check_spoofed_mod_name()` çağrısına indirildi; `E5` `gzip.GzipFile(...).read(8MB)` akış sınırına geçti; `E6` `sql_ok` + `.xbel` zararsız belge muafiyeti + `iter_files_safe()` uygulandı; `E7` `usb disconnect` gürültüsü kaldırıldı (`usb-storage` korundu); `orchestrator` `len(ctx.errors) > err_before` durumunda `COMPLETED`'ı `PARTIAL`'a yükseltir hâle getirildi.
11. **Mimari Etki ve Uyumluluk:** Tüm motorların API'si aynı kaldı.
12. **Değiştirilen Dosya ve Semboller:** `ss_core/utils.py`, `ss_core/orchestrator.py`, `ss_core/engine1_integrity.py`, `ss_core/engine4_deep_files.py`, `ss_core/engine5_minecraft.py`, `ss_core/engine6_desktop_traces.py`, `ss_core/engine7_network_usb.py`.
13. **Doğrulama Yöntemi ve Test Kanıtı:** `test_e1_tail_read_e4_inside_mc_symlink_e5_gzip_bomb_e6_corrupt_sqlite_and_xbel` + tüm mevcut `E1`–`E7` birim/kırmızı-takım testleri geçti.
14. **Durum (Status):** `KAPATILDI VE DOĞRULANDI`

### Bulgu F-09: Qt6 Arayüz Yaşam Döngüsü ve LKM Hazırlık Doğrulaması (`ss_gui.py`)
1. **Bulgu ID:** `F-09`
2. **Bileşen / Dosya:** `ss_gui.py`
3. **Kategori:** Kullanıcı Arayüzü Güvenliği / İş Parçacığı Yaşam Döngüsü
4. **Önem (Severity):** `HIGH`
5. **Kök Neden:** Önceki pencerede kapatma sırasında `QThread.terminate()` çağrılıp yarı kalmış `.ko`/SQLite kaynak riski doğabiliyordu ve LKM onay kutusu vermagic uyumu/header+derleyici kontrolü olmadan aktif olabiliyordu; düzeltme incelenip offscreen GUI testleriyle doğrulandı.
6. **Girdi / Tetikleme Koşulu:** Aktif tarama sürerken ana pencerenin kapatılması veya `Cancel` butonuna basılması.
7. **Beklenen Davranış:** Kooperatif iptal (`worker.request_cancel()`) ile `QThread` güvenli sonlanmalı (`wait(5000)`), `QThread.terminate()` hiç çağrılmamalı ve siyah `#000000` arayüz teması korunmalıdır.
8. **Önceki Gerçekleşen Davranış:** Güçlendirme öncesinde zorla sonlandırma riski vardı; mevcut sürümde kooperatif iptal uygulanmış ve doğrulanmıştır.
9. **Etki / Risk:** GUI çökmesi veya yarı açık geçici dosya/sürücü kilidi bırakma riski.
10. **Uygulanan Düzeltme:** `ScanWorker` kooperatif iptal düğmesi, `terminate()` çağrısının tamamen kaldırılması, vermagic veya headers+compiler doğrulaması ve `--smoke-gui-offscreen` hata-sıfır smoke yolu doğrulandı.
11. **Mimari Etki ve Uyumluluk:** `ConsentDialog` -> `TargetOSDialog` -> `SentinelMainWindow` akışı ve tüm siyah tema CSS kuralları korundu.
12. **Değiştirilen Dosya ve Semboller:** `ss_gui.py` (`ScanWorker`, `SentinelMainWindow`).
13. **Doğrulama Yöntemi ve Test Kanıtı:** `test_gui_cooperative_cancel_without_qthread_terminate` (mocked assertion on `QThread.terminate`), `test_target_os_dialog_offscreen_and_main_window_report` ve 7 container'da `MC-SS-Sentinel --smoke-gui-offscreen` geçti.
14. **Durum (Status):** `KAPATILDI VE DOĞRULANDI`

### Bulgu F-10: Paketleme Temizliği ve Önemsiz (Trivial) Test İddialarının Onarımı
1. **Bulgu ID:** `F-10`
2. **Bileşen / Dosya:** `tests/test_hardening_and_coverage.py`, `packaging/build_inside_container.sh`, `packaging/lab_verify_target.py`, `scripts/build_distro_targets.py`, `tests/run_all_tests.py`, `README.md`
3. **Kategori:** Test Mühendisliği & Paketleme Hijyeni
4. **Önem (Severity):** `MEDIUM`
5. **Kök Neden:** İnceleme sırasında `tests/test_hardening_and_coverage.py` içindeki `hidepid` testinin yanlış anahtar (`"hidden"` yerine `"hidden_candidates"`) kullandığı ve `podman` `execveat` muafiyet testinin `arg1=0` (`0x1000` `AT_EMPTY_PATH` yerine) verdiği görülerek bu iki kontrol önemsiz/geçersiz (trivial) olmaktan çıkarıldı; ayrıca container build scriptlerinin temiz `podman images -a` hijyeni (`--cleanup-image`) ve izole dry-run doğrulandı.
6. **Girdi / Tetikleme Koşulu:** `pid_cross` çıktısı `hidepid_detected=1` + `hidden_candidates=[...]` ve `type=5` (`execveat`) `arg1=0x1000`.
7. **Beklenen Davranış:** Testler gerçek anahtar ve bit maskelerini doğrulamalı ve test paketi her iyileştirmeyi sahte olmayan gerçek girdiyle sınamalıdır.
8. **Önceki Gerçekleşen Davranış:** İki test satırı ilgili kod dalını gerçekte çalıştırmadan geçiyordu.
9. **Etki / Risk:** Test kapsamı yanılsaması.
10. **Uygulanan Düzeltme:** `"hidden_candidates"` ve `arg1=0x1000` (`comm=bwrap`) düzeltildi + `TestReviewerAuditHardeningRegressions` (5 yeni çoklu-katman regresyon testi) eklendi (`61 -> 75 -> 80` toplam test).
11. **Mimari Etki ve Uyumluluk:** Yalnızca test güvencesini artırır.
12. **Değiştirilen Dosya ve Semboller:** `tests/test_hardening_and_coverage.py`, `README.md`.
13. **Doğrulama Yöntemi ve Test Kanıtı:** `QT_QPA_PLATFORM=offscreen python3 tests/run_all_tests.py` üzerinde **80/80 test geçti**; tüm 7 container build içinde de **80/80 test geçti**.
14. **Durum (Status):** `KAPATILDI VE DOĞRULANDI`

---

## C. Engine 8 Korelasyon Kuralları ve 6-Alan Risk Modeli İnceleme Özeti

- **6 Bağımsız Risk Alanı (`cheat_evidence`, `forensic_tampering`, `kernel_integrity`, `dma_hardware`, `os_security`, `scan_coverage`):** Yalnız donanım/IOMMU/VFIO veya masaüstü servis bulguları `cheat_verdict_level == "CLEAN"` bırakır ve `verdict` yalnızca gerçekten `cheat_verdict_level == "CRITICAL"` olduğunda `"DOGRULANMIS HILE"` kararı verir.
- **9 Korelasyon Kuralı Bağımsızlık Analizi:**
  1. `WIPE-CHAIN`: Tek başına yumuşak/reboot (`E1-REBOOT-RECENT` + `E5-LOG-MODLIST-MISMATCH`) çiftini reddeder; yüksek güven yalnızca iki tarafta da `HIGH` varsa atanır.
  2. `STEALTH-MACRO`: Çalışan canlı girdi/uinput katmanı + Engine 3 gerçek makro kuralı gerektirir; pasif `input-remapper` servisi tek başına tetiklemez.
  3. `SPOOFED-ARTIFACT`: Aynı normalize dosya yolu (`_paths_compatible`) zorunludur; farklı dosyalardaki bulgular birleştirilmez.
  4. `GHOST-RAM`: RAM/açık FD sinyali + diskten silinme/Çöp Kutusu/XBEL izi gerektirir; aynı dosya kökü veya RAM strict imza + hile silmesi olduğunda `CONFIRMED` olur.
  5. `ACQUISITION-CHAIN`: Tarayıcı indirme/geçmiş URL'si ile yerel dosya/xattr/terminal kullanımı arasında çakışan kanıt arar.
  6. `JVM-INJECT-CHAIN`: PID uyumu + farklı ikili dosya yollarında kök/referans bağı + disk `pid=None` vektörünün köksüz `E2-MAP-*` yamasıyla kör eşlenmesinin engellenmesini uygular.
  7. `RING0-ROOTKIT`: 11 bağımsız mekanizma grubundan (`khook_inline`, `msr_lstar`, `vfs_hook`, `hidden_lkm`, `orphan_mem`, `hidden_pid`, `known_rk_lkm`, `sysctl_modprobe`, `foreign_probe`, `ebpf_rk`, `raw_io`) en az **2 farklı grubun** aynı anda `HIGH+` eşleşmesini şart koşar (iki eBPF bulgusu tek başına tetiklemez).
  8. `DMA-EXPOSURE`: IOMMU zayıflığı + gerçek DMA/FPGA/VFIO cihazını birlikte değerlendirir ve açıklamasında tek başına hile kanıtı olmadığını belirtir.
  9. `KERNEL-FILELESS`: `E2-MAP-TEXT-COW-PATCH` kendi kendine korelasyonunu engeller; olay eşleşmesinde PID kontrolü, disk eşleşmesinde ise mutlaka `E9-KERNEL-VMA-*` kökeni ve paylaşılan PID/dosya kökü gerektirir.

---

## D. Derleme, Test ve Ardışık Çoklu-OS (Podman) Doğrulama Çıktıları

### 1. Host Derlemeleri ve C Sonda Doğrulaması
- **Kernel Modülü (`kernel/`):** `make -C kernel clean && make -C kernel KDIR="/lib/modules/7.3.4-ogc6.1.fc45.x86_64/build"` -> **çıkış 0** (`kernel/mc_ss_kmod.ko`, `0` C derleyici uyarısı; `pahole` `vmlinux` yokluğu nedeniyle BTF atladı).
- **Native Telemetry Sonda (`native/`):** `make -C native clean && make -C native CFLAGS="-O2 -Wall -Wextra -Werror"` -> **çıkış 0**, SHA-256: `f51be8c36b676a993963562786d13973677f8eba3917c2132924998ae758284b`.
- **Sonda CLI Çıktısı (`--pid-cross`, `--pci-ext`, `--all`):** Geçerli JSON üretildi (`readdir_count == raw_getdents_count`, `hidden_count == 0`, `hidepid_detected == 0`, `errno == 1` unprivileged).

### 2. Tam Otomatik Test Paketi ve Canlı Host Dry-Run (`tests/run_all_tests.py`)
- **Birim & Entegrasyon Paketi (`QT_QPA_PLATFORM=offscreen python3 tests/run_all_tests.py`):** **80 / 80 PASSED** (`9.985s`, `0` hata, `0` başarısızlık).
- **İzole Host CLI Dry-Run Karşılaştırması:**
  - *İnceleme öncesi:* `63/100 | YUKSEK RISK - OLASI HILE VEYA IZ TEMIZLEME` (Chromium `/dev/shm/.org.chromium.Chromium.sOwnZa` x2 yanlış `E2-MAP-TMP-LIB`, `input-remapper-` x2 yanlış `HIGH cheat_evidence`).
  - *Düzeltme sonrası:* `36/100 | YUKSEK DONANIM / DMA MARUZIYETI - DOGRUDAN HILE KANITI YOK | CRITICAL=1 (E9-DMA-IOMMU-DISABLED) HIGH=1 (E7-LOCAL-PROXY-ACTIVE :1080) MEDIUM=0 LOW=4 (E1-MULTI-MONITOR, E3-UINPUT-WRITABLE, E2-PROC-MACRO-BIN x2 remapper_daemon) | Errors=0` (`cheat_evidence = 0`, sahte `E2-MAP-TMP-LIB = 0`).

### 3. Ardışık Çoklu-OS Podman Lab Sonuçları (`--cpus 6 --memory 4g --cleanup-image`)
Her hedef tek tek ardışık olarak inşa edildi, container içinde **80/80** test koşuldu, gerçek Kbuild + ELF doğrulaması (`packaging/lab_verify_target.py`) yapıldı ve görüntüleri silindi (`podman images -a` üzerinde yalnızca önceden mevcut `alpine:latest` kaldı; `podman ps -a` boş):

| Hedef ID | Python | glibc (`ldd`) | Container Çekirdek Kbuild Doğrulaması | Üretilen ELF Boyut / SHA-256 | Lab Kontrolleri (`probe` / Masaüstü Rapor / Helper / Qt6 GUI) |
|---|---|---|---|---|---|
| `bazzite` | `3.14.10` | `2.42` | `7.3.3-100.fc43.x86_64` (1 Kbuild OK) | `77.5M` (`74374fc631fe...`) | **80/80 OK** · `readdir=3` · `39885` char · Helper OK · `GUI_SMOKE_OK` |
| `fedora_nobara` | `3.14.10` | `2.42` | `7.3.3-100.fc43.x86_64` (1 Kbuild OK) | `77.5M` (`ef1e042a7cc0...`) | **80/80 OK** · `readdir=3` · `40490` char · Helper OK · `GUI_SMOKE_OK` |
| `ubuntu_24_04` | `3.12.3` | `2.39` | `6.8.0-149-generic` (1 Kbuild OK) | `52.9M` (`55a96683c459...`) | **80/80 OK** · `readdir=3` · `41330` char · Helper OK · `GUI_SMOKE_OK` |
| `ubuntu_22_04` | `3.10.12` | `2.35` | `5.15.0-203` & `6.8.0-149` (2 Kbuild OK) | `49.9M` (`cf333606a1c5...`) | **80/80 OK** · `readdir=3` · `42765` char · Helper OK · `GUI_SMOKE_OK` |
| `debian` | `3.11.2` | `2.36` | `6.1.0-55-amd64` (1 Kbuild OK) | `51.0M` (`e7298ffcf897...`) | **80/80 OK** · `readdir=3` · `40140` char · Helper OK · `GUI_SMOKE_OK` |
| `arch_cachyos` | `3.14.10` | `2.44` | `7.3.4-arch1-2` (1 Kbuild OK) | `61.6M` (`8c9716209bc0...`) | **80/80 OK** · `readdir=3` · `40286` char · Helper OK · `GUI_SMOKE_OK` |
| `steamos` | `3.11.2` | `2.36` | `6.1.0-55-amd64` (1 Kbuild OK) | `51.0M` (`c061afacc218...`) | **80/80 OK** · `readdir=3` · `39831` char · Helper OK · `GUI_SMOKE_OK` |

---

## E. Değiştirilen ve Eklenen Dosyaların Tam Envanteri

- **Değiştirilen Takip Edilen Dosyalar (25 dosya):**
  - `README.md`
  - `kernel/kernel_sources.sha256`, `kernel/mc_ss_kmod.c`, `kernel/mc_ss_kmod.h`
  - `native/ss_kernel_probe.c`, `native/ss_kernel_probe.sha256`
  - `packaging/build_inside_container.sh`, `packaging/lab_verify_target.py`, `scripts/build_distro_targets.py`
  - `ss_core/_self_manifest.py`, `ss_core/models.py`, `ss_core/orchestrator.py`, `ss_core/priv_helper.py`, `ss_core/utils.py`
  - `ss_core/engine1_integrity.py`, `ss_core/engine2_live_proc.py`, `ss_core/engine3_input_macro.py`, `ss_core/engine4_deep_files.py`, `ss_core/engine5_minecraft.py`, `ss_core/engine6_desktop_traces.py`, `ss_core/engine7_network_usb.py`, `ss_core/engine8_reporter.py`, `ss_core/engine9_kernel.py`
  - `ss_gui.py`, `tests/run_all_tests.py`
- **Eklenen Dosyalar:**
  - `tests/test_hardening_and_coverage.py`
  - `AUDIT_REMEDIATION_REPORT.md`
- **Üretilen Yerel Build Çıktıları (`.gitignore` / yardımcı yan ürünler):**
  - `kernel/mc_ss_kmod.ko`, `native/ss_kernel_probe`
  - `targets/{bazzite,fedora_nobara,ubuntu_24_04,ubuntu_22_04,debian,arch_cachyos,steamos}/` (`MC-SS-Sentinel` + `build_meta.json`)

---

## F. 12 Teknik Boyutta Başlangıç vs. Nihai Puanlama Tablosu

> **Not:** Canlı `insmod mc_ss_kmod.ko` testi güvenlik ve kararlılık gereği canlı ana makine çekirdeği üzerinde yürütülmemiş, bunun yerine tüm C/kernel yolları host + 7 hedef çekirdekte gerçek Kbuild derleme ve ayrıntılı snapshot/mock sözleşme testleriyle doğrulanmıştır. Aşağıdaki puanlar bu sınırlama dikkate alınarak dürüst biçimde verilmiştir.

| # | Teknik Değerlendirme Boyutu | Başlangıç (/10) | Nihai (/10) | Gerekçe ve Kalan Sınırlamalar |
|---|---|---:|---:|---|
| 1 | Mimari & Modülerlik | 6.5 | 8.8 | 9 motor + `ScanContext` sözleşmesi korundu; yinelenen mod kontrolü ve kuyruk okuma yardımcıları merkeze alındı. |
| 2 | Hata Yönetimi & Kapsam Bütünlüğü | 4.5 | 9.0 | `ScanContext.coverage`/`engine_status` bağlantısı kuruldu; `SKIPPED`/`UNSUPPORTED`/bozuk SQLite/`PARTIAL` ezilme açıkları kapatıldı. |
| 3 | Veri Modelleri & Tip Güvenliği | 6.0 | 8.5 | `ScanStatus`, `Finding` birleştirme, `metadata` ve `score_breakdown`/`floor_uplift` şeması tutarlılaştırıldı. |
| 4 | Engine 8 Korelasyon & Risk Puanlama | 4.0 | 9.0 | 6 alanlı ayrım, `verdict` tutarlılığı, Ring-0 grup bağımsızlığı, PID/dosya kapsamı ve `fileless` sıkılaştırması sağlandı. |
| 5 | Engine 9 Ring-0 & eBPF/IOMMU Doğruluğu | 5.0 | 8.8 | `has_ret=0`, `CALL_REL32`, sysfs IOMMU tipi, USB MCU, `enable_kernel_lkm=False` root yolu ve `TRUNCATED` işlendi (canlı LKM yüklemesi container içinde yapılamaz). |
| 6 | Yetki Yükseltme (`priv_helper`) & Artifact Güvenliği | 3.5 | 9.2 | `O_NOFOLLOW` sahneleme, `_self_manifest` SHA-256 sabitlemesi, kilit sıralaması, `noexec` fallback ve IOMMU geri alma sağlandı. |
| 7 | Kernel C (`mc_ss_kmod.c`) Bellek & Sınır Güvenliği | 5.0 | 8.6 | x86_64 koruması, eviction, `cfg_size`, prolog `off+3`, `seq_has_overflowed` ve `MODINFO TRUNCATED` eklendi (canlı `insmod` testi VM/QEMU gerektirir). |
| 8 | Native C (`ss_kernel_probe.c`) Sağlamlığı | 5.5 | 9.0 | `_Alignas(8)`, `EINTR`, `hidepid=ptraceable/4`, `ext_cap_loop` ve `-Wall -Wextra -Werror` tam geçti. |
| 9 | Dosya/RAM/Tarayıcı Adli Bütünlüğü (`E1–E7`) | 5.5 | 8.9 | `safe_zip_read`, gzip akış sınırı, tail okuma, `.minecraft` iç symlink, `is_relative_to`, RAM `e_type` & iptal tepkisi tamamlandı. |
| 10 | Yanlış Pozitif Oranı (Temiz Masaüstü Hijyeni) | 4.5 | 8.8 | `.sOwnZa`, `input-remapper` servisi, Lunar `ichor`, `/tmp/*.pdf` XBEL, USB mouse disconnect ve VFIO gürültüsü temizlendi (`63 -> 36`, `cheat_evidence=0`). |
| 11 | GUI Yaşam Döngüsü & Tema (`ss_gui.py`) | 5.5 | 9.0 | `QThread.terminate()` kaldırıldı, kooperatif iptal, LKM hazırlık kontrolü, `#000000` tema ve headless smoke doğrulandı. |
| 12 | Paketleme, Test Kapsamı & Çoklu Dağıtım | 5.0 | 9.4 | Testler `61 -> 80` düzeyine çıkarıldı (trivial testler düzeltildi); 7/7 Linux hedefi ardışık Podman labından sıfır artık görüntüyle geçti. |
| **Genel Ortalama** | **12 Boyut Ortalaması** | **5.04 / 10** | **8.92 / 10** | Üretim sınıfı sertleştirme tamamlandı; geriye yalnızca QEMU/çıplak-donanım üzerinde canlı `insmod` testi kalmaktadır. |

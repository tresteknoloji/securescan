# SecureScan - Zafiyet Tarama Paneli PRD

## Proje Özeti
Nessus tarzı profesyonel zafiyet tarama paneli. IP, domain ve prefix tarama desteği. Nmap entegrasyonu, CVE kontrolü, SSL/TLS analizi ve PCI uyumluluk raporlaması.

## Kullanıcı Personaları
1. **Admin**: Tüm sistem yönetimi, tüm kullanıcıları ve taramaları görme
2. **Reseller (Bayi)**: Müşteri yönetimi, kendi müşterilerinin taramalarını görme, SMTP/branding ayarları
3. **Customer (Müşteri)**: Hedef ekleme, tarama başlatma, rapor indirme

## Temel Gereksinimler (Statik)
- JWT tabanlı kimlik doğrulama (Kayıt sadece Admin/Reseller tarafından yapılır)
- Çoklu dil desteği (TR/EN)
- Aydınlık/Karanlık tema desteği
- IP, domain, prefix türünde hedef yönetimi
- Port tarama (Nmap entegrasyonu)
- SSL/TLS güvenlik kontrolü
- CVE veritabanı entegrasyonu (NVD API)
- PCI DSS uyumluluk kontrolü
- Severity derecelendirme (Critical, High, Medium, Low, Info)
- HTML ve PDF rapor oluşturma
- Özelleştirilebilir branding (logo, renkler, rapor başlık/altlık)
- Reseller bazlı SMTP yapılandırması
- Kullanıcı limitleri (hedef sayısı, aylık tarama hakkı, müşteri sayısı)

## Düzeltmeler ve Geliştirmeler (2026-02-16)

### Scan Iterations & On-Demand Reports - ✅ TAMAMLANDI
- ✅ **Tarama Yinelemeleri**: "Tekrarla" (Rescan) butonu yeni tarama yerine mevcut tarama altında yeni iterasyon oluşturur
  - `current_iteration` alanı mevcut iterasyon numarasını tutar
  - `iteration_history` dizisi önceki iterasyonların özetini saklar
  - Aynı tarama ID'si korunur, zafiyet karşılaştırması kolaylaşır
- ✅ **İsteğe Bağlı Rapor Üretimi**: Raporlar sunucuda saklanmaz, indirme tıklandığında üretilir
  - `/api/scans/{id}/report?format=html&iteration=1&theme=dark` - yeni parametreler
  - Disk alanı tasarrufu, her zaman güncel rapor
- ✅ **Temalı Raporlar**: HTML/PDF raporlar için açık/koyu tema seçeneği
  - `theme=light`: Beyaz arkaplan, koyu metin
  - `theme=dark`: Koyu lacivert arkaplan, açık metin
- ✅ **Iterasyon UI**: Tarama detay sayfasında iterasyon seçici dropdown
  - Sadece `current_iteration > 1` olduğunda görünür
  - Geçmiş iterasyonların tarih ve zafiyet sayısını gösterir
- ✅ **Tema Seçici UI**: "Rapor Teması: Koyu | Açık" butonları
  - Seçilen tema rapor indirmede kullanılır

### API Endpoints Güncellemesi
- `POST /api/scans/{id}/rescan` - Yeni iterasyon başlatır (aynı scan ID)
- `GET /api/scans/{id}/history` - Iterasyon geçmişini getirir
- `GET /api/scans/{id}/vulnerabilities/{iteration}` - Belirli iterasyonun zafiyetleri
- `GET /api/scans/{id}/report?iteration=X&theme=light|dark` - Temalı rapor üretimi

### Real Risk Score - ✅ TAMAMLANDI
- ✅ **Risk Calculator Modülü**: CVSS + KEV + Verification + Exposure faktörleri
- ✅ **Formül**: `Real Risk = min(10, CVSS × Exposure_Mult + Bonuses)`
  - KEV Bonus: +1.5
  - Verified Bonus: +1.0
  - Public Exploit: +0.5
  - Exposure Multipliers: Internet(1.3), DMZ(1.1), Internal(1.0), Isolated(0.8)
- ✅ **Priority System**: P1-P5 önceliklendirme
- ✅ **Scan Config**: Exposure Level ve Data Sensitivity seçimi
- ✅ **UI Gösterimi**: Real Risk Score, Priority badge'leri

### Email Bildirimleri - ✅ TAMAMLANDI
- ✅ **Tarama Tamamlandığında Email**: Scan bitince owner'a otomatik mail
- ✅ **Hiyerarşik SMTP Seçimi**:
  - Customer → Reseller'ın SMTP'si
  - Admin'in müşterisi → Admin'in SMTP'si
  - Admin/Reseller kendi taraması → Kendi SMTP'si
  - Fallback: Admin SMTP (reseller SMTP yoksa)
- ✅ **SMTP Test Endpoint**: `/api/settings/smtp/test` - Test mail gönderme
- ✅ **Admin Genel SMTP**: `reseller_id: "admin"` olarak kaydedilir

### Faz 2: Detection Engine - ✅ TAMAMLANDI
- ✅ **Fingerprint Engine**: HTTP/HTTPS servis tespiti
  - Server header parsing (Apache, Nginx, IIS, Tomcat, etc.)
  - X-Powered-By teknoloji tespiti (PHP, ASP.NET, Express, etc.)
  - HTML içerik analizi (WordPress, Drupal, React, Vue, Angular, jQuery)
  - Favicon hash matching
  - SSL sertifika bilgi çıkarma
- ✅ **CPE Normalizasyonu**: Tespit → CPE → CVE eşleştirme
  - Servis/versiyon → CPE 2.3 string dönüşümü
  - CPE-CVE veritabanı sorgusu
  - Version range matching
- ✅ **Active Checks**: 10 güvenlik testi
  - Path Traversal (CWE-22)
  - SQL Injection (CWE-89)
  - XSS - Cross-Site Scripting (CWE-79)
  - SSRF (CWE-918)
  - Open Redirect (CWE-601)
  - Sensitive File Exposure (.git, .env, backup.sql)
  - Admin Panel Detection
  - SSL/TLS Vulnerabilities
  - CORS Misconfiguration (CWE-942)
  - Missing Security Headers (CWE-693)

### Faz 1: CVE Altyapısı - ✅ TAMAMLANDI
- ✅ **Tam CVE Senkronizasyonu**: NVD API ile pagination destekli tam veritabanı sync
- ✅ **CISA KEV Entegrasyonu**: Aktif exploit edilen zafiyetler (1518 KEV)
- ✅ **Incremental Update**: Son X günün CVE'lerini güncelleme
- ✅ **CVE Arama API**: Severity, year, KEV status filtreleme
- ✅ **CVE Database Sayfası**: İstatistikler, arama, detay görüntüleme

### Önceki Düzeltmeler (2026-02-15)
- ✅ **Rapor İndirme**: Token parametreli download endpoint
- ✅ **Arka Plan Tarama**: ThreadPool ile non-blocking scan
- ✅ **PDF Rapor**: WeasyPrint sistem bağımlılıkları

## Mevcut CVE Veritabanı Durumu
- **Total CVEs**: 8,977 (son 30 gün sync)
- **CISA KEV**: 36 aktif exploit edilen
- **Full Sync**: 240,000+ CVE için "Full Sync" butonu mevcut

## Uygulanan Özellikler (2026-02-12)

### Backend (FastAPI + MongoDB)
- ✅ JWT Authentication (login, me endpoints)
- ✅ User CRUD (Admin/Reseller/Customer rolleri)
- ✅ Target CRUD (IP/Domain/Prefix)
- ✅ Scan management (create, list, detail, cancel, delete)
- ✅ Vulnerability tracking per scan
- ✅ Dashboard statistics API
- ✅ Report generation (HTML/PDF)
- ✅ Branding settings
- ✅ SMTP configuration
- ✅ CVE database sync from NVD
- ✅ Translation API

### Frontend (React + Tailwind + Shadcn/UI)
- ✅ Landing page (kurumsal tanıtım sayfası)
- ✅ Login sayfası (kayıt kaldırıldı)
- ✅ Dashboard (grafikler, istatistikler, son taramalar)
- ✅ Hedefler yönetimi sayfası
- ✅ Taramalar listesi
- ✅ Yeni tarama oluşturma (hedef seçimi, config)
- ✅ Tarama detay sayfası (canlı ilerleme, zafiyetler)
- ✅ Raporlar sayfası
- ✅ Kullanıcı yönetimi (Admin/Reseller)
- ✅ Ayarlar (Branding, SMTP, CVE Database)
- ✅ TR/EN dil değiştirme
- ✅ Aydınlık/Karanlık tema değiştirme
- ✅ Footer: © 2026 Tres Technology LLC

### Scanner Engine
- ✅ Nmap port tarama entegrasyonu
- ✅ Socket-based fallback tarama
- ✅ SSL/TLS sürüm ve cipher kontrolü
- ✅ Servis bazlı zafiyet kontrolü
- ✅ CVE eşleştirme

### Agent Sistemi (2026-02-17) - ✅ TAMAMLANDI

#### Faz 1: Backend - Agent Gateway & API
- ✅ Agent modelleri oluşturuldu (`Agent`, `AgentTask`, `AgentResponse`, vb.)
- ✅ WebSocket Gateway implementasyonu (`agent_gateway.py`)
- ✅ Agent CRUD API endpoint'leri (`/api/agents`)
- ✅ Token tabanlı kimlik doğrulama (kalıcı token, hash ile saklama)
- ✅ Agent komut gönderme endpoint'i (`/api/agents/{id}/send-command`)
- ✅ Install script endpoint'i (`/api/agent/install.sh`)

#### Faz 2: Frontend - Agent Yönetim Sayfası
- ✅ `AgentsPage.jsx` oluşturuldu
- ✅ Agent listesi tablosu (durum, ağlar, araçlar, son görülme)
- ✅ Yeni agent oluşturma diyaloğu
- ✅ Token/kurulum komutu gösterme diyaloğu
- ✅ Agent silme işlevi
- ✅ Sidebar'a "Agentlar" linki eklendi
- ✅ Türkçe/İngilizce çeviri desteği

#### Agent Özellikleri
- WebSocket ile gerçek zamanlı iletişim
- Kalıcı token (her bağlantıda doğrulama gerekmez)
- Otomatik araç kurulumu (nmap, masscan)
- Sistem bilgisi toplama
- Tarama sonuçları işleme

### Gelişmiş Agent Tarama Yetenekleri (2026-02-19) - ✅ TAMAMLANDI

Agent artık temel port taramasının ötesinde kapsamlı güvenlik kontrolleri yapabilmektedir:

#### 1. SSL/TLS Güvenlik Analizi
- **Protokol Kontrolü**: SSLv2, SSLv3, TLSv1.0, TLSv1.1 gibi eski protokollerin tespiti
- **Cipher Suite Analizi**: RC4, DES, 3DES, MD5, NULL, EXPORT gibi zayıf şifrelerin tespiti
- **Sertifika Kontrolleri**: Süresi dolmuş, self-signed sertifika tespiti
- **DH Parametre Kontrolü**: Logjam zafiyetine karşı zayıf DH parametreleri tespiti
- **Nmap Scripts**: `ssl-enum-ciphers`, `ssl-cert`, `ssl-date`, `ssl-known-key`, `ssl-dh-params`

#### 2. NSE Vulnerability Script Taraması
- **Nmap Scripts**: `--script=vuln,auth,default` kategorileri
- **CVE Tespiti**: Script çıktılarından CVE referansları çıkarma
- **SMB Zafiyetleri**: EternalBlue ve benzeri SMB exploit tespiti
- **HTTP Zafiyetleri**: Web sunucu zafiyetleri tespiti
- **FTP Anonymous**: Anonim FTP giriş tespiti

#### 3. Aktif Web Güvenlik Kontrolleri
- **SQL Injection**: Basit SQL injection probe'ları
- **XSS (Cross-Site Scripting)**: Reflected XSS test payload'ları
- **LFI (Local File Inclusion)**: `../etc/passwd` gibi yol geçişi testleri
- **Directory Traversal**: URL encoding ile yol geçişi testleri
- **Sensitive File Exposure**: `.env`, `.git/config`, `backup.sql` gibi hassas dosya tespiti
- **Admin Panel Detection**: `/admin`, `/phpmyadmin`, `/wp-admin` gibi admin panelleri

#### 4. Teknik Uygulama
- **Agent Kodu**: `backend/server.py` içindeki `get_agent_install_script` fonksiyonunda
- **Fonksiyonlar**:
  - `run_port_scan()`: Kapsamlı tarama koordinasyonu (4 faz)
  - `parse_ssl_findings()`: SSL/TLS bulgu ayrıştırma
  - `parse_nse_findings()`: NSE script bulgu ayrıştırma
  - `run_web_checks()`: Aktif web güvenlik kontrolleri
- **Gateway İşleme**: `agent_gateway.py` - `process_scan_results()` fonksiyonu
  - SSL, NSE ve Web bulgularını ayrı ayrı işler
  - CVE veritabanından ek bilgi çeker
  - Deduplikasyon yapar

#### 5. UI Güncellemeleri
- **Yeni Badge'ler** (`ScanDetailPage.jsx`):
  - 🔒 **SSL/TLS** (sarı) - `source: ssl_scan`
  - 💻 **NSE Script** (cyan) - `source: nse_scan`
  - 🌐 **Web Check** (pembe) - `source: web_scan`
- **Evidence Alanı**: Bulguların teknik kanıtları gösteriliyor
- **Vulnerability Model**: `evidence`, `is_kev`, `source` alanları eklendi

### CVE Version Range Matching (2026-02-19) - ✅ TAMAMLANDI

CVE eşleştirmesi artık doğru versiyon aralığı kontrolü yapıyor:

#### Problem
- Önceki sistem sadece ürün adına göre CVE arıyordu
- OpenSSH 9.6p1 için CVE-2001-1459 (sadece 2.9 ve öncesi için geçerli) false positive olarak raporlanıyordu

#### Çözüm
- **Semantic Version Parsing**: `_parse_version()` - "9.6p1" → (9, 6, 1) tuple
- **Version Range Matching**: `_version_in_range()` - "<= 2.9", "7.0 - 8.8" gibi aralıklar
- **CVE Description Parsing**: `_extract_affected_versions()` - CVE açıklamasından etkilenen versiyonları çıkarma
- **Smart Filtering**: `_is_relevant_cve()` - Yanlış ürün eşleşmelerini filtreleme

#### Desteklenen Formatlar
- `"<= 2.9"` veya `"< 2.9"`
- `"before 2.9"` veya `"through 2.9"`
- `"2.9 and earlier"`
- `"7.0 - 8.8"` veya `"7.0 to 8.8"`
- `"7.x"` (herhangi minor versiyon)

#### Test Sonuçları
- OpenSSH 9.6p1 vs CVE-2001-1459 (affects <= 2.9): ✓ DOĞRU - Etkilenmiyor
- Apache 2.4.52 vs CVE (affects 2.4.0 - 2.4.51): ✓ DOĞRU - Etkilenmiyor
- Apache 2.4.50 vs CVE (affects 2.4.0 - 2.4.51): ✓ DOĞRU - Etkileniyor

### Düzeltmeler (2026-02-17) - ✅ TAMAMLANDI

#### CVE Referansları Raporda Görünmeme Hatası
- ✅ **Problem**: CVE referansları veritabanında `{url, source, tags}` obje formatında saklanıyordu ancak kod string formatı bekliyordu
- ✅ **Çözüm**: `server.py` ve `report_generator.py` dosyalarındaki referans işleme kodları her iki formatı da destekleyecek şekilde güncellendi
- ✅ **Dosyalar**: `backend/server.py` (satır 550-560), `backend/report_generator.py` (satır 51-59)

#### Başarısız Tarama Nedeni Görüntüleme
- ✅ **Problem**: Tarama başarısız olduğunda neden gösterilmiyordu
- ✅ **Çözüm**: 
  - `Scan` modeline `failure_reason` alanı eklendi
  - Backend tarama başarısız olduğunda hata mesajını kaydediyor
  - Frontend'de kırmızı uyarı kartı olarak görüntüleniyor
- ✅ **Dosyalar**: `backend/models.py` (satır 139, 177), `backend/server.py` (satır 666), `frontend/src/pages/ScanDetailPage.jsx` (satır 293-315)

#### PDF Rapor Altyapı Sorunu
- ✅ **Problem**: WeasyPrint `libpangoft2-1.0-0` sistem bağımlılığı eksikti
- ✅ **Çözüm**: `apt install libpangoft2-1.0-0` ile bağımlılık kuruldu

## Düzeltmeler (2026-02-15)

### Tamamlanan Düzeltmeler
- ✅ **Rapor İndirme Sorunu**: Token parametreli `/api/scans/{id}/report/download` endpoint'i eklendi. window.open() ile Authorization header gönderilemiyor, bu nedenle token query param olarak iletiliyor.
- ✅ **CVE Senkronizasyonu**: `sync_cve_database` fonksiyonuna NVD API pagination desteği eklendi. Artık tüm CVE'ler (2000+ kayıt) senkronize edilebilir.

## Öncelikli Backlog

### P0 (Kritik)
- [x] Rapor indirme "Method Not Allowed" hatası - ✅ Düzeltildi
- [x] CVE senkronizasyonu pagination - ✅ Düzeltildi
- [x] Scan Iterations & On-Demand Reports - ✅ Düzeltildi (2026-02-16)
- [x] CVE referansları raporda görünmüyor - ✅ Düzeltildi (2026-02-17)
- [x] Başarısız tarama nedeni UI'da gösterilmiyor - ✅ Düzeltildi (2026-02-17)
- [x] Agent Sistemi Faz 1 & 2 - ✅ Tamamlandı (2026-02-17)
- [x] Agent tabanlı tarama mimarisi - ✅ Tamamlandı (2026-02-18)
- [x] **Gelişmiş Agent Tarama Yetenekleri - ✅ Tamamlandı (2026-02-19)**
  - SSL/TLS kontrolü (sertifika, zayıf şifreler, protokol zafiyetleri)
  - NSE Script taraması (--script=vuln,auth,default)
  - Aktif Web Kontrolleri (SQLi, XSS, LFI, Directory Traversal)
  - Sensitive File Exposure (.env, .git/config, backup dosyaları)
  - Admin Panel Detection
- [x] **CVE Version Range Matching - ✅ Tamamlandı (2026-02-19)**
  - Semantic versioning ile doğru CVE eşleştirmesi
  - False positive önleme (ör: OpenSSH 9.6p1 için CVE-2001-1459 yanlış raporlanmıyor)
- [x] **UI/UX İyileştirmeleri - ✅ Tamamlandı (2026-02-19)**
  - Agent version 1.0.3
  - Agentlar sayfasında "Araçlar" yerine "Oluşturma Tarihi" gösterimi
  - Tarama detay sayfasında Başlangıç/Bitiş/Süre bilgileri
  - Raporlarda Başlangıç/Bitiş/Süre bilgileri
- [x] **Zafiyet Motoru False Positive Düzeltmeleri - ✅ Tamamlandı (2026-02-19)**
  - SQLi tespiti: Reflected parameter değil, SQL error pattern matching kullanılıyor
  - Boolean-based ve error-based SQLi doğrulama
  - Confidence scoring sistemi: confirmed / likely / possible / unlikely / informational
  - Distro-aware CVE matching: Ubuntu/Debian backport patch tespiti
  - NSE script ERROR çıktıları filtreleniyor (zafiyet olarak raporlanmıyor)
  - Exploit referansları informational olarak işaretleniyor (severity yükseltmiyor)
  - CVE yaşına göre distro patched sistemlerde downgrade
- [ ] Reseller olarak müşteri hesabına giriş ("Login as Customer")

### P1 (Yüksek)
- [x] Tarama sonrası e-posta bildirimi - ✅ Tamamlandı
- [ ] Docker Compose dosyası oluşturma (deployment kolaylığı)
- [ ] Exploit-DB ve GitHub Advisories entegrasyonu (ek zafiyet kaynakları)
- [ ] Tarama zamanlaması (scheduled scans)
- [ ] Bulk hedef import (CSV)

### P2 (Orta)
- [ ] Hafif Linux agent (local network scanning)
- [ ] 2FA (İki faktörlü doğrulama)
- [ ] API rate limiting
- [ ] Audit log

### P3 (Düşük)
- [ ] Tarama şablonları
- [ ] Karşılaştırmalı raporlar
- [ ] Webhook entegrasyonu

## Sonraki Adımlar
1. Sunucuya `apt install nmap` ile Nmap kurulumu
2. CVE database sync zamanlayıcısı (cron/celery)
3. SMTP test endpoint'i
4. Reseller login-as-customer özelliği

## Teknik Notlar
- Default admin: admin@securescan.com / admin123
- NVD API Key: Configured in backend/.env
- MongoDB: localhost:27017 (MONGO_URL env variable)
- Backend: Port 8001 with /api prefix
- Frontend: Port 3000
- Copyright: © 2026 Tres Technology LLC

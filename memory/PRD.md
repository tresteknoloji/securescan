# SecureScan - Zafiyet Tarama Paneli PRD

## Proje Özeti
Nessus tarzı profesyonel zafiyet tarama paneli. IP, domain ve prefix tarama desteği. Nmap entegrasyonu, CVE kontrolü, SSL/TLS analizi ve PCI uyumluluk raporlaması.

## Kullanıcı Personaları
1. **Admin**: Tüm sistem yönetimi, tüm kullanıcıları ve taramaları görme
2. **Reseller (Bayi)**: Müşteri yönetimi, kendi müşterilerinin taramalarını görme, SMTP/branding ayarları
3. **Customer (Müşteri)**: Hedef ekleme, tarama başlatma, rapor indirme

## Temel Gereksinimler (Statik)
- JWT tabanlı kimlik doğrulama
- Çoklu dil desteği (TR/EN)
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

## Uygulanan Özellikler (2026-02-12)

### Backend (FastAPI + MongoDB)
- ✅ JWT Authentication (login, register, me endpoints)
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
- ✅ Login/Register sayfaları
- ✅ Dashboard (grafikler, istatistikler, son taramalar)
- ✅ Hedefler yönetimi sayfası
- ✅ Taramalar listesi
- ✅ Yeni tarama oluşturma (hedef seçimi, config)
- ✅ Tarama detay sayfası (canlı ilerleme, zafiyetler)
- ✅ Raporlar sayfası
- ✅ Kullanıcı yönetimi (Admin/Reseller)
- ✅ Ayarlar (Branding, SMTP, CVE Database)
- ✅ TR/EN dil değiştirme

### Scanner Engine
- ✅ Nmap port tarama entegrasyonu
- ✅ Socket-based fallback tarama
- ✅ SSL/TLS sürüm ve cipher kontrolü
- ✅ Servis bazlı zafiyet kontrolü
- ✅ CVE eşleştirme

## Öncelikli Backlog

### P0 (Kritik)
- [ ] Sunucuya Nmap kurulumu
- [ ] Tarama sonrası e-posta bildirimi

### P1 (Yüksek)
- [ ] Reseller olarak müşteri hesabına giriş
- [ ] Tarama zamanlaması (scheduled scans)
- [ ] Bulk hedef import (CSV)

### P2 (Orta)
- [ ] 2FA (İki faktörlü doğrulama)
- [ ] API rate limiting
- [ ] Audit log
- [ ] Dark/Light tema seçimi

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

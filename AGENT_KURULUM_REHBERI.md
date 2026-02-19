# SecureScan Agent Kurulum Rehberi

## Ön Gereksinimler

- Ubuntu 20.04+ veya Debian 11+ (Linux sunucu)
- Root erişimi (sudo)
- İnternet bağlantısı
- Python 3.8+

## Adım 1: Agent Token Alma

1. SecureScan paneline giriş yapın
2. Sol menüden **"Agentlar"** sayfasına gidin
3. **"Yeni Agent"** butonuna tıklayın
4. Agent'a bir isim verin (örn: "Ofis Sunucusu")
5. **"Agent Oluştur"** butonuna tıklayın
6. Gösterilen **kurulum komutunu** kopyalayın

## Adım 2: Agent Kurulumu

Hedef Linux sunucusunda root olarak çalıştırın:

```bash
curl -sSL https://PANEL_URL/api/agent/install.sh | sudo bash -s YOUR_TOKEN
```

Bu komut otomatik olarak:
- Python 3 ve pip kurar
- Nmap kurar
- Agent'ı `/opt/securescan-agent/` dizinine yükler
- Systemd servisi oluşturur ve başlatır

## Adım 3: Agent Durumunu Kontrol Etme

```bash
# Servis durumu
sudo systemctl status securescan-agent

# Logları izleme
sudo journalctl -u securescan-agent -f

# Servisi yeniden başlatma
sudo systemctl restart securescan-agent
```

## Adım 4: Panel'de Doğrulama

1. SecureScan panelinde **"Agentlar"** sayfasına gidin
2. Agent'ın durumunun **"Çevrimiçi"** olduğunu doğrulayın
3. İşletim sistemi ve kurulu araçlar bilgilerinin göründüğünü kontrol edin

## Adım 5: İlk Tarama

1. **"Hedefler"** sayfasından taranacak IP/domain'leri ekleyin
2. **"Taramalar" > "Yeni Tarama"** sayfasına gidin
3. Çevrimiçi agent'ı seçin
4. Hedefleri seçin
5. **"Taramayı Başlat"** butonuna tıklayın

## Sorun Giderme

### Agent bağlanmıyor

1. Firewall kurallarını kontrol edin (443 portu outbound açık olmalı)
2. Token'ın doğru olduğundan emin olun
3. Log'ları kontrol edin: `sudo journalctl -u securescan-agent -n 100`

### Nmap bulunamıyor

```bash
sudo apt-get update && sudo apt-get install -y nmap
```

### Token değişikliği gerekli

Panel'den agent'ın tokeni yenilenebilir, sonra:
```bash
sudo nano /opt/securescan-agent/config.json
# token değerini güncelleyin
sudo systemctl restart securescan-agent
```

## Güvenlik Notları

- Agent sadece outbound (dışarı) bağlantı kurar
- Panel'den gelen komutlar sadece tarama ile ilgilidir
- Token hash'lenerek saklanır
- Hassas bilgiler (token) sadece config.json'da bulunur

## Desteklenen İşletim Sistemleri

- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- CentOS 8, 9 (dnf ile)
- Amazon Linux 2

## Dosya Konumları

```
/opt/securescan-agent/
├── agent.py          # Ana agent scripti
├── config.json       # Token ve panel URL
└── venv/             # Python sanal ortamı

/etc/systemd/system/securescan-agent.service  # Systemd servis dosyası
```

## İletişim

Sorun yaşarsanız destek ekibimizle iletişime geçin.

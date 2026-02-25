# Bayt Support SQL Server IEX Installer

Bu proje PowerShell IEX (Invoke-Expression) kullanarak SQL Server Express'i **tek komutla** otomatik olarak kurmak ve yapılandırmak için tasarlanmıştır.

## Hızlı Başlangıç (Tek Komut)

PowerShell'i **Yönetici olarak** açın ve şunu yapıştırın:

```powershell
iex (irm 'https://raw.githubusercontent.com/bayt-support/sql-server-iex/main/install-online.ps1')
```

> **Not:** Yönetici olarak açmadıysanız script otomatik olarak yetki yükseltme yapacaktır.

## Özellikler

- SQL Server 2014, 2017, 2019, 2022, 2025 versiyonlarını destekler
- **Web'den tek komutla çalışır** (tüm bağımlılıklar tek dosyada)
- Otomatik sa kullanıcısı oluşturma (şifre: Bay_T252!)
- Hazır instance isimleri (BaytTicariSQL, BaytBossSQL, Bayt) veya manuel girme
- SQL Native Client 2012 kurulumu (otomatik kontrol)
- Shared Memory, TCP/IP ve Named Pipes protokolü etkinleştirme
- SQL Server Browser servisi etkinleştirme
- **Tamamen otomatik kurulum** (kullanıcı müdahalesi gerektirmez - /QS modu)
- **Performans Optimizasyonu:**
  - Otomatik RAM ve CPU optimizasyonu (Express limitleri dahilinde)
  - TempDB çoklu dosya yapılandırması (2017+ kurulum sırasında, 2014 kurulum sonrası)
  - Max Degree of Parallelism ayarlama
  - Cost Threshold for Parallelism optimizasyonu
  - Backup sıkıştırma etkinleştirme (2017+)
  - Ad-hoc sorgu optimizasyonu
  - Anında dosya başlatma (Instant File Initialization, 2017+)

## Kullanım

### Yöntem 1: Web'den Tek Komut (TAVSİYE EDİLEN)
```powershell
# PowerShell'i Yönetici olarak açın ve yapıştırın:
iex (irm 'https://raw.githubusercontent.com/bayt-support/sql-server-iex/main/install-online.ps1')
```

### Yöntem 2: Alternatif Sözdizimi
```powershell
iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/bayt-support/sql-server-iex/main/install-online.ps1')
```

### Yöntem 3: Yerel Kullanım
```powershell
# Projeyi indirin ve çalıştırın
.\install-online.ps1
```

### Yöntem 4: Parametreli Kullanım (Eski Modüler Yapı)
```powershell
.\install.ps1 -SqlVersion 2019 -InstanceName BaytTicariSQL
```

## Dosya Yapısı

| Dosya | Açıklama |
|-------|----------|
| `install-online.ps1` | **Ana script - Web'den tek komutla çalışan all-in-one installer** |
| `install.ps1` | Eski modüler installer (yerel kullanım, modules/ gerektirir) |
| `quick-install.ps1` | Bootstrap script (install-online.ps1'i indirir ve çalıştırır) |
| `uninstall.ps1` | SQL Server kaldırma scripti |
| `config/` | Yapılandırma şablonları |
| `modules/` | Eski modüler yapı (yerel kullanım için) |

## Versiyon Farkları

| Özellik | 2014 | 2017 | 2019 | 2022 | 2025 |
|---------|------|------|------|------|------|
| İndirme Yöntemi | Doğrudan | SSEI | Doğrudan | SSEI | SSEI |
| Max RAM (Express) | 1 GB | 1.4 GB | 1.4 GB | 1.4 GB | 1.4 GB |
| Max CPU (Express) | 1 core | 4 core | 4 core | 4 core | 4 core |
| TempDB Setup Param | Hayır | Evet | Evet | Evet | Evet |
| Instant File Init | Hayır | Evet | Evet | Evet | Evet |
| Backup Compression | Hayır | Evet | Evet | Evet | Evet |

## Teknik Detaylar

### Kurulum Akışı
1. Yönetici hakları kontrolü (otomatik yükseltme)
2. Sistem gereksinimleri kontrolü (64-bit, PS 5.1+, disk, RAM)
3. Etkileşimli menü ile versiyon ve instance seçimi
4. SQL Server medyası indirme (SSEI veya doğrudan)
5. Dosyaları çıkarma ve setup.exe çalıştırma (/QS unattended modu)
6. Protokol yapılandırması (TCP/IP, Named Pipes, Shared Memory - Registry)
7. SQL Browser servisi başlatma
8. Performans optimizasyonu (sp_configure, TempDB)
9. SQL Native Client 2012 kurulumu (gerekirse)
10. Bağlantı testi ve özet

### Neden All-in-One?
Eski yapıda `install.ps1` ayrı modül dosyalarına (`modules/*.psm1`) bağımlıydı. IEX ile web'den çalıştırıldığında `$PSScriptRoot` boş olduğundan modüller bulunamaz ve script çalışmazdı. `install-online.ps1` tüm fonksiyonları tek dosyada içerir.

### SSEI vs Doğrudan İndirme
- **Doğrudan**: Tam installer `.exe` indirilir → `/x:` ile extract → `setup.exe` çalıştırılır
- **SSEI**: Microsoft'un küçük bootstrap aracı indirilir → `/ACTION=Download` ile medya indirilir → extract → `setup.exe` çalıştırılır

## Gereksinimler

- Windows 10/11 veya Windows Server 2016+
- PowerShell 5.1 veya üzeri
- Yönetici hakları
- En az 4GB RAM
- En az 6GB disk alanı

## Güvenlik

SA kullanıcısının varsayılan şifresi: `Bay_T252!`
Kurulum sonrası şifreyi değiştirmeniz önerilir.

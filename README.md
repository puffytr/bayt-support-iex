# Bayt Support IEX Installer

Bu proje PowerShell IEX (Invoke-Expression) kullanarak **tek komutla** aşağıdaki işlemleri otomatik olarak gerçekleştirir:

1. **Visual C++ Runtime** kütüphanelerinin tamamını kurar (2005 - 2022)
2. **.NET Framework 3.5** ve **4.8.1** etkinleştirir/kurar
3. **SQL Server Express** kurar ve yapılandırır

## Hızlı Başlangıç (Tek Komut)

PowerShell'i **Yönetici olarak** açın ve şunu yapıştırın:

```powershell
iex (irm 'https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1')
```

> **Not:** Yönetici olarak açmadıysanız script otomatik olarak yetki yükseltme yapacaktır.

## Özellikler

### Visual C++ Runtime Kurulumu
- Visual C++ 2005, 2008, 2010, 2012, 2013, 2015-2022 (x86 + x64)
- Yerel dosyalar mevcutsa onları kullanır, yoksa Microsoft'tan otomatik indirir
- Sessiz kurulum (kullanıcı müdahalesi gerektirmez)

### .NET Framework Etkinleştirme
- .NET Framework 3.5 (Windows özelliği olarak etkinleştirir)
- .NET Framework 4.8.1 (kurulu değilse Microsoft'tan indirip kurar)

### SQL Server Express Kurulumu
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
iex (irm 'https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1')
```

### Yöntem 2: Alternatif Sözdizimi
```powershell
iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1')
```

### Yöntem 3: Yerel Kullanım
```powershell
# Projeyi indirin ve çalıştırın
.\install-online.ps1
```

## Dosya Yapısı

| Dosya / Klasör | Açıklama |
|----------------|----------|
| `install-online.ps1` | **Ana script - Web'den tek komutla çalışan all-in-one installer** |
| `Visual-C-Runtimes-All-in-One-Dec-2025/` | Visual C++ Runtime kurulum dosyaları (2005-2022, x86+x64) |

## Kurulum Akışı

```
┌─────────────────────────────────────────┐
│  1. Sistem gereksinimleri kontrolü      │
│  2. SQL versiyon ve instance seçimi     │
│  3. Kullanıcı onayı                    │
├─────────────────────────────────────────┤
│  4. Visual C++ Runtimes kurulumu        │
│     (2005, 2008, 2010, 2012, 2013,     │
│      2015-2022 x86+x64)               │
├─────────────────────────────────────────┤
│  5. .NET Framework 3.5 etkinleştirme   │
│  6. .NET Framework 4.8.1 kurulumu      │
├─────────────────────────────────────────┤
│  7. SQL Server medyası indirme         │
│  8. SQL Server kurulumu                │
│  9. Protokol yapılandırması            │
│ 10. Performans optimizasyonu           │
│ 11. SQL Native Client kurulumu         │
│ 12. Bağlantı testi ve özet            │
└─────────────────────────────────────────┘
```

## SQL Server Versiyon Farkları

| Özellik | 2014 | 2017 | 2019 | 2022 | 2025 |
|---------|------|------|------|------|------|
| İndirme Yöntemi | Doğrudan | SSEI | Doğrudan | SSEI | SSEI |
| Max RAM (Express) | 1 GB | 1.4 GB | 1.4 GB | 1.4 GB | 1.4 GB |
| Max CPU (Express) | 1 core | 4 core | 4 core | 4 core | 4 core |
| TempDB Setup Param | Hayır | Evet | Evet | Evet | Evet |
| Instant File Init | Hayır | Evet | Evet | Evet | Evet |
| Backup Compression | Hayır | Evet | Evet | Evet | Evet |

## Teknik Detaylar

### Neden All-in-One?
IEX ile web'den çalıştırıldığında `$PSScriptRoot` boş olduğundan modüller bulunamaz. `install-online.ps1` tüm fonksiyonları tek dosyada içerir ve ek bağımlılık gerektirmez.

### VC++ Runtime Yönetimi
- **Yerel çalışma:** `Visual-C-Runtimes-All-in-One-Dec-2025/` klasöründeki dosyalar kullanılır
- **IEX (web) çalışma:** Microsoft resmi sunucularından otomatik indirilir

### SSEI vs Doğrudan İndirme
- **Doğrudan**: Tam installer `.exe` indirilir → `/x:` ile extract → `setup.exe` çalıştırılır
- **SSEI**: Microsoft'un küçük bootstrap aracı indirilir → `/ACTION=Download` ile medya indirilir → extract → `setup.exe` çalıştırılır

## Lisans

Bu proje serbestçe kullanılabilir.

## Gereksinimler

- Windows 10/11 veya Windows Server 2016+
- PowerShell 5.1 veya üzeri
- Yönetici hakları
- En az 4GB RAM
- En az 6GB disk alanı

## Güvenlik

SA kullanıcısının varsayılan şifresi: `Bay_T252!`
Kurulum sonrası şifreyi değiştirmeniz önerilir.

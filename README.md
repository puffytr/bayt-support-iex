# Bayt Support IEX Installer

Windows sistemler icin **tek komutla** calisan, **GUI arayuzlu** otomatik kurulum araci.

Hangi bilesenleri kurmak istediginizi gorsel arayuzden secin:

- **Visual C++ Runtime** kutuphaneleri (2005 - 2022)
- **.NET Framework 3.5** ve **4.8.1**
- **SQL Server Express** *(opsiyonel)*
- **Firewall Kurallari** (TCP 1433 / UDP 1434)
- **Guc Plani** (Nihai Performans / Ultimate Performance)
- **Bay.T Uygulama Kurulumu** (Capital / Boss) *(opsiyonel)*
- **NVMe Disk Sektor Fix** (Win11 4KB+ sorun tespiti)

> SQL Server kurulumu **zorunlu degildir**. Sadece C++ ve .NET kurulumu icin de kullanabilirsiniz.

![GUI](https://img.shields.io/badge/Aray%C3%BCz-Windows%20Forms%20GUI-blue?style=for-the-badge)
![Version](https://img.shields.io/badge/Versiyon-4.0-green?style=for-the-badge)

## Hizli Baslangic (Tek Komut)

PowerShell'i **Yonetici olarak** acin ve sunu yapistin:

```powershell
iex (irm 'https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1')
```

> **Not:** Yonetici olarak acmadiyisaniz script otomatik olarak yetki yukseltme yapacaktir.

## Nasil Calisir?

1. Komut calistirilir
2. **GUI penceresi** acilir — kurmak istediginiz bilesenleri isaretleyin
3. **Kurulumu Baslat** butonuna tiklayin
4. Sectiginiz bilesenler sirayla kurulur, ilerleme konsolda gosterilir

```
┌──────────────────────────────────────────────────┐
│  Bayt Support Otomatik Kurulum v4.0              │
│  Kurmak istediginiz bilesenleri secin             │
│                                                   │
│  KURULACAK BILESENLER                             │
│  [x] Visual C++ Runtimes (2005-2022) [2 eksik]  │
│  [x] .NET Framework 3.5  [KURULU]               │
│  [x] .NET Framework 4.8.1  [KURULU DEGIL]       │
│  [ ] SQL Server Express Kurulumu                  │
│  [x] Guc Planini Nihai Performans (Ultimate) Yap │
│  [ ] Bay.T Capital Kurulumu   [ ] Bay.T Boss   │
│                                                   │
│  SQL SERVER AYARLARI (SQL secildiginde aktif)     │
│  Versiyon:  [SQL Server 2019 (Onerilen)]         │
│  Instance:  [BaytTicariSQL            ]           │
│  SA Sifre:  [Bay_T252!               ]           │
│  [x] Firewall Kurallari Olustur                  │
│                                                   │
│  MEVCUT INSTANCE YONETIMI                         │
│  [BaytBossSQL (Running)]  [Baslat] [Durdur]     │
│  [SQL Kaldir]                                    │
│                                                   │
│  [  Kurulumu Baslat  ]  [  Iptal  ]              │
└──────────────────────────────────────────────────┘
```

## Ozellikler

### Akilli Tespit Sistemi
- Kurulu VC++ versiyonlarini tespit eder, zaten kurulu olanlari atlar
- .NET 3.5/4.8.1 kurulum durumunu kontrol eder, GUI'de `[KURULU]` etiketi gosterir
- Mevcut SQL Server instance'larini tespit eder, cakisma olan isimlerle kurulumu engeller
- NVMe disk sektor boyutunu kontrol eder (Win11 4KB+ sorunu icin)

### Visual C++ Runtime Kurulumu
- Visual C++ 2005, 2008, 2010, 2012, 2013, 2015-2022 (x86 + x64)
- **Versiyon bazli kontrol**: Her versiyon ayri ayri kontrol edilir, kurulu olanlar atlanir
- Yerel dosyalar mevcutsa onlari kullanir, yoksa Microsoft'tan otomatik indirir
- Sessiz kurulum (kullanici mudahalesi gerektirmez)

### .NET Framework Etkinlestirme
- .NET Framework 3.5 (Windows ozelligi olarak etkinlestirir)
- .NET Framework 4.8.1 (kurulu degilse Microsoft'tan indirip kurar)
- **Windows Server destegi**: Server ortamlarinda `Install-WindowsFeature` kullanir
- Her biri ayri ayri secilip devre disi birakilabilir

### SQL Server Express Kurulumu (Opsiyonel)
- SQL Server 2019, 2022, 2025 versiyonlarini destekler
- **Kurmak zorunda degilsiniz** — GUI'den isaretlemezseniz atlanir
- **Instance adi validasyonu**: Max 16 karakter, harf ile baslama, ozel karakter kontrolu
- **SA sifre karmasiklik kontrolu**: Buyuk/kucuk harf, rakam, ozel karakter zorunlu
- Otomatik sa kullanicisi olusturma
- Hazir instance isimleri (BaytTicariSQL, BaytBossSQL, Bayt) veya serbest yazi ile ozel isim
- SQL Native Client 2012 kurulumu (otomatik kontrol)
- Shared Memory, TCP/IP ve Named Pipes protokolu etkinlestirme
- SQL Server Browser servisi etkinlestirme
- **Performans Optimizasyonu:**
  - Otomatik RAM ve CPU optimizasyonu (Express limitleri dahilinde)
  - TempDB coklu dosya yapilandirmasi
  - Max Degree of Parallelism, Cost Threshold, Backup Compression
  - Aninda dosya baslatma (Instant File Initialization, 2019+)

### Firewall Kurallari
- SQL Server icin **TCP 1433** inbound kurali
- SQL Browser icin **UDP 1434** inbound kurali
- SQL Server program (sqlservr.exe) icin inbound kurali
- Mevcut kurallari kontrol eder, yeniden olusturmaz

### NVMe Disk Sektor Fix
- Win11 NVMe suruculerinde 4KB+ sektor boyutu sorununu tespit eder
- `ForcedPhysicalSectorSizeInBytes` registry duzeltmesi uygular
- SQL Server kurulumu oncesinde otomatik kontrol ve yeniden baslatma teklifi
- Referans: [Microsoft Learn - 4KB Sector Size](https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/database-file-operations/troubleshoot-os-4kb-disk-sector-size)

### Mevcut Instance Yonetimi
- Kurulu SQL Server instance'larini GUI'de listeler
- **Baslat / Durdur / Yeniden Baslat** butonlari ile servis yonetimi
- **SQL Kaldir** butonu ile mevcut instance'i tamamen kaldirma
- Kaldirma oncesi **2 asamali onay** ile yanlislikla silmeyi onler
- Kaldirma sirasinda setup.exe, registry ve uninstall string yontemleri denenir
- Kaldirma sonrasi ilgili firewall kurallari da temizlenir
- Servis durumu anlik guncellenir

### Guc Plani (Power Plan)
- **Nihai Performans (Ultimate Performance)** guc planini otomatik etkinlestirir
- Windows 10 ve Windows 11 icin ayri tespit ve uygulama mantigi
- Windows 11'de Modern Standby aktifse otomatik override eklenir
- Plan bulunamazsa otomatik olarak sisteme eklenir
- Basarisiz olursa High Performance'a fallback yapar
- SQL Server performansi icin onerilir

### Bay.T Uygulama Kurulumu
- **Bay.T Capital** ve **Bay.T Boss** kurulum dosyalarini indirir ve baslatir
- Varsayilan olarak **kapali** gelir, istek uzerine isaretlenebilir
- Capital: `https://bay-t.com.tr/assets/download/Capital/CapitalSetup.exe`
- Boss: `https://bay-t.com.tr/assets/download/BOSS/BossSetup.exe`
- Her iki uygulama bagimsiz olarak secilip kurulabilir

### Diger Ozellikler
- **Log dosyasi**: Tum kurulum ciktisi `%TEMP%\BaytSqlInstall\install-log-{tarih}.txt` dosyasina kaydedilir
- **Otomatik guncelleme kontrolu**: Script basinda GitHub'dan yeni versiyon kontrolu yapar
- **Indirme ilerleme gostergesi**: Buyuk dosya indirmelerinde `%` ilerleme gosterir

## Kullanim

### Yontem 1: Web'den Tek Komut (TAVSIYE EDILEN)
```powershell
# PowerShell'i Yonetici olarak acin ve yapistin:
iex (irm 'https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1')
```

### Yontem 2: Alternatif Sozdizimi
```powershell
iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1')
```

### Yontem 3: Yerel Kullanim
```powershell
.\install-online.ps1
```

### Yontem 4: Sessiz / Unattended Kurulum (Toplu Dagitim)
```powershell
# Tum bilesenleri kur (GUI olmadan)
.\install-online.ps1 -Silent -InstallVCPP -InstallNet35 -InstallNet481 -InstallSQL -SqlVersion 2022 -InstanceName BaytSQL -SAPass 'Guclu_S1fre!'

# Sadece VC++ ve .NET kur
.\install-online.ps1 -Silent -InstallVCPP -InstallNet35 -InstallNet481

# Parametreleri gormek icin
.\install-online.ps1 -Help
```

| Parametre | Aciklama |
|-----------|----------|
| `-Silent` | Sessiz kurulum (GUI gostermez) |
| `-InstallVCPP` | Visual C++ Runtimes kur |
| `-InstallNet35` | .NET Framework 3.5 etkinlestir |
| `-InstallNet481` | .NET Framework 4.8.1 kur |
| `-InstallSQL` | SQL Server Express kur |
| `-InstallFirewall` | Firewall kurallari olustur |
| `-SetPowerPlan` | Guc planini Nihai Performans (Ultimate) yap |
| `-InstallCapital` | Bay.T Capital kurulumunu indir ve baslat |
| `-InstallBoss` | Bay.T Boss kurulumunu indir ve baslat |
| `-SqlVersion` | SQL versiyonu: `2019`, `2022`, `2025` |
| `-InstanceName` | SQL instance adi |
| `-SAPass` | SA sifresi |
| `-Help` | Yardim mesajini goster |

## Dosya Yapisi

| Dosya / Klasor | Aciklama |
|----------------|----------|
| `install-online.ps1` | **Ana script — GUI arayuzlu all-in-one installer** |
| `Visual-C-Runtimes-All-in-One-Dec-2025/` | Visual C++ Runtime kurulum dosyalari (2005-2022, x86+x64) |

## Kurulum Akisi

```
┌─────────────────────────────────────────┐
│  1. Guncelleme kontrolu                │
│  2. GUI acilir, bilesen secimi          │
│  3. Sistem gereksinimleri kontrolu      │
├─────────────────────────────────────────┤
│  4. Visual C++ Runtimes kurulumu        │
│     (secildiyse, eksik olanlar)         │
├─────────────────────────────────────────┤
│  5. .NET Framework 3.5 etkinlestirme   │
│  6. .NET Framework 4.8.1 kurulumu      │
│     (secildiyse)                        │
├─────────────────────────────────────────┤
│  7. NVMe Disk Sektor Fix               │
│     (tespit edildiyse)                  │
├─────────────────────────────────────────┤
│  8. SQL Server indirme ve kurulumu      │
│  9. Firewall kurallari                  │
│ 10. Protokol yapilandirmasi             │
│ 11. Performans optimizasyonu            │
│ 12. Baglanti testi ve ozet             │
│     (SQL secildiyse)                    │
├─────────────────────────────────────────┤
│ 13. Guc Plani ayarlama                  │
│     (secildiyse)                        │
└─────────────────────────────────────────┘
```

## SQL Server Versiyon Farklari

| Ozellik | 2019 | 2022 | 2025 |
|---------|------|------|------|
| Indirme Yontemi | Dogrudan | SSEI | SSEI |
| Max RAM (Express) | 1.4 GB | 1.4 GB | 1.4 GB |
| Max CPU (Express) | 4 core | 4 core | 4 core |
| TempDB Setup Param | Evet | Evet | Evet |
| Instant File Init | Evet | Evet | Evet |
| Backup Compression | Evet | Evet | Evet |

## Teknik Detaylar

### Neden All-in-One?
IEX ile web'den calistirildiginda `$PSScriptRoot` bos oldugundan moduller bulunamaz. `install-online.ps1` tum fonksiyonlari tek dosyada icerir ve ek bagimlilik gerektirmez.

### VC++ Runtime Yonetimi
- **Yerel calisma:** `Visual-C-Runtimes-All-in-One-Dec-2025/` klasorundeki dosyalar kullanilir
- **IEX (web) calisma:** Microsoft resmi sunucularindan otomatik indirilir
- **Akilli atlatma:** Registry'den kurulu versiyonlar tespit edilir, yalnizca eksikler kurulur

### SSEI vs Dogrudan Indirme
- **Dogrudan**: Tam installer `.exe` indirilir → `/x:` ile extract → `setup.exe` calistirilir
- **SSEI**: Microsoft'un kucuk bootstrap araci indirilir → `/ACTION=Download` ile medya indirilir → extract → `setup.exe` calistirilir

### NVMe 4KB Sektor Sorunu
Windows 11'de bazi NVMe suruculer 4096 byte'tan buyuk fiziksel sektor boyutu rapor edebilir. SQL Server bu durumu desteklemez ve kurulum/calisma hatasi verir. Script bunu `fsutil fsinfo sectorinfo` ile tespit edip `ForcedPhysicalSectorSizeInBytes` registry duzeltmesini uygular.

## Guvenlik

SA kullanicisinin varsayilan sifresi: `Bay_T252!`

> **NOT:** `BaytTicariSQL` veya `BaytBossSQL` instance'lari icin SA sifre degisimi gerekmez. Bayt yazilim setup'lari SQL'e baglanirken bu sifreyi otomatik olarak belirler ve degistirir. Ekstra bir islem yapmaniza gerek yoktur.

> Farkli instance isimleri kullaniyorsaniz kurulum sonrasi SA sifresini degistirmeniz onerilir.

## Gereksinimler

- Windows 10/11 veya Windows Server 2016+
- PowerShell 5.1 veya uzeri
- Yonetici haklari
- En az 4GB RAM
- En az 6GB disk alani
- Internet baglantisi (web kurulumu icin)

## Lisans

Bu proje serbestce kullanilabilir.

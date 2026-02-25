# Bayt Support IEX Installer

Windows sistemler icin **tek komutla** calisan, **GUI arayuzlu** otomatik kurulum araci.

Hangi bilesenleri kurmak istediginizi gorsel arayuzden secin:

- **Visual C++ Runtime** kutuphaneleri (2005 - 2022)
- **.NET Framework 3.5** ve **4.8.1**
- **SQL Server Express** *(opsiyonel)*

> SQL Server kurulumu **zorunlu degildir**. Sadece C++ ve .NET kurulumu icin de kullanabilirsiniz.

![GUI](https://img.shields.io/badge/Aray%C3%BCz-Windows%20Forms%20GUI-blue?style=for-the-badge)

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
│  Bayt Support Otomatik Kurulum v3.0              │
│  Kurmak istediginiz bilesenleri secin             │
│                                                   │
│  KURULACAK BILESENLER                             │
│  [x] Visual C++ Runtimes (2005-2022, x86+x64)   │
│  [x] .NET Framework 3.5                          │
│  [x] .NET Framework 4.8.1                        │
│  [ ] SQL Server Express Kurulumu                  │
│                                                   │
│  SQL SERVER AYARLARI (SQL secildiginde aktif)     │
│  Versiyon: [SQL Server 2019 (Onerilen)]          │
│  Instance: [BaytTicariSQL            ]            │
│  SA Sifre: [Bay_T252!               ]            │
│                                                   │
│  [  Kurulumu Baslat  ]  [  Iptal  ]              │
└──────────────────────────────────────────────────┘
```

## Ozellikler

### Visual C++ Runtime Kurulumu
- Visual C++ 2005, 2008, 2010, 2012, 2013, 2015-2022 (x86 + x64)
- Yerel dosyalar mevcutsa onlari kullanir, yoksa Microsoft'tan otomatik indirir
- Sessiz kurulum (kullanici mudahalesi gerektirmez)

### .NET Framework Etkinlestirme
- .NET Framework 3.5 (Windows ozelligi olarak etkinlestirir)
- .NET Framework 4.8.1 (kurulu degilse Microsoft'tan indirip kurar)
- Her biri ayri ayri secilip devre disi birakilabilir

### SQL Server Express Kurulumu (Opsiyonel)
- SQL Server 2014, 2017, 2019, 2022, 2025 versiyonlarini destekler
- **Kurmak zorunda degilsiniz** — GUI'den isaretlemezseniz atlanir
- Otomatik sa kullanicisi olusturma
- Hazir instance isimleri (BaytTicariSQL, BaytBossSQL, Bayt) veya serbest yazi ile ozel isim
- SQL Native Client 2012 kurulumu (otomatik kontrol)
- Shared Memory, TCP/IP ve Named Pipes protokolu etkinlestirme
- SQL Server Browser servisi etkinlestirme
- **Performans Optimizasyonu:**
  - Otomatik RAM ve CPU optimizasyonu (Express limitleri dahilinde)
  - TempDB coklu dosya yapilandirmasi
  - Max Degree of Parallelism, Cost Threshold, Backup Compression
  - Aninda dosya baslatma (Instant File Initialization, 2017+)

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
# Projeyi indirin ve calistirin
.\install-online.ps1
```

## Dosya Yapisi

| Dosya / Klasor | Aciklama |
|----------------|----------|
| `install-online.ps1` | **Ana script — GUI arayuzlu all-in-one installer** |
| `Visual-C-Runtimes-All-in-One-Dec-2025/` | Visual C++ Runtime kurulum dosyalari (2005-2022, x86+x64) |

## Kurulum Akisi

```
┌─────────────────────────────────────────┐
│  1. GUI acilir, bilesen secimi          │
│  2. Sistem gereksinimleri kontrolu      │
├─────────────────────────────────────────┤
│  3. Visual C++ Runtimes kurulumu        │
│     (secildiyse)                        │
├─────────────────────────────────────────┤
│  4. .NET Framework 3.5 etkinlestirme   │
│  5. .NET Framework 4.8.1 kurulumu      │
│     (secildiyse)                        │
├─────────────────────────────────────────┤
│  6. SQL Server indirme ve kurulumu      │
│  7. Protokol yapilandirmasi             │
│  8. Performans optimizasyonu            │
│  9. Baglanti testi ve ozet             │
│     (SQL secildiyse)                    │
└─────────────────────────────────────────┘
```

## SQL Server Versiyon Farklari

| Ozellik | 2014 | 2017 | 2019 | 2022 | 2025 |
|---------|------|------|------|------|------|
| Indirme Yontemi | Dogrudan | SSEI | Dogrudan | SSEI | SSEI |
| Max RAM (Express) | 1 GB | 1.4 GB | 1.4 GB | 1.4 GB | 1.4 GB |
| Max CPU (Express) | 1 core | 4 core | 4 core | 4 core | 4 core |
| TempDB Setup Param | Hayir | Evet | Evet | Evet | Evet |
| Instant File Init | Hayir | Evet | Evet | Evet | Evet |
| Backup Compression | Hayir | Evet | Evet | Evet | Evet |

## Teknik Detaylar

### Neden All-in-One?
IEX ile web'den calistirildiginda `$PSScriptRoot` bos oldugundan moduller bulunamaz. `install-online.ps1` tum fonksiyonlari tek dosyada icerir ve ek bagimlilik gerektirmez.

### VC++ Runtime Yonetimi
- **Yerel calisma:** `Visual-C-Runtimes-All-in-One-Dec-2025/` klasorundeki dosyalar kullanilir
- **IEX (web) calisma:** Microsoft resmi sunucularindan otomatik indirilir

### SSEI vs Dogrudan Indirme
- **Dogrudan**: Tam installer `.exe` indirilir → `/x:` ile extract → `setup.exe` calistirilir
- **SSEI**: Microsoft'un kucuk bootstrap araci indirilir → `/ACTION=Download` ile medya indirilir → extract → `setup.exe` calistirilir

## Lisans

Bu proje serbestce kullanilabilir.

## Gereksinimler

- Windows 10/11 veya Windows Server 2016+
- PowerShell 5.1 veya üzeri
- Yönetici hakları
- En az 4GB RAM
- En az 6GB disk alanı

## Güvenlik

SA kullanıcısının varsayılan şifresi: `Bay_T252!`
Kurulum sonrası şifreyi değiştirmeniz önerilir.

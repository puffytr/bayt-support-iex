# ============================================================================
# Bayt Support SQL Server Otomatik Kurulum Scripti (All-in-One / Web Ready)
# Versiyon: 2.0
# Tarih: 2026
# ============================================================================
# Kullanim (tek komut):
#   iex (irm 'https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1')
# veya:
#   iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1')
# ============================================================================

$ErrorActionPreference = "Stop"

# TLS 1.2/1.3 zorunlu (Microsoft download servisleri icin)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

# ============================================================================
#region YAPILANDIRMA
# ============================================================================
$Script:SAPassword       = "Bay_T252!"
$Script:ScriptVersion    = "2.0"
$Script:TempBase         = "$env:TEMP\BaytSqlInstall"
$Script:ScriptUrl        = "https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1"

# SQL Server indirme bilgileri
# Type: "Direct" = dogrudan extract edilebilir installer (.exe /x: ile)
# Type: "SSEI"   = SQL Server Express Setup Installer (once /ACTION=Download ile medya indirir)
$Script:SqlDownloadInfo = @{
    "2014" = @{
        Type     = "Direct"
        Urls     = @(
            "https://download.microsoft.com/download/E/A/E/EAE6F7FC-767A-4038-A954-49B8B05D04EB/Express%2064BIT/SQLEXPR_x64_ENU.exe",
            "https://download.microsoft.com/download/E/A/E/EAE6F7FC-767A-4038-A954-49B8B05D04EB/ExpressAndTools/SQLEXPRWT_x64_ENU.exe"
        )
        Features             = "SQLENGINE"
        SupportsInstantInit  = $false
        SupportsTempDBParams = $false
        MajorVersion         = 12
        ExpressMaxMemoryMB   = 1024
        ExpressMaxCores      = 1
    }
    "2017" = @{
        Type     = "SSEI"
        Urls     = @(
            "https://go.microsoft.com/fwlink/?linkid=853017",
            "https://download.microsoft.com/download/5/E/C/5EC8BC35-4068-46D3-85AC-5F73ECCE3DDB/SQLServer2017-SSEI-Expr.exe"
        )
        Features             = "SQLENGINE"
        SupportsInstantInit  = $true
        SupportsTempDBParams = $true
        MajorVersion         = 14
        ExpressMaxMemoryMB   = 1410
        ExpressMaxCores      = 4
    }
    "2019" = @{
        Type     = "Direct"
        Urls     = @(
            "https://download.microsoft.com/download/7/c/1/7c14e92e-bdcb-4f89-b7cf-93543e7112d1/SQLEXPR_x64_ENU.exe"
        )
        FallbackType = "SSEI"
        FallbackUrls = @(
            "https://go.microsoft.com/fwlink/?linkid=866658"
        )
        Features             = "SQLENGINE"
        SupportsInstantInit  = $true
        SupportsTempDBParams = $true
        MajorVersion         = 15
        ExpressMaxMemoryMB   = 1410
        ExpressMaxCores      = 4
    }
    "2022" = @{
        Type     = "SSEI"
        Urls     = @(
            "https://go.microsoft.com/fwlink/p/?linkid=2216019",
            "https://download.microsoft.com/download/3/8/d/38de7036-2433-4207-8eae-06e247e17b25/SQLServer2022-SSEI-Expr.exe"
        )
        Features             = "SQLENGINE"
        SupportsInstantInit  = $true
        SupportsTempDBParams = $true
        MajorVersion         = 16
        ExpressMaxMemoryMB   = 1410
        ExpressMaxCores      = 4
    }
    "2025" = @{
        Type     = "SSEI"
        Urls     = @(
            "https://go.microsoft.com/fwlink/?linkid=2264125"
        )
        Features             = "SQLENGINE"
        SupportsInstantInit  = $true
        SupportsTempDBParams = $true
        MajorVersion         = 17
        ExpressMaxMemoryMB   = 1410
        ExpressMaxCores      = 4
    }
}

# SQL Native Client 2012 URL
$Script:NativeClientUrl = "https://download.microsoft.com/download/F/E/D/FEDB200F-DE2A-46D8-B661-D019DFE9D470/ENU/x64/sqlncli.msi"

# .NET Framework 4.8.1 indirme URL
$Script:DotNet481Url = "https://go.microsoft.com/fwlink/?linkid=2203306"

# Script dizinini belirle (yerel calisma icin VC++ dosyalarini bulmak uzere)
$Script:ScriptDir = $null
if ($PSScriptRoot) {
    $Script:ScriptDir = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $Script:ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
}
#endregion

# ============================================================================
#region YONETICI HAKLARI KONTROLU
# ============================================================================
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  YONETICI HAKLARI GEREKLIDIR!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""

    try {
        Write-Host "Yonetici haklari ile yeniden baslatiliyor..." -ForegroundColor Yellow
        $TempScript = "$env:TEMP\BaytSqlInstall_Elevated.ps1"

        # IEX modunda calisiyorsak, script icerigini kaydet
        if ($MyInvocation.MyCommand.ScriptBlock) {
            $MyInvocation.MyCommand.ScriptBlock.ToString() | Out-File $TempScript -Encoding UTF8 -Force
        } else {
            # Dosyadan calisiyorsak, dosyanin kendisini kullan
            Copy-Item $MyInvocation.MyCommand.Path $TempScript -Force
        }

        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$TempScript`"" -Verb RunAs
        Write-Host "Yeni yonetici PowerShell penceresi acildi." -ForegroundColor Green
        Write-Host "Bu pencereyi kapatabilirsiniz." -ForegroundColor Gray
    }
    catch {
        Write-Host ""
        Write-Host "Otomatik yukseltme basarisiz oldu. Lutfen:" -ForegroundColor Yellow
        Write-Host '  1. PowerShell''i "Yonetici olarak calistir" ile acin' -ForegroundColor White
        Write-Host "  2. Asagidaki komutu yapistin:" -ForegroundColor White
        Write-Host "     iex (irm '$($Script:ScriptUrl)')" -ForegroundColor Cyan
    }
    return
}
#endregion

# ============================================================================
#region YARDIMCI FONKSIYONLAR
# ============================================================================

function Write-Banner {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "    Bayt Support Otomatik Kurulum v$($Script:ScriptVersion)" -ForegroundColor Cyan
    Write-Host "    (VC++ Runtimes + .NET Framework + SQL Server Express)" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message, [string]$Color = "Yellow")
    Write-Host ""
    Write-Host ">> $Message" -ForegroundColor $Color
    Write-Host ("-" * 50) -ForegroundColor DarkGray
}

function Write-OK   { param([string]$Msg) Write-Host "   [OK] $Msg" -ForegroundColor Green }
function Write-Info { param([string]$Msg) Write-Host "   [i]  $Msg" -ForegroundColor Cyan }
function Write-Warn { param([string]$Msg) Write-Host "   [!]  $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "   [X]  $Msg" -ForegroundColor Red }

# ADO.NET tabanli SQL sorgusu - Invoke-Sqlcmd'ye bagimliligi kaldirir
function Invoke-SqlNonQuery {
    param(
        [string]$ServerInstance,
        [string]$Query,
        [switch]$UseWindowsAuth,
        [string]$Username = "sa",
        [string]$Password = $Script:SAPassword,
        [int]$TimeoutSec = 120
    )

    $ConnStr = if ($UseWindowsAuth) {
        "Server=$ServerInstance;Integrated Security=True;TrustServerCertificate=True;Connection Timeout=30;"
    } else {
        "Server=$ServerInstance;User ID=$Username;Password=$Password;TrustServerCertificate=True;Connection Timeout=30;"
    }

    $Conn = New-Object System.Data.SqlClient.SqlConnection($ConnStr)
    try {
        $Conn.Open()
        $Cmd = $Conn.CreateCommand()
        $Cmd.CommandText = $Query
        $Cmd.CommandTimeout = $TimeoutSec
        $Cmd.ExecuteNonQuery() | Out-Null
    }
    finally {
        if ($Conn -and $Conn.State -eq 'Open') { $Conn.Close() }
        if ($Conn) { $Conn.Dispose() }
    }
}

function Invoke-SqlScalar {
    param(
        [string]$ServerInstance,
        [string]$Query,
        [switch]$UseWindowsAuth,
        [string]$Username = "sa",
        [string]$Password = $Script:SAPassword
    )

    $ConnStr = if ($UseWindowsAuth) {
        "Server=$ServerInstance;Integrated Security=True;TrustServerCertificate=True;Connection Timeout=30;"
    } else {
        "Server=$ServerInstance;User ID=$Username;Password=$Password;TrustServerCertificate=True;Connection Timeout=30;"
    }

    $Conn = New-Object System.Data.SqlClient.SqlConnection($ConnStr)
    try {
        $Conn.Open()
        $Cmd = $Conn.CreateCommand()
        $Cmd.CommandText = $Query
        $Cmd.CommandTimeout = 60
        return $Cmd.ExecuteScalar()
    }
    finally {
        if ($Conn -and $Conn.State -eq 'Open') { $Conn.Close() }
        if ($Conn) { $Conn.Dispose() }
    }
}

function Get-SqlServiceName {
    param([string]$InstanceName)
    if ($InstanceName -eq "MSSQLSERVER") { return "MSSQLSERVER" }
    return "MSSQL`$$InstanceName"
}

function Get-SqlServerInstance {
    param([string]$InstanceName)
    if ($InstanceName -eq "MSSQLSERVER") { return "localhost" }
    return "localhost\$InstanceName"
}

function Wait-SqlServiceReady {
    param(
        [string]$InstanceName,
        [int]$TimeoutSeconds = 180
    )

    $ServiceName = Get-SqlServiceName $InstanceName
    $ServerInstance = Get-SqlServerInstance $InstanceName
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Info "SQL Server servisi bekleniyor..."

    # Once servisin baslamasini bekle
    while ($Stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $Svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($Svc -and $Svc.Status -eq "Running") { break }
        Start-Sleep -Seconds 3
    }

    # Sonra baglanti kabul etmesini bekle
    while ($Stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        try {
            $Conn = New-Object System.Data.SqlClient.SqlConnection("Server=$ServerInstance;Integrated Security=True;TrustServerCertificate=True;Connection Timeout=5;")
            $Conn.Open()
            $Conn.Close()
            $Conn.Dispose()
            Write-OK "SQL Server hazir. ($(([int]$Stopwatch.Elapsed.TotalSeconds)) saniye)"
            return $true
        }
        catch {
            Start-Sleep -Seconds 3
        }
    }

    Write-Warn "SQL Server $TimeoutSeconds saniye icerisinde baglanti kabul etmedi."
    return $false
}

function Download-FileWithRetry {
    param(
        [string[]]$Urls,
        [string]$OutputPath,
        [string]$Description = "Dosya",
        [int]$MaxRetries = 2
    )

    foreach ($Url in $Urls) {
        Write-Info "Indiriliyor: $Url"
        for ($retry = 1; $retry -le $MaxRetries; $retry++) {
            try {
                if ($retry -gt 1) {
                    Write-Warn "Tekrar deneniyor ($retry/$MaxRetries)..."
                    Start-Sleep -Seconds 3
                }

                # BITS Transfer dene (progress bar gosterir)
                try {
                    Start-BitsTransfer -Source $Url -Destination $OutputPath -DisplayName $Description -ErrorAction Stop
                }
                catch {
                    # BITS basarisiz olursa WebClient kullan
                    $wc = New-Object System.Net.WebClient
                    $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                    $wc.DownloadFile($Url, $OutputPath)
                    $wc.Dispose()
                }

                if ((Test-Path $OutputPath) -and (Get-Item $OutputPath).Length -gt 1MB) {
                    $SizeMB = [math]::Round((Get-Item $OutputPath).Length / 1MB, 1)
                    Write-OK "Indirildi: $SizeMB MB"
                    return $true
                }
                throw "Indirilen dosya gecersiz veya bos."
            }
            catch {
                Write-Warn "Indirme hatasi: $($_.Exception.Message)"
                if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force -ErrorAction SilentlyContinue }
            }
        }
    }

    Write-Err "Dosya hicbir URL'den indirilemedi!"
    return $false
}
#endregion

# ============================================================================
#region VISUAL C++ RUNTIME KURULUMU
# ============================================================================

function Install-VCRuntimes {
    Write-Step "Visual C++ Runtime kutuphaneleri kuruluyor..."

    $VCRedistDir = $null

    # Yerel dosyalar mevcut mu kontrol et
    if ($Script:ScriptDir) {
        $LocalVCDir = Join-Path $Script:ScriptDir "Visual-C-Runtimes-All-in-One-Dec-2025"
        if (Test-Path $LocalVCDir) {
            $VCRedistDir = $LocalVCDir
            Write-Info "Yerel VC++ dosyalari bulundu: $VCRedistDir"
        }
    }

    if (-not $VCRedistDir) {
        # IEX modunda - Microsoft'tan indir
        Write-Info "VC++ Runtime dosyalari Microsoft'tan indiriliyor..."
        New-Item -Path $Script:TempBase -ItemType Directory -Force | Out-Null
        $VCRedistDir = "$($Script:TempBase)\VCRedist"
        New-Item -Path $VCRedistDir -ItemType Directory -Force | Out-Null

        $VCDownloads = @(
            @{ Name = "vcredist2005_x86.exe"; Url = "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" },
            @{ Name = "vcredist2005_x64.exe"; Url = "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" },
            @{ Name = "vcredist2008_x86.exe"; Url = "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe" },
            @{ Name = "vcredist2008_x64.exe"; Url = "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe" },
            @{ Name = "vcredist2010_x86.exe"; Url = "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe" },
            @{ Name = "vcredist2010_x64.exe"; Url = "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe" },
            @{ Name = "vcredist2012_x86.exe"; Url = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe" },
            @{ Name = "vcredist2012_x64.exe"; Url = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe" },
            @{ Name = "vcredist2013_x86.exe"; Url = "https://aka.ms/highdpimfc2013x86enu" },
            @{ Name = "vcredist2013_x64.exe"; Url = "https://aka.ms/highdpimfc2013x64enu" },
            @{ Name = "vcredist2015_2017_2019_2022_x86.exe"; Url = "https://aka.ms/vs/17/release/vc_redist.x86.exe" },
            @{ Name = "vcredist2015_2017_2019_2022_x64.exe"; Url = "https://aka.ms/vs/17/release/vc_redist.x64.exe" }
        )

        foreach ($vc in $VCDownloads) {
            $OutPath = Join-Path $VCRedistDir $vc.Name
            try {
                Write-Info "Indiriliyor: $($vc.Name)..."
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                $wc.DownloadFile($vc.Url, $OutPath)
                $wc.Dispose()
            } catch {
                Write-Warn "$($vc.Name) indirilemedi: $($_.Exception.Message)"
            }
        }
    }

    # Kurulum
    $Is64Bit = [Environment]::Is64BitOperatingSystem

    $Installs = @(
        @{ Name = "2005"; x86 = "vcredist2005_x86.exe"; x64 = "vcredist2005_x64.exe"; Args = "/q" },
        @{ Name = "2008"; x86 = "vcredist2008_x86.exe"; x64 = "vcredist2008_x64.exe"; Args = "/qb" },
        @{ Name = "2010"; x86 = "vcredist2010_x86.exe"; x64 = "vcredist2010_x64.exe"; Args = "/passive /norestart" },
        @{ Name = "2012"; x86 = "vcredist2012_x86.exe"; x64 = "vcredist2012_x64.exe"; Args = "/passive /norestart" },
        @{ Name = "2013"; x86 = "vcredist2013_x86.exe"; x64 = "vcredist2013_x64.exe"; Args = "/passive /norestart" },
        @{ Name = "2015-2022"; x86 = "vcredist2015_2017_2019_2022_x86.exe"; x64 = "vcredist2015_2017_2019_2022_x64.exe"; Args = "/passive /norestart" }
    )

    $SuccessCount = 0
    $TotalCount = 0

    foreach ($inst in $Installs) {
        Write-Info "Visual C++ $($inst.Name) kuruluyor..."

        # x86
        $x86Path = Join-Path $VCRedistDir $inst.x86
        if (Test-Path $x86Path) {
            $TotalCount++
            $p = Start-Process -FilePath $x86Path -ArgumentList $inst.Args -Wait -PassThru
            if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010 -or $p.ExitCode -eq 1638) {
                Write-OK "VC++ $($inst.Name) x86 kuruldu"
                $SuccessCount++
            } else {
                Write-Warn "VC++ $($inst.Name) x86 - Exit Code: $($p.ExitCode)"
            }
        }

        # x64
        if ($Is64Bit) {
            $x64Path = Join-Path $VCRedistDir $inst.x64
            if (Test-Path $x64Path) {
                $TotalCount++
                $p = Start-Process -FilePath $x64Path -ArgumentList $inst.Args -Wait -PassThru
                if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010 -or $p.ExitCode -eq 1638) {
                    Write-OK "VC++ $($inst.Name) x64 kuruldu"
                    $SuccessCount++
                } else {
                    Write-Warn "VC++ $($inst.Name) x64 - Exit Code: $($p.ExitCode)"
                }
            }
        }
    }

    Write-OK "Visual C++ Runtime kurulumu tamamlandi ($SuccessCount/$TotalCount basarili)"
}
#endregion

# ============================================================================
#region .NET FRAMEWORK ETKINLESTIRME
# ============================================================================

function Enable-DotNetFrameworks {
    Write-Step ".NET Framework 3.5 ve 4.8.1 etkinlestiriliyor..."

    # --- .NET Framework 3.5 ---
    Write-Info ".NET Framework 3.5 kontrol ediliyor..."
    try {
        $NetFx3 = Get-WindowsOptionalFeature -Online -FeatureName "NetFx3" -ErrorAction SilentlyContinue
        if ($NetFx3 -and $NetFx3.State -eq "Enabled") {
            Write-OK ".NET Framework 3.5 zaten etkin"
        } else {
            Write-Info ".NET Framework 3.5 etkinlestiriliyor (Windows Update'ten indirilecek)..."
            Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -All -NoRestart -ErrorAction Stop | Out-Null
            Write-OK ".NET Framework 3.5 etkinlestirildi"
        }
    } catch {
        Write-Warn ".NET 3.5 etkinlestirilemedi: $($_.Exception.Message)"
        Write-Info "Manuel: Denetim Masasi > Programlar > Windows ozelliklerini ac/kapat"
    }

    # --- .NET Framework 4.8.1 ---
    Write-Info ".NET Framework 4.8.1 kontrol ediliyor..."
    try {
        $DotNet4 = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name "Release" -ErrorAction SilentlyContinue
        # .NET 4.8.1 Release numarasi: 533320 (Windows 11) veya 533325+
        if ($DotNet4 -and $DotNet4.Release -ge 533320) {
            Write-OK ".NET Framework 4.8.1 zaten kurulu (Release: $($DotNet4.Release))"
        } else {
            Write-Info ".NET Framework 4.8.1 indiriliyor ve kuruluyor..."
            New-Item -Path $Script:TempBase -ItemType Directory -Force | Out-Null
            $DotNet481Path = "$($Script:TempBase)\ndp481-setup.exe"

            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            $wc.DownloadFile($Script:DotNet481Url, $DotNet481Path)
            $wc.Dispose()

            if (Test-Path $DotNet481Path) {
                $SizeMB = [math]::Round((Get-Item $DotNet481Path).Length / 1MB, 1)
                Write-Info "Indirildi: $SizeMB MB - Kuruluyor..."
                $p = Start-Process -FilePath $DotNet481Path -ArgumentList "/passive /norestart" -Wait -PassThru
                switch ($p.ExitCode) {
                    0       { Write-OK ".NET Framework 4.8.1 basariyla kuruldu" }
                    3010    { Write-OK ".NET Framework 4.8.1 kuruldu (yeniden baslatma onerilir)" }
                    1641    { Write-OK ".NET Framework 4.8.1 kuruldu (yeniden baslatma baslatildi)" }
                    5100    { Write-Warn ".NET 4.8.1 bu isletim sistemi versiyonunu desteklemiyor" }
                    default { Write-Warn ".NET 4.8.1 kurulum kodu: $($p.ExitCode)" }
                }
                Remove-Item $DotNet481Path -Force -ErrorAction SilentlyContinue
            } else {
                Write-Warn ".NET 4.8.1 indirilemedi"
            }
        }
    } catch {
        Write-Warn ".NET 4.8.1 kurulum hatasi: $($_.Exception.Message)"
    }
}
#endregion

# ============================================================================
#region MENU FONKSIYONLARI
# ============================================================================

function Get-SqlVersionMenu {
    Write-Host ""
    Write-Host "=== SQL Server Versiyon Secimi ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. SQL Server 2019  (Stabil, Onerilen)" -ForegroundColor White
    Write-Host "  2. SQL Server 2022  (En Guncel Stabil)" -ForegroundColor White
    Write-Host "  3. SQL Server 2017" -ForegroundColor White
    Write-Host "  4. SQL Server 2014" -ForegroundColor White
    Write-Host "  5. SQL Server 2025  (En Yeni)" -ForegroundColor White
    Write-Host ""

    do {
        $Choice = Read-Host "  Seciminiz (1-5) [Varsayilan: 1]"
        if ([string]::IsNullOrWhiteSpace($Choice)) { $Choice = "1" }

        switch ($Choice) {
            "1" { return "2019" }
            "2" { return "2022" }
            "3" { return "2017" }
            "4" { return "2014" }
            "5" { return "2025" }
            default { Write-Warn "Gecersiz! Lutfen 1-5 arasi sayi girin." }
        }
    } while ($true)
}

function Get-InstanceNameMenu {
    Write-Host ""
    Write-Host "=== SQL Server Instance Secimi ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. BaytTicariSQL  (Bayt Ticari)" -ForegroundColor White
    Write-Host "  2. BaytBossSQL    (Bayt Boss)" -ForegroundColor White
    Write-Host "  3. Bayt           (Genel Bayt)" -ForegroundColor White
    Write-Host "  4. SQLEXPRESS     (Varsayilan Express)" -ForegroundColor White
    Write-Host "  5. Manuel gir     (Ozel isim)" -ForegroundColor White
    Write-Host ""

    do {
        $Choice = Read-Host "  Seciminiz (1-5) [Varsayilan: 1]"
        if ([string]::IsNullOrWhiteSpace($Choice)) { $Choice = "1" }

        switch ($Choice) {
            "1" { return "BaytTicariSQL" }
            "2" { return "BaytBossSQL" }
            "3" { return "Bayt" }
            "4" { return "SQLEXPRESS" }
            "5" {
                do {
                    $Custom = Read-Host "  Instance adi girin (sadece harf, rakam, alt cizgi)"
                    if ($Custom -match '^[a-zA-Z][a-zA-Z0-9_]{0,15}$') {
                        return $Custom.ToUpper()
                    }
                    Write-Warn "Gecersiz isim! Harf ile baslamali, max 16 karakter, ozel karakter yok."
                } while ($true)
            }
            default { Write-Warn "Gecersiz! Lutfen 1-5 arasi sayi girin." }
        }
    } while ($true)
}
#endregion

# ============================================================================
#region ON GEREKSINIM KONTROLLERI
# ============================================================================

function Test-Prerequisites {
    Write-Step "Sistem gereksinimleri kontrol ediliyor..."

    # 64-bit kontrol
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw "64-bit isletim sistemi gereklidir! SQL Server Express sadece x64 destekler."
    }
    Write-OK "64-bit isletim sistemi"

    # PowerShell versiyon
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.1 veya uzeri gereklidir! Mevcut: $($PSVersionTable.PSVersion)"
    }
    Write-OK "PowerShell $($PSVersionTable.PSVersion)"

    # Disk alani
    $SysDrive = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
    $FreeGB = [math]::Round($SysDrive.FreeSpace / 1GB, 1)
    if ($FreeGB -lt 6) {
        Write-Warn "Disk alani dusuk: $FreeGB GB (min 6 GB onerilir)"
    } else {
        Write-OK "Disk alani: $FreeGB GB bos"
    }

    # RAM
    $TotalRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    $TotalRAMGB = [math]::Round($TotalRAM / 1GB, 1)
    if ($TotalRAMGB -lt 2) {
        Write-Warn "RAM dusuk: $TotalRAMGB GB (min 4 GB onerilir)"
    } else {
        Write-OK "RAM: $TotalRAMGB GB"
    }

    # .NET Framework
    $DotNet = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name "Release" -ErrorAction SilentlyContinue
    if ($DotNet -and $DotNet.Release -ge 461808) {
        Write-OK ".NET Framework 4.7.2+"
    } else {
        Write-Warn ".NET Framework 4.7.2 bulunamadi - bazi versiyonlar sorun yasayabilir"
    }

    # Pending reboot
    $RebootKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    )
    $PendingReboot = $false
    foreach ($key in $RebootKeys) {
        if (Test-Path $key) { $PendingReboot = $true; break }
    }
    if ($PendingReboot) {
        Write-Warn "Bekleyen yeniden baslatma var! Kurulum sorun yasayabilir."
        Write-Warn "Mumkunse once bilgisayari yeniden baslatin."
    } else {
        Write-OK "Bekleyen yeniden baslatma yok"
    }

    # CPU bilgisi
    $CPUInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
    $LogicalCPUs = ($CPUInfo | Select-Object -ExpandProperty NumberOfLogicalProcessors)
    Write-OK "CPU: $($CPUInfo.Name) ($LogicalCPUs logical core)"

    Write-Host ""
}

function Test-ExistingInstance {
    param([string]$InstanceName)

    $ServiceName = Get-SqlServiceName $InstanceName
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($Service) {
        Write-Host ""
        Write-Warn "SQL Server instance '$InstanceName' zaten kurulu!"
        Write-Warn "Servis durumu: $($Service.Status)"
        Write-Host ""
        $Continue = Read-Host "  Yine de devam etmek istiyor musunuz? (E/H) [H]"
        if ($Continue -notmatch '^[EeYy]') {
            Write-Host "  Kurulum iptal edildi." -ForegroundColor Red
            return $false
        }
    }
    return $true
}
#endregion

# ============================================================================
#region INDIRME VE KURULUM
# ============================================================================

function Get-SqlSetupPath {
    param(
        [string]$Version
    )

    $Info = $Script:SqlDownloadInfo[$Version]
    $TempDir = "$($Script:TempBase)\$Version"

    # Onceki kalintilari temizle
    if (Test-Path $TempDir) {
        Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $TempDir -ItemType Directory -Force | Out-Null

    $MediaDir    = "$TempDir\Media"
    $ExtractDir  = "$TempDir\Extracted"
    New-Item -Path $MediaDir -ItemType Directory -Force | Out-Null
    New-Item -Path $ExtractDir -ItemType Directory -Force | Out-Null

    $DownloadType = $Info.Type
    $DownloadUrls = $Info.Urls

    # -------------------------------------------------------
    # ADIM 1: Installer veya SSEI'yi indir
    # -------------------------------------------------------
    $DownloaderPath = "$TempDir\SqlDownloader.exe"

    Write-Step "SQL Server $Version indiriliyor..."

    $Downloaded = Download-FileWithRetry -Urls $DownloadUrls -OutputPath $DownloaderPath -Description "SQL Server $Version"

    if (-not $Downloaded) {
        # Fallback URL'leri dene (2019 icin Direct basarisiz olursa SSEI dene)
        if ($Info.FallbackUrls) {
            Write-Info "Alternatif indirme yontemi deneniyor (SSEI)..."
            $DownloadType = $Info.FallbackType
            $Downloaded = Download-FileWithRetry -Urls $Info.FallbackUrls -OutputPath $DownloaderPath -Description "SQL Server $Version SSEI"
        }

        if (-not $Downloaded) {
            throw "SQL Server $Version indirilemedi! Internet baglantinizi kontrol edin."
        }
    }

    # -------------------------------------------------------
    # ADIM 2: SSEI ise once medyayi indir
    # -------------------------------------------------------
    $InstallerExePath = $DownloaderPath

    if ($DownloadType -eq "SSEI") {
        Write-Step "SQL Server $Version medyasi SSEI ile indiriliyor..."
        Write-Info "Bu islem internet hiziniza gore 5-20 dakika surebilir."

        $SSEIArgs = @(
            "/ACTION=Download",
            "/MEDIAPATH=`"$MediaDir`"",
            "/MEDIATYPE=Core",
            "/QUIET"
        )

        $SSEIProc = Start-Process -FilePath $DownloaderPath -ArgumentList $SSEIArgs -PassThru

        # Indirme ilerlemesini izle
        $LastSizeMB = 0
        while (-not $SSEIProc.HasExited) {
            $Files = Get-ChildItem $MediaDir -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $_.Extension -in @('.exe', '.cab', '.msi') }
            if ($Files) {
                $TotalMB = [math]::Round(($Files | Measure-Object -Property Length -Sum).Sum / 1MB, 0)
                if ($TotalMB -ne $LastSizeMB) {
                    Write-Host "`r   [i]  Indirilen: $TotalMB MB...          " -ForegroundColor Cyan -NoNewline
                    $LastSizeMB = $TotalMB
                }
            }
            Start-Sleep -Seconds 5
        }
        Write-Host ""

        if ($SSEIProc.ExitCode -ne 0) {
            throw "SSEI indirme basarisiz oldu. Exit Code: $($SSEIProc.ExitCode)"
        }

        Write-OK "Medya indirme tamamlandi."

        # Indirilen buyuk .exe dosyasini bul
        $InstallerExePath = Get-ChildItem $MediaDir -Filter "*.exe" -Recurse |
                            Where-Object { $_.Length -gt 50MB } |
                            Select-Object -First 1 -ExpandProperty FullName

        if (-not $InstallerExePath) {
            # .exe bulunamazsa, medya dizininde dogrudan setup.exe olabilir
            $DirectSetup = Get-ChildItem $MediaDir -Filter "setup.exe" -Recurse |
                           Select-Object -First 1 -ExpandProperty FullName
            if ($DirectSetup) {
                Write-OK "Setup dosyasi dogrudan bulundu: $DirectSetup"
                return $DirectSetup
            }
            throw "SSEI medya indirdikten sonra installer dosyasi bulunamadi! Dizin: $MediaDir"
        }

        Write-Info "Installer: $InstallerExePath"
    }

    # -------------------------------------------------------
    # ADIM 3: Installer'i extract et
    # -------------------------------------------------------
    Write-Step "SQL Server dosyalari cikariliyor..."

    $ExtractProc = Start-Process -FilePath $InstallerExePath -ArgumentList "/x:`"$ExtractDir`"", "/u" -Wait -PassThru

    if ($ExtractProc.ExitCode -ne 0) {
        throw "SQL Server dosyalari cikarilamadi. Exit Code: $($ExtractProc.ExitCode)"
    }

    # setup.exe'yi bul
    $SetupExe = Get-ChildItem -Path $ExtractDir -Filter "setup.exe" -Recurse |
                Select-Object -First 1 -ExpandProperty FullName

    if (-not $SetupExe) {
        throw "setup.exe bulunamadi! Extract dizini: $ExtractDir"
    }

    Write-OK "Setup dosyasi hazir: $SetupExe"
    return $SetupExe
}

function Install-SqlServerEngine {
    param(
        [string]$Version,
        [string]$InstanceName,
        [string]$SetupExePath
    )

    $Info = $Script:SqlDownloadInfo[$Version]
    $InstallPath = "C:\Program Files\Microsoft SQL Server"

    Write-Step "SQL Server $Version ($InstanceName) kuruluyor..."
    Write-Info "Bu islem 5-15 dakika surebilir. Lutfen bekleyin..."

    # Sistem bilgileri
    $LogicalCPUs = (Get-CimInstance Win32_Processor | Select-Object -ExpandProperty NumberOfLogicalProcessors | Measure-Object -Sum).Sum

    # -------------------------------------------------------
    # Kurulum argumanlari - versiyon bazli
    # -------------------------------------------------------
    $InstallArgs = [System.Collections.ArrayList]@(
        "/ACTION=Install",
        "/FEATURES=$($Info.Features)",
        "/INSTANCENAME=$($InstanceName.ToUpper())",
        "/INSTANCEDIR=`"$InstallPath`"",
        "/SQLSVCACCOUNT=`"NT AUTHORITY\SYSTEM`"",
        "/SQLSVCSTARTUPTYPE=Automatic",
        "/SQLSYSADMINACCOUNTS=`"BUILTIN\Administrators`"",
        "/SECURITYMODE=SQL",
        "/SAPWD=`"$($Script:SAPassword)`"",
        "/SQLCOLLATION=Turkish_CI_AS",
        "/TCPENABLED=1",
        "/NPENABLED=1",
        "/BROWSERSVCSTARTUPTYPE=Automatic",
        "/IACCEPTSQLSERVERLICENSETERMS",
        "/QS",
        "/UPDATEENABLED=FALSE",
        "/INDICATEPROGRESS"
    )

    # 2017+ : Instant File Initialization
    if ($Info.SupportsInstantInit) {
        $InstallArgs.Add("/SQLSVCINSTANTFILEINIT=True") | Out-Null
    }

    # 2017+ : TempDB optimizasyonu (setup sirasinda)
    if ($Info.SupportsTempDBParams) {
        $TempDBCount = [math]::Max(1, [math]::Min($LogicalCPUs, $Info.ExpressMaxCores))
        $InstallArgs.Add("/SQLTEMPDBFILECOUNT=$TempDBCount") | Out-Null
        $InstallArgs.Add("/SQLTEMPDBFILESIZE=256") | Out-Null
        $InstallArgs.Add("/SQLTEMPDBFILEGROWTH=128") | Out-Null
        $InstallArgs.Add("/SQLTEMPDBLOGFILESIZE=64") | Out-Null
        $InstallArgs.Add("/SQLTEMPDBLOGFILEGROWTH=64") | Out-Null
    }

    # 2014: .NET 3.5 gerekebilir
    if ($Version -eq "2014") {
        try {
            $NetFx3 = Get-WindowsOptionalFeature -Online -FeatureName "NetFx3" -ErrorAction SilentlyContinue
            if ($NetFx3 -and $NetFx3.State -ne "Enabled") {
                Write-Info ".NET Framework 3.5 etkinlestiriliyor (SQL 2014 icin gerekli)..."
                Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
            }
        }
        catch {
            Write-Warn ".NET 3.5 kontrol edilemedi: $($_.Exception.Message)"
        }
    }

    # -------------------------------------------------------
    # Setup.exe'yi calistir
    # -------------------------------------------------------
    Write-Info "Komut: setup.exe $($InstallArgs -join ' ')"
    Write-Host ""

    $SetupProc = Start-Process -FilePath $SetupExePath -ArgumentList $InstallArgs -Wait -PassThru

    # -------------------------------------------------------
    # Sonuc degerlendirmesi
    # -------------------------------------------------------
    switch ($SetupProc.ExitCode) {
        0 {
            Write-OK "SQL Server $Version basariyla kuruldu!"
            return $true
        }
        3010 {
            Write-OK "SQL Server $Version kuruldu. (Yeniden baslatma onerilir)"
            return $true
        }
        default {
            Write-Err "SQL Server kurulumu basarisiz! Exit Code: $($SetupProc.ExitCode)"

            # Hata detaylari
            switch ($SetupProc.ExitCode) {
                -2067529716 { Write-Err "  Konfigürasyon hatasi veya sistem gereksinimleri karsilanmadi" }
                -2068709375 { Write-Err "  Feature tanimlama hatasi veya kurulum dosyasi sorunu" }
                default      { Write-Err "  Bilinmeyen hata kodu: $($SetupProc.ExitCode)" }
            }

            # Summary log'u goster
            $SummaryLog = Get-ChildItem "$env:ProgramFiles\Microsoft SQL Server\*\Setup Bootstrap\Log" -Filter "Summary*.txt" -Recurse -ErrorAction SilentlyContinue |
                          Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($SummaryLog) {
                Write-Host ""
                Write-Info "Log dosyasi: $($SummaryLog.FullName)"
                Write-Host "--- Son 15 satir ---" -ForegroundColor DarkGray
                Get-Content $SummaryLog.FullName -Tail 15 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            }
            return $false
        }
    }
}
#endregion

# ============================================================================
#region KURULUM SONRASI YAPILANDIRMA
# ============================================================================

function Set-SqlProtocols {
    param([string]$InstanceName)

    Write-Step "SQL Server protokolleri yapilandiriliyor..."

    $SqlRegBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"

    try {
        # Instance'in registry adini bul (orn: MSSQL15.BAYTTICARISQL)
        $InstanceRegName = (Get-ItemProperty "$SqlRegBase\Instance Names\SQL" -ErrorAction Stop).$InstanceName

        if (-not $InstanceRegName) {
            Write-Warn "Registry'de '$InstanceName' instance bulunamadi."
            return
        }

        Write-Info "Registry instance: $InstanceRegName"
        $NetworkPath = "$SqlRegBase\$InstanceRegName\MSSQLServer\SuperSocketNetLib"

        # TCP/IP
        if (Test-Path "$NetworkPath\Tcp") {
            Set-ItemProperty "$NetworkPath\Tcp" -Name "Enabled" -Value 1 -Type DWord -Force
            Write-OK "TCP/IP protokolu etkinlestirildi"

            # Named instance icin dynamic port birakilir (SQL Browser halleder)
            # Default instance icin port 1433
            if ($InstanceName -eq "MSSQLSERVER") {
                $IpAllPath = "$NetworkPath\Tcp\IPAll"
                if (Test-Path $IpAllPath) {
                    Set-ItemProperty $IpAllPath -Name "TcpPort" -Value "1433" -Force
                    Set-ItemProperty $IpAllPath -Name "TcpDynamicPorts" -Value "" -Force
                    Write-Info "TCP Port: 1433 (statik)"
                }
            }
        }

        # Named Pipes
        if (Test-Path "$NetworkPath\Np") {
            Set-ItemProperty "$NetworkPath\Np" -Name "Enabled" -Value 1 -Type DWord -Force
            Write-OK "Named Pipes protokolu etkinlestirildi"
        }

        # Shared Memory
        if (Test-Path "$NetworkPath\Sm") {
            Set-ItemProperty "$NetworkPath\Sm" -Name "Enabled" -Value 1 -Type DWord -Force
            Write-OK "Shared Memory protokolu etkinlestirildi"
        }

        # Mixed Mode Authentication dogrulama (setup zaten yapmis olmali)
        $MSSQLServerPath = "$SqlRegBase\$InstanceRegName\MSSQLServer"
        $LoginMode = (Get-ItemProperty $MSSQLServerPath -Name "LoginMode" -ErrorAction SilentlyContinue).LoginMode
        if ($LoginMode -ne 2) {
            Set-ItemProperty $MSSQLServerPath -Name "LoginMode" -Value 2 -Type DWord -Force
            Write-OK "Mixed Mode Authentication etkinlestirildi"
        } else {
            Write-OK "Mixed Mode Authentication zaten etkin"
        }
    }
    catch {
        Write-Warn "Protokol yapilandirmasi sirasinda hata: $($_.Exception.Message)"
    }
}

function Restart-SqlService {
    param([string]$InstanceName)

    Write-Step "SQL Server servisi yeniden baslatiliyor (protokol degisiklikleri icin)..."

    $ServiceName = Get-SqlServiceName $InstanceName

    try {
        Restart-Service -Name $ServiceName -Force -ErrorAction Stop
        Write-OK "SQL Server servisi yeniden baslatildi."
    }
    catch {
        Write-Warn "Servis yeniden baslatma hatasi: $($_.Exception.Message)"
        # Manuel baslatma dene
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            Start-Service -Name $ServiceName -ErrorAction Stop
            Write-OK "SQL Server servisi manuel olarak yeniden baslatildi."
        }
        catch {
            Write-Err "Servis baslatilamadi: $($_.Exception.Message)"
        }
    }
}

function Set-SqlBrowserService {
    Write-Info "SQL Browser servisi yapilandiriliyor..."

    try {
        $Browser = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue
        if ($Browser) {
            Set-Service -Name "SQLBrowser" -StartupType Automatic -ErrorAction Stop
            if ($Browser.Status -ne "Running") {
                Start-Service -Name "SQLBrowser" -ErrorAction Stop
            }
            Write-OK "SQL Browser servisi baslatildi (Otomatik)"
        } else {
            Write-Warn "SQL Browser servisi bulunamadi"
        }
    }
    catch {
        Write-Warn "SQL Browser hatasi: $($_.Exception.Message)"
    }
}

function Set-SqlPerformanceConfig {
    param(
        [string]$InstanceName,
        [string]$Version
    )

    Write-Step "Performans optimizasyonu uygulanıyor..."

    $ServerInstance = Get-SqlServerInstance $InstanceName
    $Info = $Script:SqlDownloadInfo[$Version]

    # Sistem bilgileri
    $TotalRAMMB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB, 0)
    $LogicalCPUs = (Get-CimInstance Win32_Processor | Select-Object -ExpandProperty NumberOfLogicalProcessors | Measure-Object -Sum).Sum

    # Express limitleri dahilinde max memory hesapla
    $AutoMaxMemory = [math]::Min(
        [math]::Floor($TotalRAMMB * 0.75),
        $Info.ExpressMaxMemoryMB
    )
    $AutoMaxMemory = [math]::Max($AutoMaxMemory, 256) # Minimum 256 MB

    # MAXDOP hesapla
    $AutoMaxDOP = [math]::Max(1, [math]::Min([math]::Floor($LogicalCPUs / 2), $Info.ExpressMaxCores))

    Write-Info "Toplam RAM: $TotalRAMMB MB | CPU: $LogicalCPUs core"
    Write-Info "Max Memory: $AutoMaxMemory MB | MAXDOP: $AutoMaxDOP | Cost Threshold: 25"

    # sp_configure komutlari
    $ConfigCommands = @(
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
        "EXEC sp_configure 'max server memory (MB)', $AutoMaxMemory; RECONFIGURE;",
        "EXEC sp_configure 'max degree of parallelism', $AutoMaxDOP; RECONFIGURE;",
        "EXEC sp_configure 'cost threshold for parallelism', 25; RECONFIGURE;",
        "EXEC sp_configure 'optimize for ad hoc workloads', 1; RECONFIGURE;",
        "EXEC sp_configure 'remote admin connections', 1; RECONFIGURE;"
    )

    # Backup compression (2014 Express'te yok)
    if ($Version -ne "2014") {
        $ConfigCommands += "EXEC sp_configure 'backup compression default', 1; RECONFIGURE;"
    }

    $SuccessCount = 0
    foreach ($cmd in $ConfigCommands) {
        try {
            Invoke-SqlNonQuery -ServerInstance $ServerInstance -Query $cmd -UseWindowsAuth
            $SuccessCount++
        }
        catch {
            # Hata ayiklama: komutun kendisini goster
            $ShortCmd = if ($cmd.Length -gt 60) { $cmd.Substring(0, 57) + "..." } else { $cmd }
            Write-Warn "Komut basarisiz: $ShortCmd"
        }
    }

    Write-OK "Performans ayarlari uyguland: $SuccessCount/$($ConfigCommands.Count) basarili"

    # TempDB post-install optimizasyonu (sadece 2014 icin, 2017+ setup'ta yapildi)
    if (-not $Info.SupportsTempDBParams) {
        Set-TempDBOptimization -ServerInstance $ServerInstance -LogicalCPUs $LogicalCPUs -MaxCores $Info.ExpressMaxCores
    }
}

function Set-TempDBOptimization {
    param(
        [string]$ServerInstance,
        [int]$LogicalCPUs,
        [int]$MaxCores
    )

    Write-Info "TempDB optimizasyonu (post-install)..."

    try {
        # Mevcut TempDB veri dizinini bul
        $TempDBPath = Invoke-SqlScalar -ServerInstance $ServerInstance `
            -Query "SELECT LEFT(physical_name, LEN(physical_name) - CHARINDEX('\', REVERSE(physical_name))) FROM sys.master_files WHERE database_id = 2 AND file_id = 1" `
            -UseWindowsAuth

        if (-not $TempDBPath) {
            Write-Warn "TempDB yolu alinamadi, optimizasyon atlaniyor."
            return
        }

        # Ana dosyayi buyut
        try {
            Invoke-SqlNonQuery -ServerInstance $ServerInstance `
                -Query "ALTER DATABASE tempdb MODIFY FILE (NAME = 'tempdev', SIZE = 256MB, FILEGROWTH = 128MB);" `
                -UseWindowsAuth
            Invoke-SqlNonQuery -ServerInstance $ServerInstance `
                -Query "ALTER DATABASE tempdb MODIFY FILE (NAME = 'templog', SIZE = 64MB, FILEGROWTH = 64MB);" `
                -UseWindowsAuth
        }
        catch {
            Write-Warn "TempDB boyutlandirma hatasi: $($_.Exception.Message)"
        }

        Write-OK "TempDB optimizasyonu tamamlandi."
    }
    catch {
        Write-Warn "TempDB optimizasyonu hatasi: $($_.Exception.Message)"
    }
}

function Install-NativeClient {
    Write-Step "SQL Native Client 2012 kontrol ediliyor..."

    # Zaten kurulu mu?
    $NativeClientPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server Native Client 11.0",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server Native Client 11.0"
    )
    $SystemFiles = @(
        "$env:SystemRoot\System32\sqlncli11.dll",
        "$env:SystemRoot\SysWOW64\sqlncli11.dll"
    )

    $IsInstalled = $false
    foreach ($p in ($NativeClientPaths + $SystemFiles)) {
        if (Test-Path $p) { $IsInstalled = $true; break }
    }

    if ($IsInstalled) {
        Write-OK "SQL Native Client 2012 zaten kurulu - atlaniyor."
        return
    }

    Write-Info "SQL Native Client 2012 kuruluyor..."

    $NcliPath = "$($Script:TempBase)\sqlncli.msi"
    $Downloaded = Download-FileWithRetry -Urls @($Script:NativeClientUrl) -OutputPath $NcliPath -Description "SQL Native Client"

    if (-not $Downloaded) {
        Write-Warn "SQL Native Client indirilemedi - atlaniyor."
        return
    }

    try {
        $Proc = Start-Process "msiexec.exe" -ArgumentList "/i `"$NcliPath`" /quiet /norestart IACCEPTSQLNCLILICENSETERMS=YES" -Wait -PassThru
        if ($Proc.ExitCode -eq 0) {
            Write-OK "SQL Native Client 2012 basariyla kuruldu."
        } else {
            Write-Warn "Native Client kurulumu sonuclandi. Exit Code: $($Proc.ExitCode)"
        }
    }
    catch {
        Write-Warn "Native Client kurulum hatasi: $($_.Exception.Message)"
    }

    Remove-Item $NcliPath -Force -ErrorAction SilentlyContinue
}

function Test-FinalConnection {
    param(
        [string]$InstanceName
    )

    Write-Step "Baglanti testi yapiliyor..."

    $ServerInstance = Get-SqlServerInstance $InstanceName

    # Windows Auth
    try {
        $Version = Invoke-SqlScalar -ServerInstance $ServerInstance `
            -Query "SELECT @@VERSION" -UseWindowsAuth
        Write-OK "Windows Auth baglantisi basarili"
    }
    catch {
        Write-Warn "Windows Auth baglantisi basarisiz: $($_.Exception.Message)"
    }

    # SA Auth
    try {
        $Result = Invoke-SqlScalar -ServerInstance $ServerInstance `
            -Query "SELECT 'SA_OK'" `
            -Username "sa" -Password $Script:SAPassword
        if ($Result -eq "SA_OK") {
            Write-OK "SA Auth baglantisi basarili"
        }
    }
    catch {
        Write-Warn "SA Auth baglantisi basarisiz: $($_.Exception.Message)"
    }
}

function Show-Summary {
    param(
        [string]$Version,
        [string]$InstanceName
    )

    $ServerInstance = Get-SqlServerInstance $InstanceName

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "            KURULUM BASARIYLA TAMAMLANDI!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  SQL Server Versiyonu : $Version Express" -ForegroundColor White
    Write-Host "  Instance Adi         : $InstanceName" -ForegroundColor White
    Write-Host "  Baglanti Adresi      : $ServerInstance" -ForegroundColor White
    Write-Host "  SA Kullanici Adi     : sa" -ForegroundColor White
    Write-Host "  SA Sifresi           : $($Script:SAPassword)" -ForegroundColor White
    Write-Host "  Collation            : Turkish_CI_AS" -ForegroundColor White
    Write-Host ""

    # Servis durumlari
    $SqlSvc = Get-Service (Get-SqlServiceName $InstanceName) -ErrorAction SilentlyContinue
    $BrwSvc = Get-Service "SQLBrowser" -ErrorAction SilentlyContinue

    Write-Host "  Servisler:" -ForegroundColor Cyan
    Write-Host "    SQL Server : $(if ($SqlSvc) { $SqlSvc.Status } else { 'Bulunamadi' })" -ForegroundColor White
    Write-Host "    SQL Browser: $(if ($BrwSvc) { $BrwSvc.Status } else { 'Bulunamadi' })" -ForegroundColor White
    Write-Host ""
    Write-Host "  Baglanti ornegi (SSMS/sqlcmd):" -ForegroundColor Cyan
    Write-Host "    Server: $ServerInstance" -ForegroundColor Gray
    Write-Host "    Login : sa" -ForegroundColor Gray
    Write-Host "    Pass  : $($Script:SAPassword)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  ONEMLI: SA sifresini uretim ortaminda degistirin!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
}
#endregion

# ============================================================================
#region ANA AKIS
# ============================================================================

function Main {
    try {
        Write-Banner

        # 1. On gereksinimler
        Test-Prerequisites

        # 2. Versiyon secimi
        $SelectedVersion = Get-SqlVersionMenu

        # 3. Instance secimi
        $SelectedInstance = Get-InstanceNameMenu

        # 4. Mevcut instance kontrolu
        if (-not (Test-ExistingInstance $SelectedInstance)) { return }

        # 5. Ozet ve onay
        Write-Host ""
        Write-Host "  +---------------------------------+" -ForegroundColor Cyan
        Write-Host "  | KURULUM OZETI                   |" -ForegroundColor Cyan
        Write-Host "  +---------------------------------+" -ForegroundColor Cyan
        Write-Host "  | 1. Visual C++ Runtimes (Tumu)   |" -ForegroundColor Yellow
        Write-Host "  | 2. .NET 3.5 + 4.8.1 Aktivasyon |" -ForegroundColor Yellow
        Write-Host "  | 3. SQL Server $SelectedVersion Kurulumu   |" -ForegroundColor Yellow
        Write-Host "  +---------------------------------+" -ForegroundColor Cyan
        Write-Host "  | Versiyon : SQL Server $SelectedVersion     |" -ForegroundColor White
        Write-Host "  | Instance : $($SelectedInstance.PadRight(21))|" -ForegroundColor White
        Write-Host "  | SA Sifre : $($Script:SAPassword.PadRight(21))|" -ForegroundColor White
        Write-Host "  | Collation: Turkish_CI_AS        |" -ForegroundColor White
        Write-Host "  | Protokol : TCP/IP + Named Pipes |" -ForegroundColor White
        Write-Host "  | Performans: Otomatik Optimize   |" -ForegroundColor White
        Write-Host "  +---------------------------------+" -ForegroundColor Cyan
        Write-Host ""

        $Confirm = Read-Host "  Kuruluma baslansin mi? (E/H) [E]"
        if ([string]::IsNullOrWhiteSpace($Confirm)) { $Confirm = "E" }
        if ($Confirm -notmatch '^[EeYy]') {
            Write-Host "  Kurulum iptal edildi." -ForegroundColor Red
            return
        }

        # 6. Visual C++ Runtime kutuphanelerini kur
        Install-VCRuntimes

        # 7. .NET Framework 3.5 ve 4.8.1 etkinlestir
        Enable-DotNetFrameworks

        # 8. SQL Server medyasini indir ve setup path'ini al
        Write-Step "SQL Server kurulumuna geciliyor..."
        $SetupExe = Get-SqlSetupPath -Version $SelectedVersion

        # 9. SQL Server'i kur
        $InstallSuccess = Install-SqlServerEngine -Version $SelectedVersion -InstanceName $SelectedInstance -SetupExePath $SetupExe

        if (-not $InstallSuccess) {
            Write-Err "SQL Server kurulumu basarisiz oldu. Script sonlaniyor."
            return
        }

        # 10. Servisin hazir olmasini bekle
        $Ready = Wait-SqlServiceReady -InstanceName $SelectedInstance -TimeoutSeconds 120

        # 11. Protokolleri yapilandir (registry)
        Set-SqlProtocols -InstanceName $SelectedInstance

        # 12. SQL Browser servisini baslat
        Set-SqlBrowserService

        # 13. Servisi yeniden baslat (protokol degisiklikleri icin)
        Restart-SqlService -InstanceName $SelectedInstance

        # 14. Servisin tekrar hazir olmasini bekle
        $Ready = Wait-SqlServiceReady -InstanceName $SelectedInstance -TimeoutSeconds 120

        if ($Ready) {
            # 15. Performans optimizasyonu
            Set-SqlPerformanceConfig -InstanceName $SelectedInstance -Version $SelectedVersion
        }

        # 16. SQL Native Client
        Install-NativeClient

        # 17. Baglanti testi
        if ($Ready) {
            Test-FinalConnection -InstanceName $SelectedInstance
        }

        # 18. Ozet
        Show-Summary -Version $SelectedVersion -InstanceName $SelectedInstance

        # Temizlik
        if (Test-Path $Script:TempBase) {
            Remove-Item $Script:TempBase -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Host ""
        Write-Err "BEKLENMEYEN HATA: $($_.Exception.Message)"
        Write-Host ""
        Write-Host "  Hata Detayi:" -ForegroundColor DarkGray
        Write-Host "  $($_.ScriptStackTrace)" -ForegroundColor DarkGray
        Write-Host ""
    }
    finally {
        Write-Host ""
        Read-Host "Cikmak icin Enter tusuna basin"
    }
}

# Scripti calistir
Main
#endregion

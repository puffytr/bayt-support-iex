# ============================================================================
# Bayt Support Otomatik Kurulum Scripti (GUI / All-in-One / Web Ready)
# Versiyon: 5.1
# Tarih: 2026
# ============================================================================
#
# SORUMLULUK REDDI (DISCLAIMER)
# --------------------------------------------------------------------------
# Bu script YALNIZCA test, gelistirme ve demo amaclidir.
# Scriptte yer alan SA sifreleri, SQL Server product key'leri ve diger
# kimlik bilgileri tamamen TEST/DEGERLENDIRME amacli ornek degerlerdir.
# Uretim (production) ortaminda kullanilmasi TAVSIYE EDILMEZ.
#
# Kullanici bu scripti calistirarak asagidakileri kabul eder:
#   - Tum sifreler ve anahtarlar kurulum sonrasi degistirilmelidir
#   - Product key'ler Microsoft'un degerlendirme/test lisanslarina aittir
#   - Script sahibi, lisans ihlalleri veya guvenlik aciklarindan sorumlu degildir
#   - Uretim ortami icin Microsoft'tan uygun lisans satin alinmalidir
#
# ============================================================================
# Kullanim (tek komut):
#   iex (irm 'https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1')
# veya:
#   iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1')
# ============================================================================

param(
    [switch]$Silent,
    [switch]$InstallVCPP,
    [switch]$InstallNet35,
    [switch]$InstallNet481,
    [switch]$InstallSQL,
    [switch]$InstallFirewall,
    [switch]$SetPowerPlan,
    [switch]$ConfigSqlProtocols,
    [switch]$ConfigSqlPerformance,
    [switch]$InstallNativeClient,
    [switch]$InstallCapital,
    [switch]$InstallBoss,
    [string]$SqlVersion = "",
    [string]$InstanceName = "",
    [string]$SAPass = "",
    [switch]$Help
)

if ($Help) {
    Write-Host ""
    Write-Host "Bayt Support Otomatik Kurulum - Unattended Mod" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Parametreler:" -ForegroundColor Yellow
    Write-Host "  -Silent            Sessiz kurulum (GUI gosterme)"
    Write-Host "  -InstallVCPP       Visual C++ Runtimes kur"
    Write-Host "  -InstallNet35      .NET Framework 3.5 etkinlestir"
    Write-Host "  -InstallNet481     .NET Framework 4.8.1 kur"
    Write-Host "  -InstallSQL        SQL Server kur"
    Write-Host "  -InstallFirewall   Firewall kurallari olustur"
    Write-Host "  -SetPowerPlan      Guc planini Nihai Performans (Ultimate) yap"
    Write-Host "  -ConfigSqlProtocols   SQL protokollerini yapilandir (TCP/IP, Named Pipes)"
    Write-Host "  -ConfigSqlPerformance SQL performans ayarlarini uygula (Max Memory, MAXDOP)"
    Write-Host "  -InstallNativeClient  SQL Native Client 2012 kur"
    Write-Host "  -InstallCapital    Bay.T Capital kurulumunu indir ve baslat"
    Write-Host "  -InstallBoss       Bay.T Boss kurulumunu indir ve baslat"
    Write-Host "  -SqlVersion        SQL versiyonu (2019/2022/2025)"
    Write-Host "  -InstanceName      SQL instance adi"
    Write-Host "  -SAPass            SA sifresi"
    Write-Host "  -Help              Bu yardim mesajini goster"
    Write-Host ""
    Write-Host "Ornek:" -ForegroundColor Yellow
    Write-Host "  .\install-online.ps1 -Silent -InstallVCPP -InstallSQL -SqlVersion 2022 -InstanceName BaytSQL -SAPass 'Guclu_S1fre!'" -ForegroundColor Gray
    Write-Host ""
    return
}

$ErrorActionPreference = "Stop"

# TLS 1.2/1.3 zorunlu (Microsoft download servisleri icin)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

# ============================================================================
#region YAPILANDIRMA
# ============================================================================
# UYARI: Asagidaki SA sifresi YALNIZCA test/demo amaclidir.
# Uretim ortaminda mutlaka degistirilmelidir!
$Script:SAPassword       = "Bay_T252!"
$Script:ScriptVersion    = "5.3"
# Temp dizini: Kullanici adindaki Turkce karakterler sorun yaratabiliyor (8.3 path)
# Bu yuzden kullanici profilinden bagimsiz C:\Bay-T\Support-IEX kullaniyoruz
$Script:TempBase         = "C:\Bay-T\Support-IEX"
$Script:ScriptUrl        = "https://raw.githubusercontent.com/puffytr/bayt-support-iex/main/install-online.ps1"

# SQL Server indirme bilgileri
# Type: "SSEI" = SQL Server Setup Installer (once /ACTION=Download ile medya indirir)
# UYARI: Product key'ler Microsoft'un kamuya acik degerlendirme/test anahtarlaridir.
# Uretim ortami icin Microsoft'tan uygun lisans satin alinmalidir.
# Standard edition icin Evaluation/Developer SSEI kullanilir, /PID ile Standard lisanslama yapilir
$Script:SqlDownloadInfo = @{
    # --- SQL Server 2019 ---
    "2019-standard" = @{
        Type     = "SSEI"
        Urls     = @(
            "https://download.microsoft.com/download/d/a/2/da259851-b941-459d-989c-54a18a5d44dd/SQL2019-SSEI-Dev.exe",
            "https://go.microsoft.com/fwlink/?linkid=866662"
        )
        ProductKey           = "PMBDC-FXVM3-T777P-N4FY8-PKFF4"
        Features             = "SQLENGINE"
        SupportsInstantInit  = $true
        SupportsTempDBParams = $true
        MajorVersion         = 15
    }
    "2019-express" = @{
        Type     = "SSEI"
        Urls     = @(
            "https://download.microsoft.com/download/7/f/8/7f8a9c43-8c8a-4f7c-9f92-83c18d96b681/SQL2019-SSEI-Expr.exe"
        )
        ProductKey           = $null
        Features             = "SQLENGINE"
        SupportsInstantInit  = $true
        SupportsTempDBParams = $true
        MajorVersion         = 15
    }
    # --- SQL Server 2022 ---
    "2022-standard" = @{
        Type     = "SSEI"
        Urls     = @(
            "https://download.microsoft.com/download/c/c/9/cc9c6797-383c-4b24-8920-dc057c1de9d3/SQL2022-SSEI-Dev.exe",
            "https://go.microsoft.com/fwlink/?linkid=2215158"
        )
        ProductKey           = "FG86G-CHH2T-CB7NJ-XT7D2-V8V4X"
        Features             = "SQLENGINE"
        SupportsInstantInit  = $true
        SupportsTempDBParams = $true
        MajorVersion         = 16
    }
    "2022-express" = @{
        Type     = "SSEI"
        Urls     = @(
            "https://download.microsoft.com/download/5/1/4/5145fe04-4d30-4b85-b0d1-39533663a2f1/SQL2022-SSEI-Expr.exe"
        )
        ProductKey           = $null
        Features             = "SQLENGINE"
        SupportsInstantInit  = $true
        SupportsTempDBParams = $true
        MajorVersion         = 16
    }
    # --- SQL Server 2025 ---
    "2025-standard" = @{
        Type     = "SSEI"
        Urls     = @(
            "https://download.microsoft.com/download/4ba126fc-a6a0-4810-80e9-c0182d3e1f62/SQL2025-SSEI-EntDev.exe",
            "https://aka.ms/sql2025developer"
        )
        ProductKey           = "YCNJQ-CB92J-CDT88-8T63K-QWBGQ"
        Features             = "SQLENGINE"
        SupportsInstantInit  = $true
        SupportsTempDBParams = $true
        MajorVersion         = 17
    }
    "2025-express" = @{
        Type     = "SSEI"
        Urls     = @(
            "https://download.microsoft.com/download/7ab8f535-7eb8-4b16-82eb-eca0fa2d38f3/SQL2025-SSEI-Expr.exe",
            "https://aka.ms/sql2025express"
        )
        ProductKey           = $null
        Features             = "SQLENGINE"
        SupportsInstantInit  = $true
        SupportsTempDBParams = $true
        MajorVersion         = 17
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
    Write-Host "    (VC++ Runtimes + .NET Framework + SQL Server Standard)" -ForegroundColor Cyan
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
                    # BITS basarisiz olursa WebClient ile ilerleme gostererek indir
                    Write-Info "BITS basarisiz, WebClient ile indiriliyor..."
                    $wc = New-Object System.Net.WebClient
                    $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

                    $Script:DlProgress = @{ Pct = 0; Done = $false; Err = $null }
                    $evtProg = Register-ObjectEvent $wc DownloadProgressChanged -Action {
                        $Script:DlProgress.Pct = $EventArgs.ProgressPercentage
                    }
                    $evtDone = Register-ObjectEvent $wc DownloadFileCompleted -Action {
                        $Script:DlProgress.Done = $true
                        if ($EventArgs.Error) { $Script:DlProgress.Err = $EventArgs.Error }
                    }

                    $wc.DownloadFileAsync([System.Uri]$Url, $OutputPath)

                    $lastPct = -1
                    while (-not $Script:DlProgress.Done) {
                        if ($Script:DlProgress.Pct -ne $lastPct -and $Script:DlProgress.Pct -gt 0) {
                            Write-Host ("`r   [i]  Indiriliyor: %{0,-3} " -f $Script:DlProgress.Pct) -ForegroundColor Cyan -NoNewline
                            $lastPct = $Script:DlProgress.Pct
                        }
                        Start-Sleep -Milliseconds 250
                    }
                    Write-Host ""

                    Unregister-Event -SubscriptionId $evtProg.Id -ErrorAction SilentlyContinue
                    Unregister-Event -SubscriptionId $evtDone.Id -ErrorAction SilentlyContinue
                    $wc.Dispose()

                    if ($Script:DlProgress.Err) { throw $Script:DlProgress.Err.ToString() }
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

function Get-InstalledVCRuntimes {
    $Installed = @{}
    $UninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $VCEntries = Get-ItemProperty $UninstallPaths -ErrorAction SilentlyContinue |
                 Where-Object { $_.DisplayName -match "Microsoft Visual C\+\+" -or $_.DisplayName -match "Visual C\+\+ .* Redistributable" }

    $VersionPatterns = @(
        @{ Year = "2005"; Pattern = "2005" },
        @{ Year = "2008"; Pattern = "2008" },
        @{ Year = "2010"; Pattern = "2010" },
        @{ Year = "2012"; Pattern = "2012" },
        @{ Year = "2013"; Pattern = "2013" },
        @{ Year = "2015-2022"; Pattern = "201[5-9]|202[0-4]" }
    )

    foreach ($vp in $VersionPatterns) {
        $x86Found = @($VCEntries | Where-Object { $_.DisplayName -match $vp.Pattern -and $_.DisplayName -match "x86" })
        $x64Found = @($VCEntries | Where-Object { $_.DisplayName -match $vp.Pattern -and $_.DisplayName -match "x64" })
        $Installed[$vp.Year] = @{
            x86 = ($x86Found.Count -gt 0)
            x64 = ($x64Found.Count -gt 0)
        }
    }

    return $Installed
}

function Get-InstalledSqlInstances {
    $Instances = @()
    try {
        $SqlReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -ErrorAction SilentlyContinue
        if ($SqlReg) {
            $SqlReg.PSObject.Properties |
                Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } |
                ForEach-Object {
                    $InstName = $_.Name
                    $RegPath = $_.Value
                    $ServiceName = if ($InstName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$InstName" }
                    $Svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                    # Edition ve versiyon bilgisini registry'den oku
                    $SetupReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$RegPath\Setup" -ErrorAction SilentlyContinue
                    $Edition = if ($SetupReg -and $SetupReg.Edition) { $SetupReg.Edition -replace ' Edition$','' } else { "Bilinmiyor" }
                    # Major versiyon numarasini yila donustur
                    $VersionYear = "Bilinmiyor"
                    if ($SetupReg -and $SetupReg.Version) {
                        $MajorVer = [int]($SetupReg.Version -split '\.')[0]
                        $VersionYear = switch ($MajorVer) {
                            8  { "2000" }
                            9  { "2005" }
                            10 { "2008" }
                            11 { "2012" }
                            12 { "2014" }
                            13 { "2016" }
                            14 { "2017" }
                            15 { "2019" }
                            16 { "2022" }
                            17 { "2025" }
                            default { "v$MajorVer" }
                        }
                    }
                    $Instances += @{
                        Name        = $InstName
                        Status      = if ($Svc) { $Svc.Status.ToString() } else { "Bilinmiyor" }
                        Edition     = $Edition
                        VersionYear = $VersionYear
                    }
                }
        }
    } catch {}
    return $Instances
}

function Uninstall-SqlInstance {
    param(
        [Parameter(Mandatory)]
        [string]$InstanceName
    )

    Write-Step "SQL Server instance '$InstanceName' kaldiriliyor..."

    try {
        # 1. Servis adi ve durumu
        $ServiceName = if ($InstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$InstanceName" }
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Info "Servis durduruluyor: $ServiceName"
            Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }

        # SQL Agent servisini de durdur
        $agentSvc = if ($InstanceName -eq "MSSQLSERVER") { "SQLSERVERAGENT" } else { "SQLAgent`$$InstanceName" }
        $agent = Get-Service -Name $agentSvc -ErrorAction SilentlyContinue
        if ($agent -and $agent.Status -eq "Running") {
            Write-Info "SQL Agent durduruluyor: $agentSvc"
            Stop-Service $agentSvc -Force -ErrorAction SilentlyContinue
        }

        # SQL Browser servisini de durdur
        $browser = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue
        if ($browser -and $browser.Status -eq "Running") {
            Write-Info "SQL Browser durduruluyor..."
            Stop-Service "SQLBrowser" -Force -ErrorAction SilentlyContinue
        }

        # 2. Registry'den setup.exe yolunu bul
        $regBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
        $instReg = Get-ItemProperty "$regBase\Instance Names\SQL" -ErrorAction SilentlyContinue
        $instId = $null
        if ($instReg) {
            $instId = $instReg.$InstanceName
        }

        if (-not $instId) {
            Write-Err "Instance '$InstanceName' registry'de bulunamadi!"
            return $false
        }

        # 3. Setup.exe yolunu bul
        $setupInfo = Get-ItemProperty "$regBase\$instId\Setup" -ErrorAction SilentlyContinue
        $setupPath = $null

        if ($setupInfo -and $setupInfo.SqlProgramDir) {
            $possibleSetup = Join-Path $setupInfo.SqlProgramDir "Setup Bootstrap\SQL2*\setup.exe"
            $setupFiles = Get-ChildItem $possibleSetup -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
            if ($setupFiles) {
                $setupPath = $setupFiles[0].FullName
            }
        }

        # Alternatif: Bootstrap klasorundan bul
        if (-not $setupPath) {
            $bootstrapPaths = @(
                "$regBase\$instId\Setup\BootstrapDir"
                "$regBase\$instId\Setup\SQLPath"
            )
            foreach ($bp in $bootstrapPaths) {
                $val = (Get-ItemProperty -Path ($bp -replace '\\[^\\]+$','') -Name ($bp -split '\\')[-1] -ErrorAction SilentlyContinue)
                if ($val) { break }
            }

            # Setup Bootstrap altinda ara
            $commonPaths = @(
                "C:\SQL2*\setup.exe",
                "C:\Program Files\Microsoft SQL Server\*\Setup Bootstrap\SQL*\setup.exe",
                "C:\Program Files\Microsoft SQL Server\*\Setup Bootstrap\setup.exe"
            )
            foreach ($cp in $commonPaths) {
                $found = Get-ChildItem $cp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($found) {
                    $setupPath = $found.FullName
                    break
                }
            }
        }

        if (-not $setupPath -or -not (Test-Path $setupPath)) {
            Write-Warn "Setup.exe bulunamadi. Alternatif yontem deneniyor..."

            # Alternatif: Uninstall string'i kullan
            $uninstReg = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -match "SQL Server.*Database Engine" -and $_.DisplayName -match $InstanceName }

            if (-not $uninstReg) {
                $uninstReg = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
                    Get-ItemProperty -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -match "Microsoft SQL Server" -and $_.UninstallString -match $InstanceName }
            }

            if ($uninstReg) {
                $uninstStr = ($uninstReg | Select-Object -First 1).UninstallString
                Write-Info "Uninstall komutu bulundu: $uninstStr"
                Write-Info "Kaldirma islemi baslatiliyor..."
                $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $uninstStr /QS" -Wait -PassThru -ErrorAction Stop
                if ($proc.ExitCode -eq 0) {
                    Write-OK "SQL Server instance '$InstanceName' basariyla kaldirildi!"

                    # Registry temizligi
                    try {
                        $regBasePath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
                        $instNamesKey = Get-ItemProperty "$regBasePath\Instance Names\SQL" -ErrorAction SilentlyContinue
                        if ($instNamesKey -and $instNamesKey.$InstanceName) {
                            $instRegId = $instNamesKey.$InstanceName
                            Remove-ItemProperty "$regBasePath\Instance Names\SQL" -Name $InstanceName -Force -ErrorAction SilentlyContinue
                            if ($instRegId -and (Test-Path "$regBasePath\$instRegId")) {
                                Remove-Item "$regBasePath\$instRegId" -Recurse -Force -ErrorAction SilentlyContinue
                            }
                        }
                    } catch {}

                    return $true
                } else {
                    Write-Err "Kaldirma islemi basarisiz oldu (Exit Code: $($proc.ExitCode))"
                    return $false
                }
            }

            Write-Err "Kaldirma yontemi bulunamadi. Lutfen Denetim Masasi'ndan manuel kaldirin."
            return $false
        }

        # 4. Setup.exe ile kaldirma
        Write-Info "Setup yolu: $setupPath"
        Write-Info "Instance '$InstanceName' kaldiriliyor (bu islem birkac dakika surebilir)..."

        $setupArgs = "/ACTION=Uninstall /INSTANCENAME=$InstanceName /FEATURES=SQLENGINE /QS"

        $proc = Start-Process -FilePath $setupPath -ArgumentList $setupArgs -Wait -PassThru -ErrorAction Stop

        if ($proc.ExitCode -eq 0) {
            Write-OK "SQL Server instance '$InstanceName' basariyla kaldirildi!"

            # Firewall kurallarini temizle
            $fwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $InstanceName }
            if ($fwRules) {
                foreach ($rule in $fwRules) {
                    Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
                    Write-Info "Firewall kurali kaldirildi: $($rule.DisplayName)"
                }
            }

            # Registry temizligi - ayni isimle tekrar kurulum yapilabilmesi icin
            try {
                $regBasePath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
                $instNamesKey = Get-ItemProperty "$regBasePath\Instance Names\SQL" -ErrorAction SilentlyContinue
                if ($instNamesKey -and $instNamesKey.$InstanceName) {
                    $instRegId = $instNamesKey.$InstanceName
                    Remove-ItemProperty "$regBasePath\Instance Names\SQL" -Name $InstanceName -Force -ErrorAction SilentlyContinue
                    Write-Info "Registry instance girisi kaldirildi: $InstanceName"
                    if ($instRegId -and (Test-Path "$regBasePath\$instRegId")) {
                        Remove-Item "$regBasePath\$instRegId" -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Info "Registry alt anahtari kaldirildi: $instRegId"
                    }
                }
            } catch {
                Write-Warn "Registry temizligi sirasinda hata: $($_.Exception.Message)"
            }

            return $true
        } elseif ($proc.ExitCode -eq 3010) {
            Write-OK "SQL Server instance '$InstanceName' kaldirildi (yeniden baslatma gerekiyor)"

            # Registry temizligi
            try {
                $regBasePath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
                $instNamesKey = Get-ItemProperty "$regBasePath\Instance Names\SQL" -ErrorAction SilentlyContinue
                if ($instNamesKey -and $instNamesKey.$InstanceName) {
                    $instRegId = $instNamesKey.$InstanceName
                    Remove-ItemProperty "$regBasePath\Instance Names\SQL" -Name $InstanceName -Force -ErrorAction SilentlyContinue
                    if ($instRegId -and (Test-Path "$regBasePath\$instRegId")) {
                        Remove-Item "$regBasePath\$instRegId" -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch {}

            return $true
        } else {
            Write-Err "Kaldirma islemi basarisiz oldu (Exit Code: $($proc.ExitCode))"
            return $false
        }
    } catch {
        Write-Err "SQL kaldirma hatasi: $($_.Exception.Message)"
        return $false
    }
}

function Get-DotNetStatus {
    $Status = @{
        Net35Installed  = $false
        Net481Installed = $false
        Net4Release     = 0
    }

    try {
        $NetFx3 = Get-WindowsOptionalFeature -Online -FeatureName "NetFx3" -ErrorAction SilentlyContinue
        $Status.Net35Installed = ($NetFx3 -and $NetFx3.State -eq "Enabled")
    } catch {}

    try {
        $DotNet4 = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name "Release" -ErrorAction SilentlyContinue
        if ($DotNet4) {
            $Status.Net4Release = $DotNet4.Release
            $Status.Net481Installed = ($DotNet4.Release -ge 533320)
        }
    } catch {}

    return $Status
}

function Get-DiskSectorInfo {
    <#
    .SYNOPSIS
        Disk sektor boyutunu kontrol eder.
        SQL Server max 4096 byte destekler; Win11 NVMe suruculer 8K/16K raporlayabilir.
        Ref: https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/database-file-operations/troubleshoot-os-4kb-disk-sector-size
    #>
    $Result = @{
        SectorSize       = 0
        NeedsFix         = $false
        RegistryFixApplied = $false
        DriveLetter      = $env:SystemDrive
    }

    try {
        # fsutil ile fiziksel sektor boyutunu oku
        $FsInfo = & fsutil fsinfo sectorinfo $env:SystemDrive 2>&1
        $AtomLine = $FsInfo | Select-String "PhysicalBytesPerSectorForAtomicity"
        $PerfLine = $FsInfo | Select-String "PhysicalBytesPerSectorForPerformance"

        $AtomSize = 0; $PerfSize = 0
        if ($AtomLine -match ':\s*(\d+)') { $AtomSize = [int]$Matches[1] }
        if ($PerfLine -match ':\s*(\d+)') { $PerfSize = [int]$Matches[1] }

        # En buyuk degeri al (Microsoft dokumantasyonu)
        $PhysicalSector = [math]::Max($AtomSize, $PerfSize)
        $Result.SectorSize = $PhysicalSector

        # SQL Server 4096 byte'tan buyugunu desteklemiyor
        if ($PhysicalSector -gt 4096) {
            $Result.NeedsFix = $true
        }
    } catch {
        # fsutil calistirilamazsa sektor bilgisi alinamaz
        $Result.SectorSize = -1
    }

    # Registry fix kontrol - stornvme
    try {
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device"
        if (Test-Path $RegPath) {
            $RegVal = Get-ItemProperty $RegPath -Name "ForcedPhysicalSectorSizeInBytes" -ErrorAction SilentlyContinue
            if ($RegVal -and $RegVal.ForcedPhysicalSectorSizeInBytes) {
                $vals = @($RegVal.ForcedPhysicalSectorSizeInBytes)
                if ($vals -contains "* 4095") {
                    $Result.RegistryFixApplied = $true
                }
            }
        }
    } catch {}

    return $Result
}

function Set-ForcedPhysicalSectorSize {
    <#
    .SYNOPSIS
        stornvme registry key ile sektor boyutunu 4KB olarak emule eder.
        Degisiklik yeniden baslatma sonrasi aktif olur.
    #>
    try {
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device"

        # Dizin yoksa olustur
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
            Write-Info "Registry yolu olusturuldu: $RegPath"
        }

        # ForcedPhysicalSectorSizeInBytes = "* 4095"
        New-ItemProperty -Path $RegPath `
            -Name "ForcedPhysicalSectorSizeInBytes" `
            -PropertyType MultiString `
            -Value @("* 4095") `
            -Force | Out-Null

        Write-OK "Registry duzeltmesi uygulandi: ForcedPhysicalSectorSizeInBytes = '* 4095'"
        Write-Info "Kaynak: https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/database-file-operations/troubleshoot-os-4kb-disk-sector-size"
        return $true
    } catch {
        Write-Err "Registry duzeltmesi uygulanamadi: $($_.Exception.Message)"
        return $false
    }
}

function Test-ScriptUpdate {
    # Lokal/test ortaminda GitHub kontrolunu atla (XAMPP gelistirme makinesi tespiti)
    if (Test-Path "C:\xampp\htdocs\bayt-support-iex\install-online.ps1") {
        Write-Info "Lokal gelistirme ortami tespit edildi, guncelleme kontrolu atlaniyor."
        return @{ UpdateAvailable = $false; RemoteVersion = $Script:ScriptVersion }
    }

    Write-Info "Guncelleme kontrolu yapiliyor..."
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        $RemoteContent = $wc.DownloadString($Script:ScriptUrl)
        $wc.Dispose()
        if ($RemoteContent -match '\$Script:ScriptVersion\s*=\s*"([^"]+)"') {
            $RemoteVer = $Matches[1]
            if ($RemoteVer -ne $Script:ScriptVersion) {
                Write-Warn "Yeni versiyon mevcut: v$RemoteVer (mevcut: v$($Script:ScriptVersion))"
                Write-Info "Guncellemek icin: iex (irm '$($Script:ScriptUrl)')"
                return @{ UpdateAvailable = $true; RemoteVersion = $RemoteVer }
            } else {
                Write-OK "Script guncel (v$($Script:ScriptVersion))"
            }
        }
    } catch {
        Write-Info "Guncelleme kontrolu yapilamadi (internet erisimi yok olabilir)"
    }
    return @{ UpdateAvailable = $false; RemoteVersion = $Script:ScriptVersion }
}

function Set-UltimatePerformancePowerPlan {
    Write-Step "Guc plani ayarlaniyor (Nihai Performans)..."
    try {
        # Ultimate Performance GUID
        $UltimatePerfGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61"
        $OSBuild = [System.Environment]::OSVersion.Version.Build
        $IsWin11 = $OSBuild -ge 22000

        # Mevcut plan kontrolu
        $CurrentPlan = powercfg /getactivescheme 2>&1
        if ($CurrentPlan -match $UltimatePerfGUID) {
            Write-OK "Guc plani zaten 'Nihai Performans (Ultimate Performance)'"
            return
        }

        # Mevcut planlarda Ultimate Performance var mi?
        $existingPlans = powercfg /list 2>&1
        $planExists = $false
        $activateGuid = $UltimatePerfGUID

        foreach ($line in $existingPlans) {
            if ($line -match $UltimatePerfGUID) {
                $planExists = $true
                break
            }
            if ($line -match 'Nihai Performans|Ultimate Performance') {
                if ($line -match '([a-f0-9-]{36})') {
                    $planExists = $true
                    $activateGuid = $Matches[1]
                    break
                }
            }
        }

        if ($IsWin11) {
            Write-Info "Windows 11 tespit edildi (Build: $OSBuild)"
            # Windows 11: Modern Standby guc planlarini gizleyebilir
            $csEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "CsEnabled" -ErrorAction SilentlyContinue
            if ($csEnabled -and $csEnabled.CsEnabled -eq 1) {
                Write-Info "Modern Standby aktif, guc planlari icin override ekleniyor..."
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "PlatformAoAcOverride" -Value 0 -Type DWord -Force
                Write-Info "PlatformAoAcOverride registry ayari eklendi (yeniden baslatmada etkili olur)"
            }
        } else {
            Write-Info "Windows 10 tespit edildi (Build: $OSBuild)"
        }

        if (-not $planExists) {
            Write-Info "Nihai Performans plani sisteme ekleniyor..."
            $dupResult = powercfg /duplicatescheme $UltimatePerfGUID 2>&1
            if ($dupResult -match '([a-f0-9-]{36})') {
                $activateGuid = $Matches[1]
                Write-OK "Nihai Performans plani olusturuldu (GUID: $activateGuid)"
            } else {
                Write-Warn "Nihai Performans plani olusturulamadi: $dupResult"
                # Fallback: High Performance
                Write-Info "Alternatif olarak Yuksek Performans plani deneniyor..."
                $HighPerfGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
                $fbResult = powercfg /setactive $HighPerfGUID 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-OK "Guc plani 'Yuksek Performans (High Performance)' olarak ayarlandi (fallback)"
                } else {
                    Write-Warn "Hicbir performans plani ayarlanamadi"
                }
                return
            }
        }

        # Plani etkinlestir
        $result = powercfg /setactive $activateGuid 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Guc plani 'Nihai Performans (Ultimate Performance)' olarak ayarlandi"
        } else {
            Write-Warn "Guc plani etkinlestirilemedi: $result"
        }
    } catch {
        Write-Warn "Guc plani ayarlanamadi: $($_.Exception.Message)"
    }
}

function Install-BaytApplication {
    param(
        [switch]$InstallCapital,
        [switch]$InstallBoss
    )

    Write-Step "Bay.T uygulama kurulumu baslatiliyor..."

    $apps = @()
    if ($InstallCapital) {
        $apps += @{ Name = "Bay.T Capital"; Url = "https://bay-t.com.tr/assets/download/Capital/CapitalSetup.exe"; File = "CapitalSetup.exe" }
    }
    if ($InstallBoss) {
        $apps += @{ Name = "Bay.T Boss"; Url = "https://bay-t.com.tr/assets/download/BOSS/BossSetup.exe"; File = "BossSetup.exe" }
    }

    foreach ($app in $apps) {
        $destPath = "$($Script:TempBase)\$($app.File)"
        try {
            Write-Info "$($app.Name) indiriliyor: $($app.Url)"

            # Indirme islemi
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "BaytSupportInstaller/4.0")
            $webClient.DownloadFile($app.Url, $destPath)

            if (Test-Path $destPath) {
                $fileSize = [math]::Round((Get-Item $destPath).Length / 1MB, 1)
                Write-OK "$($app.Name) indirildi ($fileSize MB): $destPath"

                Write-Info "$($app.Name) kurulumu baslatiliyor..."
                Start-Process -FilePath $destPath
                Write-OK "$($app.Name) kurulumu baslandi (setup penceresi acilacaktir)"
            } else {
                Write-Err "$($app.Name) indirilemedi!"
            }
        } catch {
            Write-Err "$($app.Name) isleminde hata: $($_.Exception.Message)"
        } finally {
            if ($webClient) { $webClient.Dispose() }
        }
    }
}
#endregion

# ============================================================================
#region VISUAL C++ RUNTIME KURULUMU
# ============================================================================

function Install-VCRuntimes {
    Write-Step "Visual C++ Runtime kutuphaneleri kuruluyor..."

    # Kurulu olan VC++ versiyonlarini tespit et
    $InstalledVC = Get-InstalledVCRuntimes
    $Is64Bit = [Environment]::Is64BitOperatingSystem

    $Installs = @(
        @{ Name = "2005"; x86 = "vcredist2005_x86.exe"; x64 = "vcredist2005_x64.exe"; Args = "/q";
           DlX86 = "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE";
           DlX64 = "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" },
        @{ Name = "2008"; x86 = "vcredist2008_x86.exe"; x64 = "vcredist2008_x64.exe"; Args = "/qb";
           DlX86 = "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe";
           DlX64 = "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe" },
        @{ Name = "2010"; x86 = "vcredist2010_x86.exe"; x64 = "vcredist2010_x64.exe"; Args = "/passive /norestart";
           DlX86 = "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe";
           DlX64 = "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe" },
        @{ Name = "2012"; x86 = "vcredist2012_x86.exe"; x64 = "vcredist2012_x64.exe"; Args = "/passive /norestart";
           DlX86 = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe";
           DlX64 = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe" },
        @{ Name = "2013"; x86 = "vcredist2013_x86.exe"; x64 = "vcredist2013_x64.exe"; Args = "/passive /norestart";
           DlX86 = "https://aka.ms/highdpimfc2013x86enu";
           DlX64 = "https://aka.ms/highdpimfc2013x64enu" },
        @{ Name = "2015-2022"; x86 = "vcredist2015_2017_2019_2022_x86.exe"; x64 = "vcredist2015_2017_2019_2022_x64.exe"; Args = "/passive /norestart";
           DlX86 = "https://aka.ms/vs/17/release/vc_redist.x86.exe";
           DlX64 = "https://aka.ms/vs/17/release/vc_redist.x64.exe" }
    )

    # Yerel dosya dizinini kontrol et
    $VCRedistDir = $null
    if ($Script:ScriptDir) {
        $LocalVCDir = Join-Path $Script:ScriptDir "Visual-C-Runtimes-All-in-One-Dec-2025"
        if (Test-Path $LocalVCDir) {
            $VCRedistDir = $LocalVCDir
            Write-Info "Yerel VC++ dosyalari bulundu: $VCRedistDir"
        }
    }

    # Yerel dosya yoksa temp dizini hazirla
    if (-not $VCRedistDir) {
        New-Item -Path $Script:TempBase -ItemType Directory -Force | Out-Null
        $VCRedistDir = "$($Script:TempBase)\VCRedist"
        New-Item -Path $VCRedistDir -ItemType Directory -Force | Out-Null
    }

    $SuccessCount = 0
    $SkipCount = 0
    $TotalCount = 0

    foreach ($inst in $Installs) {
        $vcStatus = $InstalledVC[$inst.Name]
        $needX86 = -not ($vcStatus -and $vcStatus.x86)
        $needX64 = $Is64Bit -and (-not ($vcStatus -and $vcStatus.x64))

        if (-not $needX86 -and -not $needX64) {
            Write-OK "VC++ $($inst.Name) zaten kurulu - atlaniyor"
            $SkipCount++
            continue
        }

        # x86 kurulum
        if ($needX86) {
            $x86Path = Join-Path $VCRedistDir $inst.x86
            if (-not (Test-Path $x86Path)) {
                try {
                    Write-Info "Indiriliyor: $($inst.x86)..."
                    $wc = New-Object System.Net.WebClient
                    $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                    $wc.DownloadFile($inst.DlX86, $x86Path)
                    $wc.Dispose()
                } catch {
                    Write-Warn "$($inst.x86) indirilemedi: $($_.Exception.Message)"
                }
            }
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
        } else {
            Write-OK "VC++ $($inst.Name) x86 zaten kurulu"
        }

        # x64 kurulum
        if ($needX64) {
            $x64Path = Join-Path $VCRedistDir $inst.x64
            if (-not (Test-Path $x64Path)) {
                try {
                    Write-Info "Indiriliyor: $($inst.x64)..."
                    $wc = New-Object System.Net.WebClient
                    $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                    $wc.DownloadFile($inst.DlX64, $x64Path)
                    $wc.Dispose()
                } catch {
                    Write-Warn "$($inst.x64) indirilemedi: $($_.Exception.Message)"
                }
            }
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
        } elseif ($Is64Bit) {
            Write-OK "VC++ $($inst.Name) x64 zaten kurulu"
        }
    }

    if ($SkipCount -gt 0) {
        Write-OK "VC++ Runtime: $SuccessCount yeni kuruldu, $SkipCount zaten mevcuttu"
    } else {
        Write-OK "Visual C++ Runtime kurulumu tamamlandi ($SuccessCount/$TotalCount basarili)"
    }
}
#endregion

# ============================================================================
#region .NET FRAMEWORK ETKINLESTIRME
# ============================================================================

function Enable-DotNetFrameworks {
    param(
        [bool]$InstallNet35 = $true,
        [bool]$InstallNet481 = $true
    )

    Write-Step ".NET Framework etkinlestiriliyor..."

    if ($InstallNet35) {
    # --- .NET Framework 3.5 ---
    Write-Info ".NET Framework 3.5 kontrol ediliyor..."
    # Windows Server kontrolu
    $IsServer = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType -ne 1
    try {
        $NetFx3 = Get-WindowsOptionalFeature -Online -FeatureName "NetFx3" -ErrorAction SilentlyContinue
        if ($NetFx3 -and $NetFx3.State -eq "Enabled") {
            Write-OK ".NET Framework 3.5 zaten etkin"
        } else {
            if ($IsServer) {
                Write-Info ".NET Framework 3.5 etkinlestiriliyor (Windows Server)..."
                try {
                    Import-Module ServerManager -ErrorAction SilentlyContinue
                    Install-WindowsFeature -Name NET-Framework-Core -ErrorAction Stop | Out-Null
                    Write-OK ".NET Framework 3.5 etkinlestirildi (Install-WindowsFeature)"
                } catch {
                    Write-Info "Install-WindowsFeature basarisiz, alternatif deneniyor..."
                    Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -All -NoRestart -ErrorAction Stop | Out-Null
                    Write-OK ".NET Framework 3.5 etkinlestirildi (DISM)"
                }
            } else {
                Write-Info ".NET Framework 3.5 etkinlestiriliyor (Windows Update'ten indirilecek)..."
                Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -All -NoRestart -ErrorAction Stop | Out-Null
                Write-OK ".NET Framework 3.5 etkinlestirildi"
            }
        }
    } catch {
        Write-Warn ".NET 3.5 etkinlestirilemedi: $($_.Exception.Message)"
        Write-Info "Manuel: Denetim Masasi > Programlar > Windows ozelliklerini ac/kapat"
    }
    } # end InstallNet35

    if ($InstallNet481) {
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
    } # end InstallNet481
}
#endregion

# ============================================================================
#region GUI FORM
# ============================================================================

function Show-InstallGUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # --- Sistem on tespiti ---
    $DotNetStatus = Get-DotNetStatus
    $InstalledVC  = Get-InstalledVCRuntimes
    $ExistingSql  = Get-InstalledSqlInstances
    $DiskSector   = Get-DiskSectorInfo

    # VC++ kurulu sayisi hesapla
    $VCTotal = 6
    $VCInstalledCount = 0
    foreach ($key in $InstalledVC.Keys) {
        $vc = $InstalledVC[$key]
        if ($vc.x86 -and $vc.x64) { $VCInstalledCount++ }
    }
    $AllVCInstalled = ($VCInstalledCount -eq $VCTotal)

    # SQL Native Client 2012 kurulu mu kontrol et
    $NativeClientInstalled = $false
    $NativeClientCheckPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server Native Client 11.0",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server Native Client 11.0"
    )
    foreach ($ncPath in $NativeClientCheckPaths) {
        if (Test-Path $ncPath) { $NativeClientInstalled = $true; break }
    }

    # Kurulu SQL instance isimlerini listele (ArrayList: GUI icerisinden guncellenebilir)
    $ExistingSqlNames = [System.Collections.ArrayList]@()
    if ($ExistingSql -and $ExistingSql.Count -gt 0) {
        foreach ($sqlInst in $ExistingSql) { $ExistingSqlNames.Add($sqlInst.Name.ToUpperInvariant()) | Out-Null }
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Bayt Support Otomatik Kurulum v$($Script:ScriptVersion)"
    $form.Size = New-Object System.Drawing.Size(540, 700)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)

    $y = 15

    # --- Baslik ---
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = "Bayt Support Otomatik Kurulum"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(0, 100, 200)
    $lblTitle.Location = New-Object System.Drawing.Point(20, $y)
    $lblTitle.AutoSize = $true
    $form.Controls.Add($lblTitle)
    $y += 38

    $lblSub = New-Object System.Windows.Forms.Label
    $lblSub.Text = "Kurmak istediginiz bilesenleri secin ve Kurulumu Baslat'a tiklayin."
    $lblSub.ForeColor = [System.Drawing.Color]::Gray
    $lblSub.Location = New-Object System.Drawing.Point(22, $y)
    $lblSub.AutoSize = $true
    $form.Controls.Add($lblSub)
    $y += 30

    # --- Bilesenler GroupBox ---
    $grpComp = New-Object System.Windows.Forms.GroupBox
    $grpComp.Text = "Kurulacak Bilesenler"
    $grpComp.Location = New-Object System.Drawing.Point(15, $y)
    $grpComp.Size = New-Object System.Drawing.Size(495, 252)
    $grpComp.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($grpComp)

    $normalFont = New-Object System.Drawing.Font("Segoe UI", 9.5)
    $smallFont  = New-Object System.Drawing.Font("Segoe UI", 8)

    # VC++ Checkbox + durum
    $chkVCPP = New-Object System.Windows.Forms.CheckBox
    if ($AllVCInstalled) {
        $chkVCPP.Text = "Visual C++ Runtimes (2005 - 2022)  [TUMU KURULU]"
        $chkVCPP.Checked = $false
        $chkVCPP.Enabled = $false
        $chkVCPP.ForeColor = [System.Drawing.Color]::Gray
    } else {
        $vcMissing = $VCTotal - $VCInstalledCount
        $chkVCPP.Text = "Visual C++ Runtimes (2005 - 2022)  [$vcMissing eksik]"
        $chkVCPP.Checked = $true
    }
    $chkVCPP.Location = New-Object System.Drawing.Point(15, 28)
    $chkVCPP.AutoSize = $true
    $chkVCPP.Font = $normalFont
    $grpComp.Controls.Add($chkVCPP)

    # .NET 3.5 Checkbox + durum
    $chkNet35 = New-Object System.Windows.Forms.CheckBox
    if ($DotNetStatus.Net35Installed) {
        $chkNet35.Text = ".NET Framework 3.5  [KURULU]"
        $chkNet35.Checked = $false
        $chkNet35.Enabled = $false
        $chkNet35.ForeColor = [System.Drawing.Color]::Gray
    } else {
        $chkNet35.Text = ".NET Framework 3.5  [KURULU DEGIL]"
        $chkNet35.Checked = $true
    }
    $chkNet35.Location = New-Object System.Drawing.Point(15, 58)
    $chkNet35.AutoSize = $true
    $chkNet35.Font = $normalFont
    $grpComp.Controls.Add($chkNet35)

    # .NET 4.8.1 Checkbox + durum
    $chkNet481 = New-Object System.Windows.Forms.CheckBox
    if ($DotNetStatus.Net481Installed) {
        $chkNet481.Text = ".NET Framework 4.8.1  [KURULU]"
        $chkNet481.Checked = $false
        $chkNet481.Enabled = $false
        $chkNet481.ForeColor = [System.Drawing.Color]::Gray
    } else {
        $chkNet481.Text = ".NET Framework 4.8.1  [KURULU DEGIL]"
        $chkNet481.Checked = $true
    }
    $chkNet481.Location = New-Object System.Drawing.Point(15, 88)
    $chkNet481.AutoSize = $true
    $chkNet481.Font = $normalFont
    $grpComp.Controls.Add($chkNet481)

    # SQL Native Client 2012 checkbox (SQL'den bagimsiz kurulabilir)
    $chkNativeClient = New-Object System.Windows.Forms.CheckBox
    if ($NativeClientInstalled) {
        $chkNativeClient.Text = "SQL Native Client 2012  [KURULU]"
        $chkNativeClient.Checked = $false
        $chkNativeClient.Enabled = $false
        $chkNativeClient.ForeColor = [System.Drawing.Color]::Gray
    } else {
        $chkNativeClient.Text = "SQL Native Client 2012  [KURULU DEGIL]"
        $chkNativeClient.Checked = $true
    }
    $chkNativeClient.Location = New-Object System.Drawing.Point(15, 118)
    $chkNativeClient.AutoSize = $true
    $chkNativeClient.Font = $normalFont
    $grpComp.Controls.Add($chkNativeClient)

    # SQL Checkbox
    $chkSQL = New-Object System.Windows.Forms.CheckBox
    $chkSQL.Text = "SQL Server Standard Kurulumu"
    $chkSQL.Checked = $false
    $chkSQL.Location = New-Object System.Drawing.Point(15, 152)
    $chkSQL.AutoSize = $true
    $chkSQL.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $chkSQL.ForeColor = [System.Drawing.Color]::FromArgb(0, 100, 200)
    $grpComp.Controls.Add($chkSQL)

    # Power Plan Checkbox
    $chkPowerPlan = New-Object System.Windows.Forms.CheckBox
    $chkPowerPlan.Text = "Guc Planini Nihai Performans (Ultimate) Yap"
    $chkPowerPlan.Checked = $true
    $chkPowerPlan.Location = New-Object System.Drawing.Point(15, 182)
    $chkPowerPlan.AutoSize = $true
    $chkPowerPlan.Font = $normalFont
    $grpComp.Controls.Add($chkPowerPlan)

    # Bay.T Uygulama Checkboxlar (sadece 1 tanesi secilebilir)
    $chkCapital = New-Object System.Windows.Forms.CheckBox
    $chkCapital.Text = "Bay.T Capital Kurulumunu Indir ve Baslat"
    $chkCapital.Checked = $false
    $chkCapital.Location = New-Object System.Drawing.Point(15, 212)
    $chkCapital.AutoSize = $true
    $chkCapital.Font = $normalFont
    $chkCapital.ForeColor = [System.Drawing.Color]::FromArgb(180, 80, 0)
    $grpComp.Controls.Add($chkCapital)

    $chkBoss = New-Object System.Windows.Forms.CheckBox
    $chkBoss.Text = "Bay.T Boss Kurulumunu Indir ve Baslat"
    $chkBoss.Checked = $false
    $chkBoss.Location = New-Object System.Drawing.Point(280, 212)
    $chkBoss.AutoSize = $true
    $chkBoss.Font = $normalFont
    $chkBoss.ForeColor = [System.Drawing.Color]::FromArgb(180, 80, 0)
    $grpComp.Controls.Add($chkBoss)

    # Karsilikli dislama: Capital isaretlenince Boss kalkar, Boss isaretlenince Capital kalkar
    $chkCapital.Add_CheckedChanged({
        if ($chkCapital.Checked) { $chkBoss.Checked = $false }
    })
    $chkBoss.Add_CheckedChanged({
        if ($chkBoss.Checked) { $chkCapital.Checked = $false }
    })

    $y += 262

    # --- SQL Ayarlari GroupBox ---
    $grpSqlHeight = if ($ExistingSqlNames.Count -gt 0) { 275 } else { 238 }
    $grpSql = New-Object System.Windows.Forms.GroupBox
    $grpSql.Text = "SQL Server Ayarlari (SQL secildiginde aktif olur)"
    $grpSql.Location = New-Object System.Drawing.Point(15, $y)
    $grpSql.Size = New-Object System.Drawing.Size(495, $grpSqlHeight)
    $grpSql.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $grpSql.Enabled = $false
    $form.Controls.Add($grpSql)

    $lblVer = New-Object System.Windows.Forms.Label
    $lblVer.Text = "Versiyon:"
    $lblVer.Location = New-Object System.Drawing.Point(15, 32)
    $lblVer.AutoSize = $true
    $lblVer.Font = $normalFont
    $grpSql.Controls.Add($lblVer)

    # Windows surum tespiti: Win10 -> 2019 Express, Win11 -> 2022 Express onerilen
    $osBuild = [System.Environment]::OSVersion.Version.Build
    $isWin11 = $osBuild -ge 22000

    $cmbVersion = New-Object System.Windows.Forms.ComboBox
    if ($isWin11) {
        $cmbVersion.Items.AddRange(@(
            "SQL Server 2019 Express",
            "SQL Server 2022 Express (Onerilen)",
            "SQL Server 2025 Express",
            "SQL Server 2019 Standard",
            "SQL Server 2022 Standard",
            "SQL Server 2025 Standard"
        ))
        $cmbVersion.SelectedIndex = 1
    } else {
        $cmbVersion.Items.AddRange(@(
            "SQL Server 2019 Express (Onerilen)",
            "SQL Server 2022 Express",
            "SQL Server 2025 Express",
            "SQL Server 2019 Standard",
            "SQL Server 2022 Standard",
            "SQL Server 2025 Standard"
        ))
        $cmbVersion.SelectedIndex = 0
    }
    $cmbVersion.Location = New-Object System.Drawing.Point(115, 29)
    $cmbVersion.Size = New-Object System.Drawing.Size(290, 25)
    $cmbVersion.DropDownStyle = "DropDownList"
    $cmbVersion.Font = $normalFont
    $grpSql.Controls.Add($cmbVersion)

    $lblInst = New-Object System.Windows.Forms.Label
    $lblInst.Text = "Instance:"
    $lblInst.Location = New-Object System.Drawing.Point(15, 68)
    $lblInst.AutoSize = $true
    $lblInst.Font = $normalFont
    $grpSql.Controls.Add($lblInst)

    $cmbInstance = New-Object System.Windows.Forms.ComboBox
    $cmbInstance.Items.AddRange(@("BaytTicariSQL", "BaytBossSQL", "PERFECTUS", "Bayt", "MSSQLSERVER"))
    $cmbInstance.Text = "BaytTicariSQL"
    $cmbInstance.Location = New-Object System.Drawing.Point(115, 65)
    $cmbInstance.Size = New-Object System.Drawing.Size(290, 25)
    $cmbInstance.DropDownStyle = "DropDown"  # Listeden sec veya serbest yaz
    $cmbInstance.Font = $normalFont
    $grpSql.Controls.Add($cmbInstance)

    $lblInstHint = New-Object System.Windows.Forms.Label
    $lblInstHint.Text = "(Listeden secin veya kendiniz yazin)"
    $lblInstHint.Location = New-Object System.Drawing.Point(410, 68)
    $lblInstHint.AutoSize = $true
    $lblInstHint.Font = New-Object System.Drawing.Font("Segoe UI", 7)
    $lblInstHint.ForeColor = [System.Drawing.Color]::Gray
    $grpSql.Controls.Add($lblInstHint)

    $lblPass = New-Object System.Windows.Forms.Label
    $lblPass.Text = "SA Sifre:"
    $lblPass.Location = New-Object System.Drawing.Point(15, 104)
    $lblPass.AutoSize = $true
    $lblPass.Font = $normalFont
    $grpSql.Controls.Add($lblPass)

    $txtPassword = New-Object System.Windows.Forms.TextBox
    $txtPassword.Text = $Script:SAPassword
    $txtPassword.Location = New-Object System.Drawing.Point(115, 101)
    $txtPassword.Size = New-Object System.Drawing.Size(290, 25)
    $txtPassword.Font = $normalFont
    $grpSql.Controls.Add($txtPassword)

    # Firewall checkbox
    $chkFirewall = New-Object System.Windows.Forms.CheckBox
    $chkFirewall.Text = "Firewall Kurallari Olustur (TCP 1433 / UDP 1434)"
    $chkFirewall.Checked = $false
    $chkFirewall.Location = New-Object System.Drawing.Point(15, 135)
    $chkFirewall.AutoSize = $true
    $chkFirewall.Font = $normalFont
    $grpSql.Controls.Add($chkFirewall)

    # SQL Protokol yapilandirmasi checkbox
    $chkSqlProtocols = New-Object System.Windows.Forms.CheckBox
    $chkSqlProtocols.Text = "SQL Protokollerini Yapilandir (TCP/IP, Named Pipes, Browser)"
    $chkSqlProtocols.Checked = $true
    $chkSqlProtocols.Location = New-Object System.Drawing.Point(15, 165)
    $chkSqlProtocols.AutoSize = $true
    $chkSqlProtocols.Font = $normalFont
    $grpSql.Controls.Add($chkSqlProtocols)

    # SQL Performans ayarlari checkbox
    $chkSqlPerformance = New-Object System.Windows.Forms.CheckBox
    $chkSqlPerformance.Text = "SQL Performans Ayarlarini Uygula (Max Memory, MAXDOP)"
    $chkSqlPerformance.Checked = $true
    $chkSqlPerformance.Location = New-Object System.Drawing.Point(15, 195)
    $chkSqlPerformance.AutoSize = $true
    $chkSqlPerformance.Font = $normalFont
    $grpSql.Controls.Add($chkSqlPerformance)

    # Mevcut SQL Instance bilgisi goster
    if ($ExistingSqlNames.Count -gt 0) {
        $sqlInstStr = ($ExistingSql | ForEach-Object { "$($_.Name) [SQL $($_.VersionYear) $($_.Edition)] ($($_.Status))" }) -join ", "
        $lblExistSql = New-Object System.Windows.Forms.Label
        $lblExistSql.Text = "Mevcut instance: $sqlInstStr"
        $lblExistSql.Location = New-Object System.Drawing.Point(15, 228)
        $lblExistSql.Size = New-Object System.Drawing.Size(470, 35)
        $lblExistSql.Font = $smallFont
        $lblExistSql.ForeColor = [System.Drawing.Color]::OrangeRed
        $grpSql.Controls.Add($lblExistSql)
    }

    # SQL checkbox toggle + sektor boyutu kontrolu
    $chkSQL.Add_CheckedChanged({
        $grpSql.Enabled = $chkSQL.Checked

        # SQL isaretlendiginde disk sektor boyutunu kontrol et
        if ($chkSQL.Checked) {
            $sectorInfo = Get-DiskSectorInfo
            if ($sectorInfo.NeedsFix) {
                $sKB = [math]::Round($sectorInfo.SectorSize / 1024, 0)
                if ($sectorInfo.RegistryFixApplied) {
                    # Registry fix zaten uygulanmis, bilgilendirme yap
                    [System.Windows.Forms.MessageBox]::Show(
                        "Disk sektor boyutu ${sKB}KB olarak tespit edildi (SQL Server max 4KB destekler).`n`nRegistry duzeltmesi (ForcedPhysicalSectorSizeInBytes) zaten uygulanmis.`nYeniden baslatma sonrasi aktif olacaktir.",
                        "Disk Sektor Bilgisi",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    )
                } else {
                    # Registry fix uygulanmamis, kullaniciya sor
                    $fixAnswer = [System.Windows.Forms.MessageBox]::Show(
                        "UYARI: Disk sektor boyutu ${sKB}KB olarak tespit edildi!`n`nSQL Server maksimum 4096 byte (4KB) sektor boyutu destekler.`nBu sorunu cozmek icin registry duzeltmesi uygulanmalidir.`n`n(ForcedPhysicalSectorSizeInBytes = 4KB)`nRef: MS Learn - 4KB disk sector size fix`n`nRegistry duzeltmesini simdi uygulamak istiyor musunuz?`n(Duzeltme sonrasi bilgisayarin YENIDEN BASLATILMASI gerekir)",
                        "NVMe Disk Sektor Sorunu - SQL Server Uyumsuzlugu",
                        [System.Windows.Forms.MessageBoxButtons]::YesNo,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                    if ($fixAnswer -eq [System.Windows.Forms.DialogResult]::Yes) {
                        $fixResult = Set-ForcedPhysicalSectorSize
                        if ($fixResult) {
                            $DiskSector.RegistryFixApplied = $true
                            [System.Windows.Forms.MessageBox]::Show(
                                "Registry duzeltmesi basariyla uygulandi!`n`nONEMLI: Duzeltmenin aktif olmasi icin bilgisayarin YENIDEN BASLATILMASI gerekir.`nYeniden baslatma olmadan SQL Server kurulumu basarisiz olabilir.",
                                "Duzeltme Uygulandi",
                                [System.Windows.Forms.MessageBoxButtons]::OK,
                                [System.Windows.Forms.MessageBoxIcon]::Warning
                            )
                        } else {
                            # Fix uygulanamadi, SQL secimini kaldir
                            $chkSQL.Checked = $false
                            [System.Windows.Forms.MessageBox]::Show(
                                "Registry duzeltmesi uygulanamadi!`nSQL Server kurulumu yapilamaz.",
                                "Hata",
                                [System.Windows.Forms.MessageBoxButtons]::OK,
                                [System.Windows.Forms.MessageBoxIcon]::Error
                            )
                        }
                    } else {
                        # Kullanici fix'i reddetti, SQL secimini kaldir
                        $chkSQL.Checked = $false
                        [System.Windows.Forms.MessageBox]::Show(
                            "Disk sektor boyutu duzeltmesi uygulanmadan SQL Server kurulamaz.`nOnce duzeltmeyi uygulayip bilgisayari yeniden baslatin.",
                            "SQL Server Kurulamaz",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Information
                        )
                    }
                }
            }
        }
    })

    $y += ($grpSqlHeight + 10)

    # --- Mevcut Instance Yonetimi ---
    if ($ExistingSqlNames.Count -gt 0) {
        $grpMgmt = New-Object System.Windows.Forms.GroupBox
        $grpMgmt.Text = "Mevcut Instance Yonetimi"
        $grpMgmt.Location = New-Object System.Drawing.Point(15, $y)
        $grpMgmt.Size = New-Object System.Drawing.Size(495, 100)
        $grpMgmt.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
        $form.Controls.Add($grpMgmt)

        $cmbMgmtInst = New-Object System.Windows.Forms.ComboBox
        $cmbMgmtInst.DropDownStyle = "DropDownList"
        $cmbMgmtInst.Location = New-Object System.Drawing.Point(12, 24)
        $cmbMgmtInst.Size = New-Object System.Drawing.Size(200, 25)
        $cmbMgmtInst.Font = $normalFont
        foreach ($inst in $ExistingSql) {
            $cmbMgmtInst.Items.Add("$($inst.Name) ($($inst.Status))")
        }
        if ($cmbMgmtInst.Items.Count -gt 0) { $cmbMgmtInst.SelectedIndex = 0 }
        $grpMgmt.Controls.Add($cmbMgmtInst)

        $btnSvcStart = New-Object System.Windows.Forms.Button
        $btnSvcStart.Text = "Baslat"
        $btnSvcStart.Location = New-Object System.Drawing.Point(220, 23)
        $btnSvcStart.Size = New-Object System.Drawing.Size(78, 28)
        $btnSvcStart.FlatStyle = "Flat"
        $btnSvcStart.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
        $btnSvcStart.ForeColor = [System.Drawing.Color]::White
        $btnSvcStart.Font = $smallFont
        $btnSvcStart.Cursor = [System.Windows.Forms.Cursors]::Hand
        $grpMgmt.Controls.Add($btnSvcStart)

        $btnSvcStop = New-Object System.Windows.Forms.Button
        $btnSvcStop.Text = "Durdur"
        $btnSvcStop.Location = New-Object System.Drawing.Point(303, 23)
        $btnSvcStop.Size = New-Object System.Drawing.Size(78, 28)
        $btnSvcStop.FlatStyle = "Flat"
        $btnSvcStop.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
        $btnSvcStop.ForeColor = [System.Drawing.Color]::White
        $btnSvcStop.Font = $smallFont
        $btnSvcStop.Cursor = [System.Windows.Forms.Cursors]::Hand
        $grpMgmt.Controls.Add($btnSvcStop)

        $btnSvcRestart = New-Object System.Windows.Forms.Button
        $btnSvcRestart.Text = "Yen. Baslat"
        $btnSvcRestart.Location = New-Object System.Drawing.Point(386, 23)
        $btnSvcRestart.Size = New-Object System.Drawing.Size(100, 28)
        $btnSvcRestart.FlatStyle = "Flat"
        $btnSvcRestart.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
        $btnSvcRestart.ForeColor = [System.Drawing.Color]::Black
        $btnSvcRestart.Font = $smallFont
        $btnSvcRestart.Cursor = [System.Windows.Forms.Cursors]::Hand
        $grpMgmt.Controls.Add($btnSvcRestart)

        $btnSvcUninstall = New-Object System.Windows.Forms.Button
        $btnSvcUninstall.Text = "SQL Kaldir"
        $btnSvcUninstall.Location = New-Object System.Drawing.Point(12, 55)
        $btnSvcUninstall.Size = New-Object System.Drawing.Size(200, 28)
        $btnSvcUninstall.FlatStyle = "Flat"
        $btnSvcUninstall.BackColor = [System.Drawing.Color]::FromArgb(139, 0, 0)
        $btnSvcUninstall.ForeColor = [System.Drawing.Color]::White
        $btnSvcUninstall.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)
        $btnSvcUninstall.Cursor = [System.Windows.Forms.Cursors]::Hand
        $grpMgmt.Controls.Add($btnSvcUninstall)

        $lblMgmtResult = New-Object System.Windows.Forms.Label
        $lblMgmtResult.Text = ""
        $lblMgmtResult.Location = New-Object System.Drawing.Point(220, 60)
        $lblMgmtResult.Size = New-Object System.Drawing.Size(266, 16)
        $lblMgmtResult.Font = $smallFont
        $grpMgmt.Controls.Add($lblMgmtResult)

        # Servis adi yardimci fonksiyonu
        $GetInstSvcName = {
            param($Name)
            if ($Name -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$Name" }
        }

        $RefreshMgmtCombo = {
            $idx = $cmbMgmtInst.SelectedIndex
            if ($idx -lt 0) { return }
            $iName = ($cmbMgmtInst.SelectedItem -split ' \(')[0]
            $sName = & $GetInstSvcName $iName
            $svc = Get-Service $sName -ErrorAction SilentlyContinue
            if ($svc) { $cmbMgmtInst.Items[$idx] = "$iName ($($svc.Status))" }
        }

        $btnSvcStart.Add_Click({
            if ($cmbMgmtInst.SelectedIndex -lt 0) { return }
            $iName = ($cmbMgmtInst.SelectedItem -split ' \(')[0]
            $sName = & $GetInstSvcName $iName
            try {
                $lblMgmtResult.ForeColor = [System.Drawing.Color]::Gray
                $lblMgmtResult.Text = "$iName baslatiliyor..."
                [System.Windows.Forms.Application]::DoEvents()
                Start-Service $sName -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                & $RefreshMgmtCombo
                $lblMgmtResult.ForeColor = [System.Drawing.Color]::Green
                $lblMgmtResult.Text = "$iName baslatildi."
            } catch {
                $lblMgmtResult.ForeColor = [System.Drawing.Color]::Red
                $lblMgmtResult.Text = "Hata: $($_.Exception.Message)"
            }
        })

        $btnSvcStop.Add_Click({
            if ($cmbMgmtInst.SelectedIndex -lt 0) { return }
            $iName = ($cmbMgmtInst.SelectedItem -split ' \(')[0]
            $sName = & $GetInstSvcName $iName
            try {
                $lblMgmtResult.ForeColor = [System.Drawing.Color]::Gray
                $lblMgmtResult.Text = "$iName durduruluyor..."
                [System.Windows.Forms.Application]::DoEvents()
                Stop-Service $sName -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                & $RefreshMgmtCombo
                $lblMgmtResult.ForeColor = [System.Drawing.Color]::OrangeRed
                $lblMgmtResult.Text = "$iName durduruldu."
            } catch {
                $lblMgmtResult.ForeColor = [System.Drawing.Color]::Red
                $lblMgmtResult.Text = "Hata: $($_.Exception.Message)"
            }
        })

        $btnSvcRestart.Add_Click({
            if ($cmbMgmtInst.SelectedIndex -lt 0) { return }
            $iName = ($cmbMgmtInst.SelectedItem -split ' \(')[0]
            $sName = & $GetInstSvcName $iName
            try {
                $lblMgmtResult.ForeColor = [System.Drawing.Color]::Gray
                $lblMgmtResult.Text = "$iName yeniden baslatiliyor..."
                [System.Windows.Forms.Application]::DoEvents()
                Restart-Service $sName -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                & $RefreshMgmtCombo
                $lblMgmtResult.ForeColor = [System.Drawing.Color]::Green
                $lblMgmtResult.Text = "$iName yeniden baslatildi."
            } catch {
                $lblMgmtResult.ForeColor = [System.Drawing.Color]::Red
                $lblMgmtResult.Text = "Hata: $($_.Exception.Message)"
            }
        })

        $btnSvcUninstall.Add_Click({
            if ($cmbMgmtInst.SelectedIndex -lt 0) { return }
            $iName = ($cmbMgmtInst.SelectedItem -split ' \(')[0]

            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "'$iName' SQL Server instance'ini tamamen kaldirmak istediginize emin misiniz?`n`nBu islem geri alinamaz! Tum veritabanlari silinecektir.",
                "SQL Server Kaldirma Onayi",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )

            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

            $confirm2 = [System.Windows.Forms.MessageBox]::Show(
                "SON UYARI: '$iName' instance'i ve tum veritabanlari kalici olarak silinecek!`n`nDevam etmek istiyor musunuz?",
                "Son Onay",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Stop
            )

            if ($confirm2 -ne [System.Windows.Forms.DialogResult]::Yes) { return }

            $lblMgmtResult.ForeColor = [System.Drawing.Color]::Gray
            $lblMgmtResult.Text = "$iName kaldiriliyor..."
            [System.Windows.Forms.Application]::DoEvents()

            $btnSvcUninstall.Enabled = $false
            $btnSvcStart.Enabled = $false
            $btnSvcStop.Enabled = $false
            $btnSvcRestart.Enabled = $false

            try {
                $result = Uninstall-SqlInstance -InstanceName $iName
                if ($result) {
                    $lblMgmtResult.ForeColor = [System.Drawing.Color]::Green
                    $lblMgmtResult.Text = "$iName basariyla kaldirildi!"
                    $cmbMgmtInst.Items.RemoveAt($cmbMgmtInst.SelectedIndex)
                    $ExistingSqlNames.Remove($iName.ToUpperInvariant())
                    if ($cmbMgmtInst.Items.Count -gt 0) { $cmbMgmtInst.SelectedIndex = 0 }

                    # SQL kaldirma sonrasi GUI'yi yeniden baslatarak tum tespitleri guncelle
                    [System.Windows.Forms.MessageBox]::Show(
                        "'$iName' basariyla kaldirildi.`n`nGuncel sistem durumunu yansitmak icin arayuz yeniden yuklenecek.",
                        "GUI Yeniden Yukleniyor",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    ) | Out-Null
                    $form.DialogResult = [System.Windows.Forms.DialogResult]::Retry
                    $form.Close()
                    return
                } else {
                    $lblMgmtResult.ForeColor = [System.Drawing.Color]::Red
                    $lblMgmtResult.Text = "Kaldirma basarisiz oldu."
                }
            } catch {
                $lblMgmtResult.ForeColor = [System.Drawing.Color]::Red
                $lblMgmtResult.Text = "Hata: $($_.Exception.Message)"
            } finally {
                $btnSvcUninstall.Enabled = $true
                $btnSvcStart.Enabled = $true
                $btnSvcStop.Enabled = $true
                $btnSvcRestart.Enabled = $true
            }
        })

        $y += 110
    }

    # --- Disk Sektor Uyarisi (4KB sorunu) ---
    # Not: Sektor kontrolu artik SQL checkbox isaretlendiginde yapiliyor.
    # Fix gerekiyorsa SQL checkbox event'inda kullaniciya sorulup aninda uygulanir.

    # --- Sistem Bilgisi ---
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Location = New-Object System.Drawing.Point(20, $y)
    $lblInfo.Size = New-Object System.Drawing.Size(490, 18)
    $lblInfo.ForeColor = [System.Drawing.Color]::Gray
    $lblInfo.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $form.Controls.Add($lblInfo)
    try {
        $cpuName = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1).Name
        $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory / 1GB, 1)
        $diskGB = [math]::Round((Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -eq $env:SystemDrive }).FreeSpace / 1GB, 1)
        $lblInfo.Text = "$cpuName | RAM: ${ramGB} GB | Bos Disk: ${diskGB} GB"
    } catch { $lblInfo.Text = "" }

    $y += 25

    # --- Butonlar ---
    $btnInstall = New-Object System.Windows.Forms.Button
    $btnInstall.Text = "Kurulumu Baslat"
    $btnInstall.Location = New-Object System.Drawing.Point(130, $y)
    $btnInstall.Size = New-Object System.Drawing.Size(170, 42)
    $btnInstall.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $btnInstall.ForeColor = [System.Drawing.Color]::White
    $btnInstall.FlatStyle = "Flat"
    $btnInstall.Font = New-Object System.Drawing.Font("Segoe UI", 10.5, [System.Drawing.FontStyle]::Bold)
    $btnInstall.Cursor = [System.Windows.Forms.Cursors]::Hand
    $form.Controls.Add($btnInstall)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Iptal"
    $btnCancel.Location = New-Object System.Drawing.Point(315, $y)
    $btnCancel.Size = New-Object System.Drawing.Size(100, 42)
    $btnCancel.FlatStyle = "Flat"
    $btnCancel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $btnCancel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $form.Controls.Add($btnCancel)

    # Form boyutunu ayarla
    $form.ClientSize = New-Object System.Drawing.Size(524, ($y + 55))

    $form.AcceptButton = $btnInstall
    $form.CancelButton = $btnCancel

    # --- Buton Olaylari ---
    $Script:GUIResult = $null

    $btnInstall.Add_Click({
        if (-not $chkVCPP.Checked -and -not $chkNet35.Checked -and -not $chkNet481.Checked -and -not $chkSQL.Checked -and -not $chkPowerPlan.Checked -and -not $chkCapital.Checked -and -not $chkBoss.Checked) {
            [System.Windows.Forms.MessageBox]::Show(
                "Lutfen en az bir bilesen secin!",
                "Uyari",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        if ($chkSQL.Checked -and [string]::IsNullOrWhiteSpace($cmbInstance.Text)) {
            [System.Windows.Forms.MessageBox]::Show(
                "SQL Server secildi fakat Instance ismi bos!",
                "Uyari",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        # Mevcut SQL instance ile cakisma kontrolu
        if ($chkSQL.Checked) {
            $wantedName = $cmbInstance.Text.Trim().ToUpperInvariant()
            if ($ExistingSqlNames -contains $wantedName) {
                $answer = [System.Windows.Forms.MessageBox]::Show(
                    "SQL Server instance '$wantedName' bu bilgisayarda zaten kurulu!`n`nAyni isimle kurulum yapilamaz. Farkli bir instance adi girin.",
                    "Instance Cakismasi",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
                return
            }
        }

        # Instance adi validasyonu
        if ($chkSQL.Checked) {
            $instNameVal = $cmbInstance.Text.Trim()
            if ($instNameVal.Length -gt 16) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Instance adi en fazla 16 karakter olabilir!`nGirilen: $($instNameVal.Length) karakter",
                    "Gecersiz Instance Adi",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }
            if ($instNameVal -notmatch '^[A-Za-z][A-Za-z0-9_]*$') {
                [System.Windows.Forms.MessageBox]::Show(
                    "Instance adi gecersiz!`n`nKurallar:`n- Harf ile baslamali`n- Sadece harf, rakam ve alt cizgi (_) icerebilir`n- Bosluk ve ozel karakter kullanilamaz",
                    "Gecersiz Instance Adi",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }
        }

        # SA sifre karmasiklik kontrolu
        if ($chkSQL.Checked) {
            $pwd = $txtPassword.Text
            $pwdErrors = @()
            if ($pwd.Length -lt 8) { $pwdErrors += "- En az 8 karakter olmali" }
            if ($pwd -cnotmatch '[A-Z]') { $pwdErrors += "- En az 1 buyuk harf icermeli (A-Z)" }
            if ($pwd -cnotmatch '[a-z]') { $pwdErrors += "- En az 1 kucuk harf icermeli (a-z)" }
            if ($pwd -notmatch '[0-9]') { $pwdErrors += "- En az 1 rakam icermeli (0-9)" }
            if ($pwd -notmatch '[^A-Za-z0-9]') { $pwdErrors += "- En az 1 ozel karakter icermeli (!@#$%)" }
            if ($pwdErrors.Count -gt 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    "SA sifresi SQL Server gereksinimlerini karsilamiyor:`n`n" + ($pwdErrors -join "`n") + "`n`nGuclu bir sifre girin.",
                    "Zayif Sifre",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }
        }

        # Versiyon + edition haritasi (combo index -> SqlDownloadInfo key)
        # Siralama: Express'ler once, Standard'lar sonra
        $versionMap = @{
            0 = "2019-express"
            1 = "2022-express"
            2 = "2025-express"
            3 = "2019-standard"
            4 = "2022-standard"
            5 = "2025-standard"
        }

        # Disk sector fix secimi (artik SQL checkbox event'inda uygulanıyor)
        $applySectorFix = $false

        $Script:GUIResult = @{
            InstallVCPP      = $chkVCPP.Checked
            InstallNet35     = $chkNet35.Checked
            InstallNet481    = $chkNet481.Checked
            InstallSQL       = $chkSQL.Checked
            SqlVersion       = $versionMap[$cmbVersion.SelectedIndex]  # ornek: "2022-standard"
            InstanceName     = $cmbInstance.Text.Trim().ToUpperInvariant()
            SAPassword       = $txtPassword.Text
            InstallFirewall      = if ($chkSQL.Checked) { $chkFirewall.Checked } else { $false }
            ConfigSqlProtocols   = if ($chkSQL.Checked) { $chkSqlProtocols.Checked } else { $false }
            ConfigSqlPerformance = if ($chkSQL.Checked) { $chkSqlPerformance.Checked } else { $false }
            InstallNativeClient  = $chkNativeClient.Checked
            SetPowerPlan     = $chkPowerPlan.Checked
            InstallCapital   = $chkCapital.Checked
            InstallBoss      = $chkBoss.Checked
            ApplySectorFix   = $applySectorFix
            SectorNeedsFix   = $DiskSector.NeedsFix
            SectorFixApplied = $DiskSector.RegistryFixApplied
            SectorSize       = $DiskSector.SectorSize
        }

        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })

    $btnCancel.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    })

    $dialogResult = $form.ShowDialog()
    $form.Dispose()

    # SQL kaldirma sonrasi GUI'yi yeniden baslat (Retry sinyali)
    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::Retry) {
        return Show-InstallGUI
    }

    return $Script:GUIResult
}
#endregion

# ============================================================================
#region ON GEREKSINIM KONTROLLERI
# ============================================================================

function Test-Prerequisites {
    Write-Step "Sistem gereksinimleri kontrol ediliyor..."

    # 64-bit kontrol
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw "64-bit isletim sistemi gereklidir! SQL Server sadece x64 destekler."
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

    # Onceki extract kalintilari temizle, indirme dosyalarini koru
    if (Test-Path "$TempDir\Extracted") {
        Remove-Item "$TempDir\Extracted" -Recurse -Force -ErrorAction SilentlyContinue
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

    # Mevcut indirme dosyasini kontrol et - varsa tekrar indirme
    $Downloaded = $false
    if ((Test-Path $DownloaderPath) -and (Get-Item $DownloaderPath).Length -gt 1MB) {
        $ExistingSizeMB = [math]::Round((Get-Item $DownloaderPath).Length / 1MB, 1)
        Write-Step "SQL Server $Version indirme dosyasi mevcut ($ExistingSizeMB MB), tekrar indirilmiyor."
        $Downloaded = $true
    } else {
        Write-Step "SQL Server $Version indiriliyor..."
        $Downloaded = Download-FileWithRetry -Urls $DownloadUrls -OutputPath $DownloaderPath -Description "SQL Server $Version"
    }

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
        # Onceden indirilmis medya dosyasi var mi kontrol et
        # Express: buyuk .exe (>50MB), Developer: kucuk .exe + buyuk .box
        $ExistingMediaExe = Get-ChildItem $MediaDir -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                            Select-Object -First 1
        $ExistingMediaBox = Get-ChildItem $MediaDir -Filter "*.box" -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.Length -gt 50MB } |
                            Select-Object -First 1

        if ($ExistingMediaExe -and ($ExistingMediaExe.Length -gt 50MB -or $ExistingMediaBox)) {
            $MediaSizeMB = if ($ExistingMediaBox) { [math]::Round($ExistingMediaBox.Length / 1MB, 1) } else { [math]::Round($ExistingMediaExe.Length / 1MB, 1) }
            Write-Step "SQL Server $Version medya dosyasi mevcut ($MediaSizeMB MB), tekrar indirilmiyor."
            $InstallerExePath = $ExistingMediaExe.FullName
        } else {
            Write-Step "SQL Server $Version medyasi SSEI ile indiriliyor..."
            Write-Info "Bu islem internet hiziniza gore 5-20 dakika surebilir."

            # SSEI argumanlari - Express SSEI icin /MEDIATYPE=Core gerekli, Developer SSEI desteklemiyor
            if ($Version -like '*-express') {
                $SSEIArgs = @(
                    "/ACTION=Download",
                    "/MEDIAPATH=`"$MediaDir`"",
                    "/MEDIATYPE=Core",
                    "/QUIET"
                )
            } else {
                $SSEIArgs = @(
                    "/ACTION=Download",
                    "/MEDIAPATH=`"$MediaDir`"",
                    "/QUIET"
                )
            }

            $SSEIProc = Start-Process -FilePath $DownloaderPath -ArgumentList $SSEIArgs -PassThru

            # Indirme ilerlemesini izle
            $LastSizeMB = 0
            while (-not $SSEIProc.HasExited) {
                $Files = Get-ChildItem $MediaDir -Recurse -File -ErrorAction SilentlyContinue |
                         Where-Object { $_.Extension -in @('.exe', '.cab', '.msi', '.box') }
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

            # Indirilen installer .exe dosyasini bul
            # Developer SSEI: kucuk .exe (bootstrapper) + buyuk .box dosyasi indirir
            # Express SSEI: buyuk .exe (all-in-one) indirir
            $InstallerExePath = Get-ChildItem $MediaDir -Filter "*.exe" -Recurse |
                                Sort-Object Length -Descending |
                                Select-Object -First 1 -ExpandProperty FullName

            if (-not $InstallerExePath) {
                throw "SSEI medya indirdikten sonra installer dosyasi bulunamadi! Dizin: $MediaDir"
            }
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
        "/INSTANCENAME=$($InstanceName.ToUpperInvariant())",
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

    # Product Key (Standard Edition)
    if ($Info.ProductKey) {
        $InstallArgs.Add("/PID=`"$($Info.ProductKey)`"") | Out-Null
    }

    # Instant File Initialization (2019+)
    if ($Info.SupportsInstantInit) {
        $InstallArgs.Add("/SQLSVCINSTANTFILEINIT=True") | Out-Null
    }

    # TempDB optimizasyonu (2019+ setup'ta otomatik yapilir)
    if ($Info.SupportsTempDBParams) {
        $TempDBCount = [math]::Max(1, [math]::Min($LogicalCPUs, 8))
        $InstallArgs.Add("/SQLTEMPDBFILECOUNT=$TempDBCount") | Out-Null
        $InstallArgs.Add("/SQLTEMPDBFILESIZE=256") | Out-Null
        $InstallArgs.Add("/SQLTEMPDBFILEGROWTH=128") | Out-Null
        $InstallArgs.Add("/SQLTEMPDBLOGFILESIZE=64") | Out-Null
        $InstallArgs.Add("/SQLTEMPDBLOGFILEGROWTH=64") | Out-Null
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

function Set-SqlFirewallRules {
    param([string]$InstanceName)
    Write-Step "Windows Firewall kurallari olusturuluyor..."
    $RulesCreated = 0

    # TCP 1433 (SQL Server)
    try {
        $ruleName = "SQL Server ($InstanceName) - TCP 1433"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound -Protocol TCP -LocalPort 1433 `
                -Action Allow -Profile Any -Enabled True `
                -Description "SQL Server $InstanceName icin TCP 1433 portu - Bayt Support" `
                -ErrorAction Stop | Out-Null
            Write-OK "Firewall kurali olusturuldu: TCP 1433"
            $RulesCreated++
        } else {
            Write-OK "Firewall kurali zaten mevcut: TCP 1433"
        }
    } catch {
        Write-Warn "TCP 1433 firewall kurali olusturulamadi: $($_.Exception.Message)"
    }

    # UDP 1434 (SQL Browser)
    try {
        $ruleName = "SQL Server Browser - UDP 1434"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound -Protocol UDP -LocalPort 1434 `
                -Action Allow -Profile Any -Enabled True `
                -Description "SQL Server Browser servisi icin UDP 1434 - Bayt Support" `
                -ErrorAction Stop | Out-Null
            Write-OK "Firewall kurali olusturuldu: UDP 1434"
            $RulesCreated++
        } else {
            Write-OK "Firewall kurali zaten mevcut: UDP 1434"
        }
    } catch {
        Write-Warn "UDP 1434 firewall kurali olusturulamadi: $($_.Exception.Message)"
    }

    # SQL Server executable
    try {
        $SqlRegBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
        $InstanceRegName = (Get-ItemProperty "$SqlRegBase\Instance Names\SQL" -ErrorAction SilentlyContinue).$InstanceName
        if ($InstanceRegName) {
            $SqlExePath = "$env:ProgramFiles\Microsoft SQL Server\$InstanceRegName\MSSQL\Binn\sqlservr.exe"
            if (Test-Path $SqlExePath) {
                $ruleName = "SQL Server ($InstanceName) - Program"
                $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                if (-not $existing) {
                    New-NetFirewallRule -DisplayName $ruleName `
                        -Direction Inbound -Program $SqlExePath `
                        -Action Allow -Profile Any -Enabled True `
                        -Description "SQL Server $InstanceName executable - Bayt Support" `
                        -ErrorAction Stop | Out-Null
                    Write-OK "Firewall kurali olusturuldu: sqlservr.exe"
                    $RulesCreated++
                }
            }
        }
    } catch {
        Write-Warn "SQL Server program firewall kurali olusturulamadi"
    }

    if ($RulesCreated -gt 0) {
        Write-OK "Toplam $RulesCreated yeni firewall kurali olusturuldu"
    } else {
        Write-OK "Tum firewall kurallari zaten mevcut"
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

    # Max memory: RAM'in %75'i (Standard edition icin 128GB limit)
    $AutoMaxMemory = [math]::Max([math]::Floor($TotalRAMMB * 0.75), 256)

    # MAXDOP: Tum CPU core'lari kullan (edition upgrade'de tekrar ayar gerekmez)
    $AutoMaxDOP = [math]::Max(1, $LogicalCPUs)

    Write-Info "Toplam RAM: $TotalRAMMB MB | CPU: $LogicalCPUs core"
    Write-Info "Max Memory: $AutoMaxMemory MB (%75 RAM) | MAXDOP: $AutoMaxDOP (tum core) | Cost Threshold: 25"

    # sp_configure komutlari
    $ConfigCommands = @(
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
        "EXEC sp_configure 'max server memory (MB)', $AutoMaxMemory; RECONFIGURE;",
        "EXEC sp_configure 'max degree of parallelism', $AutoMaxDOP; RECONFIGURE;",
        "EXEC sp_configure 'cost threshold for parallelism', 25; RECONFIGURE;",
        "EXEC sp_configure 'optimize for ad hoc workloads', 1; RECONFIGURE;",
        "EXEC sp_configure 'remote admin connections', 1; RECONFIGURE;"
    )

    # Backup compression
    $ConfigCommands += "EXEC sp_configure 'backup compression default', 1; RECONFIGURE;"

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

    # TempDB post-install optimizasyonu
    # Sorgu basarili olduysa TempDB ayarlamasi yapilmis demektir
    if (-not $Info.SupportsTempDBParams) {
        Set-TempDBOptimization -ServerInstance $ServerInstance -LogicalCPUs $LogicalCPUs -MaxCores 8
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
    Write-Host "  SQL Server Versiyonu : $Version Standard" -ForegroundColor White
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
    Write-Host "  NOT: BaytTicariSQL/BaytBossSQL instance'lari icin sifre degisimi" -ForegroundColor DarkCyan
    Write-Host "  gerekmez. Setup otomatik olarak sifreyi degistirir." -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
}
#endregion

# ============================================================================
#region ANA AKIS
# ============================================================================

function Main {
    # Log dosyasi baslat
    $Script:LogFile = "$($Script:TempBase)\install-log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    New-Item -Path $Script:TempBase -ItemType Directory -Force | Out-Null
    try { Start-Transcript -Path $Script:LogFile -Append | Out-Null } catch {}

    try {
        Write-Banner
        Write-Info "Log dosyasi: $($Script:LogFile)"

        # C:\Bay-T klasorune Everyone tam yetki ver
        try {
            $BaytRoot = Split-Path $Script:TempBase -Parent
            $Acl = Get-Acl $BaytRoot
            $EveryoneSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $EveryoneSid,
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $Acl.SetAccessRule($AccessRule)
            Set-Acl $BaytRoot $Acl
            Write-OK "$BaytRoot klasorune Everyone tam yetki verildi"
        } catch {
            Write-Warn "$BaytRoot klasorune yetki verilemedi: $($_.Exception.Message)"
        }

        # Guncelleme kontrolu
        Test-ScriptUpdate

        # 1. GUI goster veya Unattended mod
        if ($Silent) {
            Write-Info "Sessiz kurulum modu aktif"
            if (-not $InstallVCPP -and -not $InstallNet35 -and -not $InstallNet481 -and -not $InstallSQL -and -not $SetPowerPlan -and -not $InstallCapital -and -not $InstallBoss) {
                Write-Err "Sessiz modda en az bir bilesen secilmelidir! -Help ile parametreleri gorun."
                return
            }
            $DiskSectorInfo = Get-DiskSectorInfo
            $Selections = @{
                InstallVCPP      = $InstallVCPP.IsPresent
                InstallNet35     = $InstallNet35.IsPresent
                InstallNet481    = $InstallNet481.IsPresent
                InstallSQL       = $InstallSQL.IsPresent
                SqlVersion       = if ($SqlVersion) { $SqlVersion } else { "2019-standard" }
                InstanceName     = if ($InstanceName) { $InstanceName.ToUpperInvariant() } else { "BAYTTICARISQL" }
                SAPassword       = if ($SAPass) { $SAPass } else { $Script:SAPassword }
                InstallFirewall      = $InstallFirewall.IsPresent
                ConfigSqlProtocols   = $ConfigSqlProtocols.IsPresent
                ConfigSqlPerformance = $ConfigSqlPerformance.IsPresent
                InstallNativeClient  = $InstallNativeClient.IsPresent
                SetPowerPlan     = $SetPowerPlan.IsPresent
                InstallCapital   = $InstallCapital.IsPresent
                InstallBoss      = $InstallBoss.IsPresent
                ApplySectorFix   = $DiskSectorInfo.NeedsFix -and (-not $DiskSectorInfo.RegistryFixApplied)
                SectorNeedsFix   = $DiskSectorInfo.NeedsFix
                SectorFixApplied = $DiskSectorInfo.RegistryFixApplied
                SectorSize       = $DiskSectorInfo.SectorSize
            }
        } else {
            $Selections = Show-InstallGUI
        }

        if (-not $Selections) {
            Write-Host ""
            Write-Host "  Kurulum iptal edildi." -ForegroundColor Red
            return
        }

        # SA password guncelle
        if ($Selections.InstallSQL -and $Selections.SAPassword) {
            $Script:SAPassword = $Selections.SAPassword
        }

        # Secilen bilesenleri goster
        Write-Host ""
        Write-Host "  +-----------------------------------------+" -ForegroundColor Cyan
        Write-Host "  |         SECILEN BILESENLER               |" -ForegroundColor Cyan
        Write-Host "  +-----------------------------------------+" -ForegroundColor Cyan
        if ($Selections.InstallVCPP)   { Write-Host "  |  [+] Visual C++ Runtimes (2005-2022)   |" -ForegroundColor Green }
        if ($Selections.InstallNet35)  { Write-Host "  |  [+] .NET Framework 3.5                |" -ForegroundColor Green }
        if ($Selections.InstallNet481) { Write-Host "  |  [+] .NET Framework 4.8.1              |" -ForegroundColor Green }
        if ($Selections.InstallSQL) {
            # SqlVersion ornegi: "2022-standard" -> "2022 Standard" seklinde gosterim
            $sqlDisplayName = $Selections.SqlVersion -replace '-',' ' -replace 'standard','Standard' -replace 'express','Express'
            $sqlLine = "  |  [+] SQL Server $sqlDisplayName - $($Selections.InstanceName)"
            $sqlLine = $sqlLine.PadRight(43) + "|"
            Write-Host $sqlLine -ForegroundColor Green
        }
        if ($Selections.ApplySectorFix) { Write-Host "  |  [+] Disk Sektor Boyutu Fix (4KB)      |" -ForegroundColor Yellow }
        if ($Selections.InstallFirewall)      { Write-Host "  |  [+] Firewall Kurallari (1433/1434)    |" -ForegroundColor Green }
        if ($Selections.ConfigSqlProtocols)   { Write-Host "  |  [+] SQL Protokol Yapilandirmasi       |" -ForegroundColor Green }
        if ($Selections.ConfigSqlPerformance) { Write-Host "  |  [+] SQL Performans Ayarlari           |" -ForegroundColor Green }
        if ($Selections.InstallNativeClient)  { Write-Host "  |  [+] SQL Native Client 2012            |" -ForegroundColor Green }
        if ($Selections.SetPowerPlan)    { Write-Host "  |  [+] Guc Plani: Nihai Performans       |" -ForegroundColor Green }
        if ($Selections.InstallCapital)  { Write-Host "  |  [+] Bay.T Capital Kurulumu            |" -ForegroundColor Yellow }
        if ($Selections.InstallBoss)     { Write-Host "  |  [+] Bay.T Boss Kurulumu               |" -ForegroundColor Yellow }
        Write-Host "  +-----------------------------------------+" -ForegroundColor Cyan
        Write-Host ""

        # 2. On gereksinimler
        Test-Prerequisites

        # 3. Visual C++ Runtime
        if ($Selections.InstallVCPP) {
            Install-VCRuntimes
        } else {
            Write-Info "Visual C++ Runtimes atlaniyor (secilmedi)"
        }

        # 4. .NET Framework
        if ($Selections.InstallNet35 -or $Selections.InstallNet481) {
            Enable-DotNetFrameworks -InstallNet35:$Selections.InstallNet35 -InstallNet481:$Selections.InstallNet481
        } else {
            Write-Info ".NET Framework atlaniyor (secilmedi)"
        }

        # 5. Disk Sektor Boyutu Kontrolu (SQL oncesi - guvenlik agi)
        # Not: Sektor fix artik GUI'de SQL checkbox isaretlendiginde uygulanir.
        # Burasi sadece Silent mod veya beklenmedik durumlar icin guvenlik kontrolu.
        if ($Selections.ApplySectorFix -and $Selections.InstallSQL) {
            # Silent modda fix henuz uygulanmamis olabilir, burada uygula
            Write-Step "Disk sektor boyutu duzeltmesi uygulanıyor..."
            Write-Warn "Sistem diskiniz $($Selections.SectorSize) byte sektor boyutuna sahip (SQL Server max 4096 byte destekler)"
            $FixApplied = Set-ForcedPhysicalSectorSize
            if ($FixApplied) {
                Write-OK "Registry duzeltmesi uygulandi."
                Write-Warn "ONEMLI: Bu duzeltmenin aktif olmasi icin bilgisayarin yeniden baslatilmasi gerekir!"
                Write-Warn "SQL Server kurulumu sektor fix'i aktif olmadan basarisiz olabilir."
            }
        } elseif ($Selections.InstallSQL -and $Selections.SectorNeedsFix -and -not $Selections.SectorFixApplied) {
            Write-Warn "Disk sektor boyutu ($($Selections.SectorSize) byte) SQL Server ile uyumsuz!"
            Write-Warn "Registry duzeltmesi (ForcedPhysicalSectorSizeInBytes) uygulanmamis."
            Write-Warn "SQL Server kurulumu basarisiz olabilir."
        }

        # 6. SQL Server (opsiyonel)
        if ($Selections.InstallSQL) {
            $SelectedVersion = $Selections.SqlVersion
            $SelectedInstance = $Selections.InstanceName

            Write-Step "SQL Server kurulumuna geciliyor..."
            $SetupExe = Get-SqlSetupPath -Version $SelectedVersion

            $InstallSuccess = Install-SqlServerEngine -Version $SelectedVersion -InstanceName $SelectedInstance -SetupExePath $SetupExe

            if ($InstallSuccess) {
                $Ready = Wait-SqlServiceReady -InstanceName $SelectedInstance -TimeoutSeconds 120

                # SQL protokol yapilandirmasi (kullanici secimi)
                if ($Selections.ConfigSqlProtocols) {
                    Set-SqlProtocols -InstanceName $SelectedInstance
                    Set-SqlBrowserService
                } else {
                    Write-Info "SQL Protokol yapilandirmasi atlaniyor (secilmedi)"
                }

                # Firewall kurallari
                if ($Selections.InstallFirewall) {
                    Set-SqlFirewallRules -InstanceName $SelectedInstance
                }

                # Protokol degisiklikleri varsa servisi yeniden baslat
                if ($Selections.ConfigSqlProtocols) {
                    Restart-SqlService -InstanceName $SelectedInstance
                    $Ready = Wait-SqlServiceReady -InstanceName $SelectedInstance -TimeoutSeconds 120
                }

                # SQL performans ayarlari (kullanici secimi)
                if ($Ready -and $Selections.ConfigSqlPerformance) {
                    Set-SqlPerformanceConfig -InstanceName $SelectedInstance -Version $SelectedVersion
                } elseif (-not $Selections.ConfigSqlPerformance) {
                    Write-Info "SQL Performans ayarlari atlaniyor (secilmedi)"
                }

                if ($Ready) {
                    Test-FinalConnection -InstanceName $SelectedInstance
                }

                Show-Summary -Version $SelectedVersion -InstanceName $SelectedInstance
            } else {
                Write-Err "SQL Server kurulumu basarisiz oldu."
            }
        } else {
            Write-Info "SQL Server kurulumu atlaniyor (secilmedi)"
        }

        # 7. SQL Native Client (SQL'den bagimsiz)
        if ($Selections.InstallNativeClient) {
            Install-NativeClient
        } else {
            Write-Info "SQL Native Client kurulumu atlaniyor (secilmedi)"
        }

        # 8. Power Plan
        if ($Selections.SetPowerPlan) {
            Set-UltimatePerformancePowerPlan
        }

        # 9. Bay.T Uygulama Kurulumu
        if ($Selections.InstallCapital -or $Selections.InstallBoss) {
            Install-BaytApplication -InstallCapital:$Selections.InstallCapital -InstallBoss:$Selections.InstallBoss
        }

        # Temizlik - SQL indirme dosyalarini koru (yavas internet olan lokasyonlar icin)
        if (Test-Path $Script:TempBase) {
            # Extract dizinlerini temizle
            Get-ChildItem $Script:TempBase -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\d{4}$' } |
                ForEach-Object {
                    $extractPath = Join-Path $_.FullName "Extracted"
                    if (Test-Path $extractPath) {
                        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            # VCRedist ve diger gecici dosyalari temizle
            $cleanItems = @(
                "$($Script:TempBase)\VCRedist",
                "$($Script:TempBase)\ndp481-setup.exe",
                "$($Script:TempBase)\sqlncli.msi"
            )
            foreach ($item in $cleanItems) {
                if (Test-Path $item) { Remove-Item $item -Recurse -Force -ErrorAction SilentlyContinue }
            }
            Write-Info "SQL Server indirme dosyalari korundu: $($Script:TempBase)"
        }

        # Final
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "            TUM ISLEMLER TAMAMLANDI!" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
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
        try { Stop-Transcript | Out-Null } catch {}
        if ($Script:LogFile -and (Test-Path $Script:LogFile)) {
            Write-Host ""
            Write-Host "  Log dosyasi: $($Script:LogFile)" -ForegroundColor Gray
        }
        Write-Host ""
        if (-not $Silent) {
            Read-Host "Cikmak icin Enter tusuna basin"
        }
    }
}

# Scripti calistir
Main
#endregion

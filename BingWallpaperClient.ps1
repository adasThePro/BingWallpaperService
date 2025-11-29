#Requires -Version 3.0

<#
.SYNOPSIS
    Bing Wallpaper Changer Client
.DESCRIPTION
    CLI tool for automatic Windows wallpaper rotation using Bing daily images
.NOTES
    Version: 1.0.0
    Supports: Windows 7, 8, 8.1, 10, 11
    Modes: Current User or System-Wide (All Users)
.EXAMPLE
    bwc apply
    bwc status
    bwc config
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('apply', 'status', 'config', 'enable', 'disable', 'uninstall', 'help', 'version')]
    [string]$Command = 'help',
    
    [Parameter()]
    [switch]$Force,
    
    [Parameter()]
    [switch]$Silent
)

$Script:AppName = "BingWallpaperClient"
$Script:Version = "1.0.0"
$Script:ConfigPath = Join-Path $env:APPDATA "$Script:AppName\config.json"
$Script:ScriptPath = $PSCommandPath
$Script:TaskName = "BingWallpaperSync"
$Script:InstallPath = Join-Path $env:ProgramFiles $Script:AppName

$Script:ValidMarkets = @(
    'en-US', 'en-GB', 'en-CA', 'en-AU', 'en-IN', 'en-NZ', 'en-ZA',
    'de-DE', 'de-AT', 'de-CH',
    'fr-FR', 'fr-CA', 'fr-CH', 'fr-BE',
    'es-ES', 'es-MX', 'es-AR', 'es-CL',
    'it-IT',
    'ja-JP',
    'zh-CN', 'zh-TW', 'zh-HK',
    'pt-BR', 'pt-PT',
    'ru-RU',
    'ko-KR',
    'nl-NL', 'nl-BE',
    'pl-PL',
    'tr-TR',
    'sv-SE',
    'da-DK',
    'nb-NO',
    'fi-FI',
    'cs-CZ',
    'hu-HU',
    'ro-RO',
    'sk-SK',
    'bg-BG',
    'hr-HR',
    'et-EE',
    'lv-LV',
    'lt-LT',
    'sl-SI',
    'th-TH',
    'id-ID',
    'vi-VN',
    'ar-SA',
    'he-IL',
    'uk-UA'
)

$Script:DefaultConfig = @{
    Market = "en-US"
    DownloadPath = Join-Path $env:USERPROFILE "Pictures\BingWallpapers"
    MaxImages = 30
    KeepAllImages = $false
    ChangeDesktop = $true
    ChangeLockScreen = $true
    UpdateInterval = 24
    EnableLogging = $false
    Scope = "User"
    LastUpdate = $null
    Version = $Script:Version
    InstallPath = $null
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    if ($Script:Silent -and $Level -eq 'Info') { return }
    
    $colors = @{
        Info = 'White'
        Success = 'Green'
        Warning = 'Yellow'
        Error = 'Red'
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host "[$Level] " -NoNewline -ForegroundColor $colors[$Level]
    Write-Host $Message
    
    $config = Get-Config
    if ($config.EnableLogging) {
        try {
            $logPath = Join-Path $env:APPDATA "$Script:AppName\logs"
            if (-not (Test-Path $logPath)) {
                New-Item -ItemType Directory -Path $logPath -Force | Out-Null
            }
            $logFile = Join-Path $logPath "$(Get-Date -Format 'yyyy-MM-dd').log"
            "[$timestamp] [$Level] $Message" | Add-Content -Path $logFile -ErrorAction SilentlyContinue
        }
        catch {
            # Silently fail if logging fails
        }
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-NetworkConnectivity {
    try {
        $result = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
        return $result
    }
    catch {
        return $false
    }
}

function Test-BingApiReachability {
    param([string]$Market = "en-US")
    
    $url = "https://services.bingapis.com/ge-apps/api/v2/bwc/hpimages?mkt=$Market"
    
    try {
        $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 30 -ErrorAction Stop
        return $response.StatusCode -eq 200
    }
    catch {
        return $false
    }
}

function Test-ValidMarket {
    param([string]$Market)
    return $Script:ValidMarkets -contains $Market
}

function Get-Config {
    if (Test-Path $Script:ConfigPath) {
        try {
            $json = Get-Content $Script:ConfigPath -Raw | ConvertFrom-Json
            $config = @{}
            $json.PSObject.Properties | ForEach-Object { $config[$_.Name] = $_.Value }
            
            foreach ($key in $Script:DefaultConfig.Keys) {
                if (-not $config.ContainsKey($key)) {
                    $config[$key] = $Script:DefaultConfig[$key]
                }
            }
            return $config
        }
        catch {
            Write-Log "Failed to load config: $_" -Level Warning
            return $Script:DefaultConfig.Clone()
        }
    }
    return $Script:DefaultConfig.Clone()
}

function Save-Config {
    param([hashtable]$Config)
    
    $configDir = Split-Path $Script:ConfigPath -Parent
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    try {
        $Config | ConvertTo-Json -Depth 10 | Set-Content $Script:ConfigPath -Force
        return $true
    }
    catch {
        Write-Log "Failed to save configuration: $_" -Level Error
        return $false
    }
}

function Get-MD5Hash {
    param([string]$String)
    
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
    $hash = $md5.ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace('-', '').ToLower()
}

function Get-WindowsVersion {
    $version = [System.Environment]::OSVersion.Version
    if ($version.Major -eq 10 -and $version.Build -ge 22000) { return "Windows11" }
    elseif ($version.Major -eq 10) { return "Windows10" }
    elseif ($version.Major -eq 6 -and $version.Minor -eq 3) { return "Windows81" }
    elseif ($version.Major -eq 6 -and $version.Minor -eq 2) { return "Windows8" }
    elseif ($version.Major -eq 6 -and $version.Minor -eq 1) { return "Windows7" }
    else { return "Unknown" }
}

function Test-LockScreenSupport {
    $winVer = Get-WindowsVersion
    return $winVer -in @("Windows10", "Windows11")
}

function Get-BingImages {
    param([string]$Market = "en-US")
    
    $url = "https://services.bingapis.com/ge-apps/api/v2/bwc/hpimages?mkt=$Market"
    
    try {
        Write-Log "Fetching images from Bing API..."
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 30 -ErrorAction Stop
        return $response.images
    }
    catch {
        Write-Log "Failed to fetch Bing images: $_" -Level Error
        return $null
    }
}

function Download-Image {
    param(
        [string]$UrlBase,
        [string]$DestinationPath
    )
    
    $hash = Get-MD5Hash -String $UrlBase
    $fileName = "$hash.jpg"
    $filePath = Join-Path $DestinationPath $fileName
    
    if (Test-Path $filePath) {
        Write-Log "Image already exists: $fileName"
        return $filePath
    }
    
    try {
        Write-Log "Downloading: $fileName"
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0")
        $webClient.DownloadFile($UrlBase, $filePath)
        $webClient.Dispose()
        Write-Log "Downloaded successfully" -Level Success
        return $filePath
    }
    catch {
        Write-Log "Download failed: $_" -Level Error
        return $null
    }
}

function Set-WallpaperGroupPolicy {
    param(
        [string]$ImagePath,
        [bool]$Enable = $true
    )
    
    if (-not (Test-Administrator)) {
        Write-Log "Administrator rights required for Group Policy changes" -Level Warning
        return $false
    }
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        }
        
        if ($Enable) {
            Set-ItemProperty -Path $regPath -Name "NoChangingWallPaper" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path $regPath -Name "WallPaper" -Value $ImagePath -Force -ErrorAction Stop
            Set-ItemProperty -Path $regPath -Name "WallPaperStyle" -Value 10 -Force -ErrorAction Stop
            Write-Log "Group Policy: Desktop wallpaper enforced system-wide" -Level Success
        } else {
            Remove-ItemProperty -Path $regPath -Name "NoChangingWallPaper" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $regPath -Name "WallPaper" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $regPath -Name "WallPaperStyle" -ErrorAction SilentlyContinue
            Write-Log "Group Policy: Desktop wallpaper enforcement removed" -Level Success
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to set Group Policy: $_" -Level Error
        return $false
    }
}

function Set-LockScreenGroupPolicy {
    param(
        [string]$ImagePath,
        [bool]$Enable = $true
    )
    
    if (-not (Test-Administrator)) {
        Write-Log "Administrator rights required for Group Policy changes" -Level Warning
        return $false
    }
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        }
        
        if ($Enable) {
            Set-ItemProperty -Path $regPath -Name "NoChangingLockScreen" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path $regPath -Name "LockScreenImage" -Value $ImagePath -Force -ErrorAction Stop
            Set-ItemProperty -Path $regPath -Name "PersonalColors_Background" -Value 0 -Force -ErrorAction Stop
            Write-Log "Group Policy: Lock screen enforced system-wide" -Level Success
        } else {
            Remove-ItemProperty -Path $regPath -Name "NoChangingLockScreen" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $regPath -Name "LockScreenImage" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $regPath -Name "PersonalColors_Background" -ErrorAction SilentlyContinue
            Write-Log "Group Policy: Lock screen enforcement removed" -Level Success
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to set Group Policy: $_" -Level Error
        return $false
    }
}

function Set-DesktopWallpaper {
    param([string]$ImagePath)
    
    if (-not (Test-Path $ImagePath)) {
        Write-Log "Image not found: $ImagePath" -Level Error
        return $false
    }
    
    $config = Get-Config
    
    try {
        if ($config.Scope -eq "System") {
            if (Test-Administrator) {
                Set-WallpaperGroupPolicy -ImagePath $ImagePath -Enable $true
                
                $code = @"
using System;
using System.Runtime.InteropServices;
namespace Wallpaper {
    public class Setter {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    }
}
"@
                
                if (-not ([System.Management.Automation.PSTypeName]'Wallpaper.Setter').Type) {
                    Add-Type -TypeDefinition $code
                }
                
                $SPI_SETDESKWALLPAPER = 0x0014
                $SPIF_UPDATEINIFILE = 0x01
                $SPIF_SENDCHANGE = 0x02
                
                [Wallpaper.Setter]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $ImagePath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE) | Out-Null
                
                Write-Log "Desktop wallpaper applied system-wide" -Level Success
                return $true
            } else {
                Write-Log "System-wide scope requires administrator privileges" -Level Error
                return $false
            }
        } else {
            $code = @"
using System;
using System.Runtime.InteropServices;
namespace Wallpaper {
    public class Setter {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    }
}
"@
            
            if (-not ([System.Management.Automation.PSTypeName]'Wallpaper.Setter').Type) {
                Add-Type -TypeDefinition $code
            }
            
            $SPI_SETDESKWALLPAPER = 0x0014
            $SPIF_UPDATEINIFILE = 0x01
            $SPIF_SENDCHANGE = 0x02
            
            [Wallpaper.Setter]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $ImagePath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE) | Out-Null
            
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value $ImagePath -Force -ErrorAction SilentlyContinue

            Start-Sleep -Milliseconds 500
            rundll32.exe user32.dll, UpdatePerUserSystemParameters, 1, True
            
            Write-Log "Desktop wallpaper applied for current user" -Level Success
            return $true
        }
    }
    catch {
        Write-Log "Failed to set desktop wallpaper: $_" -Level Error
        return $false
    }
}

function Set-LockScreenWallpaper {
    param([string]$ImagePath)
    
    if (-not (Test-LockScreenSupport)) {
        Write-Log "Lock screen not supported on this Windows version" -Level Warning
        return $false
    }
    
    if (-not (Test-Path $ImagePath)) {
        Write-Log "Image not found: $ImagePath" -Level Error
        return $false
    }
    
    $config = Get-Config
    $success = $false
    
    if ($config.Scope -eq "System") {
        if (Test-Administrator) {
            $success = Set-LockScreenGroupPolicy -ImagePath $ImagePath -Enable $true
        } else {
            Write-Log "System-wide scope requires administrator privileges" -Level Error
            return $false
        }
    } else {
        if (Test-Administrator) {
            try {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
                
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                }
                
                Set-ItemProperty -Path $regPath -Name "LockScreenImage" -Value $ImagePath -Force -ErrorAction Stop
                Set-ItemProperty -Path $regPath -Name "PersonalColors_Background" -Value 0 -Force -ErrorAction Stop
                
                Write-Log "Lock screen wallpaper applied (Policy)" -Level Success
                $success = $true
            }
            catch {
                Write-Log "Policy method failed: $_" -Level Warning
            }
        }
        
        try {
            $imageName = [System.IO.Path]::GetFileName($ImagePath)
            $userLockScreen = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Themes\$imageName"
            $userDir = Split-Path $userLockScreen -Parent
            
            if (-not (Test-Path $userDir)) {
                New-Item -ItemType Directory -Path $userDir -Force | Out-Null
            }
            
            Copy-Item -Path $ImagePath -Destination $userLockScreen -Force
            
            $regUserPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen\Creative"
            if (-not (Test-Path $regUserPath)) {
                New-Item -Path $regUserPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $regUserPath -Name "LandscapeAssetPath" -Value $userLockScreen -Force
            Set-ItemProperty -Path $regUserPath -Name "PortraitAssetPath" -Value $userLockScreen -Force
            
            Write-Log "Lock screen wallpaper applied (User)" -Level Success
            $success = $true
        }
        catch {
            Write-Log "User profile method failed: $_" -Level Warning
        }
    }
    
    return $success
}

function Cleanup-OldImages {
    param(
        [string]$Path,
        [int]$MaxImages
    )
    
    if ($MaxImages -le 0) { return }
    
    try {
        $images = Get-ChildItem -Path $Path -Filter "*.jpg" -ErrorAction SilentlyContinue | 
                  Sort-Object CreationTime -Descending
        
        if ($images.Count -gt $MaxImages) {
            $toDelete = $images | Select-Object -Skip $MaxImages
            foreach ($img in $toDelete) {
                Remove-Item $img.FullName -Force -ErrorAction SilentlyContinue
                Write-Log "Deleted old image: $($img.Name)"
            }
        }
    }
    catch {
        Write-Log "Cleanup warning: $_" -Level Warning
    }
}

function Remove-FromSystemPath {
    param([string]$Path)
    
    try {
        $currentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
        $newPath = ($currentPath.Split(';') | Where-Object { $_ -ne $Path }) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $newPath, [EnvironmentVariableTarget]::Machine)
        return $true
    }
    catch {
        Write-Log "Failed to remove from PATH: $_" -Level Warning
        return $false
    }
}

function Invoke-Apply {
    try {
        Write-Log "Starting wallpaper update..." -Level Info
        
        $config = Get-Config
        
        $images = Get-BingImages -Market $config.Market
        if (-not $images -or $images.Count -eq 0) {
            Write-Log "No images available from API" -Level Error
            return
        }
        
        if (-not (Test-Path $config.DownloadPath)) {
            New-Item -ItemType Directory -Path $config.DownloadPath -Force | Out-Null
        }
        
        $downloadedCount = 0
        foreach ($img in ($images | Select-Object -First 2)) {
            $filePath = Download-Image -UrlBase $img.urlbase -DestinationPath $config.DownloadPath
            if ($filePath) { $downloadedCount++ }
        }
        
        if ($downloadedCount -eq 0) {
            Write-Log "No new images downloaded" -Level Warning
        }
        
        $existingImages = Get-ChildItem -Path $config.DownloadPath -Filter "*.jpg" -ErrorAction SilentlyContinue | 
                         Sort-Object CreationTime -Descending
        
        if ($existingImages.Count -eq 0) {
            Write-Log "No images available locally" -Level Error
            return
        }
        
        $successCount = 0
        
        if ($config.ChangeDesktop) {
            if (Set-DesktopWallpaper -ImagePath $existingImages[0].FullName) {
                $successCount++
            }
        }
        
        if ($config.ChangeLockScreen) {
            $lockScreenImage = if ($existingImages.Count -gt 1) { $existingImages[1] } else { $existingImages[0] }
            if (Set-LockScreenWallpaper -ImagePath $lockScreenImage.FullName) {
                $successCount++
            }
        }
        
        if (-not $config.KeepAllImages) {
            Cleanup-OldImages -Path $config.DownloadPath -MaxImages $config.MaxImages
        }
        
        $config.LastUpdate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Save-Config -Config $config
        
        if ($successCount -gt 0) {
            Write-Log "Wallpaper update completed successfully!" -Level Success
        } else {
            Write-Log "Wallpaper update completed with warnings" -Level Warning
        }
    }
    catch {
        Write-Log "Critical error during apply: $_" -Level Error
        Write-Log $_.ScriptStackTrace -Level Error
    }
}

function Invoke-Status {
    if (-not (Test-Administrator)) {
        Write-Host "Requesting administrator privileges for detailed status..." -ForegroundColor Yellow
        $psPath = if (Test-Path (Join-Path $Script:InstallPath "BingWallpaperClient.ps1")) {
            Join-Path $Script:InstallPath "BingWallpaperClient.ps1"
        } else {
            $Script:ScriptPath
        }
        
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$psPath`" status"
        
        try {
            Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -Wait
            return
        }
        catch {
            Write-Host "Failed to elevate. Status might be inaccurate..." -ForegroundColor Yellow
        }
    }
    
    $config = Get-Config
    
    Write-Host "`n=== $Script:AppName Status ===" -ForegroundColor Cyan
    Write-Host "Version: $Script:Version`n"
    
    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  Scope: $($config.Scope) $(if ($config.Scope -eq 'System') { '(All Users)' } else { '(Current User)' })"
    Write-Host "  Market: $($config.Market)"
    Write-Host "  Download Path: $($config.DownloadPath)"
    Write-Host "  Max Images: $(if ($config.KeepAllImages) { 'Unlimited' } else { $config.MaxImages })"
    Write-Host "  Desktop: $(if ($config.ChangeDesktop) { 'Enabled' } else { 'Disabled' })"
    Write-Host "  Lock Screen: $(if ($config.ChangeLockScreen) { 'Enabled' } else { 'Disabled' })"
    Write-Host "  Logging: $(if ($config.EnableLogging) { 'Enabled' } else { 'Disabled' })"
    Write-Host "  Last Update: $(if ($config.LastUpdate) { $config.LastUpdate } else { 'Never' })`n"
    
    Write-Host "Network & API Status:" -ForegroundColor Yellow
    Write-Host "  Internet Connection: " -NoNewline
    $networkStatus = Test-NetworkConnectivity
    if ($networkStatus) {
        Write-Host "Connected" -ForegroundColor Green
    } else {
        Write-Host "Disconnected" -ForegroundColor Red
    }
    
    Write-Host "  Bing API Reachable: " -NoNewline
    if ($networkStatus) {
        $apiStatus = Test-BingApiReachability -Market $config.Market
        if ($apiStatus) {
            Write-Host "Yes" -ForegroundColor Green
        } else {
            Write-Host "No" -ForegroundColor Red
        }
    } else {
        Write-Host "Unable to check (No internet)" -ForegroundColor Gray
    }
    Write-Host ""
    
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    Write-Host "Scheduled Task:" -ForegroundColor Yellow
    if ($task) {
        Write-Host "  Status: " -NoNewline
        Write-Host "Enabled" -ForegroundColor Green
        Write-Host "  State: $($task.State)"
        Write-Host "  Last Run: $(if ($task.LastRunTime) { $task.LastRunTime } else { 'Never' })"
        Write-Host "  Next Run: $(if ($task.NextRunTime) { $task.NextRunTime } else { 'N/A' })"
    } else {
        Write-Host "  Status: " -NoNewline
        Write-Host "Not Registered" -ForegroundColor Red
    }
    
    Write-Host "`nSystem Information:" -ForegroundColor Yellow
    Write-Host "  Windows: $(Get-WindowsVersion)"
    Write-Host "  Lock Screen Support: $(if (Test-LockScreenSupport) { 'Yes' } else { 'No' })"
    Write-Host "  Running as Admin: $(if (Test-Administrator) { 'Yes' } else { 'No' })"
    
    if (Test-Path $config.DownloadPath) {
        $images = Get-ChildItem -Path $config.DownloadPath -Filter "*.jpg" -ErrorAction SilentlyContinue
        $totalSize = ($images | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Host "  Downloaded Images: $($images.Count) ($([math]::Round($totalSize, 2)) MB)"
    }
    
    Write-Host ""
    
    if (Test-Administrator) {
        Write-Host "Press any key to exit..." -NoNewline
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

function Invoke-ConfigUpdate {
    $config = Get-Config
    
    Write-Host "`n=== Update Configuration ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Change market (current: $($config.Market))"
    Write-Host "2. Change download path"
    Write-Host "3. Change max images (current: $(if ($config.KeepAllImages) { 'Unlimited' } else { $config.MaxImages }))"
    Write-Host "4. Toggle desktop (current: $(if ($config.ChangeDesktop) { 'ON' } else { 'OFF' }))"
    Write-Host "5. Toggle lock screen (current: $(if ($config.ChangeLockScreen) { 'ON' } else { 'OFF' }))"
    Write-Host "6. Toggle logging (current: $(if ($config.EnableLogging) { 'ON' } else { 'OFF' }))"
    Write-Host "7. Change scope (current: $($config.Scope)) $(if ($config.Scope -eq 'System') { '[Requires Admin]' } else { '' })"
    Write-Host "0. Cancel`n"
    
    $choice = Read-Host "Select option"
    
    switch ($choice) {
        '1' {
            Write-Host "`nAvailable markets:" -ForegroundColor Yellow
            
            $markets = $Script:ValidMarkets
            $columns = 5
            for ($i = 0; $i -lt $markets.Count; $i += $columns) {
                $row = $markets[$i..([Math]::Min($i + $columns - 1, $markets.Count - 1))]
                Write-Host ("  " + ($row -join ", "))
            }
            
            Write-Host ""
            $market = Read-Host "Enter market code"
            
            if ($market) {
                $market = $market.Trim()
                
                if (Test-ValidMarket -Market $market) {
                    $config.Market = $market 
                    Write-Log "Market updated to $market" -Level Success
                } else {
                    Write-Log "Invalid market code: $market" -Level Error
                    Write-Log "Market code must be one from the list above" -Level Warning
                    return
                }
            }
        }
        '2' {
            $path = Read-Host "Enter new download path"
            if ($path -and (Test-Path (Split-Path $path -Parent))) {
                $config.DownloadPath = $path
                if (-not (Test-Path $path)) {
                    New-Item -ItemType Directory -Path $path -Force | Out-Null
                }
                Write-Log "Download path updated" -Level Success
            }
        }
        '3' {
            $max = Read-Host "Enter max images (0 for unlimited)"
            if ($max -match '^\d+$') {
                $config.MaxImages = [int]$max
                $config.KeepAllImages = ($max -eq 0)
                Write-Log "Max images updated to $max" -Level Success
            }
        }
        '4' {
            $config.ChangeDesktop = -not $config.ChangeDesktop
            Write-Log "Desktop wallpaper $(if ($config.ChangeDesktop) { 'enabled' } else { 'disabled' })" -Level Success
        }
        '5' {
            $config.ChangeLockScreen = -not $config.ChangeLockScreen
            Write-Log "Lock screen $(if ($config.ChangeLockScreen) { 'enabled' } else { 'disabled' })" -Level Success
        }
        '6' {
            $config.EnableLogging = -not $config.EnableLogging
            Write-Log "Logging $(if ($config.EnableLogging) { 'enabled' } else { 'disabled' })" -Level Success
        }
        '7' {
            Write-Host ""
            Write-Host "Wallpaper Scope:" -ForegroundColor Yellow
            Write-Host "  1. Current User Only - Changes wallpaper only for your account"
            Write-Host "  2. System-Wide (All Users) - Enforces wallpaper for all users [Requires Admin]"
            Write-Host ""
            Write-Host "Select scope (1 or 2): " -NoNewline
            $scopeChoice = Read-Host
            
            $oldScope = $config.Scope
            $newScope = if ($scopeChoice -eq "2") { "System" } else { "User" }
            
            if ($newScope -eq "System" -and -not (Test-Administrator)) {
                Write-Log "System-wide scope requires administrator privileges" -Level Error
                Write-Log "Please run 'bwc config' as Administrator to change to system-wide scope" -Level Warning
                return
            }
            
            if ($oldScope -ne $newScope) {
                $config.Scope = $newScope
                
                if ($oldScope -eq "System" -and $newScope -eq "User") {
                    if (Test-Administrator) {
                        Set-WallpaperGroupPolicy -ImagePath "" -Enable $false
                        Set-LockScreenGroupPolicy -ImagePath "" -Enable $false
                        Write-Log "Removed system-wide Group Policy enforcement" -Level Success
                    }
                }
                
                Write-Log "Scope changed to: $newScope" -Level Success
                Write-Log "Note: You may need to re-run the installer to update the scheduled task" -Level Warning
            }
        }
        '0' { return }
        default { Write-Log "Invalid option" -Level Warning; return }
    }
    
    Save-Config -Config $config
}

function Invoke-Enable {
    if (-not (Test-Administrator)) {
        Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
        $psPath = if (Test-Path (Join-Path $Script:InstallPath "BingWallpaperClient.ps1")) {
            Join-Path $Script:InstallPath "BingWallpaperClient.ps1"
        } else {
            $Script:ScriptPath
        }
        
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$psPath`" enable"
        
        try {
            Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -Wait
            return
        }
        catch {
            Write-Log "Failed to elevate privileges: $_" -Level Error
            return
        }
    }
    
    Write-Log "Enabling scheduled task..." -Level Info
    try {
        $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Enable-ScheduledTask -TaskName $Script:TaskName -ErrorAction Stop | Out-Null
            Write-Log "Scheduled task enabled" -Level Success
        } else {
            Write-Log "Scheduled task not found. Run installer first." -Level Error
        }
    }
    catch {
        Write-Log "Failed to enable task: $_" -Level Error
    }
    
    Write-Host "`nPress any key to exit..." -NoNewline
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Invoke-Disable {
    if (-not (Test-Administrator)) {
        Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
        $psPath = if (Test-Path (Join-Path $Script:InstallPath "BingWallpaperClient.ps1")) {
            Join-Path $Script:InstallPath "BingWallpaperClient.ps1"
        } else {
            $Script:ScriptPath
        }
        
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$psPath`" disable"
        
        try {
            Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -Wait
            return
        }
        catch {
            Write-Log "Failed to elevate privileges: $_" -Level Error
            return
        }
    }
    
    Write-Log "Disabling scheduled task..." -Level Info
    try {
        $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Disable-ScheduledTask -TaskName $Script:TaskName -ErrorAction Stop | Out-Null
            Write-Log "Scheduled task disabled" -Level Success
        } else {
            Write-Log "Scheduled task not found" -Level Warning
        }
    }
    catch {
        Write-Log "Failed to disable task: $_" -Level Error
    }
    
    Write-Host "`nPress any key to exit..." -NoNewline
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Invoke-Uninstall {
    Write-Host "`n=== Bing Wallpaper Client Uninstaller ===" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Test-Administrator)) {
        Write-Host "Administrator privileges required for uninstallation." -ForegroundColor Yellow
        Write-Host "Requesting administrator privileges...`n" -ForegroundColor Yellow
        
        $psPath = Join-Path $Script:InstallPath "BingWallpaperClient.ps1"
        
        if (-not (Test-Path $psPath)) {
            $psPath = $Script:ScriptPath
        }
        
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$psPath`" uninstall"
        
        try {
            $process = Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -PassThru
            if ($process) {
                $process.WaitForExit()
            }
            exit 0
        }
        catch {
            Write-Host "Failed to elevate privileges: $_" -ForegroundColor Red
            exit 1
        }
    }
    
    $config = Get-Config
    
    Write-Host "This will remove:" -ForegroundColor Yellow
    Write-Host "  - Client application (bwc command)"
    Write-Host "  - Scheduled tasks"
    Write-Host "  - Configuration files"
    Write-Host "  - System PATH entry"
    if ($config.Scope -eq "System") {
        Write-Host "  - Group Policy enforcement"
    }
    Write-Host ""
    Write-Host "Downloaded wallpapers location: $($config.DownloadPath)" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Continue with uninstallation? (y/N): " -NoNewline
    $confirm = Read-Host
    
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Uninstallation cancelled" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Press any key to exit..." -NoNewline
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host ""
    Write-Host "Delete downloaded wallpaper images? (y/N): " -NoNewline
    $deleteImages = Read-Host
    $shouldDeleteImages = ($deleteImages -eq 'y' -or $deleteImages -eq 'Y')
    
    Write-Host ""
    Write-Host "Uninstalling..." -ForegroundColor Yellow
    Write-Host ""
    
    $errors = 0

    if ($config.Scope -eq "System") {
        try {
            Set-WallpaperGroupPolicy -ImagePath "" -Enable $false
            Set-LockScreenGroupPolicy -ImagePath "" -Enable $false
            Write-Host "[+] Group Policy enforcement removed" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed to remove Group Policy: $_" -ForegroundColor Yellow
            $errors++
        }
    }
    
    try {
        $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction Stop
            Write-Host "[+] Scheduled task removed" -ForegroundColor Green
        } else {
            Write-Host "[i] Scheduled task not found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[!] Failed to remove scheduled task: $_" -ForegroundColor Yellow
        $errors++
    }
    
    try {
        if (Remove-FromSystemPath -Path $Script:InstallPath) {
            Write-Host "[+] Removed from system PATH" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] Failed to remove from PATH: $_" -ForegroundColor Yellow
        $errors++
    }
    
    if ($shouldDeleteImages -and (Test-Path $config.DownloadPath)) {
        try {
            $images = Get-ChildItem -Path $config.DownloadPath -Filter "*.jpg" -ErrorAction SilentlyContinue
            $imageCount = $images.Count
            
            Remove-Item -Path $config.DownloadPath -Recurse -Force -ErrorAction Stop
            Write-Host "[+] Deleted $imageCount wallpaper images" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed to delete images: $_" -ForegroundColor Yellow
            $errors++
        }
    }
    elseif (-not $shouldDeleteImages) {
        Write-Host "[i] Wallpaper images preserved at: $($config.DownloadPath)" -ForegroundColor Cyan
    }
    
    $configDir = Split-Path $Script:ConfigPath -Parent
    if (Test-Path $configDir) {
        try {
            Remove-Item -Path $configDir -Recurse -Force -ErrorAction Stop
            Write-Host "[+] Configuration and logs removed" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed to remove configuration: $_" -ForegroundColor Yellow
            $errors++
        }
    }
    
    $cleanupScript = Join-Path $env:TEMP "bwc_cleanup.cmd"
    $cleanupContent = @"
@echo off
timeout /t 2 /nobreak >nul
rd /s /q "$Script:InstallPath" 2>nul
if exist "$Script:InstallPath" (
    echo [!] Warning: Could not remove installation directory
    pause
) else (
    echo [+] Installation directory removed
)
del "%~f0" 2>nul
exit
"@
    
    try {
        $cleanupContent | Set-Content -Path $cleanupScript -Force
        Write-Host "[+] Prepared cleanup script" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to create cleanup script" -ForegroundColor Yellow
    }
    
    Write-Host ""
    if ($errors -eq 0) {
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  Uninstallation Completed!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
    }
    else {
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  Uninstallation completed with $errors warning(s)" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Thank you for using Bing Wallpaper Client!" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Finalizing cleanup..." -ForegroundColor Gray
    
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$cleanupScript`"" -WindowStyle Hidden
    
    Write-Host ""
    Write-Host "Press Enter to exit..." -NoNewline
    Read-Host | Out-Null
}

function Show-Help {
    Write-Host "`n=== $Script:AppName v$Script:Version ===" -ForegroundColor Cyan
    Write-Host "Automatic Windows wallpaper rotation using Bing daily images`n"
    
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  bwc <command> [options]`n"
    
    Write-Host "Commands:" -ForegroundColor Yellow
    Write-Host "  apply       Apply wallpaper now"
    Write-Host "  status      Show configuration and status"
    Write-Host "  config      Update configuration"
    Write-Host "  enable      Enable scheduled task"
    Write-Host "  disable     Disable scheduled task"
    Write-Host "  uninstall   Remove client completely"
    Write-Host "  version     Show version"
    Write-Host "  help        Show this help`n"
    
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  bwc apply"
    Write-Host "  bwc status"
    Write-Host "  bwc config"
    Write-Host "  bwc uninstall`n"
}

function Show-Version {
    Write-Host "$Script:AppName v$Script:Version"
}

try {
    switch ($Command.ToLower()) {
        'apply' { Invoke-Apply }
        'status' { Invoke-Status }
        'config' { Invoke-ConfigUpdate }
        'enable' { Invoke-Enable }
        'disable' { Invoke-Disable }
        'uninstall' { Invoke-Uninstall }
        'version' { Show-Version }
        'help' { Show-Help }
        default { Show-Help }
    }
}
catch {
    Write-Log "Critical error: $_" -Level Error
    Write-Log $_.ScriptStackTrace -Level Error
    exit 1
}
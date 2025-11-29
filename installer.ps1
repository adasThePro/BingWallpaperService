#Requires -Version 3.0

<#
.SYNOPSIS
    Bing Wallpaper Client Installer
.DESCRIPTION
    Installer for the Bing Wallpaper Client.
.NOTES
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('install', 'uninstall', 'update')]
    [string]$Action = 'install',
    
    [Parameter()]
    [string]$ClientUrl = "https://raw.githubusercontent.com/adasThePro/BingWallpaperService/refs/heads/main/BingWallpaperClient.ps1",
    
    [Parameter()]
    [switch]$IsElevated
)

$Script:AppName = "BingWallpaperClient"
$Script:Version = "1.0.0"
$Script:InstallPath = Join-Path $env:ProgramFiles $Script:AppName
$Script:ClientScript = "BingWallpaperClient.ps1"
$Script:ClientAlias = "bwc.cmd"
$Script:TaskName = "BingWallpaperSync"
$Script:ConfigPath = Join-Path $env:APPDATA "$Script:AppName\config.json"

# Available markets
$Script:Markets = @(
    @{Code="en-US"; Name="United States"}
    @{Code="en-GB"; Name="United Kingdom"}
    @{Code="en-CA"; Name="Canada"}
    @{Code="en-AU"; Name="Australia"}
    @{Code="en-IN"; Name="India"}
    @{Code="en-NZ"; Name="New Zealand"}
    @{Code="en-ZA"; Name="South Africa"}
    @{Code="de-DE"; Name="Germany"}
    @{Code="de-AT"; Name="Austria"}
    @{Code="de-CH"; Name="Switzerland"}
    @{Code="fr-FR"; Name="France"}
    @{Code="fr-CA"; Name="Canada (French)"}
    @{Code="fr-CH"; Name="Switzerland (French)"}
    @{Code="fr-BE"; Name="Belgium (French)"}
    @{Code="es-ES"; Name="Spain"}
    @{Code="es-MX"; Name="Mexico"}
    @{Code="es-AR"; Name="Argentina"}
    @{Code="es-CL"; Name="Chile"}
    @{Code="it-IT"; Name="Italy"}
    @{Code="ja-JP"; Name="Japan"}
    @{Code="zh-CN"; Name="China"}
    @{Code="zh-TW"; Name="Taiwan"}
    @{Code="pt-BR"; Name="Brazil"}
    @{Code="pt-PT"; Name="Portugal"}
    @{Code="ru-RU"; Name="Russia"}
    @{Code="ko-KR"; Name="Korea"}
    @{Code="nl-NL"; Name="Netherlands"}
    @{Code="nl-BE"; Name="Belgium (Dutch)"}
    @{Code="pl-PL"; Name="Poland"}
    @{Code="tr-TR"; Name="Turkey"}
    @{Code="sv-SE"; Name="Sweden"}
    @{Code="da-DK"; Name="Denmark"}
    @{Code="nb-NO"; Name="Norway"}
    @{Code="fi-FI"; Name="Finland"}
    @{Code="cs-CZ"; Name="Czech Republic"}
    @{Code="hu-HU"; Name="Hungary"}
    @{Code="ro-RO"; Name="Romania"}
    @{Code="sk-SK"; Name="Slovakia"}
    @{Code="bg-BG"; Name="Bulgaria"}
    @{Code="hr-HR"; Name="Croatia"}
    @{Code="et-EE"; Name="Estonia"}
    @{Code="lv-LV"; Name="Latvia"}
    @{Code="lt-LT"; Name="Lithuania"}
    @{Code="sl-SI"; Name="Slovenia"}
    @{Code="th-TH"; Name="Thailand"}
    @{Code="id-ID"; Name="Indonesia"}
    @{Code="vi-VN"; Name="Vietnam"}
    @{Code="ar-SA"; Name="Saudi Arabia"}
    @{Code="he-IL"; Name="Israel"}
    @{Code="uk-UA"; Name="Ukraine"}
)

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-AdminPrivileges {
    if (-not (Test-Administrator)) {
        Write-ColorOutput "`n[!] Administrator privileges required for installation" "Yellow"
        Write-ColorOutput "[!] Requesting administrator privileges...`n" "Yellow"
        
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Action $Action -IsElevated"
        if ($ClientUrl) {
            $arguments += " -ClientUrl `"$ClientUrl`""
        }
        
        try {
            $process = Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -PassThru
            
            if ($process) {
                $process.WaitForExit()
            }
            
            exit 0
        }
        catch {
            Write-ColorOutput "[X] Failed to elevate privileges: $_" "Red"
            Write-Host ""
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
}

function Add-ToSystemPath {
    param([string]$Path)
    
    try {
        $currentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
        
        if ($currentPath -notlike "*$Path*") {
            $newPath = if ($currentPath.EndsWith(';')) {
                "$currentPath$Path"
            } else {
                "$currentPath;$Path"
            }
            
            [Environment]::SetEnvironmentVariable("Path", $newPath, [EnvironmentVariableTarget]::Machine)
            
            $env:Path = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine) + ";" + [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
            
            Write-ColorOutput "[+] Added to system PATH" "Green"
            return $true
        } else {
            Write-ColorOutput "[i] Already in system PATH" "Cyan"
            return $true
        }
    }
    catch {
        Write-ColorOutput "[X] Failed to add to PATH: $_" "Red"
        return $false
    }
}

function New-CommandAlias {
    param(
        [string]$AliasPath,
        [string]$TargetScript
    )
    
    try {
        $batchContent = @"
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '$TargetScript' %*"
"@
        
        $batchContent | Set-Content -Path $AliasPath -Force
        Write-ColorOutput "[+] Created command alias: bwc" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[X] Failed to create command alias: $_" "Red"
        return $false
    }
}

function Remove-FromSystemPath {
    param([string]$Path)
    
    try {
        $currentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
        $pathArray = $currentPath.Split(';') | Where-Object { $_ -and $_ -ne $Path }
        $newPath = $pathArray -join ';'
        
        [Environment]::SetEnvironmentVariable("Path", $newPath, [EnvironmentVariableTarget]::Machine)
        Write-ColorOutput "[+] Removed from system PATH" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[X] Failed to remove from PATH: $_" "Red"
        return $false
    }
}

function Download-Client {
    param([string]$Url, [string]$Destination)
    
    Write-ColorOutput "[i] Downloading client from: $Url" "Cyan"
    
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop
        
        Write-ColorOutput "[+] Client downloaded successfully" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[X] Failed to download client: $_" "Red"
        return $false
    }
}

function New-ScheduledTaskWithTriggers {
    param(
        [string]$TaskName,
        [string]$ScriptPath,
        [string]$Scope = "User"
    )

    try {
        $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }

        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& '$ScriptPath' apply -Silent`""

        if ($Scope -eq "System") {
            $userId = "Users"
            $logonType = "Interactive"
            $description = "Automatically changes Windows wallpaper for ALL USERS using Bing daily images. Runs daily at 9 AM, at logon, and when network connects."
        }
        else {
            if ($env:USERDOMAIN -and ($env:USERDOMAIN -ne $env:COMPUTERNAME)) {
                $userId = "$env:USERDOMAIN\$env:USERNAME"
            } else {
                $userId = "$env:COMPUTERNAME\$env:USERNAME"
            }
            $logonType = "Interactive"
            $description = "Automatically changes Windows wallpaper for $env:USERNAME using Bing daily images. Runs daily at 9 AM, at logon, and when network connects."
        }

        $principal = New-ScheduledTaskPrincipal `
            -GroupId "BUILTIN\Users" `
            -RunLevel Highest

        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
            -MultipleInstances IgnoreNew

        $triggers = @()
        
        # Daily trigger at 9 AM
        $dailyTrigger = New-ScheduledTaskTrigger -Daily -At "09:00AM"
        $triggers += $dailyTrigger
        
        if ($Scope -eq "System") {
            $logonTrigger = New-ScheduledTaskTrigger -AtLogOn
        } else {
            $logonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
        }
        $triggers += $logonTrigger

        try {
            $CIMTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler -ErrorAction Stop
            
            $networkTrigger = New-CimInstance -CimClass $CIMTriggerClass -ClientOnly
            $networkTrigger.Subscription = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">
    <Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000)]]</Select>
  </Query>
</QueryList>
"@
            $networkTrigger.Enabled = $true
            $networkTrigger.Delay = "PT1M"
            
            $triggers += $networkTrigger
            
            Write-ColorOutput "[+] Created network connection trigger" "Green"
        }
        catch {
            Write-ColorOutput "[!] Warning: Could not create network trigger (task will still work): $($_.Exception.Message)" "Yellow"
        }

        $task = Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $triggers `
            -Principal $principal `
            -Settings $settings `
            -Description $description `
            -ErrorAction Stop

        if ($Scope -eq "System") {
            Write-ColorOutput "[+] Scheduled task created for ALL USERS (runs at each user's logon)" "Green"
        } else {
            Write-ColorOutput "[+] Scheduled task created for user: $userId" "Green"
        }
        Write-ColorOutput "    - Daily at 9:00 AM" "Gray"
        Write-ColorOutput "    - At user logon" "Gray"
        Write-ColorOutput "    - 1 minute after network connects" "Gray"

        return $true
    }
    catch {
        Write-ColorOutput "[X] Failed to create scheduled task: $_" "Red"
        Write-ColorOutput "[X] Error details: $($_.Exception.Message)" "Red"
        return $false
    }
}

function Get-UserConfiguration {
    Write-Host ""
    Write-ColorOutput "=== Bing Wallpaper Client Setup ===" "Cyan"
    Write-Host ""
    
    $config = @{}
    
    Write-ColorOutput "Available Markets:" "Yellow"
    $marketCodes = $Script:Markets | ForEach-Object { $_.Code }
    $columns = 5
    for ($i = 0; $i -lt $marketCodes.Count; $i += $columns) {
        $row = $marketCodes[$i..([Math]::Min($i + $columns - 1, $marketCodes.Count - 1))]
        Write-Host ("  " + ($row -join ", "))
    }
    Write-Host ""
    Write-Host "Enter market code (default: en-US): " -NoNewline
    $marketCode = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($marketCode)) {
        $marketCode = "en-US"
    }
    
    if ($marketCodes -contains $marketCode) {
        $config.Market = $marketCode
        $marketName = ($Script:Markets | Where-Object { $_.Code -eq $marketCode }).Name
        Write-ColorOutput "[+] Market: $marketName [$marketCode]" "Green"
    } else {
        Write-ColorOutput "[!] Invalid market code, using default: United States [en-US]" "Yellow"
        $config.Market = "en-US"
    }
    Write-Host ""
    
    $defaultPath = Join-Path $env:USERPROFILE "Pictures\BingWallpapers"
    Write-Host "Download path (default: $defaultPath): " -NoNewline
    $path = Read-Host
    $config.DownloadPath = if ([string]::IsNullOrWhiteSpace($path)) { $defaultPath } else { $path }
    Write-ColorOutput "[+] Download path: $($config.DownloadPath)" "Green"
    Write-Host ""
    
    if (-not (Test-Path $config.DownloadPath)) {
        New-Item -ItemType Directory -Path $config.DownloadPath -Force | Out-Null
    }
    
    Write-Host "Maximum images to keep (0 for unlimited, default: 30): " -NoNewline
    $max = Read-Host
    $config.MaxImages = if ([string]::IsNullOrWhiteSpace($max)) { 30 } else { [int]$max }
    $config.KeepAllImages = ($config.MaxImages -eq 0)
    Write-ColorOutput "[+] Max images: $(if ($config.KeepAllImages) { 'Unlimited' } else { $config.MaxImages })" "Green"
    Write-Host ""
    
    Write-Host "Change desktop wallpaper? (Y/n): " -NoNewline
    $desktop = Read-Host
    $config.ChangeDesktop = ($desktop -ne 'n' -and $desktop -ne 'N')
    Write-ColorOutput "[+] Desktop wallpaper: $(if ($config.ChangeDesktop) { 'Enabled' } else { 'Disabled' })" "Green"
    Write-Host ""
    
    Write-Host "Change lock screen wallpaper? (Y/n): " -NoNewline
    $lock = Read-Host
    $config.ChangeLockScreen = ($lock -ne 'n' -and $lock -ne 'N')
    Write-ColorOutput "[+] Lock screen: $(if ($config.ChangeLockScreen) { 'Enabled' } else { 'Disabled' })" "Green"
    Write-Host ""
    
    Write-Host "Wallpaper scope:" -ForegroundColor Yellow
    Write-Host "  1. Current User Only - Changes wallpaper only for your account"
    Write-Host "  2. System-Wide (All Users) - Enforces wallpaper for all users via Group Policy"
    Write-Host ""
    Write-Host "Select scope (1 or 2, default: 1): " -NoNewline
    $scopeChoice = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($scopeChoice) -or $scopeChoice -eq "1") {
        $config.Scope = "User"
        Write-ColorOutput "[+] Scope: Current User Only" "Green"
    } else {
        $config.Scope = "System"
        Write-ColorOutput "[+] Scope: System-Wide (All Users)" "Green"
        Write-ColorOutput "[!] Note: System-wide mode will enforce wallpaper via Group Policy" "Yellow"
        Write-ColorOutput "[!] Users will not be able to change their wallpaper manually" "Yellow"
    }
    Write-Host ""

    Write-Host "Enable logging to track operations? (y/N): " -NoNewline
    $logging = Read-Host
    $config.EnableLogging = ($logging -eq 'y' -or $logging -eq 'Y')
    Write-ColorOutput "[+] Logging: $(if ($config.EnableLogging) { 'Enabled' } else { 'Disabled' })" "Green"
    Write-Host ""
    
    $config.Version = $Script:Version
    $config.InstallPath = $Script:InstallPath
    $config.LastUpdate = $null
    $config.UpdateInterval = 24
    
    return $config
}

function Save-Configuration {
    param([hashtable]$Config)
    
    $configDir = Split-Path $Script:ConfigPath -Parent
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    try {
        $Config | ConvertTo-Json -Depth 10 | Set-Content $Script:ConfigPath -Force
        Write-ColorOutput "[+] Configuration saved" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[X] Failed to save configuration: $_" "Red"
        return $false
    }
}

function Install-Client {
    Write-Host ""
    Write-ColorOutput "========================================" "Cyan"
    Write-ColorOutput "  Bing Wallpaper Client v$Script:Version" "Cyan"
    Write-ColorOutput "  Installation Wizard" "Cyan"
    Write-ColorOutput "========================================" "Cyan"
    Write-Host ""
    
    Request-AdminPrivileges
    
    Write-ColorOutput "[i] Starting installation..." "Cyan"
    Write-Host ""
    
    if (-not (Test-Path $Script:InstallPath)) {
        try {
            New-Item -ItemType Directory -Path $Script:InstallPath -Force | Out-Null
            Write-ColorOutput "[+] Created installation directory: $Script:InstallPath" "Green"
        }
        catch {
            Write-ColorOutput "[X] Failed to create installation directory: $_" "Red"
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
    
    $clientPath = Join-Path $Script:InstallPath $Script:ClientScript
    
    if ($ClientUrl -match "^https?://") {
        if (-not (Download-Client -Url $ClientUrl -Destination $clientPath)) {
            Write-ColorOutput "[X] Installation failed" "Red"
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
    else {
        Write-ColorOutput "[!] Client URL not provided. Please set the -ClientUrl parameter." "Yellow"
        Write-ColorOutput "[i] Example: -ClientUrl 'https://raw.githubusercontent.com/user/repo/main/BingWallpaperClient.ps1'" "Cyan"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    if (-not (Add-ToSystemPath -Path $Script:InstallPath)) {
        Write-ColorOutput "[!] Warning: Could not add to PATH." "Yellow"
    }
    
    $aliasPath = Join-Path $Script:InstallPath $Script:ClientAlias
    if (-not (New-CommandAlias -AliasPath $aliasPath -TargetScript $clientPath)) {
        Write-ColorOutput "[!] Warning: Could not create command alias." "Yellow"
    }
    
    Write-Host ""
    
    $config = Get-UserConfiguration
    
    if (-not (Save-Configuration -Config $config)) {
        Write-ColorOutput "[X] Installation failed" "Red"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    Write-Host ""
    Write-ColorOutput "[i] Setting up scheduled task..." "Cyan"
    
    if (-not (New-ScheduledTaskWithTriggers -TaskName $Script:TaskName -ScriptPath $clientPath -Scope $config.Scope)) {
        Write-ColorOutput "[!] Warning: Scheduled task setup failed. You can run manually." "Yellow"
    }
    
    Write-Host ""
    Write-ColorOutput "========================================" "Green"
    Write-ColorOutput "  Installation Completed Successfully!" "Green"
    Write-ColorOutput "========================================" "Green"
    Write-Host ""
    
    Write-ColorOutput "You can now use the following commands:" "Cyan"
    Write-Host "  bwc apply    - Apply wallpaper now"
    Write-Host "  bwc status   - Check status"
    Write-Host "  bwc config   - Update settings"
    Write-Host "  bwc help     - Show help"
    Write-Host ""
    Write-ColorOutput "[i] Note: Open a new terminal window for the 'bwc' command to be available" "Yellow"
    Write-Host ""
    
    Write-Host "Apply wallpaper now? (Y/n): " -NoNewline
    $applyNow = Read-Host
    
    if ($applyNow -ne 'n' -and $applyNow -ne 'N') {
        Write-Host ""
        Write-ColorOutput "[i] Applying wallpaper..." "Cyan"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '$clientPath' apply"
    }
    
    Write-Host ""
    Write-ColorOutput "[i] Installation complete! Wallpaper will update automatically." "Green"
    Write-Host ""
    
    if ($IsElevated) {
        Write-Host "Press Enter to exit..." -NoNewline
        Read-Host
    }
}

function Uninstall-Client {
    Write-Host ""
    Write-ColorOutput "=== Bing Wallpaper Client Uninstaller ===" "Cyan"
    Write-Host ""
    
    Request-AdminPrivileges
    
    Write-Host "This will remove the client, scheduled task, and configuration."
    Write-Host "Downloaded images will be preserved."
    Write-Host ""
    Write-Host "Continue? (y/N): " -NoNewline
    $confirm = Read-Host
    
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-ColorOutput "[i] Uninstall cancelled" "Cyan"
        
        if ($IsElevated) {
            Write-Host ""
            Write-Host "Press Enter to exit..." -NoNewline
            Read-Host
        }
        return
    }
    
    Write-Host ""
    Write-ColorOutput "[i] Uninstalling..." "Cyan"
    
    try {
        $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false
            Write-ColorOutput "[+] Scheduled task removed" "Green"
        }
    }
    catch {
        Write-ColorOutput "[!] Warning: Could not remove scheduled task: $_" "Yellow"
    }
    
    Remove-FromSystemPath -Path $Script:InstallPath
    
    if (Test-Path $Script:InstallPath) {
        try {
            Remove-Item -Path $Script:InstallPath -Recurse -Force
            Write-ColorOutput "[+] Installation directory removed" "Green"
            Write-ColorOutput "[+] Command alias 'bwc' removed" "Green"
        }
        catch {
            Write-ColorOutput "[!] Warning: Could not remove installation directory: $_" "Yellow"
        }
    }
    
    $configDir = Split-Path $Script:ConfigPath -Parent
    if (Test-Path $configDir) {
        try {
            Remove-Item -Path $configDir -Recurse -Force
            Write-ColorOutput "[+] Configuration and logs removed" "Green"
        }
        catch {
            Write-ColorOutput "[!] Warning: Could not remove configuration: $_" "Yellow"
        }
    }
    
    Write-Host ""
    Write-ColorOutput "[+] Uninstall completed successfully!" "Green"
    Write-Host ""
    
    if ($IsElevated) {
        Write-Host "Press Enter to exit..." -NoNewline
        Read-Host
    }
}

function Update-Client {
    Write-Host ""
    Write-ColorOutput "=== Bing Wallpaper Client Updater ===" "Cyan"
    Write-Host ""
    
    Request-AdminPrivileges
    
    Write-ColorOutput "[i] Updating client..." "Cyan"
    
    $clientPath = Join-Path $Script:InstallPath $Script:ClientScript
    $backupPath = "$clientPath.backup"
    
    if (Test-Path $clientPath) {
        Copy-Item -Path $clientPath -Destination $backupPath -Force
    }
    
    if (Download-Client -Url $ClientUrl -Destination $clientPath) {
        Remove-Item -Path $backupPath -Force -ErrorAction SilentlyContinue
        Write-ColorOutput "[+] Client updated successfully" "Green"
    }
    else {
        if (Test-Path $backupPath) {
            Move-Item -Path $backupPath -Destination $clientPath -Force
            Write-ColorOutput "[!] Update failed, restored previous version" "Yellow"
        }
    }
    
    Write-Host ""
    
    if ($IsElevated) {
        Write-Host "Press Enter to exit..." -NoNewline
        Read-Host
    }
}

try {
    switch ($Action.ToLower()) {
        'install' { Install-Client }
        'uninstall' { Uninstall-Client }
        'update' { Update-Client }
        default { Install-Client }
    }
}
catch {
    Write-ColorOutput "[X] Critical error: $_" "Red"
    Write-Host $_.ScriptStackTrace
    Write-Host ""
    
    if ($IsElevated) {
        Write-Host "Press Enter to exit..." -NoNewline
        Read-Host
    }
    
    exit 1
}
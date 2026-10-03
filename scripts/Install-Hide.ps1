<#
.SYNOPSIS
    Installs and registers Hide CLI integration for Windows & PowerShell.
.DESCRIPTION
    Configures user PATH, PowerShell profile aliases, and File Explorer context integration.
#>

[CmdletBinding()]
param (
    [switch]$AddContextMenu
)

$ErrorActionPreference = "Stop"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "    HIDE — Windows Shell Integration Setup   " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Determine executable directory
$InstallDir = Split-Path -Parent $PSScriptRoot
$HideExe = Join-Path $InstallDir "dist\hide.exe"

# If standalone exe doesn't exist yet, look for python script or current python venv
if (-not (Test-Path $HideExe)) {
    $HideCommand = Get-Command "hide" -ErrorAction SilentlyContinue
    if ($HideCommand) {
        $BinPath = Split-Path -Parent $HideCommand.Source
        Write-Host "[✔] Detected active hide binary in PATH: $BinPath" -ForegroundColor Green
    } else {
        $BinPath = $InstallDir
        Write-Host "[!] Note: Standalone hide.exe not found yet in dist\. Using current installation path." -ForegroundColor Yellow
    }
} else {
    $BinPath = Split-Path -Parent $HideExe
    Write-Host "[✔] Found standalone binary at: $HideExe" -ForegroundColor Green
}

# 2. Add to User PATH if not present
$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
$PathEntries = $UserPath -split ";" | Where-Object { $_ -ne "" }

if ($PathEntries -notcontains $BinPath) {
    Write-Host "[*] Adding $BinPath to User PATH environment variable..." -ForegroundColor Yellow
    $NewPath = "$UserPath;$BinPath"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, [EnvironmentVariableTarget]::User)
    $env:Path = "$env:Path;$BinPath"
    Write-Host "[✔] User PATH updated successfully." -ForegroundColor Green
} else {
    Write-Host "[✔] $BinPath is already in User PATH." -ForegroundColor Green
}

# 3. Configure PowerShell Profile Aliases
$ProfilePath = $PROFILE
if (-not (Test-Path $ProfilePath)) {
    $ProfileDir = Split-Path -Parent $ProfilePath
    if (-not (Test-Path $ProfileDir)) {
        New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
    }
    New-Item -ItemType File -Path $ProfilePath -Force | Out-Null
}

$ProfileContent = Get-Content $ProfilePath -Raw -ErrorAction SilentlyContinue
if (-not $ProfileContent) { $ProfileContent = "" }

$HideProfileBlock = @"

# >>> HIDE CLI INTEGRATION >>>
function hopen { hide open @args }
function hclose { hide close @args }
function hlist { hide list @args }
function hstatus { hide status @args }
function hpanic { hide panic @args }
# <<< HIDE CLI INTEGRATION <<<
"@

if ($ProfileContent -notmatch "# >>> HIDE CLI INTEGRATION >>>") {
    Write-Host "[*] Registering convenient PowerShell aliases (hopen, hclose, hlist, hpanic)..." -ForegroundColor Yellow
    Add-Content -Path $ProfilePath -Value $HideProfileBlock
    Write-Host "[✔] PowerShell profile updated ($ProfilePath)." -ForegroundColor Green
} else {
    Write-Host "[✔] PowerShell profile already contains Hide aliases." -ForegroundColor Green
}

# 4. Optional Context Menu Integration
if ($AddContextMenu) {
    Write-Host "[*] Adding Windows Explorer context menu 'Open with Hide'..." -ForegroundColor Yellow
    $RegPath = "HKCU:\Software\Classes\Directory\shell\HideVault"
    New-Item -Path $RegPath -Force | Out-Null
    Set-ItemProperty -Path $RegPath -Name "(Default)" -Value "Open with Hide Vault"
    Set-ItemProperty -Path $RegPath -Name "Icon" -Value "imageres.dll,26" # Key/Lock icon

    $CommandReg = "$RegPath\command"
    New-Item -Path $CommandReg -Force | Out-Null
    Set-ItemProperty -Path $CommandReg -Name "(Default)" -Value "powershell.exe -NoExit -Command `"cd '%1'; hide .`""
    Write-Host "[✔] Context menu registered for folders." -ForegroundColor Green
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host " [✔] Hide Windows Shell Setup Completed!     " -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "You can now run 'hide' or aliases directly from any PowerShell or Command Prompt."

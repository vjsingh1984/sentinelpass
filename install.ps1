# SentinelPass one-stop installer for Windows (user-level)

param(
    [Parameter(Mandatory=$false)]
    [string]$ExtensionId = "",

    [Parameter(Mandatory=$false)]
    [string]$BinaryDir = "",

    [Parameter(Mandatory=$false)]
    [switch]$SkipBuild,

    [Parameter(Mandatory=$false)]
    [switch]$RegisterFirefox
)

$ErrorActionPreference = "Stop"

$installDir = Join-Path $env:LOCALAPPDATA "SentinelPass"
$installScript = Join-Path $PSScriptRoot "installation\install.ps1"
$registerChromeScript = Join-Path $PSScriptRoot "register-chrome.ps1"
$registerFirefoxScript = Join-Path $PSScriptRoot "register-firefox.ps1"

Write-Host "=== SentinelPass One-Stop Installer (Windows, user-level) ===" -ForegroundColor Cyan
Write-Host "Install directory: $installDir" -ForegroundColor Cyan

if (-not $SkipBuild) {
    Write-Host "`n[1/3] Building release binaries..." -ForegroundColor Yellow
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed. Aborting install." -ForegroundColor Red
        exit 1
    }
    Write-Host "Build complete" -ForegroundColor Green
} else {
    Write-Host "`n[1/3] Skipping build as requested" -ForegroundColor Yellow
}

if (!(Test-Path $installScript)) {
    Write-Host "Install script not found: $installScript" -ForegroundColor Red
    exit 1
}

Write-Host "`n[2/3] Installing user-level binaries + native host manifest..." -ForegroundColor Yellow
if (-not [string]::IsNullOrWhiteSpace($BinaryDir)) {
    & $installScript -ExtensionId $ExtensionId -BinaryDir $BinaryDir
} else {
    & $installScript -ExtensionId $ExtensionId
}
if (-not $?) {
    Write-Host "Installation step failed." -ForegroundColor Red
    exit 1
}

if ($RegisterFirefox) {
    Write-Host "`n[3/3] Registering Firefox native host..." -ForegroundColor Yellow
    if (Test-Path $registerFirefoxScript) {
        & $registerFirefoxScript
        if (-not $?) {
            Write-Host "Firefox registration failed." -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "Firefox registration script not found: $registerFirefoxScript" -ForegroundColor Yellow
    }
} else {
    Write-Host "`n[3/3] Firefox registration skipped" -ForegroundColor Yellow
}

Write-Host "`nInstallation completed." -ForegroundColor Green
Write-Host "Installed to: $installDir" -ForegroundColor Green

if ($ExtensionId -notmatch '^[a-z]{32}$') {
    Write-Host "`nChrome finalization:" -ForegroundColor Yellow
    Write-Host "1. Load extension from: $PSScriptRoot\browser-extension\chrome" -ForegroundColor White
    Write-Host "2. Copy extension ID from chrome://extensions" -ForegroundColor White
    Write-Host "3. Run: .\register-chrome.ps1 -ExtensionId <ID> -InstallDir '$installDir'" -ForegroundColor White
} else {
    Write-Host "Chrome host manifest already configured for extension ID: $ExtensionId" -ForegroundColor Green
}

if (Test-Path $registerChromeScript) {
    Write-Host "Tip: Use -ExtensionId to fully automate Chrome registration in one run." -ForegroundColor Cyan
}

Write-Host "Start daemon: $installDir\sentinelpass-daemon.exe" -ForegroundColor Cyan
Write-Host "Open UI: $installDir\sentinelpass-ui.exe" -ForegroundColor Cyan

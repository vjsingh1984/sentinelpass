# Register Chrome Extension with Native Messaging Host
# Usage: .\register-chrome.ps1 -ExtensionId <id> [-InstallDir "$env:LOCALAPPDATA\SentinelPass"]

param(
    [Parameter(Mandatory=$true)]
    [string]$ExtensionId,

    [Parameter(Mandatory=$false)]
    [string]$InstallDir = "$env:LOCALAPPDATA\SentinelPass"
)

# Validate extension ID format
if ($ExtensionId -notmatch '^[a-z]{32}$') {
    Write-Host "Invalid extension ID format!" -ForegroundColor Red
    Write-Host "Extension ID should be 32 lowercase letters (a-z)" -ForegroundColor Red
    Write-Host "Example: abcdefghijklmnopqrstuvwxyzabcdef" -ForegroundColor Yellow
    exit 1
}

$hostJson = "$InstallDir\com.passwordmanager.host.json"
$chromeRegistryPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.passwordmanager.host"
$hostExePath = "$InstallDir\sentinelpass-host.exe"

if (!(Test-Path $hostExePath)) {
    Write-Host "Host executable not found at: $hostExePath" -ForegroundColor Red
    Write-Host "Build and install SentinelPass first, or pass the correct -InstallDir." -ForegroundColor Yellow
    exit 1
}

Write-Host "Registering Chrome extension: $ExtensionId" -ForegroundColor Cyan
Write-Host "Install directory: $InstallDir" -ForegroundColor Cyan

# Create the host manifest
$hostManifest = @{
    name = "com.passwordmanager.host"
    description = "SentinelPass Native Messaging Host"
    path = $hostExePath
    type = "stdio"
    allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json -Depth 10

# Save to install directory
$hostManifest | Out-File -FilePath $hostJson -Encoding UTF8
Write-Host "Created: $hostJson" -ForegroundColor Green

# Register with Chrome
New-Item -Path $chromeRegistryPath -Force | Out-Null
Set-ItemProperty -Path $chromeRegistryPath -Name "(default)" -Value $hostJson
Write-Host "Registered with Chrome registry" -ForegroundColor Green

Write-Host "`nChrome extension registered!" -ForegroundColor Green
Write-Host "Allowed origin: chrome-extension://$ExtensionId/" -ForegroundColor Green
Write-Host "Please restart Chrome for changes to take effect."

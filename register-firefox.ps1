# Register Firefox Native Messaging Host
# Firefox doesn't need extension ID - uses the manifest ID

$installDir = Join-Path $env:LOCALAPPDATA "SentinelPass"
$hostJson = "$installDir\com.passwordmanager.host.firefox.json"
$ffRegistryPath = "HKCU:\Software\Mozilla\NativeMessagingHosts\com.passwordmanager.host"

Write-Host "Registering Firefox native messaging host" -ForegroundColor Cyan

# The manifest should already exist from install.ps1
if (!(Test-Path $hostJson)) {
    Write-Host "Firefox manifest not found! Please run install.ps1 first." -ForegroundColor Red
    exit 1
}

# Register with Firefox
New-Item -Path $ffRegistryPath -Force | Out-Null
Set-ItemProperty -Path $ffRegistryPath -Name "(default)" -Value $hostJson
Write-Host "Registered with Firefox registry" -ForegroundColor Green

Write-Host "`nFirefox extension registered!" -ForegroundColor Green
Write-Host "Please restart Firefox for changes to take effect."

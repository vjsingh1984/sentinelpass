# Update Native Messaging Host with Extension ID
# Usage: .\update-extension-id.ps1 -ExtensionId <id> [-InstallDir "$env:LOCALAPPDATA\SentinelPass"]

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

& "$PSScriptRoot\register-chrome.ps1" -ExtensionId $ExtensionId -InstallDir $InstallDir
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "`nSetup complete!" -ForegroundColor Green
Write-Host "Please restart Chrome for changes to take effect."

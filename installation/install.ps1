# Password Manager Installation Script for Windows

# Requires Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You need Administrator privileges to run this script"
    Write-Warning "Please run PowerShell as Administrator and try again"
    exit 1
}

$ErrorActionPreference = "Stop"

# Configuration
$InstallDir = "C:\Program Files\SentinelPass"
$NativeHostFileName = "com.passwordmanager.host.json"
$RegistryPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.passwordmanager.host"

Write-Host "Installing SentinelPass..." -ForegroundColor Green

# Create installation directory
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force
    Write-Host "Created installation directory: $InstallDir" -ForegroundColor Cyan
}

# Copy binaries
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BinaryDir = Join-Path $ProjectRoot "target\release"

if (!(Test-Path $BinaryDir)) {
    Write-Error "Binary directory not found. Please run 'cargo build --release' first."
    exit 1
}

Copy-Item (Join-Path $BinaryDir "sentinelpass-host.exe") -Destination $InstallDir -Force
Copy-Item (Join-Path $BinaryDir "sentinelpass-daemon.exe") -Destination $InstallDir -Force
Copy-Item (Join-Path $BinaryDir "sentinelpass.exe") -Destination $InstallDir -Force

Write-Host "Copied binaries to $InstallDir" -ForegroundColor Cyan

# Generate native messaging host manifest with correct path
$ManifestDest = Join-Path $InstallDir $NativeHostFileName
$BinaryPath = Join-Path $InstallDir "sentinelpass-host.exe"

$ManifestContent = @{
    name = "com.passwordmanager.host"
    description = "SentinelPass Native Messaging Host"
    path = $BinaryPath
    type = "stdio"
    allowed_origins = @("chrome-extension://*/")
}

$ManifestContent | ConvertTo-Json -Depth 10 | Out-File -FilePath $ManifestDest -Encoding UTF8

Write-Host "Created manifest: $ManifestDest" -ForegroundColor Cyan

# Read and update manifest with actual extension ID
Write-Host "`nIMPORTANT: You need to update the extension ID in the manifest." -ForegroundColor Yellow
Write-Host "1. Load the unpacked extension in Chrome from: browser-extension\chrome" -ForegroundColor Yellow
Write-Host "2. Get the extension ID from chrome://extensions/" -ForegroundColor Yellow
Write-Host "3. Update the 'allowed_origins' in: $ManifestDest" -ForegroundColor Yellow

# Create registry key for native messaging host
if (!(Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force
    Write-Host "Created registry key: $RegistryPath" -ForegroundColor Cyan
}

Set-ItemProperty -Path $RegistryPath -Name "(default)" -Value $ManifestDest
Write-Host "Registered native messaging host" -ForegroundColor Cyan

# Add to PATH for convenience
$PathEnv = [Environment]::GetEnvironmentVariable("Path", "User")
if ($PathEnv -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", $PathEnv + ";$InstallDir", "User")
    Write-Host "Added $InstallDir to user PATH" -ForegroundColor Cyan
    Write-Warning "You may need to restart your terminal for PATH changes to take effect"
}

Write-Host "`nInstallation completed successfully!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Load the browser extension from browser-extension\chrome" -ForegroundColor White
Write-Host "2. Run 'sentinelpass init' to create a new vault" -ForegroundColor White
Write-Host "3. Start the daemon: sentinelpass-daemon" -ForegroundColor White
Write-Host "4. Use the browser extension to autofill passwords" -ForegroundColor White

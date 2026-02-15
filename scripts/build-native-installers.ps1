param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$TauriArgs
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

function Invoke-Step($Message) {
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

Invoke-Step "Checking cargo"
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo not found in PATH"
}

Invoke-Step "Checking cargo tauri"
$tauriAvailable = $true
try {
    cargo tauri --help | Out-Null
} catch {
    $tauriAvailable = $false
}

if (-not $tauriAvailable) {
    Write-Host "Installing tauri-cli (cargo-tauri)..." -ForegroundColor Yellow
    cargo install tauri-cli --version '^2.0.0' --locked
}

Invoke-Step "Building runtime binaries (daemon + host)"
cargo build --release --locked --bin sentinelpass-daemon --bin sentinelpass-host

Invoke-Step "Preparing bundled runtime resources"
New-Item -ItemType Directory -Force -Path sentinelpass-ui/src-tauri/resources/bin | Out-Null
Copy-Item target/release/sentinelpass-daemon.exe sentinelpass-ui/src-tauri/resources/bin/ -Force
Copy-Item target/release/sentinelpass-host.exe sentinelpass-ui/src-tauri/resources/bin/ -Force

Invoke-Step "Building native installers via Tauri"
$tauriCmd = @("tauri", "build", "--manifest-path", "sentinelpass-ui/Cargo.toml", "--ci")
if ($TauriArgs) {
    $tauriCmd += $TauriArgs
}
& cargo @tauriCmd

Invoke-Step "Native installer artifacts"
Get-ChildItem sentinelpass-ui/src-tauri/target/release/bundle -Recurse -File |
    Where-Object {
        $_.Extension -in '.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm' -or $_.Name -like '*.AppImage'
    } |
    Select-Object -ExpandProperty FullName

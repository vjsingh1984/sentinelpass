# Install SentinelPass Daemon as Windows Startup Service
# This will create a scheduled task that runs the daemon on user login

$installDir = Join-Path $env:LOCALAPPDATA "SentinelPass"
$daemonExe = "$installDir\sentinelpass-daemon.exe"
$taskName = "SentinelPassDaemon"

Write-Host "=== SentinelPass Daemon Service Setup ===" -ForegroundColor Cyan

# Check if daemon exists
if (!(Test-Path $daemonExe)) {
    Write-Host "ERROR: Daemon not found at $daemonExe" -ForegroundColor Red
    Write-Host "Please run install.ps1 first" -ForegroundColor Yellow
    exit 1
}

# Delete existing task if it exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "Removing existing scheduled task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

# Create trigger to run on user logon
$trigger = New-ScheduledTaskTrigger -AtLogon

# Create action to run the daemon in locked mode (non-interactive)
$action = New-ScheduledTaskAction -Execute $daemonExe -Argument "--start-locked" -WorkingDirectory $installDir

# Create principal (run as current user, no elevation required)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

# Create settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# Register the scheduled task
Write-Host "Creating scheduled task..." -ForegroundColor Yellow
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "SentinelPass Daemon for browser integration"

Write-Host "Scheduled task created successfully!" -ForegroundColor Green

# Verify
$task = Get-ScheduledTask -TaskName $taskName
Write-Host "`nTask Details:" -ForegroundColor Cyan
Write-Host "  Name: $($task.TaskName)"
Write-Host "  State: $($task.State)"
Write-Host "  Trigger: At Logon"

Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
Write-Host "  1. The daemon starts locked (no console password prompt)." -ForegroundColor White
Write-Host "  2. Unlock from SentinelPass UI to enable browser autofill/save." -ForegroundColor White
Write-Host "  3. Auto-lock still applies after inactivity." -ForegroundColor White
Write-Host ""
Write-Host "To test the scheduled task:" -ForegroundColor Cyan
Write-Host "  Start-ScheduledTask -TaskName '$taskName'"
Write-Host ""
Write-Host "To stop the daemon from auto-starting:" -ForegroundColor Cyan
Write-Host "  Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"

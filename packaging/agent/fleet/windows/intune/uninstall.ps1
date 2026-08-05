# Intune Win32 uninstall command (elevated).
$ErrorActionPreference = "Continue"
$Prefix = "C:\Program Files\BSDM Agent"
$agent = Join-Path $Prefix "bin\bsdm-agent.exe"
if (Test-Path $agent) {
    try { & $agent --clear-system-proxy } catch {}
}
Unregister-ScheduledTask -TaskName "BSDM-Agent" -Confirm:$false -ErrorAction SilentlyContinue
if (Test-Path $Prefix) {
    Remove-Item -Recurse -Force $Prefix -ErrorAction SilentlyContinue
}
exit 0

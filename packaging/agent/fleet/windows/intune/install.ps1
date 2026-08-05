# Intune Win32 install command (elevated). Package layout after IntuneWinAppUtil:
#   bsdm-agent.exe
#   install.ps1  (this file)
#   agent.env.example (optional)
#
# Set Intune app secrets via script parameters or company portal variables:
#   CONTROL_PLANE_URL, CONTROL_API_TOKEN, AGENT_ENROLL_TOKEN
param(
    [string]$ControlPlaneUrl = $env:CONTROL_PLANE_URL,
    [string]$ControlToken = $env:CONTROL_API_TOKEN,
    [string]$EnrollToken = $env:AGENT_ENROLL_TOKEN
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$bin = Join-Path $here "bsdm-agent.exe"
if (-not (Test-Path $bin)) {
    Write-Error "bsdm-agent.exe not found next to install.ps1"
}

# Prefer full installer from source tree if present (dev); else minimal copy.
$repoInstaller = Join-Path $here "..\..\..\install-windows.ps1"
if (Test-Path $repoInstaller) {
    & $repoInstaller -Silent -BinSrc $bin `
        -ControlPlaneUrl $ControlPlaneUrl `
        -ControlToken $ControlToken `
        -EnrollToken $EnrollToken `
        -DeviceId $env:COMPUTERNAME `
        -SetSystemProxy
    exit $LASTEXITCODE
}

# Minimal standalone install (Intune package without repo tree)
$Prefix = "C:\Program Files\BSDM Agent"
New-Item -ItemType Directory -Force -Path (Join-Path $Prefix "bin") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Prefix "etc") | Out-Null
Copy-Item -Force $bin (Join-Path $Prefix "bin\bsdm-agent.exe")
$envDest = Join-Path $Prefix "etc\agent.env"
@(
    "CONTROL_PLANE_URL=$ControlPlaneUrl"
    "CONTROL_API_TOKEN=$ControlToken"
    "AGENT_ENROLL_TOKEN=$EnrollToken"
    "DEVICE_ID=$env:COMPUTERNAME"
    "DEVICE_NAME=$env:COMPUTERNAME"
    "SYSTEM_PROXY_HOST=127.0.0.1"
    "SYSTEM_PROXY_PORT=3128"
) | Set-Content -Path $envDest -Encoding UTF8

$action = New-ScheduledTaskAction -Execute (Join-Path $Prefix "bin\bsdm-agent.exe") -WorkingDirectory (Join-Path $Prefix "bin")
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "BUILTIN\Users" -LogonType Group -RunLevel Highest
Register-ScheduledTask -TaskName "BSDM-Agent" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

$agent = Join-Path $Prefix "bin\bsdm-agent.exe"
Get-Content $envDest | ForEach-Object {
    if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}
& $agent --set-system-proxy
exit 0

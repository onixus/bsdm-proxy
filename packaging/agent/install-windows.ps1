# Install BSDM Local Policy Agent on Windows (pilot / lab / fleet silent).
# Run elevated PowerShell:
#   .\packaging\agent\install-windows.ps1
#   .\packaging\agent\install-windows.ps1 -SetSystemProxy
#   .\packaging\agent\install-windows.ps1 -ClearSystemProxy
# Fleet (Intune / GPO script):
#   .\packaging\agent\install-windows.ps1 -Silent `
#     -ControlPlaneUrl "https://control.example:9090" `
#     -ControlToken $env:CONTROL_API_TOKEN `
#     -EnrollToken $env:AGENT_ENROLL_TOKEN `
#     -DeviceId $env:COMPUTERNAME `
#     -SetSystemProxy
param(
    [string]$Prefix = "C:\Program Files\BSDM Agent",
    [string]$BinSrc = "",
    [switch]$SetSystemProxy,
    [switch]$ClearSystemProxy,
    [switch]$SkipTask,
    [switch]$Silent,
    [string]$ControlPlaneUrl = "",
    [string]$ControlToken = "",
    [string]$EnrollToken = "",
    [string]$DeviceId = "",
    [string]$DeviceName = "",
    [string]$SystemProxyHost = "",
    [string]$SystemProxyPort = ""
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run elevated (Administrator) PowerShell."
}

if ($Silent -and -not $ControlPlaneUrl -and -not $env:CONTROL_PLANE_URL) {
    Write-Error "-Silent requires -ControlPlaneUrl or CONTROL_PLANE_URL env."
}

if (-not $BinSrc) {
    $candidate = Join-Path $Root "target\release\agent-spike.exe"
    if (Test-Path $candidate) {
        $BinSrc = $candidate
    } else {
        if ($Silent) {
            Write-Error "Binary not found at $candidate. Build or pass -BinSrc for silent fleet install."
        }
        Write-Host "Building agent-spike (release)..."
        Push-Location $Root
        cargo build -p agent-spike --release
        Pop-Location
        $BinSrc = $candidate
    }
}

New-Item -ItemType Directory -Force -Path (Join-Path $Prefix "bin") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Prefix "etc") | Out-Null
Copy-Item -Force $BinSrc (Join-Path $Prefix "bin\bsdm-agent.exe")
$envExample = Join-Path $Root "packaging\agent\agent.env.example"
$envDest = Join-Path $Prefix "etc\agent.env"
if (-not (Test-Path $envDest)) {
    Copy-Item $envExample $envDest
    if (-not $Silent) {
        Write-Host "Wrote $envDest — edit CONTROL_PLANE_URL / tokens"
    }
}

function Set-AgentEnvKey {
    param([string]$Path, [string]$Key, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $lines = @()
    if (Test-Path $Path) {
        $lines = Get-Content $Path | Where-Object { $_ -notmatch "^\s*$Key=" }
    }
    $lines += "$Key=$Value"
    Set-Content -Path $Path -Value $lines -Encoding UTF8
}

$cp = if ($ControlPlaneUrl) { $ControlPlaneUrl } else { $env:CONTROL_PLANE_URL }
$ct = if ($ControlToken) { $ControlToken } else { $env:CONTROL_API_TOKEN }
$et = if ($EnrollToken) { $EnrollToken } else { $env:AGENT_ENROLL_TOKEN }
$did = if ($DeviceId) { $DeviceId } else { $env:DEVICE_ID }
if (-not $did) { $did = $env:COMPUTERNAME }
$dname = if ($DeviceName) { $DeviceName } else { $did }
$sph = if ($SystemProxyHost) { $SystemProxyHost } else { $env:SYSTEM_PROXY_HOST }
$spp = if ($SystemProxyPort) { $SystemProxyPort } else { $env:SYSTEM_PROXY_PORT }

Set-AgentEnvKey -Path $envDest -Key "CONTROL_PLANE_URL" -Value $cp
Set-AgentEnvKey -Path $envDest -Key "CONTROL_API_TOKEN" -Value $ct
Set-AgentEnvKey -Path $envDest -Key "AGENT_ENROLL_TOKEN" -Value $et
Set-AgentEnvKey -Path $envDest -Key "DEVICE_ID" -Value $did
Set-AgentEnvKey -Path $envDest -Key "DEVICE_NAME" -Value $dname
Set-AgentEnvKey -Path $envDest -Key "SYSTEM_PROXY_HOST" -Value $sph
Set-AgentEnvKey -Path $envDest -Key "SYSTEM_PROXY_PORT" -Value $spp

# Scheduled task at logon (user-visible pilot path). Machine fleet: use SYSTEM via Intune script.
if (-not $SkipTask) {
    $action = New-ScheduledTaskAction `
        -Execute (Join-Path $Prefix "bin\bsdm-agent.exe") `
        -WorkingDirectory (Join-Path $Prefix "bin")
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName "BSDM-Agent" -Action $action -Trigger $trigger `
        -Principal $principal -Force | Out-Null
    if (-not $Silent) {
        Write-Host "Scheduled task 'BSDM-Agent' registered (AtLogOn)."
    }
}

$agent = Join-Path $Prefix "bin\bsdm-agent.exe"
if ($SetSystemProxy) {
    # Load simple KEY=VAL from agent.env into process env
    Get-Content $envDest | ForEach-Object {
        if ($_ -match '^\s*#') { return }
        if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2].Trim('"'), "Process")
        }
    }
    & $agent --set-system-proxy
    if ($LASTEXITCODE -ne 0 -and $Silent) {
        Write-Error "set-system-proxy failed with exit $LASTEXITCODE"
    }
}
if ($ClearSystemProxy) {
    & $agent --clear-system-proxy
}

if (-not $Silent) {
    Write-Host "Installed bsdm-agent → $Prefix\bin\bsdm-agent.exe"
    Write-Host "Config → $envDest"
    Write-Host "System proxy: bsdm-agent.exe --set-system-proxy | --clear-system-proxy"
}

exit 0

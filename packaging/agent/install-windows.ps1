# Install BSDM Local Policy Agent on Windows (pilot / lab).
# Run elevated PowerShell:
#   .\packaging\agent\install-windows.ps1
#   .\packaging\agent\install-windows.ps1 -SetSystemProxy
#   .\packaging\agent\install-windows.ps1 -ClearSystemProxy
param(
    [string]$Prefix = "C:\Program Files\BSDM Agent",
    [string]$BinSrc = "",
    [switch]$SetSystemProxy,
    [switch]$ClearSystemProxy,
    [switch]$SkipTask
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run elevated (Administrator) PowerShell."
}

if (-not $BinSrc) {
    $candidate = Join-Path $Root "target\release\agent-spike.exe"
    if (Test-Path $candidate) {
        $BinSrc = $candidate
    } else {
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
    Write-Host "Wrote $envDest — edit CONTROL_PLANE_URL / tokens"
}

# Scheduled task at logon (user-visible pilot path).
if (-not $SkipTask) {
    $action = New-ScheduledTaskAction `
        -Execute (Join-Path $Prefix "bin\bsdm-agent.exe") `
        -WorkingDirectory (Join-Path $Prefix "bin")
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName "BSDM-Agent" -Action $action -Trigger $trigger `
        -Principal $principal -Force | Out-Null
    Write-Host "Scheduled task 'BSDM-Agent' registered (AtLogOn)."
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
}
if ($ClearSystemProxy) {
    & $agent --clear-system-proxy
}

Write-Host "Installed bsdm-agent → $Prefix\bin\bsdm-agent.exe"
Write-Host "Config → $envDest"
Write-Host "System proxy: bsdm-agent.exe --set-system-proxy | --clear-system-proxy"

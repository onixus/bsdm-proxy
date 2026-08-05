# GPO startup script: map HKLM\SOFTWARE\Policies\BSDM\Agent → agent.env
# Deploy after binary install (Intune or GPO software install).
$ErrorActionPreference = "Stop"
$regPath = "HKLM:\SOFTWARE\Policies\BSDM\Agent"
$envDest = "C:\Program Files\BSDM Agent\etc\agent.env"
if (-not (Test-Path $regPath)) { exit 0 }
if (-not (Test-Path (Split-Path $envDest))) {
    Write-Error "Agent not installed under Program Files\BSDM Agent"
}

function Upsert([string]$Key, [string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $lines = @()
    if (Test-Path $envDest) {
        $lines = Get-Content $envDest | Where-Object { $_ -notmatch "^\s*$Key=" }
    }
    $lines += "$Key=$Value"
    Set-Content -Path $envDest -Value $lines -Encoding UTF8
}

$props = Get-ItemProperty -Path $regPath
if ($props.ControlPlaneUrl) { Upsert "CONTROL_PLANE_URL" $props.ControlPlaneUrl }
if ($props.SystemProxyHost) { Upsert "SYSTEM_PROXY_HOST" $props.SystemProxyHost }
if ($props.SystemProxyPort) { Upsert "SYSTEM_PROXY_PORT" "$($props.SystemProxyPort)" }
if ($props.EnrollTokenPath -and (Test-Path $props.EnrollTokenPath)) {
    $tok = (Get-Content -Raw $props.EnrollTokenPath).Trim()
    Upsert "AGENT_ENROLL_TOKEN" $tok
}
if ($props.ManageSystemProxy -eq 1) {
    Upsert "AGENT_MANAGE_SYSTEM_PROXY" "1"
    $agent = "C:\Program Files\BSDM Agent\bin\bsdm-agent.exe"
    if (Test-Path $agent) {
        Get-Content $envDest | ForEach-Object {
            if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
                [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
            }
        }
        & $agent --set-system-proxy
    }
}
exit 0

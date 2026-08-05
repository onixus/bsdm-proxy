# Intune Win32 detection rule (run as detection script).
# Exit 0 + stdout "Detected" = installed; non-zero = not installed.
$ErrorActionPreference = "Stop"
$exe = "C:\Program Files\BSDM Agent\bin\bsdm-agent.exe"
$envf = "C:\Program Files\BSDM Agent\etc\agent.env"
if (-not (Test-Path $exe)) { exit 1 }
if (-not (Test-Path $envf)) { exit 1 }
$hasUrl = Select-String -Path $envf -Pattern "^\s*CONTROL_PLANE_URL=.+" -Quiet
if (-not $hasUrl) { exit 1 }
Write-Output "Detected"
exit 0

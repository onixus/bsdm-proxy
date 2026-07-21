# BSDM-Proxy Setup & Run Script for Windows
# This script generates CA certificates using Git for Windows OpenSSL (if available)
# and starts the proxy locally.

$ErrorActionPreference = "Stop"

$CertsDir = Join-Path $PSScriptRoot "certs"
$CaKey = Join-Path $CertsDir "ca.key"
$CaCrt = Join-Path $CertsDir "ca.crt"

Write-Host "BSDM-Proxy Windows Setup Tool" -ForegroundColor Cyan

# 1. Ensure certs directory exists
if (-not (Test-Path -Path $CertsDir)) {
    New-Item -ItemType Directory -Path $CertsDir | Out-Null
    Write-Host "Created certs directory." -ForegroundColor Green
}

# 2. Generate certificates if missing
if (-not (Test-Path -Path $CaKey) -or -not (Test-Path -Path $CaCrt)) {
    Write-Host "Generating MITM CA keypair..." -ForegroundColor Yellow
    
    # Try to find openssl from Git for Windows
    $OpensslPath = "openssl.exe"
    $GitPath = Get-Command "git.exe" -ErrorAction SilentlyContinue
    if ($GitPath) {
        $GitBinDir = Split-Path $GitPath.Path
        $GitUsrBinOpenssl = Join-Path (Split-Path $GitBinDir) "usr\bin\openssl.exe"
        if (Test-Path $GitUsrBinOpenssl) {
            $OpensslPath = $GitUsrBinOpenssl
        }
    }

    try {
        & $OpensslPath req -x509 -newkey rsa:4096 -keyout "$CaKey" -out "$CaCrt" -days 3650 -nodes -subj "/CN=BSDM Proxy Root CA/O=BSDM Security"
        Write-Host "MITM Root CA generated successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to run OpenSSL. Please ensure OpenSSL is installed and in your PATH, or run './scripts/gen-ca.sh' in WSL/Git Bash." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "MITM CA certificates already exist." -ForegroundColor Green
}

# 3. Ask to run the proxy
$runProxy = Read-Host "Do you want to run the proxy now in Lite mode? (Y/n)"
if ($runProxy -eq "" -or $runProxy.ToLower() -eq "y" -or $runProxy.ToLower() -eq "yes") {
    Write-Host "Starting proxy..." -ForegroundColor Cyan
    
    $env:HTTP_PORT = "1488"
    $env:METRICS_PORT = "9090"
    $env:MITM_ENABLED = "true"
    
    cargo run -p bsdm-proxy --bin proxy --no-default-features --features auth-basic
}

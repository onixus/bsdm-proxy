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

    # Same CA profile as scripts/gen-ca.sh: 2-year lifetime, pathlen:0 so this
    # root cannot sign intermediates, and keyUsage limited to certificate/CRL
    # signing. Written through a temporary config instead of -addext, which
    # needs OpenSSL 1.1.1+ and is missing from the OpenSSL shipped with Git.
    $CaDays = if ($env:CA_DAYS) { $env:CA_DAYS } else { 730 }
    $CaExtConf = Join-Path ([System.IO.Path]::GetTempPath()) ("bsdm-ca-" + [guid]::NewGuid().ToString() + ".cnf")
    @"
[req]
distinguished_name = req_dn
x509_extensions    = v3_ca
prompt             = no

[req_dn]
CN = BSDM Proxy Root CA
O  = BSDM Security

[v3_ca]
basicConstraints     = critical,CA:TRUE,pathlen:0
keyUsage             = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
"@ | Set-Content -Path $CaExtConf -Encoding ascii

    try {
        & $OpensslPath req -x509 -newkey rsa:4096 -keyout "$CaKey" -out "$CaCrt" -days $CaDays -nodes -config "$CaExtConf"
        if ($LASTEXITCODE -ne 0) { throw "openssl exited with $LASTEXITCODE" }
        Write-Host "MITM Root CA generated successfully (valid $CaDays days)." -ForegroundColor Green
    } catch {
        Write-Host "Failed to run OpenSSL. Please ensure OpenSSL is installed and in your PATH, or run './scripts/gen-ca.sh' in WSL/Git Bash." -ForegroundColor Red
        exit 1
    } finally {
        Remove-Item -Path $CaExtConf -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "MITM CA certificates already exist." -ForegroundColor Green
}

# 3. Ask to run the proxy
$runProxy = Read-Host "Do you want to run the proxy now in Lite mode? (Y/n)"
if ($runProxy -eq "" -or $runProxy.ToLower() -eq "y" -or $runProxy.ToLower() -eq "yes") {
    Write-Host "Starting proxy..." -ForegroundColor Cyan
    
    $env:HTTP_PORT = "3128"
    $env:METRICS_PORT = "9090"
    $env:MITM_ENABLED = "true"
    
    cargo run -p bsdm-proxy --bin proxy --no-default-features --features auth-basic
}

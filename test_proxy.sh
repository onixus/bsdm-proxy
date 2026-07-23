#!/bin/bash

PROXY="http://127.0.0.1:1488"
CA_CERT="certs/ca.crt"

# 10 Normal Sites
NORMAL_SITES=(
    "google.com"
    "github.com"
    "apple.com"
    "microsoft.com"
    "amazon.com"
    "cloudflare.com"
    "ubuntu.com"
    "rust-lang.org"
    "ycombinator.com"
    "example.com"
)

# ACL specific sites (e.g., from acl-rules.test.json or standard categories)
ACL_SITES=(
    "blocked.test"      # Test domain explicitly blocked in acl-rules.test.json
    "eicar.org"         # Malware testing (might trigger malware category)
)

# RKN blocked sites (common examples)
RKN_SITES=(
    "rutracker.org"
    "nnmclub.to"
)

check_site() {
    local domain=$1
    local label=$2

    echo -n "Checking [$label] $domain ... "
    
    # We use -s for silent, -o /dev/null to discard body, -w "%{http_code}" for status code
    # We pass the CA cert in case MITM is enabled
    status_code=$(curl --cacert "$CA_CERT" -x "$PROXY" -s -o /dev/null -w "%{http_code}" -I --connect-timeout 5 "https://$domain")
    
    if [ "$status_code" = "000" ]; then
        # HTTP fallback
        status_code=$(curl -x "$PROXY" -s -o /dev/null -w "%{http_code}" -I --connect-timeout 5 "http://$domain")
    fi

    echo "HTTP $status_code"
}

echo "=== Normal Sites ==="
for site in "${NORMAL_SITES[@]}"; do
    check_site "$site" "Normal"
done

echo ""
echo "=== ACL Blocked Sites ==="
for site in "${ACL_SITES[@]}"; do
    check_site "$site" "ACL"
done

echo ""
echo "=== RKN Blocked Sites ==="
for site in "${RKN_SITES[@]}"; do
    check_site "$site" "RKN"
done

echo ""
echo "Done."

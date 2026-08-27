#!/usr/bin/env bash
# Zero-Compilation Release Binary Installer for BSDM-Proxy
# Downloads pre-compiled release tarballs from GitHub Releases and installs them.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/onixus/bsdm-proxy/main/scripts/install-binaries.sh | sudo bash
#   sudo ./scripts/install-binaries.sh [VERSION]
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPO="onixus/bsdm-proxy"
PREFIX="/opt/bsdm-proxy"
ETC_DIR="/etc/bsdm-proxy"
CERTS_DIR="${ETC_DIR}/certs"

banner() {
  echo -e "${CYAN}${BOLD}"
  echo '  ____   _____ _____  __  __   ____  ____   ______   ____   __'
  echo ' |  _ \ / ____|  __ \|  \/  | |  _ \|  _ \ / __ \ \ / /\ \ / /'
  echo ' | |_) | (___ | |  | | \  / | | |_) | |_) | |  | \ V /  \ V / '
  echo ' |  _ < \___ \| |  | | |\/| | |  __/|  _ <| |  | |> <    > <  '
  echo ' | |_) |____) | |__| | |  | | | |   | |_) | |__| / . \  / . \ '
  echo ' |____/|_____/|_____/|_|  |_| |_|   |____/ \____/_/ \_\/_/ \_\'
  echo -e "${NC}"
  echo -e "${BOLD}  Zero-Compilation Binary Release Installer${NC}\n"
}

check_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}${BOLD}Error: Installer must be run as root (sudo ./install-binaries.sh)${NC}" >&2
    exit 1
  fi
}

detect_system() {
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"

  case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)
      echo -e "${RED}Unsupported architecture: ${ARCH}${NC}" >&2
      exit 1
      ;;
  esac

  if [[ "$OS" != "linux" ]]; then
    echo -e "${RED}Native binary installation is supported on Linux only; detected ${OS}.${NC}" >&2
    exit 1
  fi

  echo -e "${GREEN}✓ Detected System:${NC} OS=${BOLD}${OS}${NC}, Arch=${BOLD}${ARCH}${NC}"
}

fetch_latest_version() {
  local version_arg="${1:-}"
  if [[ -n "$version_arg" ]]; then
    VERSION="${version_arg#v}"
    echo -e "${GREEN}✓ Target Version:${NC} v${VERSION}"
    return
  fi

  echo -e "${YELLOW}Fetching latest release info from GitHub (${REPO})...${NC}"
  local api_url="https://api.github.com/repos/${REPO}/releases/latest"
  local json tag
  json="$(curl -fsSL "$api_url" || true)"

  if [[ -n "$json" ]]; then
    tag="$(printf '%s\n' "$json" | grep '"tag_name":' | head -1 | sed -E 's/.*"([^"]+)".*/\1/' || true)"
    VERSION="${tag#v}"
  fi

  if [[ -z "${VERSION:-}" ]]; then
    echo -e "${RED}Could not determine the latest release. Pass an explicit version, for example: sudo ./scripts/install-binaries.sh 0.9.13${NC}" >&2
    exit 1
  fi

  echo -e "${GREEN}✓ Latest Release Found:${NC} v${VERSION}"
}

download_and_install() {
  local tmp_dir package_version package_name tarball_url checksum_url unpacked_dir
  tmp_dir="$(mktemp -d -t bsdm-install-XXXXXX)"
  trap 'rm -rf "$tmp_dir"' EXIT

  package_version="${VERSION//-b/b}"
  package_version="${package_version//-test/test}"
  package_version="${package_version//+/.}"
  package_name="bsdm-proxy-${package_version}-${OS}-${ARCH}"
  tarball_url="https://github.com/${REPO}/releases/download/v${VERSION}/${package_name}.tar.gz"
  checksum_url="${tarball_url}.sha256"

  echo -e "${YELLOW}Downloading pre-compiled release package:${NC} ${tarball_url}"
  curl -fsSL -o "${tmp_dir}/${package_name}.tar.gz" "$tarball_url" || {
    echo -e "${RED}Failed to download release tarball for v${VERSION} (${OS}-${ARCH}).${NC}" >&2
    exit 1
  }

  curl -fsSL -o "${tmp_dir}/${package_name}.tar.gz.sha256" "$checksum_url" || {
    echo -e "${RED}Failed to download release checksum for v${VERSION}.${NC}" >&2
    exit 1
  }

  (
    cd "$tmp_dir"
    sha256sum -c "${package_name}.tar.gz.sha256"
  )

  echo -e "${GREEN}✓ Download verified. Unpacking package...${NC}"
  tar -xzf "${tmp_dir}/${package_name}.tar.gz" -C "$tmp_dir"

  unpacked_dir="${tmp_dir}/${package_name}"
  [[ -x "${unpacked_dir}/install.sh" ]] || {
    echo -e "${RED}Release package is missing install.sh.${NC}" >&2
    exit 1
  }

  echo -e "${GREEN}✓ Installing pre-compiled binaries and configuration...${NC}"
  "${unpacked_dir}/install.sh" --prefix "$PREFIX" --etc "$ETC_DIR" --create-user --systemd

  # Installs that predate MITM_CA_DIR keep their CA in /certs; carry it over so
  # clients that already trust it keep working.
  if [[ ! -e "${CERTS_DIR}/ca.key" && -f /certs/ca.key && -f /certs/ca.crt ]]; then
    install -d -m 0750 "$CERTS_DIR"
    cp -p -- /certs/ca.key /certs/ca.crt "$CERTS_DIR"
    echo -e "${GREEN}✓ Migrated MITM CA from /certs to ${CERTS_DIR}${NC}"
  fi

  if [[ -e "${CERTS_DIR}/ca.key" || -e "${CERTS_DIR}/ca.crt" ]]; then
    if [[ ! -f "${CERTS_DIR}/ca.key" || ! -f "${CERTS_DIR}/ca.crt" ]]; then
      echo -e "${RED}Incomplete CA state in ${CERTS_DIR}; expected both ca.key and ca.crt or neither.${NC}" >&2
      exit 1
    fi
    echo -e "${GREEN}✓ Existing MITM CA preserved${NC}"
  else
    echo -e "${YELLOW}Generating MITM CA keypair in ${CERTS_DIR}...${NC}"
    install -d -m 0750 "$CERTS_DIR"
    openssl req -x509 -newkey rsa:4096 \
      -keyout "${CERTS_DIR}/ca.key" \
      -out "${CERTS_DIR}/ca.crt" \
      -days 3650 -nodes \
      -subj "/CN=BSDM Proxy Root CA/O=BSDM Security"
    chmod 0600 "${CERTS_DIR}/ca.key"
    chmod 0644 "${CERTS_DIR}/ca.crt"
    if id bsdm-proxy >/dev/null 2>&1; then
      chown bsdm-proxy:bsdm-proxy "${CERTS_DIR}/ca.key" "${CERTS_DIR}/ca.crt"
    fi
    echo -e "${GREEN}✓ MITM Root CA generated successfully${NC}"
  fi
}

main() {
  banner
  check_root
  command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
  command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }
  command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }
  detect_system
  fetch_latest_version "${1:-}"
  download_and_install

  echo -e "\n${GREEN}${BOLD}============================================================${NC}"
  echo -e "${GREEN}${BOLD}   BSDM-Proxy Installed Successfully (Zero-Compilation)!   ${NC}"
  echo -e "${GREEN}${BOLD}============================================================${NC}\n"
  echo -e "Start proxy service:"
  echo -e "  ${CYAN}sudo systemctl enable --now bsdm-proxy${NC}"
  echo -e "\nVerify installation:"
  echo -e "  ${CYAN}curl http://127.0.0.1:9090/health${NC}"
  echo -e "  ${CYAN}curl --cacert ${CERTS_DIR}/ca.crt -x http://127.0.0.1:3128 https://httpbin.org/get${NC}"
  echo ""
}

main "$@"

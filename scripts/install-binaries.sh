#!/usr/bin/env bash
# Zero-Compilation Release Binary Installer for BSDM-Proxy
# Downloads pre-compiled release tarballs from GitHub Releases and installs them.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/onixus/bsdm-proxy/main/scripts/install-binaries.sh | sudo bash
#   sudo ./scripts/install-binaries.sh [VERSION]
set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPO="onixus/bsdm-proxy"
PREFIX="/opt/bsdm-proxy"
ETC_DIR="/etc/bsdm-proxy"
CERTS_DIR="/certs"

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
    x86_64|amd64)
      ARCH="x86_64"
      ;;
    aarch64|arm64)
      ARCH="aarch64"
      ;;
    *)
      echo -e "${RED}Unsupported architecture: ${ARCH}${NC}" >&2
      exit 1
      ;;
  esac

  if [[ "$OS" != "linux" && "$OS" != "darwin" ]]; then
    echo -e "${RED}Unsupported operating system: ${OS}${NC}" >&2
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
  local json
  json="$(curl -fsSL "$api_url" || echo "")"

  if [[ -n "$json" ]]; then
    TAG="$(echo "$json" | grep '"tag_name":' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
    VERSION="${TAG#v}"
  fi

  if [[ -z "${VERSION:-}" ]]; then
    VERSION="0.6.0"
    echo -e "${YELLOW}Warning: Could not fetch latest release tag via GitHub API. Defaulting to v${VERSION}.${NC}"
  else
    echo -e "${GREEN}✓ Latest Release Found:${NC} v${VERSION}"
  fi
}

download_and_install() {
  TMP_DIR="$(mktemp -d -t bsdm-install-XXXXXX)"
  trap 'rm -rf "$TMP_DIR"' EXIT

  # Cargo version substitution rules: 0.5.7+033 → 0.5.7.033
  PACKAGE_VERSION="${VERSION//+/.}"
  PACKAGE_NAME="bsdm-proxy-${PACKAGE_VERSION}-${OS}-${ARCH}"
  TARBALL_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${PACKAGE_NAME}.tar.gz"

  echo -e "${YELLOW}Downloading pre-compiled release package:${NC} ${TARBALL_URL}"

  if ! curl -fsSL -o "${TMP_DIR}/${PACKAGE_NAME}.tar.gz" "${TARBALL_URL}"; then
    # Fallback attempt to download latest release asset pattern
    echo -e "${YELLOW}Retrying download with latest release artifact...${NC}"
    TARBALL_URL="https://github.com/${REPO}/releases/latest/download/${PACKAGE_NAME}.tar.gz"
    curl -fsSL -o "${TMP_DIR}/${PACKAGE_NAME}.tar.gz" "${TARBALL_URL}" || {
      echo -e "${RED}Failed to download release tarball for v${VERSION} (${OS}-${ARCH}).${NC}" >&2
      echo -e "${RED}URL: ${TARBALL_URL}${NC}" >&2
      exit 1
    }
  fi

  echo -e "${GREEN}✓ Download complete. Unpacking package...${NC}"
  tar -xzf "${TMP_DIR}/${PACKAGE_NAME}.tar.gz" -C "${TMP_DIR}"

  UNPACKED_DIR="${TMP_DIR}/${PACKAGE_NAME}"
  if [[ ! -d "$UNPACKED_DIR" ]]; then
    UNPACKED_DIR="$(find "${TMP_DIR}" -mindepth 1 -maxdepth 1 -type d | head -1)"
  fi

  echo -e "${GREEN}✓ Installing pre-compiled binaries and configuration...${NC}"
  chmod +x "${UNPACKED_DIR}/install.sh"
  "${UNPACKED_DIR}/install.sh" --prefix "${PREFIX}" --etc "${ETC_DIR}" --create-user --systemd

  # Generate CA certificates if missing
  if [[ ! -f "${CERTS_DIR}/ca.key" || ! -f "${CERTS_DIR}/ca.crt" ]]; then
    echo -e "${YELLOW}Generating MITM CA keypair in ${CERTS_DIR}...${NC}"
    mkdir -p "${CERTS_DIR}"
    openssl req -x509 -newkey rsa:4096 -keyout "${CERTS_DIR}/ca.key" -out "${CERTS_DIR}/ca.crt" \
      -days 3650 -nodes -subj "/CN=BSDM Proxy Root CA/O=BSDM Security" 2>/dev/null || true
    chmod 0600 "${CERTS_DIR}/ca.key"
    chmod 0644 "${CERTS_DIR}/ca.crt"
    if id bsdm-proxy &>/dev/null; then
      chown bsdm-proxy:bsdm-proxy "${CERTS_DIR}" "${CERTS_DIR}"/* 2>/dev/null || true
    fi
    echo -e "${GREEN}✓ MITM Root CA generated successfully${NC}"
  fi
}

main() {
  banner
  check_root
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
  echo -e "  ${CYAN}curl --cacert ${CERTS_DIR}/ca.crt -x http://127.0.0.1:1488 https://httpbin.org/get${NC}"
  echo ""
}

main "$@"

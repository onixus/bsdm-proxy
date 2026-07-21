#!/usr/bin/env bash
# Interactive Installer & Wizard for BSDM-Proxy
set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

PREFIX="/opt/bsdm-proxy"
ETC_DIR="/etc/bsdm-proxy"
CERTS_DIR="/certs"
HTTP_PORT="1488"
METRICS_PORT="9090"
GRPC_PORT="50051"
CREATE_USER=true
INSTALL_SYSTEMD=true
GENERATE_CA=true
ENABLE_GRPC=true
ENABLE_AI_CACHE=true
ENABLE_DNS_SINKHOLE=false
ENABLE_ICAP=false
INSTALL_MODE="full" # full, lite, docker

banner() {
  clear 2>/dev/null || true
  echo -e "${CYAN}${BOLD}"
  echo '  ____   _____ _____  __  __   ____  ____   ______   ____   __'
  echo ' |  _ \ / ____|  __ \|  \/  | |  _ \|  _ \ / __ \ \ / /\ \ / /'
  echo ' | |_) | (___ | |  | | \  / | | |_) | |_) | |  | \ V /  \ V / '
  echo ' |  _ < \___ \| |  | | |\/| | |  __/|  _ <| |  | |> <    > <  '
  echo ' | |_) |____) | |__| | |  | | | |   | |_) | |__| / . \  / . \ '
  echo ' |____/|_____/|_____/|_|  |_| |_|   |____/ \____/_/ \_\/_/ \_\'
  echo -e "${NC}"
  echo -e "${BOLD}  Interactive Installer & Deployment Wizard v0.5.0${NC}\n"
}

prompt_choice() {
  local prompt="$1"
  shift
  local options=("$@")
  local default="$1"

  echo -e "${YELLOW}${BOLD}${prompt}${NC}"
  for i in "${!options[@]}"; do
    echo -e "  ${CYAN}$((i+1)))${NC} ${options[$i]}"
  done

  read -r -p "Select option [1-${#options[@]}] (Default: 1): " choice
  choice=${choice:-1}

  if [[ "$choice" -ge 1 && "$choice" -le "${#options[@]}" ]]; then
    echo "${options[$((choice-1))]}"
  else
    echo "${options[0]}"
  fi
}

prompt_input() {
  local prompt="$1"
  local default="$2"
  local var_name="$3"

  read -r -p "$(echo -e "${YELLOW}${BOLD}${prompt}${NC} [${default}]: ")" input
  input=${input:-$default}
  eval "$var_name=\"$input\""
}

prompt_yn() {
  local prompt="$1"
  local default="$2" # true or false
  local hint="Y/n"
  if [[ "$default" == "false" ]]; then
    hint="y/N"
  fi

  read -r -p "$(echo -e "${YELLOW}${BOLD}${prompt}${NC} (${hint}): ")" resp
  resp=$(echo "${resp}" | tr '[:upper:]' '[:lower:]')

  if [[ -z "$resp" ]]; then
    eval "$3=$default"
  elif [[ "$resp" == "y" || "$resp" == "yes" ]]; then
    eval "$3=true"
  else
    eval "$3=false"
  fi
}

check_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}${BOLD}Error: Installer must be run as root (sudo ./install.sh)${NC}" >&2
    exit 1
  fi
}

main() {
  banner
  check_root

  echo -e "${GREEN}${BOLD}=== Step 1: Select Deployment Topology ===${NC}\n"
  
  echo "1) Full Standalone Production (Proxy + Control Plane + Systemd + Analytics)"
  echo "2) Lite Mode (Proxy + SQLite Search API — No Kafka/ClickHouse needed)"
  echo "3) Docker Compose Quickstart (Generate CA & start container stack)"
  echo "4) Custom Advanced Installation"
  echo ""
  read -r -p "Select Mode [1-4] (Default: 1): " mode_choice
  mode_choice=${mode_choice:-1}

  case "$mode_choice" in
    2)
      INSTALL_MODE="lite"
      ;;
    3)
      INSTALL_MODE="docker"
      ;;
    4)
      INSTALL_MODE="custom"
      ;;
    *)
      INSTALL_MODE="full"
      ;;
  esac

  if [[ "$INSTALL_MODE" == "docker" ]]; then
    echo -e "\n${GREEN}${BOLD}=== Docker Quickstart Selected ===${NC}"
    if [[ ! -f "./certs/ca.key" ]]; then
      echo -e "${YELLOW}Generating MITM CA certificates in ./certs...${NC}"
      ./scripts/gen-ca.sh 2>/dev/null || true
    fi
    echo -e "${GREEN}Starting Docker Compose stack...${NC}"
    docker compose up -d --build
    echo -e "\n${GREEN}${BOLD}BSDM Proxy stack running in Docker!${NC}"
    echo -e "Proxy: http://127.0.0.1:1488"
    echo -e "Health: http://127.0.0.1:9090/health"
    echo -e "Admin Console: http://127.0.0.1:3000 (via Grafana/UI)"
    exit 0
  fi

  echo -e "\n${GREEN}${BOLD}=== Step 2: System Configuration & Paths ===${NC}\n"
  prompt_input "Installation Prefix Directory" "/opt/bsdm-proxy" PREFIX
  prompt_input "Configuration Directory" "/etc/bsdm-proxy" ETC_DIR
  prompt_input "MITM CA Certificates Directory" "/certs" CERTS_DIR
  prompt_yn "Create system user 'bsdm-proxy'?" true CREATE_USER
  prompt_yn "Install and enable Systemd service units?" true INSTALL_SYSTEMD
  prompt_yn "Generate MITM CA keypair if missing?" true GENERATE_CA

  echo -e "\n${GREEN}${BOLD}=== Step 3: Network & Feature Configuration ===${NC}\n"
  prompt_input "HTTP Proxy Port" "1488" HTTP_PORT
  prompt_input "Metrics & REST Control Plane Port" "9090" METRICS_PORT
  prompt_yn "Enable gRPC Control Plane Mesh (bsdm.control.v1)?" true ENABLE_GRPC
  if $ENABLE_GRPC; then
    prompt_input "gRPC Mesh Listen Port" "50051" GRPC_PORT
  fi
  prompt_yn "Enable AI & LLM Semantic Cache (Qdrant/Local)?" true ENABLE_AI_CACHE
  prompt_yn "Enable DNS Sinkhole RPZ Sidecar?" false ENABLE_DNS_SINKHOLE
  prompt_yn "Enable ICAP Content Inspection (RFC 3507)?" false ENABLE_ICAP

  echo -e "\n${CYAN}${BOLD}=================== Installation Summary ===================${NC}"
  echo -e "  Installation Mode  : ${BOLD}${INSTALL_MODE}${NC}"
  echo -e "  Binary Path        : ${BOLD}${PREFIX}/bin${NC}"
  echo -e "  Config Directory   : ${BOLD}${ETC_DIR}${NC}"
  echo -e "  Certificates Dir   : ${BOLD}${CERTS_DIR}${NC}"
  echo -e "  System User        : ${BOLD}$([ "$CREATE_USER" = true ] && echo "bsdm-proxy" || echo "root")${NC}"
  echo -e "  HTTP Proxy Port    : ${BOLD}${HTTP_PORT}${NC}"
  echo -e "  Control Plane Port : ${BOLD}${METRICS_PORT}${NC}"
  echo -e "  gRPC Mesh          : ${BOLD}$([ "$ENABLE_GRPC" = true ] && echo "Enabled (Port ${GRPC_PORT})" || echo "Disabled")${NC}"
  echo -e "  AI Semantic Cache  : ${BOLD}$([ "$ENABLE_AI_CACHE" = true ] && echo "Enabled" || echo "Disabled")${NC}"
  echo -e "  DNS Sinkhole       : ${BOLD}$([ "$ENABLE_DNS_SINKHOLE" = true ] && echo "Enabled" || echo "Disabled")${NC}"
  echo -e "  ICAP Inspection    : ${BOLD}$([ "$ENABLE_ICAP" = true ] && echo "Enabled" || echo "Disabled")${NC}"
  echo -e "${CYAN}${BOLD}============================================================${NC}\n"

  prompt_yn "Proceed with installation?" true PROCEED
  if ! $PROCEED; then
    echo -e "${YELLOW}Installation cancelled.${NC}"
    exit 0
  fi

  echo -e "\n${GREEN}${BOLD}=== Step 4: Installing BSDM Proxy ===${NC}\n"

  # Create user if needed
  if $CREATE_USER; then
    if ! id bsdm-proxy &>/dev/null; then
      useradd --system --no-create-home --shell /usr/sbin/nologin bsdm-proxy
      echo -e "${GREEN}✓ Created system user bsdm-proxy${NC}"
    fi
  fi

  # Create directories
  mkdir -p "${PREFIX}/bin" "${ETC_DIR}" "${CERTS_DIR}"

  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

  # Build / install binaries if present
  if [[ -f "${SCRIPT_DIR}/target/release/proxy" ]]; then
    cp "${SCRIPT_DIR}/target/release/proxy" "${PREFIX}/bin/proxy"
    chmod 0755 "${PREFIX}/bin/proxy"
    echo -e "${GREEN}✓ Installed proxy binary${NC}"
  fi

  if [[ -f "${SCRIPT_DIR}/target/release/cache-indexer" ]]; then
    cp "${SCRIPT_DIR}/target/release/cache-indexer" "${PREFIX}/bin/cache-indexer"
    chmod 0755 "${PREFIX}/bin/cache-indexer"
    echo -e "${GREEN}✓ Installed cache-indexer binary${NC}"
  fi

  # Generate CA certs if requested
  if $GENERATE_CA; then
    if [[ ! -f "${CERTS_DIR}/ca.key" || ! -f "${CERTS_DIR}/ca.crt" ]]; then
      echo -e "${YELLOW}Generating MITM CA keypair in ${CERTS_DIR}...${NC}"
      openssl req -x509 -newkey rsa:4096 -keyout "${CERTS_DIR}/ca.key" -out "${CERTS_DIR}/ca.crt" \
        -days 3650 -nodes -subj "/CN=BSDM Proxy Root CA/O=BSDM Security" 2>/dev/null || true
      chmod 0600 "${CERTS_DIR}/ca.key"
      chmod 0644 "${CERTS_DIR}/ca.crt"
      echo -e "${GREEN}✓ MITM Root CA generated successfully${NC}"
    fi
  fi

  # Generate / update config file
  ENV_FILE="${ETC_DIR}/bsdm-proxy.env"
  cat <<EOF > "${ENV_FILE}"
# BSDM-Proxy Environment Configuration
HTTP_PORT=${HTTP_PORT}
METRICS_PORT=${METRICS_PORT}
MITM_ENABLED=true
CA_KEY_PATH=${CERTS_DIR}/ca.key
CA_CERT_PATH=${CERTS_DIR}/ca.crt

# gRPC Control Plane Mesh
CONTROL_GRPC_ENABLED=${ENABLE_GRPC}
CONTROL_GRPC_BIND=127.0.0.1:${GRPC_PORT}

# AI & LLM Semantic Cache
SEMANTIC_CACHE_ENABLED=${ENABLE_AI_CACHE}
SEMANTIC_CACHE_PATH_PREFIXES=/v1/chat/completions,/v1/completions,/chat/completions
SEMANTIC_VECTOR_BACKEND=qdrant
SEMANTIC_VECTOR_URL=http://127.0.0.1:6333
SEMANTIC_VECTOR_COLLECTION=bsdm_semantic

# ICAP Content Inspection
ICAP_ENABLED=${ENABLE_ICAP}
ICAP_URL=icap://127.0.0.1:1344/avscan

# DNS Sinkhole Sidecar
DNS_SINKHOLE_ENABLED=${ENABLE_DNS_SINKHOLE}
EOF
  chmod 0640 "${ENV_FILE}"
  echo -e "${GREEN}✓ Configured ${ENV_FILE}${NC}"

  # Set permissions
  if $CREATE_USER; then
    chown -R bsdm-proxy:bsdm-proxy "${PREFIX}" "${ETC_DIR}" "${CERTS_DIR}" 2>/dev/null || true
  fi

  # Install systemd units if requested
  if $INSTALL_SYSTEMD && command -v systemctl &>/dev/null; then
    cat <<EOF > /etc/systemd/system/bsdm-proxy.service
[Unit]
Description=BSDM HTTPS Forward Proxy Service
After=network.target

[Service]
Type=simple
User=$([ "$CREATE_USER" = true ] && echo "bsdm-proxy" || echo "root")
EnvironmentFile=${ETC_DIR}/bsdm-proxy.env
ExecStart=${PREFIX}/bin/proxy
Restart=always
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo -e "${GREEN}✓ Systemd unit /etc/systemd/system/bsdm-proxy.service installed${NC}"
  fi

  echo -e "\n${GREEN}${BOLD}============================================================${NC}"
  echo -e "${GREEN}${BOLD}       BSDM-Proxy Installation Complete Successfully!      ${NC}"
  echo -e "${GREEN}${BOLD}============================================================${NC}\n"
  echo -e "Start proxy service:"
  echo -e "  ${CYAN}sudo systemctl enable --now bsdm-proxy${NC}"
  echo -e "\nVerify installation:"
  echo -e "  ${CYAN}curl http://127.0.0.1:${METRICS_PORT}/health${NC}"
  echo -e "  ${CYAN}curl --cacert ${CERTS_DIR}/ca.crt -x http://127.0.0.1:${HTTP_PORT} https://httpbin.org/get${NC}"
  echo ""
}

main "$@"

#!/usr/bin/env bash
# Install BSDM-Proxy from a prebuilt GitHub Release — no Rust toolchain, no
# Node, no Docker on the target host. Self-contained on purpose: it is meant
# to be run from a clone, from the interactive installer, or straight from
# the raw URL:
#
#   curl -fsSL https://raw.githubusercontent.com/onixus/bsdm-proxy/main/scripts/install-release.sh \
#     | sudo bash -s -- --version 0.9.16
#
# What it does:
#   1. resolves the release tag (--version X.Y.Z or the latest release),
#   2. downloads bsdm-proxy-<ver>-linux-<arch>.tar.gz and its .sha256,
#   3. verifies the checksum, unpacks into a scratch directory,
#   4. runs the package's own install.sh (binaries, Admin Console, config
#      templates, systemd units, service user).
#
# It does NOT start the service or generate a CA: the config in
# /etc/bsdm-proxy needs a look first (CONTROL_API_TOKEN is generated, the
# MITM CA is not). The interactive installer (./install.sh → "Prebuilt release")
# does that part on top of this script.
set -euo pipefail

REPO="${BSDM_RELEASE_REPO:-onixus/bsdm-proxy}"
VERSION=""
ARCH=""
PREFIX="/opt/bsdm-proxy"
ETC_DIR="/etc/bsdm-proxy"
CERTS_DIR=""
WITH_SYSTEMD=true
CREATE_USER=true
KEEP_DIR=""
ARCHIVE=""

usage() {
  cat <<'EOF'
Usage: sudo ./scripts/install-release.sh [OPTIONS]

Options:
  --version X.Y.Z     Release to install (default: latest GitHub Release)
  --arch ARCH         x86_64 or aarch64 (default: uname -m)
  --archive PATH      Use an already downloaded tarball (its .sha256 must sit
                      next to it); no network access
  --prefix PATH       Install binaries to PATH (default: /opt/bsdm-proxy)
  --etc PATH          Config directory (default: /etc/bsdm-proxy)
  --certs PATH        MITM CA directory (default: <etc>/certs)
  --no-systemd        Do not install systemd units
  --no-create-user    Do not create the bsdm-proxy system user
  --keep DIR          Keep the downloaded and unpacked package in DIR
  -h, --help          Show this help

Environment:
  BSDM_RELEASE_REPO   GitHub repository (default: onixus/bsdm-proxy)
  GITHUB_TOKEN        Optional; raises the API rate limit when resolving "latest"
EOF
}

need_value() { [[ "$2" -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 2; }; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) need_value "$1" "$#"; VERSION="$2"; shift 2 ;;
    --arch) need_value "$1" "$#"; ARCH="$2"; shift 2 ;;
    --archive) need_value "$1" "$#"; ARCHIVE="$2"; shift 2 ;;
    --prefix) need_value "$1" "$#"; PREFIX="$2"; shift 2 ;;
    --etc) need_value "$1" "$#"; ETC_DIR="$2"; shift 2 ;;
    --certs) need_value "$1" "$#"; CERTS_DIR="$2"; shift 2 ;;
    --no-systemd) WITH_SYSTEMD=false; shift ;;
    --no-create-user) CREATE_USER=false; shift ;;
    --keep) need_value "$1" "$#"; KEEP_DIR="$2"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

VERSION="${VERSION#v}"
if [[ -n "$VERSION" && ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][A-Za-z0-9.]+)?$ ]]; then
  echo "Invalid --version: ${VERSION}" >&2
  exit 2
fi

[[ "$(uname -s)" == "Linux" ]] || { echo "Prebuilt packages are Linux only (this is $(uname -s))" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root (sudo ...)" >&2; exit 1; }

for cmd in curl tar sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Required command not found: $cmd" >&2; exit 1; }
done

if [[ -z "$ARCH" ]]; then
  ARCH="$(uname -m)"
fi
case "$ARCH" in
  x86_64 | amd64) ARCH=x86_64 ;;
  aarch64 | arm64) ARCH=aarch64 ;;
  *) echo "Unsupported architecture: ${ARCH} (packages exist for x86_64 and aarch64)" >&2; exit 1 ;;
esac

curl_gh() {
  # GitHub API + release downloads; the token is optional and only used for the
  # API lookup of "latest" (60 unauthenticated requests/hour is plenty for an
  # install, but CI runners share an IP).
  local -a auth=()
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  curl --fail --silent --show-error --location --retry 3 --retry-delay 2 "${auth[@]}" "$@"
}

resolve_latest() {
  # The redirect target of /releases/latest is /releases/tag/vX.Y.Z; reading it
  # avoids parsing JSON without jq.
  local location
  location="$(curl --silent --show-error --head --location --retry 3 \
    -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"
  location="${location##*/}"
  [[ "$location" == v* ]] || { echo "Cannot resolve the latest release of ${REPO} (got '${location}')" >&2; exit 1; }
  echo "${location#v}"
}

WORK=""
cleanup() {
  if [[ -n "$WORK" && -z "$KEEP_DIR" ]]; then
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

if [[ -n "$KEEP_DIR" ]]; then
  mkdir -p "$KEEP_DIR"
  WORK="$(cd "$KEEP_DIR" && pwd)"
else
  WORK="$(mktemp -d /tmp/bsdm-proxy-install.XXXXXX)"
fi

if [[ -n "$ARCHIVE" ]]; then
  [[ -f "$ARCHIVE" ]] || { echo "Archive not found: ${ARCHIVE}" >&2; exit 1; }
  [[ -f "${ARCHIVE}.sha256" ]] || { echo "Checksum not found: ${ARCHIVE}.sha256" >&2; exit 1; }
  TARBALL="$ARCHIVE"
else
  if [[ -z "$VERSION" ]]; then
    VERSION="$(resolve_latest)"
    echo "==> Latest release of ${REPO}: v${VERSION}"
  fi
  # Package names normalise the Cargo pre-release syntax (build-package.sh):
  # 0.2.2-b → 0.2.2b, 0.2.3-test → 0.2.3test, 0.5.7+033 → 0.5.7.033
  PACKAGE_VERSION="${VERSION//-b/b}"
  PACKAGE_VERSION="${PACKAGE_VERSION//-test/test}"
  PACKAGE_VERSION="${PACKAGE_VERSION//+/.}"
  NAME="bsdm-proxy-${PACKAGE_VERSION}-linux-${ARCH}.tar.gz"
  BASE="https://github.com/${REPO}/releases/download/v${VERSION}"
  TARBALL="${WORK}/${NAME}"

  echo "==> Downloading ${NAME}"
  curl_gh -o "$TARBALL" "${BASE}/${NAME}"
  curl_gh -o "${TARBALL}.sha256" "${BASE}/${NAME}.sha256"
fi

echo "==> Verifying checksum"
(
  cd "$(dirname "$TARBALL")"
  # The .sha256 names the file as it was published; check against the local
  # name so --archive with a renamed file still verifies the right bytes.
  expected="$(awk '{print $1}' "$(basename "$TARBALL").sha256")"
  actual="$(sha256sum "$(basename "$TARBALL")" | awk '{print $1}')"
  [[ -n "$expected" && "$expected" == "$actual" ]] || {
    echo "Checksum mismatch for $(basename "$TARBALL"): expected ${expected}, got ${actual}" >&2
    exit 1
  }
)

echo "==> Unpacking"
UNPACK="${WORK}/unpacked"
rm -rf "$UNPACK"
mkdir -p "$UNPACK"
tar -C "$UNPACK" -xzf "$TARBALL"
PKG_DIR="$(find "$UNPACK" -mindepth 1 -maxdepth 1 -type d -name 'bsdm-proxy-*' | head -1)"
[[ -n "$PKG_DIR" && -x "${PKG_DIR}/install.sh" ]] || { echo "Package layout not recognised in ${TARBALL}" >&2; exit 1; }
(
  cd "$PKG_DIR"
  sha256sum --check --quiet SHA256SUMS
)

# Sanity: the packaged binary must actually run here (arch + static linkage).
# `proxy hash-password` is the one offline subcommand — it hashes stdin and
# exits without touching the network or the config.
if ! printf 'probe' | "${PKG_DIR}/bin/proxy" hash-password >/dev/null 2>&1; then
  echo "${PKG_DIR}/bin/proxy does not run on this host; check the architecture (${ARCH}) and kernel" >&2
  exit 1
fi

echo "==> Installing v$(cat "${PKG_DIR}/VERSION") to ${PREFIX}"
install_args=(--prefix "$PREFIX" --etc "$ETC_DIR")
[[ -n "$CERTS_DIR" ]] && install_args+=(--certs "$CERTS_DIR")
$WITH_SYSTEMD && install_args+=(--systemd)
$CREATE_USER && install_args+=(--create-user)
"${PKG_DIR}/install.sh" "${install_args[@]}"

if [[ -n "$KEEP_DIR" ]]; then
  echo "Package kept in ${WORK}"
fi

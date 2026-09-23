#!/usr/bin/env bash
# Build BSDM-Proxy release package (binaries + Admin Console + config +
# systemd + installer).
#
# Two ways to produce the binaries:
#
#   ./scripts/build-package.sh            cargo build --release on this host
#                                         (development; binaries link against
#                                         the host libc and are only portable
#                                         to hosts with the same or newer glibc)
#   ./scripts/build-package.sh --docker   export the `artifacts` stage of the
#                                         Dockerfile: static musl binaries and
#                                         the Admin Console bundle, identical to
#                                         what the container images ship. This
#                                         is what CI uses for GitHub Releases so
#                                         the tarball runs on any Linux of the
#                                         same architecture without a compiler.
#
# PACKAGE_VIA_DOCKER=1 is the environment equivalent of --docker.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VIA_DOCKER="${PACKAGE_VIA_DOCKER:-0}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker) VIA_DOCKER=1 ;;
    --cargo) VIA_DOCKER=0 ;;
    -h | --help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
  shift
done

BINARIES=(proxy cache-indexer alert-worker ml-worker dns-sinkhole threat-intel)

VERSION="$(grep '^version' proxy/Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')"
# Cargo 0.2.2-b → 0.2.2b, 0.2.3-test → 0.2.3test, 0.5.7+033 → 0.5.7.033
PACKAGE_VERSION="${VERSION//-b/b}"
PACKAGE_VERSION="${PACKAGE_VERSION//-test/test}"
PACKAGE_VERSION="${PACKAGE_VERSION//+/.}"
ARCH="$(uname -m)"
[[ "$ARCH" == "arm64" ]] && ARCH="aarch64"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
PACKAGE_NAME="bsdm-proxy-${PACKAGE_VERSION}-${OS}-${ARCH}"
STAGING="${ROOT}/dist/${PACKAGE_NAME}"

BIN_SRC=""
CONSOLE_SRC=""

if [[ "$VIA_DOCKER" == "1" ]]; then
  # The artifacts stage is `FROM scratch`, so the export contains exactly
  # /bin/* and /admin-console and nothing else. buildx exports for the host
  # platform by default; the package is always named after the host arch, so
  # a cross-platform export would produce a mislabelled tarball — refuse it.
  command -v docker >/dev/null 2>&1 || { echo "docker is required for --docker" >&2; exit 1; }
  docker buildx version >/dev/null 2>&1 || { echo "docker buildx is required for --docker" >&2; exit 1; }
  [[ "$OS" == "linux" ]] || {
    echo "--docker packages the Linux artifacts but this host is ${OS}; the package would be mislabelled." >&2
    echo "Run it on a Linux host (or in CI) — see .github/workflows/release.yml." >&2
    exit 1
  }
  ARTIFACTS="${ROOT}/dist/artifacts"
  rm -rf "$ARTIFACTS"
  echo "==> Exporting static binaries and Admin Console from the Dockerfile (v${VERSION})"
  docker buildx build \
    --target artifacts \
    --output "type=local,dest=${ARTIFACTS}" \
    -f Dockerfile .
  BIN_SRC="${ARTIFACTS}/bin"
  CONSOLE_SRC="${ARTIFACTS}/admin-console"
else
  echo "==> Building release binaries (v${VERSION})"
  cargo_args=()
  for bin in "${BINARIES[@]}"; do
    case "$bin" in
      proxy) cargo_args+=(-p bsdm-proxy --bin proxy) ;;
      *) cargo_args+=(-p "$bin" --bin "$bin") ;;
    esac
  done
  cargo build --release "${cargo_args[@]}"
  BIN_SRC="${ROOT}/target/release"

  # Admin Console: ADMIN_CONSOLE_DIST points at a prebuilt bundle (CI caches
  # one), otherwise build it here. npm is a hard requirement: a package
  # without the console has no /admin/ and that is not a release.
  if [[ -n "${ADMIN_CONSOLE_DIST:-}" ]]; then
    CONSOLE_SRC="${ADMIN_CONSOLE_DIST}"
  else
    command -v npm >/dev/null 2>&1 || {
      echo "npm is required to build the Admin Console (or set ADMIN_CONSOLE_DIST=<prebuilt dist>)" >&2
      exit 1
    }
    echo "==> Building Admin Console"
    (cd admin-console && npm ci --no-audit --no-fund && npm run build)
    CONSOLE_SRC="${ROOT}/admin-console/dist"
  fi
fi

for bin in "${BINARIES[@]}"; do
  [[ -x "${BIN_SRC}/${bin}" ]] || { echo "missing binary: ${BIN_SRC}/${bin}" >&2; exit 1; }
done
[[ -f "${CONSOLE_SRC}/index.html" ]] || { echo "Admin Console bundle not found in ${CONSOLE_SRC}" >&2; exit 1; }

echo "==> Assembling package ${PACKAGE_NAME}"
rm -rf "$STAGING"
mkdir -p "$STAGING"/{bin,config,systemd,share}

for bin in "${BINARIES[@]}"; do
  cp "${BIN_SRC}/${bin}" "$STAGING/bin/"
done
cp -R "${CONSOLE_SRC}" "$STAGING/share/admin-console"
cp packaging/config/*.example "$STAGING/config/"
cp config/acl-rules.example.json "$STAGING/config/"
cp examples/dns/blocklist.rpz "$STAGING/config/blocklist.rpz.example"
cp packaging/systemd/*.service "$STAGING/systemd/"
cp packaging/install.sh "$STAGING/"
cp packaging/README.md "$STAGING/"
chmod +x "$STAGING/install.sh" "$STAGING/bin/"*

echo "${VERSION}" >"$STAGING/VERSION"

# Portability check. A static binary runs on any Linux of this architecture;
# a dynamic one only where the build host's glibc (or newer) is present. CI
# packages must be static; a developer's cargo build only gets a warning.
if [[ "$OS" == "linux" ]] && command -v ldd >/dev/null 2>&1; then
  if ldd "$STAGING/bin/proxy" >/dev/null 2>&1 && ! ldd "$STAGING/bin/proxy" 2>&1 | grep -q 'not a dynamic executable\|statically linked'; then
    if [[ "$VIA_DOCKER" == "1" ]]; then
      echo "bin/proxy is dynamically linked; the Docker builder must produce static binaries" >&2
      ldd "$STAGING/bin/proxy" >&2
      exit 1
    fi
    echo "!! bin/proxy is dynamically linked against this host's libc; the package is not portable."
    echo "   Use ./scripts/build-package.sh --docker for a release build."
  fi
fi

(
  cd "$STAGING"
  sha256sum bin/* >SHA256SUMS
)

TARBALL="${ROOT}/dist/${PACKAGE_NAME}.tar.gz"
tar -C "${ROOT}/dist" -czf "$TARBALL" "$PACKAGE_NAME"
(
  cd "${ROOT}/dist"
  sha256sum "$(basename "$TARBALL")" >"$(basename "$TARBALL").sha256"
)

echo "==> Package ready"
echo "    Directory: ${STAGING}"
echo "    Archive:   ${TARBALL}"
echo "    Size:      $(du -h "$TARBALL" | cut -f1)"
echo ""
cat "$STAGING/SHA256SUMS"

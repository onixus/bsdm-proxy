#!/usr/bin/env bash
# Portable CI entrypoint shared by Jenkins, GitHub Actions, and local runs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

log() {
  printf '\n==> %s\n' "$*"
}

require_commands() {
  local command_name
  for command_name in "$@"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      echo "required command is not available: ${command_name}" >&2
      return 1
    fi
  done
}

rust_ca() {
  log "CA rotation drill"
  ./scripts/test-ca-rotation.sh
}

rust_fmt() {
  log "Rust formatting"
  cargo fmt --all -- --check
}

rust_clippy() {
  log "Rust clippy"
  cargo clippy --workspace --all-targets -- -D warnings
}

rust_build() {
  log "Rust workspace build"
  cargo build --workspace --all-targets
}

rust_lite() {
  log "Lite build without rdkafka"
  cargo build -p bsdm-proxy --no-default-features --features auth-basic --all-targets
  cargo build -p cache-indexer --no-default-features --all-targets
}

rust_test() {
  log "Rust unit, integration, smoke, and E2E tests"
  cargo test --workspace --all-targets
}

rust_grpc() {
  log "gRPC control plane feature"
  cargo clippy -p bsdm-proxy --features grpc --all-targets -- -D warnings
  cargo test -p bsdm-proxy --features grpc --lib -- control_grpc
}

rust_wasm() {
  log "Wasm plugin host feature"
  cargo clippy -p bsdm-proxy --features wasm --lib -- -D warnings
  cargo test -p bsdm-proxy --features wasm --lib -- wasm_host
}

rust_all() {
  require_commands cargo rustc
  rust_ca
  rust_fmt
  rust_clippy
  rust_build
  rust_lite
  rust_test
  rust_grpc
  rust_wasm
}

docs() {
  require_commands python3
  log "Markdown links"
  python3 scripts/check-doc-links.py
  if grep -q -- "--validate" scripts/sync-wiki.py; then
    log "Wiki catalog"
    python3 scripts/sync-wiki.py --validate
  else
    echo "Wiki catalog validation is not supported by this branch; skipping"
  fi
}

install_chromium() {
  if [[ "${PLAYWRIGHT_INSTALL_DEPS:-0}" == "1" ]]; then
    npx playwright-core install --with-deps chromium
  else
    npx playwright-core install chromium
  fi
}

admin_console_core() {
  require_commands node npm
  log "Admin Console lint, unit tests, and build"
  (
    cd admin-console
    npm ci
    npm run lint
    npm test
    npm run build
  )
}

admin_console_ui() {
  require_commands node npm
  log "Admin Console Chromium smoke test"
  (
    cd admin-console
    npm ci
    install_chromium
    UI_TEST_SCREENSHOTS="${UI_TEST_SCREENSHOTS:-1}" npm run test:ui
  )
}

admin_console() {
  require_commands node npm
  log "Admin Console full gate"
  (
    cd admin-console
    npm ci
    npm run lint
    npm test
    if [[ "${RUN_UI_TESTS:-1}" == "1" ]]; then
      install_chromium
      UI_TEST_SCREENSHOTS="${UI_TEST_SCREENSHOTS:-1}" npm run test:ui
    else
      npm run build
    fi
  )
}

trust_ui() {
  require_commands node npm
  log "Trust UI"
  (
    cd trust-ui
    npm ci
    npm run build
  )
}

sast() {
  require_commands docker
  # An array, not a string: these have to reach semgrep as separate argv
  # entries, and an unquoted string expansion to achieve that trips SC2086.
  local rules=(--config p/security-audit --config p/secrets --config p/rust)

  # Pass 1 — full report over every severity. --no-error keeps the build green
  # here so the artifact is always produced, even when pass 2 will fail.
  log "SAST (semgrep): full report"
  docker run --rm -v "${ROOT}:/src" -w /src semgrep/semgrep:latest \
    semgrep scan "${rules[@]}" --metrics=off --no-error \
      --json --output semgrep.json

  # Pass 2 — the gate itself: ERROR severity only, findings become the exit code.
  log "SAST (semgrep): gate on ERROR"
  docker run --rm -v "${ROOT}:/src" -w /src semgrep/semgrep:latest \
    semgrep scan "${rules[@]}" --metrics=off --severity ERROR --error
}

secrets() {
  require_commands docker
  # Not a duplicate of semgrep's p/secrets: that one only sees the working tree,
  # while gitleaks walks the whole commit history — and a leaked key stays in
  # history after it is deleted from the working copy.
  #
  # Single pass, unlike semgrep: findings carry no severity, so splitting report
  # from gate buys nothing. The report is written before the non-zero exit, so
  # callers can archive it on failure. --redact keeps secrets out of CI logs.
  # False positives are silenced via .gitleaksignore in the repo root, keyed by
  # the finding fingerprint from gitleaks.json.
  #
  # The version is pinned, unlike semgrep above: the `detect` subcommand is
  # deprecated in favour of `git`/`dir`, and a floating :latest would one day
  # break this gate on a CLI change rather than on a real finding.
  local no_git=()
  [[ -d "${ROOT}/.git" ]] || no_git=(--no-git)

  log "Secrets (gitleaks)"
  docker run --rm -v "${ROOT}:/src" -w /src zricethezav/gitleaks:v8.30.1 \
    detect --source /src "${no_git[@]}" \
      --report-format json --report-path /src/gitleaks.json \
      --redact --no-banner --exit-code 1
}

security_audit() {
  require_commands cargo
  if ! cargo audit --version >/dev/null 2>&1; then
    echo "cargo-audit is required on this CI agent" >&2
    return 1
  fi
  log "RustSec dependency audit"
  cargo audit
}

release_validate() {
  log "Release metadata"
  CI_RELEASE_TAG="${CI_RELEASE_TAG:-${2:-}}" ./scripts/ci/validate-release.sh
}

package() {
  local actual_arch="$(uname -m)"
  if [[ -n "${EXPECTED_ARCH:-}" && "$actual_arch" != "$EXPECTED_ARCH" ]]; then
    echo "package agent architecture mismatch: expected ${EXPECTED_ARCH}, found ${actual_arch}" >&2
    return 1
  fi
  log "Release package"
  ./scripts/build-package.sh
  (
    cd dist
    sha256sum -c ./*.tar.gz.sha256
  )
}

preflight() {
  require_commands bash git python3 cargo rustc node npm
  local rust_version rust_major rust_minor node_major
  rust_version="$(rustc --version | awk '{print $2}')"
  rust_major="$(cut -d. -f1 <<<"$rust_version")"
  rust_minor="$(cut -d. -f2 <<<"$rust_version")"
  node_major="$(node --version | sed 's/^v//' | cut -d. -f1)"
  if (( rust_major < 1 || (rust_major == 1 && rust_minor < 88) )); then
    echo "Rust 1.88+ is required; found ${rust_version}" >&2
    return 1
  fi
  if [[ "$node_major" -lt 24 ]]; then
    echo "Node.js 24+ is required; found $(node --version)" >&2
    return 1
  fi
  log "Toolchain"
  git --version
  rustc --version
  cargo --version
  node --version
  npm --version
  python3 --version
}

usage() {
  cat <<'EOF'
Usage: scripts/ci/run.sh <task>

Tasks:
  preflight          Check the base CI toolchain
  rust-all           Run the complete Rust quality gate
  rust-ca            Run the offline CA rotation drill
  rust-fmt           Check rustfmt
  rust-clippy        Run clippy for the workspace
  rust-build         Build the workspace and all targets
  rust-lite          Build the no-rdkafka profile
  rust-test          Run workspace tests
  rust-grpc          Check the optional gRPC feature
  rust-wasm          Check the optional Wasm feature
  docs               Validate Markdown links and the Wiki catalog
  admin-console      Lint, test, build, and optionally UI-test the admin console
  admin-console-core Lint, test, and build the admin console
  admin-console-ui   Run the Admin Console Chromium smoke test
  trust-ui           Build the experimental trust UI
  sast               Run the semgrep SAST gate (needs Docker)
  secrets            Scan commit history for leaked secrets (needs Docker)
  security-audit     Run cargo-audit (must be installed on the agent)
  release-validate   Validate version, tag, changelog, and Cargo metadata
  package            Build and verify the native release package
  load-test          Run the Docker-based lite/hybrid load-test profile
EOF
}

task="${1:-}"
case "$task" in
  preflight) preflight ;;
  rust-all) rust_all ;;
  rust-ca) rust_ca ;;
  rust-fmt) rust_fmt ;;
  rust-clippy) rust_clippy ;;
  rust-build) rust_build ;;
  rust-lite) rust_lite ;;
  rust-test) rust_test ;;
  rust-grpc) rust_grpc ;;
  rust-wasm) rust_wasm ;;
  docs) docs ;;
  admin-console) admin_console ;;
  admin-console-core) admin_console_core ;;
  admin-console-ui) admin_console_ui ;;
  trust-ui) trust_ui ;;
  sast) sast ;;
  secrets) secrets ;;
  security-audit) security_audit ;;
  release-validate) release_validate "$@" ;;
  package) package ;;
  load-test) exec ./scripts/ci/run-load-tests.sh ;;
  -h|--help|help) usage ;;
  *)
    usage >&2
    [[ -n "$task" ]] && echo "unknown task: ${task}" >&2
    exit 2
    ;;
esac

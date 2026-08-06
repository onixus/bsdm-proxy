// Локальный Jenkins (http://localhost:8081) — порт .github/workflows/ci.yml.
// Всё собирается в контейнере rust:1-bookworm через docker.sock хоста;
// на контроллере Rust не нужен.
//
// Swatinem/rust-cache заменён именованными volume'ами: CARGO_HOME и target/
// переживают сборки, поэтому холодный прогон долгий, а дальше — как в GHA.

def RUST_IMAGE = 'rust:1-bookworm'
def CACHE_ARGS = '-v bsdm-cargo-home:/usr/local/cargo/registry -v bsdm-cargo-target:/build-target'
def RUST_ENV = ['CARGO_TERM_COLOR=always', 'RUST_BACKTRACE=1', 'CARGO_TARGET_DIR=/build-target']

// Системные зависимости из .github/actions/setup-rust.
// Ставятся каждый прогон: кэшируются только volume'ы, а корень контейнера
// эфемерный — маркер «уже поставлено» тут соврал бы на втором билде.
def SYS_DEPS = '''
  apt-get update -qq
  apt-get install -y --no-install-recommends \
    libssl-dev pkg-config cmake librdkafka-dev libclang-dev protobuf-compiler
'''

pipeline {
  agent none

  options {
    timestamps()
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '20'))
    timeout(time: 120, unit: 'MINUTES')
  }

  stages {
    stage('CA rotation drill') {
      agent { docker { image RUST_IMAGE; args CACHE_ARGS; reuseNode true } }
      steps {
        sh """
          set -eu
          ${SYS_DEPS}
          ./scripts/test-ca-rotation.sh
        """
      }
    }

    stage('Format & lint') {
      agent { docker { image RUST_IMAGE; args CACHE_ARGS; reuseNode true } }
      steps {
        withEnv(RUST_ENV) {
          sh """
            set -eu
            ${SYS_DEPS}
            rustup component add rustfmt clippy
            cargo fmt --all -- --check
            cargo clippy --workspace --all-targets -- -D warnings
          """
        }
      }
    }

    stage('Build') {
      agent { docker { image RUST_IMAGE; args CACHE_ARGS; reuseNode true } }
      steps {
        withEnv(RUST_ENV) {
          sh """
            set -eu
            ${SYS_DEPS}
            cargo build --workspace --all-targets

            # lite-профиль: без rdkafka
            cargo build -p bsdm-proxy --no-default-features --features auth-basic --all-targets
            cargo build -p cache-indexer --no-default-features --all-targets
          """
        }
      }
    }

    stage('Test') {
      agent { docker { image RUST_IMAGE; args CACHE_ARGS; reuseNode true } }
      steps {
        withEnv(RUST_ENV) {
          sh """
            set -eu
            ${SYS_DEPS}
            cargo test --workspace --all-targets
          """
        }
      }
    }

    stage('Feature gates') {
      parallel {
        stage('grpc') {
          agent { docker { image RUST_IMAGE; args CACHE_ARGS; reuseNode true } }
          steps {
            withEnv(RUST_ENV) {
              sh """
                set -eu
                ${SYS_DEPS}
                rustup component add clippy
                cargo clippy -p bsdm-proxy --features grpc --all-targets -- -D warnings
                cargo test -p bsdm-proxy --features grpc --lib -- control_grpc
              """
            }
          }
        }
        stage('wasm') {
          agent { docker { image RUST_IMAGE; args CACHE_ARGS; reuseNode true } }
          steps {
            withEnv(RUST_ENV) {
              sh """
                set -eu
                ${SYS_DEPS}
                rustup component add clippy
                cargo clippy -p bsdm-proxy --features wasm --lib -- -D warnings
                cargo test -p bsdm-proxy --features wasm --lib -- wasm_host
              """
            }
          }
        }
      }
    }

    stage('Security audit') {
      agent { docker { image RUST_IMAGE; args CACHE_ARGS; reuseNode true } }
      steps {
        withEnv(RUST_ENV) {
          // rustsec/audit-check недоступен вне GHA. Ставим cargo-audit через
          // --root в кэшируемый volume (в CARGO_HOME его класть нельзя: том,
          // навешенный на /usr/local/cargo, перекрыл бы сам cargo из образа).
          sh """
            set -eu
            ${SYS_DEPS}
            export PATH="/build-target/tools/bin:\$PATH"
            command -v cargo-audit >/dev/null 2>&1 || \
              cargo install cargo-audit --locked --root /build-target/tools
            cargo audit
          """
        }
      }
    }
  }
}

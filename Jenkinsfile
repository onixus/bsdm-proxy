// Локальный Jenkins (http://localhost:8081) — порт .github/workflows/ci.yml.
// Всё собирается в контейнере rust:1-bookworm через docker.sock хоста;
// на контроллере Rust не нужен.
//
// Swatinem/rust-cache заменён именованными volume'ами: CARGO_HOME и target/
// переживают сборки, поэтому холодный прогон долгий, а дальше — как в GHA.

def RUST_IMAGE = 'rust:1-bookworm'

// target/ НЕ кэшируется томом — намеренно, после двух неудачных попыток:
//
//   1. CARGO_TARGET_DIR=/build-target ломал e2e: e2e/src/lib.rs ищет бинарь по
//      жёсткому <workspace>/target/{debug,release}/proxy.
//   2. Том на захардкоженный <workspace>/target ломается о параллельные
//      стадии: Jenkins выдаёт им отдельные воркспейсы (bsdm-proxy@2), и один
//      branch писал мимо тома, а другой — в него.
//
// target/ и так переживает сборки: воркспейс Jenkins между билдами не чистится.
// Кэшируем только пути, фиксированные внутри контейнера и от воркспейса не
// зависящие: реестр cargo и каталог с cargo-audit.
def CACHE_ARGS = '-v bsdm-cargo-home:/usr/local/cargo/registry -v bsdm-cargo-tools:/opt/cargo-tools'
def RUST_ENV = ['CARGO_TERM_COLOR=always', 'RUST_BACKTRACE=1']

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

    // Quality gate — блокирующие security-проверки, обе до сборки.
    // Холодный cargo build тут идёт десятки минут, и ловить криты после него
    // бессмысленно; ни SAST, ни аудит зависимостей сборки не требуют.
    stage('Quality gate') {
      parallel {
        stage('SAST (semgrep)') {
          agent any
          steps {
            sh '''
              set -eu
              RULES="--config p/security-audit --config p/secrets --config p/rust"

              # Проход 1 — полный отчёт, все severity, билд не роняет (--no-error).
              echo "[sast] полный отчёт"
              docker run --rm -v "$WORKSPACE":/src -w /src semgrep/semgrep:latest \
                semgrep scan $RULES --metrics=off --no-error \
                  --json --output semgrep.json

              # Проход 2 — гейт: только ERROR, находки уходят в код возврата.
              echo "[sast] quality gate: блок при ERROR"
              docker run --rm -v "$WORKSPACE":/src -w /src semgrep/semgrep:latest \
                semgrep scan $RULES --metrics=off --severity ERROR --error
            '''
          }
          post {
            always {
              archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
            }
          }
        }

        stage('Dependency audit') {
          agent { docker { image RUST_IMAGE; args CACHE_ARGS; reuseNode true } }
          steps {
            withEnv(RUST_ENV) {
              // rustsec/audit-check недоступен вне GHA. cargo-audit ставим через
              // --root в кэшируемый volume (в CARGO_HOME его класть нельзя: том,
              // навешенный на /usr/local/cargo, перекрыл бы сам cargo из образа).
              // Блокирует сам по себе: любая advisory — ненулевой код возврата.
              //
              // БЕЗ --deny warnings намеренно. С ним билд роняли таймауты
              // проверки yanked-пакетов ("couldn't check if the package is
              // yanked: registry: request could not be completed"), то есть
              // флаки-сеть, а не находки. Гейт должен блокировать на
              // уязвимостях — это и есть поведение по умолчанию.
              sh """
                set -eu
                ${SYS_DEPS}
                export PATH="/opt/cargo-tools/bin:\$PATH"
                command -v cargo-audit >/dev/null 2>&1 || \
                  cargo install cargo-audit --locked --root /opt/cargo-tools
                cargo audit
              """
            }
          }
        }
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

  }
}

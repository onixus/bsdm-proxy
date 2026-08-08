// Локальный Jenkins (http://localhost:8081) — порт .github/workflows/ci.yml.
// Всё собирается в контейнере rust:1-bookworm через docker.sock хоста;
// на контроллере Rust не нужен.
//
// Swatinem/rust-cache заменён именованными volume'ами: CARGO_HOME и target/
// переживают сборки, поэтому холодный прогон долгий, а дальше — как в GHA.

def RUST_IMAGE = 'rust:1-bookworm'

// target/ ОБЯЗАН лежать на нативном томе, а не в воркспейсе.
//
// Воркспейс Jenkins — bind-mount macOS через VirtioFS, и сборка Rust на нём
// разваливается: cargo пишет десятки тысяч мелких файлов, часть записей не
// доезжает, зависимые крейты падают с "E0463: can't find crate for tokio".
// Замерено на одном и том же коде: 3 холодных прогона на bind-mount'е — 3
// падения (26, 7 и 2 ошибки, число убывает по мере прогрева кэша хостовой ФС);
// 2 прогона на файловой системе контейнера — 0 ошибок. Отсюда же прежние
// «то падает, то нет» и спасительный эффект тёплого target/.
//
// Путь фиксирован внутри контейнера, поэтому параллельные стадии с их
// отдельными воркспейсами (bsdm-proxy@2) больше не при чём: cargo сам берёт
// файловую блокировку на target и сериализует доступ.
def CACHE_ARGS = '-v bsdm-cargo-home:/usr/local/cargo/registry -v bsdm-cargo-tools:/opt/cargo-tools -v bsdm-cargo-target:/build-target'

// BSDM_PROXY_BIN — штатное переопределение из e2e/src/lib.rs (proxy_binary()
// проверяет его первым). Без него e2e ищет бинарь по жёсткому
// <workspace>/target/debug/proxy и с уводом CARGO_TARGET_DIR не находит —
// ровно на это я уже наступал.
def RUST_ENV = [
  'CARGO_TERM_COLOR=always',
  'RUST_BACKTRACE=1',
  'CARGO_TARGET_DIR=/build-target',
  'BSDM_PROXY_BIN=/build-target/debug/proxy',
]

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

    // Quality gate — блокирующие security-проверки, все до сборки.
    // Холодный cargo build тут идёт десятки минут, и ловить криты после него
    // бессмысленно; ни SAST, ни скан секретов, ни аудит зависимостей сборки
    // не требуют.
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

        // Дубликатом p/secrets из semgrep не является: тот смотрит только
        // рабочее дерево, gitleaks — всю историю коммитов, а утёкший ключ
        // остаётся в ней и после удаления из рабочей копии.
        stage('Secrets (gitleaks)') {
          agent any
          steps {
            sh '''
              set -eu
              # Один проход, в отличие от semgrep: severity у находок нет,
              # делить отчёт и гейт незачем. Отчёт пишется до выхода с
              # ненулевым кодом, поэтому post заберёт его и на падении.
              # --redact держит сами секреты вне лога Jenkins.
              # Ложные срабатывания глушатся .gitleaksignore в корне репо —
              # fingerprint находки берётся из gitleaks.json.
              NO_GIT=""
              [ -d .git ] || NO_GIT="--no-git"   # не из SCM — сканируем дерево
              # Версия запинена, в отличие от соседнего semgrep: подкоманда
              # detect объявлена устаревшей в пользу git/dir, и плавающий
              # :latest однажды уронит стадию не находкой, а сменой CLI.
              docker run --rm -v "$WORKSPACE":/src -w /src zricethezav/gitleaks:v8.30.1 \
                detect --source /src $NO_GIT \
                  --report-format json --report-path /src/gitleaks.json \
                  --redact --no-banner --exit-code 1
            '''
          }
          post {
            always {
              archiveArtifacts artifacts: 'gitleaks.json', allowEmptyArchive: true
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

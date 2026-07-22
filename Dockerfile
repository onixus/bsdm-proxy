# syntax=docker/dockerfile:1

# ============================================================
# Unified builder stage - собирает все бинарники
# ============================================================
FROM rust:alpine AS builder
ARG TARGETARCH
ARG LITE_BUILD=0
WORKDIR /build

# Установка зависимостей для сборки (включая bash для rdkafka)
RUN apk add --no-cache \
    musl-dev \
    protoc \
    g++ \
    cmake \
    make \
    bash \
    perl \
    git \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    librdkafka-dev \
    cyrus-sasl-dev \
    lz4-dev \
    zlib-dev \
    zlib-static \
    zstd-dev

# Определение Rust target на основе архитектуры
RUN case "$TARGETARCH" in \
      "amd64") echo "x86_64-unknown-linux-musl" > /rust_target.txt ;; \
      "arm64") echo "aarch64-unknown-linux-musl" > /rust_target.txt ;; \
      *) echo "Unsupported architecture: $TARGETARCH"; exit 1 ;; \
    esac

# Добавляем musl target
RUN rustup target add $(cat /rust_target.txt)

# Настройка окружения для статической линковки. `strip=symbols` убирает
# debug-символы прямо во время линковки — бинарники получаются меньше и
# не нужен отдельный шаг `strip`.
ENV OPENSSL_STATIC=1 \
    OPENSSL_LIB_DIR=/usr/lib \
    OPENSSL_INCLUDE_DIR=/usr/include \
    RUSTFLAGS="-C target-feature=+crt-static -C strip=symbols" \
    CARGO_NET_RETRY=3 \
    CARGO_INCREMENTAL=0

# ---- Dependency cache layer ----
# Копируем только манифесты и lock-файл, создаём заглушки src,
# собираем зависимости — этот слой кэшируется, пока Cargo.lock не изменится.
COPY Cargo.toml Cargo.lock ./
COPY bsdm-events/Cargo.toml ./bsdm-events/Cargo.toml
COPY proxy/Cargo.toml ./proxy/Cargo.toml
COPY cache-indexer/Cargo.toml ./cache-indexer/Cargo.toml
COPY alert-worker/Cargo.toml ./alert-worker/Cargo.toml
COPY ml-worker/Cargo.toml ./ml-worker/Cargo.toml
COPY dns-sinkhole/Cargo.toml ./dns-sinkhole/Cargo.toml
COPY e2e/Cargo.toml ./e2e/Cargo.toml
COPY bsdm-wasm-sdk/Cargo.toml ./bsdm-wasm-sdk/Cargo.toml

# Создаём минимальные lib.rs/main.rs-заглушки чтобы cargo fetch + build deps
RUN mkdir -p bsdm-events/src proxy/src cache-indexer/src \
             alert-worker/src ml-worker/src dns-sinkhole/src \
             e2e/src bsdm-wasm-sdk/src && \
    echo "pub fn _stub() {}" > bsdm-events/src/lib.rs && \
    echo "fn main() {}" > proxy/src/main.rs && \
    touch proxy/src/lib.rs && \
    echo "fn main() {}" > cache-indexer/src/main.rs && \
    echo "fn main() {}" > alert-worker/src/main.rs && \
    echo "fn main() {}" > ml-worker/src/main.rs && \
    echo "fn main() {}" > dns-sinkhole/src/main.rs && \
    echo "pub fn _stub() {}" > e2e/src/lib.rs && \
    echo "pub fn _stub() {}" > bsdm-wasm-sdk/src/lib.rs

# Fetch + compile dependencies only (stubs will fail to link but deps get
# cached). BuildKit cache mounts persist the cargo registry/git checkouts
# and the incremental target dir across builds so only changed deps are
# rebuilt instead of the whole dependency graph every time.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release --locked --target $(cat /rust_target.txt) \
      -p bsdm-events -p bsdm-proxy -p cache-indexer \
      -p alert-worker -p ml-worker -p dns-sinkhole 2>/dev/null || true

# ---- Source copy (invalidates cache only when source changes) ----
COPY bsdm-events ./bsdm-events
COPY proxy ./proxy
COPY cache-indexer ./cache-indexer
COPY alert-worker ./alert-worker
COPY ml-worker ./ml-worker
COPY dns-sinkhole ./dns-sinkhole
COPY e2e ./e2e
COPY bsdm-wasm-sdk ./bsdm-wasm-sdk
COPY examples ./examples

# Собираем бинарники workspace в release режиме. --locked гарантирует, что
# сборка использует именно зафиксированные версии из Cargo.lock (без
# неожиданного дрейфа зависимостей в CI/CD). Копируем результат в /dist
# внутри того же RUN, пока кэш-том /build/target ещё смонтирован.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    set -eux; \
    if [ "$LITE_BUILD" = "1" ]; then \
      cargo build --release --locked --target $(cat /rust_target.txt) \
        --no-default-features --features auth-basic -p bsdm-proxy; \
      cargo build --release --locked --target $(cat /rust_target.txt) \
        --no-default-features -p cache-indexer; \
    else \
      cargo build --release --locked --target $(cat /rust_target.txt) \
        -p bsdm-proxy -p cache-indexer -p alert-worker -p ml-worker -p dns-sinkhole; \
    fi; \
    mkdir -p /dist; \
    for bin in proxy cache-indexer alert-worker ml-worker dns-sinkhole; do \
      cp "/build/target/$(cat /rust_target.txt)/release/$bin" /dist/ 2>/dev/null || true; \
    done

# ============================================================
# Common runtime base - общие пакеты и non-root пользователь
# собираются один раз и переиспользуются всеми runtime-стадиями,
# вместо повторной установки apk-пакетов в каждой из 5 стадий.
# ============================================================
FROM alpine:3.21 AS runtime-base

RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    dumb-init \
    wget && \
    addgroup -g 1000 bsdm && \
    adduser -D -u 1000 -G bsdm bsdm

USER bsdm
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# ============================================================
# Proxy runtime
# ============================================================
FROM runtime-base AS proxy

COPY --from=builder --chmod=755 /dist/proxy /usr/local/bin/proxy

EXPOSE 1488
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- --spider http://127.0.0.1:1488/health || exit 1
CMD ["proxy"]

# ============================================================
# Cache-indexer runtime
# ============================================================
FROM runtime-base AS cache-indexer

COPY --from=builder --chmod=755 /dist/cache-indexer /usr/local/bin/cache-indexer

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- --spider http://127.0.0.1:8080/health || exit 1
CMD ["cache-indexer"]

# ============================================================
# Alert-worker runtime (ClickHouse → webhook / SIEM)
# ============================================================
FROM runtime-base AS alert-worker

COPY --from=builder --chmod=755 /dist/alert-worker /usr/local/bin/alert-worker

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- --spider http://127.0.0.1:8090/health || exit 1
CMD ["alert-worker"]

# ============================================================
# ML-worker runtime (ClickHouse features + scores, M5)
# ============================================================
FROM runtime-base AS ml-worker

COPY --from=builder --chmod=755 /dist/ml-worker /usr/local/bin/ml-worker

EXPOSE 8091
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- --spider http://127.0.0.1:8091/health || exit 1
CMD ["ml-worker"]

# ============================================================
# DNS sinkhole sidecar (RPZ-lite UDP proxy, P3 / #108)
# ============================================================
FROM runtime-base AS dns-sinkhole

COPY --from=builder --chmod=755 /dist/dns-sinkhole /usr/local/bin/dns-sinkhole
COPY --chmod=644 examples/dns/blocklist.rpz /etc/bsdm-proxy/blocklist.rpz

ENV DNS_SINKHOLE_ZONE_PATH=/etc/bsdm-proxy/blocklist.rpz \
    DNS_SINKHOLE_BIND=0.0.0.0:53 \
    METRICS_PORT=8092

EXPOSE 53/udp 8092
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- --spider http://127.0.0.1:8092/health || exit 1
CMD ["dns-sinkhole"]

# syntax=docker/dockerfile:1

# ============================================================
# Unified builder stage - собирает все бинарники
# ============================================================
FROM rust:1-alpine AS builder
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

# Настройка окружения для статической линковки
ENV OPENSSL_STATIC=1 \
    OPENSSL_LIB_DIR=/usr/lib \
    OPENSSL_INCLUDE_DIR=/usr/include \
    RUSTFLAGS="-C target-feature=+crt-static"

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

# Fetch + compile dependencies only (stubs will fail to link but deps get cached)
RUN cargo build --release --target $(cat /rust_target.txt) \
      -p bsdm-events 2>/dev/null || true && \
    cargo build --release --target $(cat /rust_target.txt) \
      -p bsdm-proxy 2>/dev/null || true

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

# Собираем бинарники workspace в release режиме
RUN if [ "$LITE_BUILD" = "1" ]; then \
      cargo build --release --target $(cat /rust_target.txt) \
        --no-default-features --features auth-basic -p bsdm-proxy && \
      cargo build --release --target $(cat /rust_target.txt) \
        --no-default-features -p cache-indexer; \
    else \
      cargo build --release --target $(cat /rust_target.txt) \
        -p bsdm-proxy -p cache-indexer -p alert-worker -p ml-worker -p dns-sinkhole; \
    fi

# Копируем результаты в общую директорию
RUN mkdir -p /dist && \
    cp /build/target/$(cat /rust_target.txt)/release/proxy /dist/ || true && \
    cp /build/target/$(cat /rust_target.txt)/release/cache-indexer /dist/ || true && \
    cp /build/target/$(cat /rust_target.txt)/release/alert-worker /dist/ || true && \
    cp /build/target/$(cat /rust_target.txt)/release/ml-worker /dist/ || true && \
    cp /build/target/$(cat /rust_target.txt)/release/dns-sinkhole /dist/ || true

# ============================================================
# Proxy runtime
# ============================================================
FROM alpine:3.21 AS proxy
# wget: used by docker-compose healthchecks (Alpine has no curl by default)
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    wget

# Копируем скомпилированный бинарник
COPY --from=builder /dist/proxy /usr/local/bin/proxy

EXPOSE 1488
CMD ["proxy"]

# ============================================================
# Cache-indexer runtime
# ============================================================
FROM alpine:3.21 AS cache-indexer
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    wget

# Копируем скомпилированный бинарник
COPY --from=builder /dist/cache-indexer /usr/local/bin/cache-indexer

EXPOSE 8080
CMD ["cache-indexer"]

# ============================================================
# Alert-worker runtime (ClickHouse → webhook / SIEM)
# ============================================================
FROM alpine:3.21 AS alert-worker
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    wget

COPY --from=builder /dist/alert-worker /usr/local/bin/alert-worker

EXPOSE 8090
CMD ["alert-worker"]

# ============================================================
# ML-worker runtime (ClickHouse features + scores, M5)
# ============================================================
FROM alpine:3.21 AS ml-worker
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    wget

COPY --from=builder /dist/ml-worker /usr/local/bin/ml-worker

EXPOSE 8091
CMD ["ml-worker"]

# ============================================================
# DNS sinkhole sidecar (RPZ-lite UDP proxy, P3 / #108)
# ============================================================
FROM alpine:3.21 AS dns-sinkhole
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    wget

COPY --from=builder /dist/dns-sinkhole /usr/local/bin/dns-sinkhole
COPY examples/dns/blocklist.rpz /etc/bsdm-proxy/blocklist.rpz

ENV DNS_SINKHOLE_ZONE_PATH=/etc/bsdm-proxy/blocklist.rpz \
    DNS_SINKHOLE_BIND=0.0.0.0:53 \
    METRICS_PORT=8092

EXPOSE 53/udp 8092
CMD ["dns-sinkhole"]

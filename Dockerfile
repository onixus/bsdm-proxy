# syntax=docker/dockerfile:1

# ============================================================
# Unified builder stage - собирает оба бинарника
# ============================================================
FROM rust:1-alpine AS builder
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

# Добавляем musl target
RUN rustup target add x86_64-unknown-linux-musl

# Копируем весь workspace
COPY Cargo.toml Cargo.lock ./
COPY bsdm-events ./bsdm-events
COPY proxy ./proxy
COPY cache-indexer ./cache-indexer
COPY alert-worker ./alert-worker
COPY ml-worker ./ml-worker
COPY dns-sinkhole ./dns-sinkhole
COPY e2e ./e2e
COPY bsdm-wasm-sdk ./bsdm-wasm-sdk
COPY examples ./examples

# Настройка окружения для статической линковки
ENV OPENSSL_STATIC=1 \
    OPENSSL_LIB_DIR=/usr/lib \
    OPENSSL_INCLUDE_DIR=/usr/include \
    RUSTFLAGS="-C target-feature=+crt-static"

# Собираем бинарники workspace в release режиме
RUN if [ "$LITE_BUILD" = "1" ]; then \
      cargo build --release --target x86_64-unknown-linux-musl \
        --no-default-features --features auth-basic -p bsdm-proxy && \
      cargo build --release --target x86_64-unknown-linux-musl \
        --no-default-features -p cache-indexer; \
    else \
      cargo build --release --target x86_64-unknown-linux-musl \
        -p bsdm-proxy -p cache-indexer -p alert-worker -p ml-worker -p dns-sinkhole; \
    fi

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
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/proxy /usr/local/bin/proxy

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
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/cache-indexer /usr/local/bin/cache-indexer

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

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/alert-worker /usr/local/bin/alert-worker

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

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/ml-worker /usr/local/bin/ml-worker

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

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/dns-sinkhole /usr/local/bin/dns-sinkhole
COPY examples/dns/blocklist.rpz /etc/bsdm-proxy/blocklist.rpz

ENV DNS_SINKHOLE_ZONE_PATH=/etc/bsdm-proxy/blocklist.rpz \
    DNS_SINKHOLE_BIND=0.0.0.0:53 \
    METRICS_PORT=8092

EXPOSE 53/udp 8092
CMD ["dns-sinkhole"]

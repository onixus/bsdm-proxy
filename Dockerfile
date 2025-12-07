# syntax=docker/dockerfile:1

# ============================================================
# Unified builder stage - собирает оба бинарника
# ============================================================
FROM rust:1.83-alpine AS builder
WORKDIR /build

# Установка зависимостей для сборки
RUN apk add --no-cache \
    musl-dev \
    protoc \
    g++ \
    cmake \
    make \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    librdkafka-dev \
    cyrus-sasl-dev \
    lz4-dev \
    zlib-dev \
    zlib-static \
    zstd-dev

# Копируем весь workspace
COPY Cargo.toml Cargo.lock ./
COPY proxy ./proxy
COPY cache-indexer ./cache-indexer

# Настройка окружения для статической линковки OpenSSL
ENV OPENSSL_STATIC=1 \
    OPENSSL_LIB_DIR=/usr/lib \
    OPENSSL_INCLUDE_DIR=/usr/include

# Собираем оба бинарника в release режиме
RUN cargo build --release --target x86_64-unknown-linux-musl

# ============================================================
# Proxy runtime
# ============================================================
FROM alpine:3.21 AS proxy
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    librdkafka \
    cyrus-sasl \
    lz4-libs \
    zlib \
    zstd-libs

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
    librdkafka \
    cyrus-sasl \
    lz4-libs \
    zlib \
    zstd-libs

# Копируем скомпилированный бинарник
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/cache-indexer /usr/local/bin/cache-indexer

EXPOSE 8080
CMD ["cache-indexer"]

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

# Копируем только Cargo.toml и Cargo.lock сначала для кеширования зависимостей
COPY Cargo.toml Cargo.lock ./
COPY proxy/Cargo.toml ./proxy/
COPY cache-indexer/Cargo.toml ./cache-indexer/

# Создаем пустые src директории для сборки зависимостей
RUN mkdir -p proxy/src cache-indexer/src && \
    echo 'fn main() {}' > proxy/src/main.rs && \
    echo 'fn main() {}' > cache-indexer/src/main.rs

# Настройка окружения
ENV OPENSSL_STATIC=1 \
    OPENSSL_LIB_DIR=/usr/lib \
    OPENSSL_INCLUDE_DIR=/usr/include

# Собираем зависимости (этот слой будет кешироваться)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --target x86_64-unknown-linux-musl && \
    rm -rf proxy/src cache-indexer/src

# Копируем реальный исходный код
COPY proxy/src ./proxy/src
COPY cache-indexer/src ./cache-indexer/src

# Собираем финальные бинарники
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --target x86_64-unknown-linux-musl && \
    cp target/x86_64-unknown-linux-musl/release/proxy /tmp/proxy && \
    cp target/x86_64-unknown-linux-musl/release/cache-indexer /tmp/cache-indexer

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

COPY --from=builder /tmp/proxy /usr/local/bin/proxy

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

COPY --from=builder /tmp/cache-indexer /usr/local/bin/cache-indexer

EXPOSE 8080
CMD ["cache-indexer"]

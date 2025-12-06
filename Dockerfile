# ============================================================
# Unified builder stage - собирает оба бинарника
# ============================================================
FROM rust:1.83-alpine AS builder
WORKDIR /build

# Установка зависимостей
RUN apk add --no-cache \
    musl-dev \
    protoc \
    g++ \
    cmake \
    make \
    openssl-dev \
    pkgconfig

# Копируем workspace целиком
COPY Cargo.toml Cargo.lock ./
COPY proxy ./proxy
COPY cache-indexer ./cache-indexer

# Собираем оба бинарника в release режиме
RUN cargo build --release

# ============================================================
# Proxy runtime
# ============================================================
FROM alpine:3.21 AS proxy
RUN apk add --no-cache ca-certificates libgcc

# Копируем скомпилированный бинарник
COPY --from=builder /build/target/release/proxy /usr/local/bin/proxy

EXPOSE 1488
CMD ["proxy"]

# ============================================================
# Cache-indexer runtime
# ============================================================
FROM alpine:3.21 AS cache-indexer
RUN apk add --no-cache ca-certificates libgcc

# Копируем скомпилированный бинарник
COPY --from=builder /build/target/release/cache-indexer /usr/local/bin/cache-indexer

EXPOSE 8080
CMD ["cache-indexer"]

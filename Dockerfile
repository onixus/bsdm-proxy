# syntax=docker/dockerfile:1

# ============================================================
# Unified builder stage - собирает оба бинарника
# ============================================================
FROM rust:1-bookworm AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    pkg-config \
    cmake \
    librdkafka-dev \
    libclang-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Копируем workspace (e2e нужен как member в корневом Cargo.toml)
COPY Cargo.toml Cargo.lock ./
COPY proxy ./proxy
COPY cache-indexer ./cache-indexer
COPY e2e ./e2e

RUN cargo build --release \
    -p bsdm-proxy --bin proxy \
    -p cache-indexer --bin cache-indexer

# ============================================================
# Proxy runtime
# ============================================================
FROM debian:bookworm-slim AS proxy
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/proxy /usr/local/bin/proxy

EXPOSE 1488
CMD ["proxy"]

# ============================================================
# Cache-indexer runtime
# ============================================================
FROM debian:bookworm-slim AS cache-indexer
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/cache-indexer /usr/local/bin/cache-indexer

EXPOSE 8080
CMD ["cache-indexer"]

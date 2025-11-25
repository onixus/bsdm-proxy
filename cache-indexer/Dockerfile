FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Copy workspace files
COPY Cargo.toml ./
COPY cache-indexer/Cargo.toml ./cache-indexer/

# Copy source
COPY cache-indexer/src ./cache-indexer/src

# Build release
RUN cargo build --bin cache-indexer --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/cache-indexer /app/cache-indexer

CMD ["/app/cache-indexer"]
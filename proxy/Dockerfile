FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Copy workspace files
COPY Cargo.toml ./
COPY proxy/Cargo.toml ./proxy/

# Copy source
COPY proxy/src ./proxy/src

# Build release
RUN cargo build --bin proxy --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/proxy /app/proxy

# Port 3128 for HTTP/HTTPS proxy
EXPOSE 3128

CMD ["/app/proxy"]
# ─── OpenGit Dockerfile ────────────────────────────────────────
# Multi-stage build for minimal image size

# Stage 1: Build
FROM rust:1.88-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y     gcc     pkg-config     libssl-dev     && rm -rf /var/lib/apt/lists/*

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build all binaries
RUN cargo build --release -p opengit-cli -p opengit-server

# ─── Stage 2: Runtime ──────────────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="OpenGit"
LABEL org.opencontainers.image.description="Git Gateway - Mirror repositories to multiple Git hosts"
LABEL org.opencontainers.image.source="https://github.com/youbanzhishi/OpenGit"
LABEL org.opencontainers.image.licenses="MIT"

# Install runtime dependencies
RUN apt-get update && apt-get install -y     ca-certificates     curl     git     openssh-client     && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1000 opengit     && useradd --uid 1000 --gid opengit --shell /bin/bash --create-home opengit

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/target/release/og /app/og
COPY --from=builder /build/target/release/opengit-server /app/opengit-server

# Create config directories
RUN mkdir -p /app/config /app/repos /app/logs     && chown -R opengit:opengit /app

USER opengit

# Default command
CMD ["/app/og", "--help"]

# ─── Exposed Ports ──────────────────────────────────────────────
# Default OpenGit server port
EXPOSE 9418

# ─── Health Check ────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3     CMD curl -f http://localhost:9418/health || exit 1

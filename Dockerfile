# OpenGit Dockerfile - Multi-stage build
# P5: Docker deployment support

# -- Build stage -------------------------------------------------------
FROM rust:1.82-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests first (for dependency caching)
COPY Cargo.toml Cargo.lock ./
COPY crates/opengit-core/Cargo.toml crates/opengit-core/Cargo.toml
COPY crates/opengit-server/Cargo.toml crates/opengit-server/Cargo.toml
COPY crates/opengit-hooks/Cargo.toml crates/opengit-hooks/Cargo.toml
COPY crates/opengit-storage/Cargo.toml crates/opengit-storage/Cargo.toml
COPY crates/opengit-cli/Cargo.toml crates/opengit-cli/Cargo.toml
COPY crates/opengit-ssh/Cargo.toml crates/opengit-ssh/Cargo.toml

# Create dummy source files to cache dependencies
RUN mkdir -p crates/opengit-core/src && touch crates/opengit-core/src/lib.rs \
    && mkdir -p crates/opengit-server/src && touch crates/opengit-server/src/main.rs \
    && mkdir -p crates/opengit-hooks/src && touch crates/opengit-hooks/src/main.rs \
    && mkdir -p crates/opengit-storage/src && touch crates/opengit-storage/src/lib.rs \
    && mkdir -p crates/opengit-cli/src && touch crates/opengit-cli/src/main.rs \
    && mkdir -p crates/opengit-ssh/src && touch crates/opengit-ssh/src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release 2>/dev/null || true

# Copy actual source code
COPY crates/ crates/

# Build all binaries
RUN cargo build --release

# -- Runtime stage -----------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r opengit && useradd -r -g opengit -d /home/opengit -s /bin/bash opengit

WORKDIR /home/opengit

# Copy binaries from builder
COPY --from=builder /build/target/release/opengit /usr/local/bin/
COPY --from=builder /build/target/release/og /usr/local/bin/
COPY --from=builder /build/target/release/opengit-sshd /usr/local/bin/

# Copy default config
COPY config/ ./config/

# Create data directories
RUN mkdir -p repos data && chown -R opengit:opengit /home/opengit

USER opengit

EXPOSE 9418

VOLUME ["/home/opengit/repos", "/home/opengit/data", "/home/opengit/config"]

ENTRYPOINT ["opengit"]
CMD ["--config", "config/server.toml"]

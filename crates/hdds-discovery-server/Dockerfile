# HDDS Discovery Server Docker Image
#
# Build:
#   docker build -t hdds-discovery-server -f crates/hdds-discovery-server/Dockerfile .
#
# Run:
#   docker run -p 7400:7400 hdds-discovery-server
#   docker run -p 7400:7400 hdds-discovery-server --relay
#   docker run -p 7400:7400 -v $(pwd)/config.json:/etc/hdds/config.json hdds-discovery-server -c /etc/hdds/config.json

# Build stage
FROM rust:1.82-bookworm AS builder

WORKDIR /usr/src/hdds

# Copy only what we need for building
COPY Cargo.toml Cargo.lock ./
COPY crates/hdds/Cargo.toml crates/hdds/
COPY crates/hdds/build.rs crates/hdds/
COPY crates/hdds/src crates/hdds/src
COPY crates/hdds/idl crates/hdds/idl
COPY crates/hdds-codegen crates/hdds-codegen
COPY crates/hdds-discovery-server crates/hdds-discovery-server

# Build release binary
RUN cargo build --release -p hdds-discovery-server

# Runtime stage - minimal image
FROM debian:bookworm-slim

# Install ca-certificates for TLS
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /usr/src/hdds/target/release/hdds-discovery-server /usr/local/bin/

# Create non-root user
RUN useradd -r -s /bin/false hdds
USER hdds

# Default port
EXPOSE 7400

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD nc -z localhost 7400 || exit 1

# Default command
ENTRYPOINT ["hdds-discovery-server"]
CMD ["--bind", "0.0.0.0", "--port", "7400"]

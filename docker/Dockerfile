# syntax=docker/dockerfile:1

FROM rust:1.74-bookworm AS builder
WORKDIR /workspace

# Cache dependency compilation by copying manifest files first
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

# Copy the rest of the workspace (docs and ancillary files are useful for build scripts)
COPY doc ./doc
COPY Justfile README.md LICENSE ./

RUN cargo build --release --bin veen --bin veen-hub --bin veen-selftest --bin veen-bridge

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG VEEN_UID=10001
ARG VEEN_GID=10001
RUN groupadd --system --gid ${VEEN_GID} veen \
    && useradd --system --uid ${VEEN_UID} --gid ${VEEN_GID} --create-home \
        --home-dir /var/lib/veen veen

WORKDIR /var/lib/veen

COPY --from=builder /workspace/target/release/veen /usr/local/bin/veen
COPY --from=builder /workspace/target/release/veen-hub /usr/local/bin/veen-hub
COPY --from=builder /workspace/target/release/veen-selftest /usr/local/bin/veen-selftest
COPY --from=builder /workspace/target/release/veen-bridge /usr/local/bin/veen-bridge

COPY docker/entrypoint.sh /usr/local/bin/veen-entrypoint.sh
RUN chmod 0755 /usr/local/bin/veen-entrypoint.sh \
    && mkdir -p /var/lib/veen \
    && chown -R veen:veen /var/lib/veen

ENV VEEN_DATA_DIR=/var/lib/veen \
    VEEN_LISTEN=0.0.0.0:37411 \
    VEEN_LOG_LEVEL=info \
    RUST_LOG=info,veen_hub=info

EXPOSE 37411
VOLUME ["/var/lib/veen"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["veen", "hub", "health", "--endpoint", "http://127.0.0.1:37411"]

USER veen

ENTRYPOINT ["/usr/local/bin/veen-entrypoint.sh"]
CMD []

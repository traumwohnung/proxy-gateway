# ============================================================================
# Stage 1: Build dependencies (cached unless Cargo.toml/Cargo.lock change)
#
# Copies workspace + crate manifests and dummy sources to cache dep compilation
# as a separate Docker layer that survives source-only changes.
# ============================================================================
FROM rust:1.87-slim-bookworm AS deps

WORKDIR /app

# Workspace manifest + crate manifest + lockfile
COPY Cargo.toml Cargo.lock ./
COPY proxy-rotator/Cargo.toml proxy-rotator/

# Dummy sources matching the real crate layout (lib + 2 bins)
RUN mkdir -p proxy-rotator/src/bin \
    && echo 'fn main() {}' > proxy-rotator/src/main.rs \
    && echo 'fn main() {}' > proxy-rotator/src/bin/gen_openapi.rs \
    && touch proxy-rotator/src/lib.rs

RUN cargo build --release 2>&1 \
    && rm -rf proxy-rotator/src

# ============================================================================
# Stage 2: Build the actual binary
# ============================================================================
FROM deps AS builder

COPY proxy-rotator/src/ proxy-rotator/src/

RUN find proxy-rotator/src -name '*.rs' -exec touch {} +

RUN cargo build --release --bin proxy-rotator \
    && strip target/release/proxy-rotator

# ============================================================================
# Stage 3: Minimal runtime image
# ============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin appuser

COPY --from=builder /app/target/release/proxy-rotator /usr/local/bin/proxy-rotator

RUN mkdir -p /data/config && chown appuser:appuser /data/config
VOLUME /data/config

ENV RUST_LOG=info

USER appuser
EXPOSE 8100

ENTRYPOINT ["proxy-rotator"]
CMD ["/data/config/config.toml"]

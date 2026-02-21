# ============================================================================
# Stage 1: Build dependencies (cached unless Cargo.toml/Cargo.lock change)
# ============================================================================
FROM rust:1.93.1-slim-trixie AS deps

WORKDIR /app

# Copy only manifests — triggers dep rebuild only when these change.
# The dummy src/main.rs lets `cargo build` compile all deps.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release 2>&1 && rm -rf src

# ============================================================================
# Stage 2: Build the actual binary (cached deps from stage 1)
# ============================================================================
FROM deps AS builder

COPY src/ src/
# Touch main.rs so cargo sees it's newer than the dummy
RUN touch src/main.rs
RUN cargo build --release --bin proxy-rotator \
    && strip target/release/proxy-rotator

# ============================================================================
# Stage 3: Minimal runtime image
# ============================================================================
FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin appuser

COPY --from=builder /app/target/release/proxy-rotator /usr/local/bin/proxy-rotator

# Config + proxies volume
RUN mkdir -p /data/config && chown appuser:appuser /data/config
VOLUME /data/config

ENV RUST_LOG=info

USER appuser
EXPOSE 8100

ENTRYPOINT ["proxy-rotator"]
CMD ["/data/config/config.toml"]

# Dockerfile for Sentinel Interceptor (Rust)

# Build stage
FROM rust:1.75 as builder
WORKDIR /app
RUN cargo install cargo-chef
COPY Cargo.toml Cargo.lock ./
RUN cargo chef prepare --recipe-path recipe.json
COPY . .
RUN cargo chef cook --release --recipe-path recipe.json
RUN cargo build --release

# Runtime stage
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/sentinel-interceptor /usr/local/bin/sentinel-interceptor
COPY --from=builder /app/policies.yaml /app/policies.yaml
COPY --from=builder /app/tool_registry.yaml /app/tool_registry.yaml
ENTRYPOINT ["/usr/local/bin/sentinel-interceptor"]


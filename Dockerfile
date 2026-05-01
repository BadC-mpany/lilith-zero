FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the pre-built release binary
COPY lilith-zero/target/release/lilith-zero /app/lilith-zero
COPY examples/copilot_studio/copilot_studio_policy.yaml /app/policy.yaml

RUN chmod +x /app/lilith-zero && \
    mkdir -p /home/.lilith/sessions /home/LogFiles

# Azure App Service sets PORT env var; default to 8080
ENV PORT=8080
ENV RUST_LOG=info

# Entry point: run in webhook serve mode
# Auth mode is set to 'entra' via env vars (see startup.sh or app settings)
CMD ["/app/lilith-zero", "serve", \
     "--bind", "0.0.0.0:8080", \
     "--auth-mode", "none", \
     "--policy", "/app/policy.yaml"]

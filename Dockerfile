FROM ubuntu:24.04


RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the pre-built release binary and multi-tenant policies
COPY lilith-zero/target/release/lilith-zero /app/lilith-zero
COPY examples/copilot_studio/policies /app/policies

RUN chmod +x /app/lilith-zero && \
    mkdir -p /home/.lilith/sessions /home/LogFiles

# Azure App Service sets PORT env var; default to 8080
ENV PORT=8080
ENV RUST_LOG=info
# Use /home/.lilith/sessions — Azure App Service mounts /home as persistent Azure Files storage.
# Without this, the app defaults to $HOME/.lilith/sessions = /root/.lilith/sessions,
# which is ephemeral container storage and is lost on every container restart.
ENV LILITH_ZERO_SESSION_STORAGE_DIR=/home/.lilith/sessions

# Entry point: run in webhook serve mode
# Pointing --policy to a directory enables multi-tenant routing based on filenames (policy_<agent_id>.cedar)
CMD ["/app/lilith-zero", "serve", "--bind", "0.0.0.0:8080", "--auth-mode", "none", "--policy", "/app/policies"]



# Dockerfile for running Kani on Windows via Docker
# Usage: docker build -t lilith-kani -f kani.Dockerfile .
#        docker run --rm -v $(pwd):/app lilith-kani cargo kani

FROM rust:latest

# Install Kani dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Kani
RUN cargo install --locked kani-verifier
RUN cargo kani setup

WORKDIR /app

# Pre-fetch dependencies to speed up repeated runs
# (Optional optimization, skipping for simplicity to avoid cache invalidation issues)

CMD ["cargo", "kani"]

FROM debian:bullseye-slim

LABEL maintainer="base-images@example.com"
LABEL description="Base image with incorrect ONBUILD usage"

# Install common dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Positive case 1: ONBUILD FROM is not allowed (incorrect)
ONBUILD FROM debian

# Set up common build patterns
ONBUILD RUN mkdir -p /app/logs

# Positive case 2: ONBUILD MAINTAINER is not allowed (incorrect)
ONBUILD MAINTAINER Ron Weasley

# Configure build-time dependencies
ONBUILD RUN apt-get update && apt-get install -y build-essential

# Set environment variables
ENV APP_ENV=production \
    LOG_LEVEL=info

# Create application user
RUN groupadd -r appuser && \
    useradd -r -g appuser appuser

# Expose default port
EXPOSE 8080

USER appuser

CMD ["/bin/bash"]

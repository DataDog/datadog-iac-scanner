FROM ubuntu:22.04

LABEL maintainer="platform@example.com"
LABEL description="Redis container with proper useradd flags"
LABEL version="7.0.0"

# Install Redis and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    redis-server \
    ca-certificates \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create Redis directories
RUN mkdir -p /var/lib/redis /var/log/redis /etc/redis && \
    chown -R redis:redis /var/lib/redis /var/log/redis

WORKDIR /var/lib/redis

# Negative case 1: useradd with -l flag (prevents large UID in lastlog, reduces disk usage)
RUN useradd -l -u 123456 foobar --no-log-init

# Negative case 2: useradd with -ul flag (prevents large UID in lastlog, reduces disk usage)
RUN useradd -ul 123456 foobar

# Negative case 2: useradd with --no-log-init flag (prevents large UID in lastlog, reduces disk usage)
RUN useradd -u 123456 foobar --no-log-init

# Copy Redis configuration
COPY redis.conf /etc/redis/redis.conf

# Set proper permissions on config
RUN chown redis:redis /etc/redis/redis.conf && \
    chmod 644 /etc/redis/redis.conf

# Set environment variables
ENV REDIS_PORT=6379 \
    REDIS_MAXMEMORY=256mb \
    REDIS_MAXMEMORY_POLICY=allkeys-lru

# Expose Redis port
EXPOSE 6379

# Create volume for Redis data
VOLUME ["/var/lib/redis"]

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD redis-cli ping || exit 1

# Switch to Redis user
USER redis

# Start Redis server
CMD ["redis-server", "/etc/redis/redis.conf"]

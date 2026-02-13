---
title: "Use recommended flags with useradd"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/use_recommended_flags_with_useradd"
  id: "44fbf45c-87a6-3b95-64ef-07e1fef7395b"
  display_name: "Use recommended flags with useradd"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `44fbf45c-87a6-3b95-64ef-07e1fef7395b`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://man7.org/linux/man-pages/man8/useradd.8.html)

### Description

Creating users in Docker images without disabling login record creation causes `utmp`, `wtmp`, and `lastlog` entries to be written into image layers. This increases image size and can embed unnecessary host or user metadata in the image.  

This rule scans `dockerfile_container` `RUN` commands for `useradd` invocations and requires the command to include either the short `-l` flag (which may be combined with other short flags) or the long `--no-log-init` option to prevent login file initialization.  

Resources that invoke `useradd` without `-l` or `--no-log-init` are flagged. Use one of the safe invocations below when creating users in Dockerfiles:

```dockerfile
# using short flag (can be combined with other short flags)
RUN useradd -l -r -s /sbin/nologin myuser
```

```dockerfile
# using long option
RUN useradd --no-log-init -r -s /sbin/nologin myuser
```

## Compliant Code Examples
```dockerfile
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

```
## Non-Compliant Code Examples
```dockerfile
FROM ubuntu:22.04

LABEL maintainer="platform@example.com"
LABEL description="Database container without proper useradd flags"

# Install PostgreSQL and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-14 \
    postgresql-contrib-14 \
    postgresql-client-14 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create data directory
RUN mkdir -p /var/lib/postgresql/data && \
    chown -R postgres:postgres /var/lib/postgresql

WORKDIR /var/lib/postgresql

# Positive case: useradd without -l flag and --no-log-init flag (doesn't prevent large UID in lastlog)
RUN useradd -u 123456 foobar


# Configure PostgreSQL
RUN mkdir -p /var/run/postgresql && \
    chown -R postgres:postgres /var/run/postgresql

# Set environment variables
ENV POSTGRES_DB=myapp \
    POSTGRES_USER=appuser \
    PGDATA=/var/lib/postgresql/data

# Expose PostgreSQL port
EXPOSE 5432

# Volume for data persistence
VOLUME ["/var/lib/postgresql/data"]

USER postgres

CMD ["postgres"]

```
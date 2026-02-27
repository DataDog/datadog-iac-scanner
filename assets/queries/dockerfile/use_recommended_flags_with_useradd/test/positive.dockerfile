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

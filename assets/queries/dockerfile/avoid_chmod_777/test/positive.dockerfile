FROM alpine:3.14 AS builder

LABEL maintainer="security-team@example.com"
LABEL description="Build stage for application compilation"

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    make

WORKDIR /build

# Positive case 1: ADD with chmod 777 - insecure permissions on source code
ADD --chmod=777 src dst

# Copy build scripts
COPY build.sh /build/

# Compile application
RUN make build

# Final stage
FROM alpine:3.14

LABEL maintainer="security-team@example.com"
LABEL description="Production image for web application"

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    curl

WORKDIR /app

# Create application user
RUN addgroup -g 1000 appgroup && \
    adduser -D -u 1000 -G appgroup appuser

# Positive case 2: COPY with chmod 777 - world-writable configuration files
COPY --chmod=777 src dst

# Positive case 3: ADD with chmod 777 and other flags - insecure data directory
ADD --chown=user:group --chmod=777 src dst

# Positive case 4: COPY with chmod 777 and other flags - insecure application binary
COPY --chown=user:group --chmod=777 src dst

# Copy application files from builder
COPY --from=builder /build/app /app/

# Set environment variables
ENV APP_PORT=8080 \
    APP_ENV=production

# Expose application port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

USER appuser

CMD ["/app/app"]

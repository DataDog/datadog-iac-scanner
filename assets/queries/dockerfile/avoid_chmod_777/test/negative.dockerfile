FROM golang:1.21-alpine AS builder

LABEL maintainer="security-team@example.com"
LABEL description="Secure build stage for Go application"

# Install build dependencies
RUN apk add --no-cache \
    git \
    gcc \
    musl-dev

WORKDIR /build

# Copy go module files
COPY go.mod go.sum ./
RUN go mod download

# Negative case 1: ADD with safe permissions (755) for executable scripts
ADD --chmod=755 src dst

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# Final stage
FROM alpine:3.14

LABEL maintainer="security-team@example.com"
LABEL description="Secure production image for Go application"
LABEL version="1.0.0"

# Install CA certificates and other runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl

WORKDIR /app

# Create non-root user with specific UID/GID
RUN addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup -h /app appuser

# Negative case 2: COPY with safe permissions (755) for application binary
COPY --chmod=755 src dst

# Negative case 3: ADD with restrictive permissions (644) for config files
ADD --chmod=644 src dst

# Negative case 4: COPY with restrictive permissions (600) for secrets
COPY --chmod=600 src dst

# Negative case 5: ADD without chmod flag - uses default secure permissions
ADD src dst

# Negative case 6: COPY without chmod flag - uses default secure permissions
COPY src dst

# Negative case 7: ADD with chown but no chmod - secure ownership
ADD --chown=user:group src dst

# Negative case 8: COPY with chown but no chmod - secure ownership
COPY --chown=user:group src dst

# Copy application binary from builder with proper ownership
COPY --from=builder --chown=appuser:appgroup /build/app /app/

# Set secure environment variables
ENV APP_PORT=8080 \
    APP_ENV=production \
    APP_LOG_LEVEL=info

# Create necessary directories with proper permissions
RUN mkdir -p /app/data /app/logs && \
    chown -R appuser:appgroup /app

# Expose application port
EXPOSE 8080

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Switch to non-root user
USER appuser

# Use exec form for proper signal handling
CMD ["/app/app"]

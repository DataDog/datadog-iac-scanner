# Negative case: Proper Dockerfile with FROM statements

FROM image as base

LABEL maintainer="backend-team@example.com"
LABEL description="Backend API service"

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source code
COPY . /build/

# Build the application
RUN make build

# Negative case: Multi-stage build with proper second FROM
FROM image2

LABEL maintainer="backend-team@example.com"
LABEL description="Production backend API"
LABEL version="1.5.0"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built artifacts from builder stage
COPY --from=base /build/dist /app/

# Create application user
RUN groupadd -r apiuser && \
    useradd -r -g apiuser -d /app -s /sbin/nologin apiuser && \
    chown -R apiuser:apiuser /app

# Set environment variables
ENV APP_ENV=production \
    PORT=8080 \
    LOG_LEVEL=info

# Expose application port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Switch to non-root user
USER apiuser

# Start the application
CMD ["/app/server"]

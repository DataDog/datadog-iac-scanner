# Negative case 1: Starting with ARG (correct - can precede FROM)
ARG foo

FROM nginx:${foo:-1.25}-alpine AS builder

LABEL maintainer="web-team@example.com"
LABEL description="Nginx static site builder with proper first instruction"

# Set build arguments
ARG BUILD_DATE
ARG VERSION=1.0.0

LABEL build_date="${BUILD_DATE}"
LABEL version="${VERSION}"

# Install build tools
RUN apk add --no-cache \
    nodejs \
    npm \
    git

WORKDIR /build

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build static site
RUN npm run build

# Production stage
FROM nginx:1.25-alpine

LABEL maintainer="web-team@example.com"
LABEL description="Production Nginx static site"

# Install runtime dependencies
RUN apk add --no-cache \
    curl \
    tzdata

# Negative case 2: RUN command after FROM (correct order)
RUN something

# Remove default nginx config
RUN rm -rf /usr/share/nginx/html/*

# Copy built site from builder
COPY --from=builder --chown=nginx:nginx /build/dist /usr/share/nginx/html

# Copy custom nginx configuration
COPY --chown=nginx:nginx nginx.conf /etc/nginx/nginx.conf
COPY --chown=nginx:nginx default.conf /etc/nginx/conf.d/default.conf

# Create necessary directories
RUN mkdir -p /var/cache/nginx /var/log/nginx && \
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx && \
    chmod -R 755 /var/cache/nginx

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Switch to non-root user
USER nginx

# Start nginx
CMD ["nginx", "-g", "daemon off;"]

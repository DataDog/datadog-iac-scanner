FROM node:18-alpine AS builder

LABEL maintainer="frontend-team@example.com"
LABEL description="Vue.js application builder with proper cache cleanup"

# Install system dependencies for node-gyp
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git

WORKDIR /build

# Set yarn configuration for optimal performance
RUN yarn config set network-timeout 300000

# Copy package files for dependency installation
COPY package.json yarn.lock ./

# Negative case 1: yarn install with cache clean (reduces image size)
RUN yarn install \
 && yarn cache clean

# Copy application source code
COPY . .

# Run linting
RUN yarn lint

# Build the application for production
RUN yarn build

# Production stage
FROM nginx:1.25-alpine

LABEL maintainer="frontend-team@example.com"
LABEL description="Production Vue.js application with Nginx"
LABEL version="2.1.0"

# Install curl for health checks
RUN apk add --no-cache curl

# Copy built application from builder
COPY --from=builder /build/dist /usr/share/nginx/html

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf

# Create cache directory with proper permissions
RUN mkdir -p /var/cache/nginx && \
    chown -R nginx:nginx /var/cache/nginx && \
    chmod -R 755 /var/cache/nginx

# Negative case 2.1: yarn install with cache clean (reduces image size)
RUN yarn install

# Remove default nginx config
RUN rm -f /etc/nginx/conf.d/default.conf.dpkg-dist

# Negative case 2.2: yarn install with cache clean (reduces image size)
RUN yarn cache clean

# Set proper permissions
RUN chown -R nginx:nginx /usr/share/nginx/html

# Expose HTTP port
EXPOSE 80

# Health check for the application
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Switch to non-root user
USER nginx

# Start nginx
CMD ["nginx", "-g", "daemon off;"]

---
title: "Run yarn clean after yarn install"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/run_yarn_clean_after_yarn_install"
  id: "9e13082c-2e00-278b-8ee9-34f43fffc791"
  display_name: "Run yarn clean after yarn install"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `9e13082c-2e00-278b-8ee9-34f43fffc791`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://classic.yarnpkg.com/en/docs/cli/cache/)

### Description

Dockerfiles that run `yarn install` must remove the Yarn package cache afterward, because leftover cache files increase image size and may retain build-time artifacts in image layers, expanding the attack surface.  

This rule inspects Dockerfile `RUN` instructions (resource type `dockerfile_container`) and flags cases where a `RUN` executes `yarn install` without a corresponding `yarn cache clean`.  

To remediate, chain the cleanup in the same `RUN` instruction (for example, `RUN yarn install && yarn cache clean`) so the cache is removed within the same layer. Running `yarn cache clean` in a later `RUN` may not eliminate cache files stored in earlier layers.

Secure example:

```dockerfile
RUN yarn install --production && yarn cache clean --force
```

## Compliant Code Examples
```dockerfile
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

```
## Non-Compliant Code Examples
```dockerfile
FROM node:18-alpine AS builder

LABEL maintainer="frontend-team@example.com"
LABEL description="React application builder without cache cleanup"

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++

WORKDIR /build

# Copy package files
COPY package.json yarn.lock ./

# Positive case: yarn install without cache clean (leaves cache, increases image size)
RUN yarn install

# Copy application source
COPY . .

# Build the application
RUN yarn build

# Production stage
FROM node:18-alpine

LABEL maintainer="frontend-team@example.com"
LABEL description="Production React application"

# Install serve to run the static site
RUN apk add --no-cache curl && \
    yarn global add serve

WORKDIR /app

# Copy built application from builder
COPY --from=builder /build/dist ./dist

# Create application user
RUN addgroup -g 1001 nodeapp && \
    adduser -D -u 1001 -G nodeapp nodeapp && \
    chown -R nodeapp:nodeapp /app

# Set environment variables
ENV NODE_ENV=production \
    PORT=3000

# Expose application port
EXPOSE 3000

USER nodeapp

CMD ["serve", "-s", "dist", "-l", "3000"]

```
---
title: "First instruction must be ARG or FROM"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/first_instruction_should_be_arg_or_from"
  id: "52e2b1c6-56e4-5264-2fc6-523166b2c8f3"
  display_name: "First instruction must be ARG or FROM"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `52e2b1c6-56e4-5264-2fc6-523166b2c8f3`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#from)

### Description

Dockerfiles must start with either an `ARG` or `FROM` instruction, because the initial instruction defines the base image and the scope of build-time variables. Placing another instruction first can result in unintended base images, mis-scoped build arguments, and unpredictable build-time behavior that increases supply-chain and configuration risks.  

This rule inspects `dockerfile_container` resources and flags cases where the earliest parsed instruction is not `ARG` or `FROM`.  

To remediate, ensure the first non-comment line in the Dockerfile is an `ARG` (when build-time variables must be substituted into `FROM`) or a `FROM` instruction that explicitly defines the base image.  

Secure examples:

```dockerfile
# ARG before FROM to allow substitution in the base image
ARG BASE_IMAGE=alpine:3.16
FROM ${BASE_IMAGE}
```

```dockerfile
# Direct FROM as the first instruction
FROM ubuntu:22.04
```

## Compliant Code Examples
```dockerfile
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

```
## Non-Compliant Code Examples
```dockerfile
# Positive case 1: Starting with COPY instead of FROM or ARG (incorrect)
COPY foo bar

RUN command

FROM nginx:1.25-alpine

LABEL maintainer="web-team@example.com"
LABEL description="Nginx static site with incorrect first instruction"

# Install additional tools
RUN apk add --no-cache \
    curl \
    bash

WORKDIR /usr/share/nginx/html

ADD foo bar

# Copy website files
COPY --chown=nginx:nginx ./dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create cache directory
RUN mkdir -p /var/cache/nginx && \
    chown -R nginx:nginx /var/cache/nginx

# Expose HTTP and HTTPS ports
EXPOSE 80 443

USER nginx

CMD ["nginx", "-g", "daemon off;"]

```
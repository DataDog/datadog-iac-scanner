---
title: "Multiple HEALTHCHECK instructions"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/do_not_use_multiple_healthcheck"
  id: "1c2d47bd-eec6-6485-7ed7-3d0650e960a4"
  display_name: "Multiple HEALTHCHECK instructions"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `1c2d47bd-eec6-6485-7ed7-3d0650e960a4`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#healthcheck)

### Description

Multiple `HEALTHCHECK` instructions in a Dockerfile create ambiguity and can cause health monitoring to behave unpredictably. This can hide failing containers or produce false healthy or failed signals.  

Dockerfile resources must include at most one `HEALTHCHECK` instruction, because Docker applies only the last `HEALTHCHECK` it encounters. Additional `HEALTHCHECK` lines are ignored and can lead to unintended monitoring behavior.  

This rule scans `dockerfile_container` resources for `HEALTHCHECK` commands and flags any occurrences beyond the first. Fix by consolidating probe logic into a single `HEALTHCHECK` or removing redundant instructions so the container's health status is unambiguous and reflects the intended check.

Secure example with a single `HEALTHCHECK`:

```dockerfile
FROM alpine:3.18
COPY app /usr/local/bin/app
HEALTHCHECK --interval=30s --timeout=5s CMD wget -q -O- http://localhost:8080/health || exit 1
CMD ["app"]
```

## Compliant Code Examples
```dockerfile
FROM python:3.11-slim AS builder

LABEL maintainer="devops@example.com"
LABEL description="Python FastAPI application builder"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# Production stage
FROM python:3.11-slim

LABEL maintainer="devops@example.com"
LABEL description="Production Python FastAPI application"
LABEL version="2.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/appuser/.local/bin:$PATH \
    PORT=8000

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create non-root user
RUN groupadd -r appuser && \
    useradd -r -g appuser -d /home/appuser -s /sbin/nologin -c "Application user" appuser && \
    mkdir -p /home/appuser/.local && \
    chown -R appuser:appuser /home/appuser /app

# Copy Python dependencies from builder
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appuser . /app/

# Expose application port
EXPOSE 8000

# Negative case: Single HEALTHCHECK instruction (correct)
HEALTHCHECK CMD foo

# Switch to non-root user
USER appuser

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

```
## Non-Compliant Code Examples
```dockerfile
FROM node:18-alpine AS builder

LABEL maintainer="platform-team@example.com"
LABEL description="Node.js application with multiple healthchecks (incorrect)"

WORKDIR /build

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application source
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine

LABEL maintainer="platform-team@example.com"
LABEL description="Production Node.js application"

# Install curl for health checks
RUN apk add --no-cache curl

WORKDIR /app

# Copy built application from builder
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/package.json ./

# Create application user
RUN addgroup -g 1001 nodeapp && \
    adduser -D -u 1001 -G nodeapp nodeapp && \
    chown -R nodeapp:nodeapp /app

# Set environment variables
ENV NODE_ENV=production \
    PORT=3000

# Expose application port
EXPOSE 3000

HEALTHCHECK CMD foo

# Positive case 1: Second healthcheck for database (multiple HEALTHCHECKs - only last one applies)
HEALTHCHECK CMD bar

USER nodeapp

CMD ["node", "dist/server.js"]

```
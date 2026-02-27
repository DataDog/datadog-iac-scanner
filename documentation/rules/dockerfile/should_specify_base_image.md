---
title: "Dockerfile should specify base image"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/should_specify_base_image"
  id: "19619060-f22e-094f-fda1-aacf37b69bba"
  display_name: "Dockerfile should specify base image"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `19619060-f22e-094f-fda1-aacf37b69bba`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#from)

### Description

Dockerfiles must include a `FROM` instruction that specifies a base image to ensure the built image has the intended runtime and dependencies. Without it, the build may unintentionally produce a bare `scratch` image that lacks essential components.  

This rule inspects `dockerfile_container` resources and checks the `command` entries for at least one `FROM` instruction.  

Resources that do not contain a `FROM` instruction are flagged. To remediate, add a top-level `FROM <image>` line to explicitly declare the base image.  

Secure example Dockerfile:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```

## Compliant Code Examples
```dockerfile
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

```
## Non-Compliant Code Examples
```dockerfile
# Positive case: Dockerfile without FROM statement (missing base image)

LABEL maintainer="broken-team@example.com"
LABEL description="Invalid file without base image"

# Install packages (this won't work without a base image)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim

WORKDIR /app

# Set environment variables
ENV APP_ENV=production \
    PORT=8080

# Copy application files
COPY . /app/

# Positive case: RUN command without a base image context
RUN echo "hello"

# Expose port
EXPOSE 8080

# This Dockerfile is invalid because it doesn't start with FROM
CMD ["echo", "This will never execute"]

```
---
title: "Use only allowed registry in FROM"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/use_only_an_allowed_registry_in_the_from_image"
  id: "d0b535a2-5e5f-d18f-52f8-cc59a3f236bd"
  display_name: "Use only allowed registry in FROM"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "HIGH"
  category: "Supply-Chain"
---
## Metadata

**Id:** `d0b535a2-5e5f-d18f-52f8-cc59a3f236bd`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** High

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#from)

### Description

Base images referenced in Dockerfiles must originate from trusted registries to reduce the risk of supply-chain compromise, malicious image insertion, or execution of unvetted binaries in containers.  

This rule inspects the `FROM` instruction in `dockerfile_container` resources and requires the registry prefix (the substring before the first `/`) to match an allowed registry. By default, only `docker.io` is permitted.  

Any `FROM` instruction that explicitly specifies a registry not in the allowed list (for example, `gcr.io/myimage`) is flagged. Images that do not include an explicit registry (no `/`) are not evaluated by this rule, and multi-stage references containing a space (for example, `FROM builder AS final`) are excluded.

Secure example:

```Dockerfile
FROM docker.io/library/nginx:1.21
```

## Compliant Code Examples
```dockerfile
# Negative case: Using image from trusted Docker Hub registry (default)
FROM python:3.6

LABEL maintainer="ml-team@example.com"
LABEL description="Machine learning application from trusted registry"
LABEL version="1.3.0"

# Set Python environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Negative case: Running command on trusted base image
RUN acommand

# Copy application code
COPY . .

# Create application directories
RUN mkdir -p /app/models /app/data /app/logs && \
    chmod -R 755 /app

# Create non-root user
RUN groupadd -r mluser && \
    useradd -r -g mluser -d /app -s /sbin/nologin mluser && \
    chown -R mluser:mluser /app

# Set additional environment variables
ENV MODEL_DIR=/app/models \
    DATA_DIR=/app/data \
    LOG_DIR=/app/logs \
    PORT=5000

# Expose application port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')" || exit 1

# Switch to non-root user
USER mluser

# Start the application
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]

```
## Non-Compliant Code Examples
```dockerfile
# Positive case 1: Using image from untrusted/random registry
FROM randomrepo/python:3.6

LABEL maintainer="data-science@example.com"
LABEL description="Python data processing application from untrusted registry"

# Install Python packages
RUN pip install --no-cache-dir \
    pandas \
    numpy \
    scipy \
    scikit-learn

WORKDIR /app

# Copy application code
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directories
RUN mkdir -p /app/data /app/output && \
    chmod 755 /app/data /app/output

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data \
    OUTPUT_DIR=/app/output

EXPOSE 8000

CMD ["python", "app.py"]

# Positive case 2: Using image from non-standard registry
FROM registry.something.io/images/base/ubuntu_2204:release

LABEL maintainer="infrastructure@example.com"
LABEL description="Ubuntu base from untrusted registry"

# Update and install packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Positive case 3: Running commands on untrusted base image
RUN acommand

# Install development tools
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m -s /bin/bash developer && \
    chown -R developer:developer /workspace

USER developer

CMD ["/bin/bash"]

```
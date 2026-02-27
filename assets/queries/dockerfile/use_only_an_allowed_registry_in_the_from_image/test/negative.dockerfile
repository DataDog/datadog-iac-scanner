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

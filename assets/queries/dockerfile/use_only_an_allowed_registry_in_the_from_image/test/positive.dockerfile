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

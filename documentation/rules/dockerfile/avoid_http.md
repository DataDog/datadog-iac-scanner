---
title: "Avoid HTTP"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/avoid_http"
  id: "d5b3c9a1-7e8f-4c2a-9d6e-3f1a8b4c7e9d"
  display_name: "Avoid HTTP"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `d5b3c9a1-7e8f-4c2a-9d6e-3f1a8b4c7e9d`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/)

### Description

Dockerfile `RUN` commands must not fetch resources over unencrypted HTTP, because clear-text downloads can be intercepted or modified in transit. This increases the risk of supply-chain compromise or execution of malicious code in the built image.  

This rule inspects `dockerfile_container` resources' `RUN` entries and flags tokens containing `http://` (matches `http:` but not `https:`). URLs must use `https://` instead of `http://`. Localhost addresses (`http://localhost`, `http://127.0.0.1`, `http://[::1]`) are excluded from detection.  

When switching to HTTPS, also verify artifact integrity (for example, with checksums or signatures) or use trusted TLS-protected registries to further reduce tampering risk.

Secure example using HTTPS and checksum verification:

```Dockerfile
RUN curl -fsSL https://example.com/artifact.tar.gz -o /tmp/artifact.tar.gz && \
    echo "3b7d6f...  /tmp/artifact.tar.gz" | sha256sum -c -
```

## Compliant Code Examples
```dockerfile
FROM ubuntu:22.04

LABEL maintainer="security-team@example.com"
LABEL description="Secure Scala application with proper HTTPS downloads"
LABEL version="1.0.0"

# Set environment variables
ENV SCALA_VERSION=2.13.10 \
    SBT_VERSION=1.9.0 \
    DEBIAN_FRONTEND=noninteractive \
    APP_HOME=/app

# Install system dependencies with security considerations
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    ca-certificates \
    openjdk-11-jdk \
    gnupg2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR ${APP_HOME}

# Negative case 1: Download configuration file using HTTPS with wget (secure)
RUN cd /tmp && wget https://www.scalastyle.org/scalastyle_config.xml && mv scalastyle_config.xml /scalastyle_config.xml

# Install Scala from trusted source
RUN wget https://downloads.lightbend.com/scala/${SCALA_VERSION}/scala-${SCALA_VERSION}.tgz && \
    wget https://downloads.lightbend.com/scala/${SCALA_VERSION}/scala-${SCALA_VERSION}.tgz.sha256 && \
    sha256sum -c scala-${SCALA_VERSION}.tgz.sha256 && \
    tar xzf scala-${SCALA_VERSION}.tgz && \
    mv scala-${SCALA_VERSION} /usr/local/scala && \
    rm scala-${SCALA_VERSION}.tgz scala-${SCALA_VERSION}.tgz.sha256

# Set Scala environment
ENV PATH="/usr/local/scala/bin:${PATH}" \
    SCALA_HOME="/usr/local/scala"

# Negative case 2: Download configuration file using HTTPS with curl (secure)
RUN cd /tmp && curl -O https://www.scalastyle.org/scalastyle_config.xml && mv scalastyle_config.xml /scalastyle_config.xml

# Install SBT from trusted source
RUN curl -fsSL "https://github.com/sbt/sbt/releases/download/v${SBT_VERSION}/sbt-${SBT_VERSION}.tgz" -o sbt-${SBT_VERSION}.tgz && \
    tar xzf sbt-${SBT_VERSION}.tgz && \
    mv sbt /usr/local/ && \
    rm sbt-${SBT_VERSION}.tgz

# Set SBT environment
ENV PATH="/usr/local/sbt/bin:${PATH}" \
    SBT_OPTS="-Xmx2048M -Xss2M"

# Negative case 3: HTTP to localhost is acceptable (local service)
RUN cd /tmp && curl -O http://localhost:8080/path

# Negative case 4: HTTP to 127.0.0.1 is acceptable (local service)
RUN cd /tmp && curl -O http://127.0.0.1:8080/path

# Negative case 5: HTTP to IPv6 localhost is acceptable (local service)
RUN cd /tmp && curl -O http://[::1]:8080/path

# Copy application source
COPY --chown=scalaapp:scalaapp . ${APP_HOME}/

# Create application user with no login shell
RUN groupadd -r -g 1000 scalaapp && \
    useradd -r -u 1000 -g scalaapp -d ${APP_HOME} -s /sbin/nologin scalaapp && \
    chown -R scalaapp:scalaapp ${APP_HOME}

# Create directories for logs and cache
RUN mkdir -p ${APP_HOME}/logs ${APP_HOME}/cache && \
    chown -R scalaapp:scalaapp ${APP_HOME}

# Expose application port
EXPOSE 9000

# Health check for the application
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9000/health || exit 1

# Switch to non-root user
USER scalaapp

# Set working directory
WORKDIR ${APP_HOME}

# Use exec form for proper signal handling
CMD ["sbt", "-Dconfig.file=/app/application.conf", "run"]

```
## Non-Compliant Code Examples
```dockerfile
FROM ubuntu:22.04

LABEL maintainer="devops@example.com"
LABEL description="Scala application with linting configuration"

# Set environment variables
ENV SCALA_VERSION=2.13.10 \
    SBT_VERSION=1.9.0 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    openjdk-11-jdk \
    gnupg2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Positive case 1: Download configuration file using HTTP with wget (insecure)
RUN cd /tmp && wget http://www.scalastyle.org/scalastyle_config.xml && mv scalastyle_config.xml /scalastyle_config.xml

# Install Scala
RUN wget https://downloads.lightbend.com/scala/${SCALA_VERSION}/scala-${SCALA_VERSION}.tgz && \
    tar xzf scala-${SCALA_VERSION}.tgz && \
    mv scala-${SCALA_VERSION} /usr/local/scala && \
    rm scala-${SCALA_VERSION}.tgz

# Set Scala environment
ENV PATH="/usr/local/scala/bin:${PATH}"

# Positive case 2: Download configuration file using HTTP with curl (insecure)
RUN cd /tmp && curl -O http://www.scalastyle.org/scalastyle_config.xml && mv scalastyle_config.xml /scalastyle_config.xml

# Install SBT
RUN wget https://github.com/sbt/sbt/releases/download/v${SBT_VERSION}/sbt-${SBT_VERSION}.tgz && \
    tar xzf sbt-${SBT_VERSION}.tgz && \
    mv sbt /usr/local/ && \
    rm sbt-${SBT_VERSION}.tgz

# Set SBT environment
ENV PATH="/usr/local/sbt/bin:${PATH}"

# Copy application source
COPY . /app/

# Create application user
RUN groupadd -r scalaapp && useradd -r -g scalaapp scalaapp && \
    chown -R scalaapp:scalaapp /app

# Expose application port
EXPOSE 9000

USER scalaapp

CMD ["sbt", "run"]

```
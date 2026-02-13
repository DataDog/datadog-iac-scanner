---
title: "ONBUILD cannot trigger FROM or MAINTAINER"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/from_or_maintainer_cannot_be_triggered_within_onbuild"
  id: "408460f2-2a0f-21ab-ab37-4fb86ac3b5ce"
  display_name: "ONBUILD cannot trigger FROM or MAINTAINER"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `408460f2-2a0f-21ab-ab37-4fb86ac3b5ce`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#onbuild)

### Description

`ONBUILD` instructions must not trigger `FROM`, `MAINTAINER`, or another `ONBUILD`, because these directives can change the base image or persisted metadata in downstream builds. This can create recursive or unexpected build behavior that undermines build integrity and supply-chain security.  

This rule inspects `dockerfile_container` resources for Dockerfile `ONBUILD` instructions and verifies that the triggered subcommand is not `FROM`, `MAINTAINER`, or `ONBUILD`.  

Resources where `ONBUILD` triggers `FROM`, `MAINTAINER`, or `ONBUILD` are flagged and should be refactored to invoke safer build actions (for example, `RUN` or `COPY`).

Secure `ONBUILD` example:

```
ONBUILD RUN apt-get update && apt-get install -y curl
```

## Compliant Code Examples
```dockerfile
FROM maven:3-jdk-8

LABEL maintainer="java-platform@example.com"
LABEL description="Maven base image for Java applications"
LABEL version="1.0.0"

# Set Maven environment variables
ENV MAVEN_CONFIG=/root/.m2 \
    MAVEN_OPTS="-XX:+TieredCompilation -XX:TieredStopAtLevel=1"

# Install additional build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Configure Maven settings
RUN mkdir -p /root/.m2 && \
    echo '<settings><localRepository>/root/.m2/repository</localRepository></settings>' > /root/.m2/settings.xml

# Create application directory
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

# Negative case 1: ONBUILD ADD is allowed (correct)
ONBUILD ADD . /usr/src/app

# Copy Maven wrapper if present
ONBUILD COPY mvnw* ./
ONBUILD COPY .mvn .mvn

# Download dependencies (will be cached)
ONBUILD COPY pom.xml ./
ONBUILD RUN mvn dependency:go-offline

# Copy source and build
ONBUILD COPY src ./src

# Negative case 2: ONBUILD RUN is allowed (correct)
ONBUILD RUN mvn install

# Package the application
ONBUILD RUN mvn clean package -DskipTests

# Set default command
CMD ["mvn", "--version"]

```
## Non-Compliant Code Examples
```dockerfile
FROM debian:bullseye-slim

LABEL maintainer="base-images@example.com"
LABEL description="Base image with incorrect ONBUILD usage"

# Install common dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Positive case 1: ONBUILD FROM is not allowed (incorrect)
ONBUILD FROM debian

# Set up common build patterns
ONBUILD RUN mkdir -p /app/logs

# Positive case 2: ONBUILD MAINTAINER is not allowed (incorrect)
ONBUILD MAINTAINER Ron Weasley

# Configure build-time dependencies
ONBUILD RUN apt-get update && apt-get install -y build-essential

# Set environment variables
ENV APP_ENV=production \
    LOG_LEVEL=info

# Create application user
RUN groupadd -r appuser && \
    useradd -r -g appuser appuser

# Expose default port
EXPOSE 8080

USER appuser

CMD ["/bin/bash"]

```
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

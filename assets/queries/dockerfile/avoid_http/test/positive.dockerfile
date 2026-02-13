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

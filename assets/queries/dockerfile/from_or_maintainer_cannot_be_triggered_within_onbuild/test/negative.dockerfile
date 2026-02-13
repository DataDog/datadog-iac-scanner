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

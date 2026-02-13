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

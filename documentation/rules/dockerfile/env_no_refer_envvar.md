---
title: "ENV refers to itself"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/env_no_refer_envvar"
  id: "be8aab51-94cb-cc12-c40e-f6928d9b544a"
  display_name: "ENV refers to itself"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `be8aab51-94cb-cc12-c40e-f6928d9b544a`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#env)

### Description

Referencing an environment variable that is declared in the same Dockerfile `ENV` instruction is unreliable and can result in unexpected literal values, broken configuration, or accidental exposure of secrets when the build does not behave as intended.  

This rule inspects Dockerfile `ENV` instructions (resource type: `dockerfile_container`) and flags any `ENV` value that contains references such as `$VAR` or `${VAR}` where `VAR` is defined in the same `ENV` command.  

To fix this issue, define the referenced variable in an earlier `ENV` instruction (or use a build-time `ARG`) so Docker can expand it when processing the later `ENV` instruction.  

Secure example with expansion working as intended:

```dockerfile
ENV BASE_URL=https://example.com
ENV API_ENDPOINT=${BASE_URL}/api
```

## Compliant Code Examples
```dockerfile
FROM ruby:3.2-alpine AS builder

LABEL maintainer="ruby-team@example.com"
LABEL description="Ruby on Rails application with proper environment variable usage"

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    postgresql-dev \
    nodejs \
    yarn \
    git \
    tzdata

WORKDIR /build

# Negative case 1: Define base environment variable first
ENV FOO=bar

# Copy dependency files
COPY Gemfile Gemfile.lock package.json yarn.lock ./

# Install dependencies
RUN bundle config set --local deployment 'true' && \
    bundle config set --local without 'development test' && \
    bundle install --jobs 4 && \
    yarn install --frozen-lockfile --production

# Negative case 2: Reference previously defined variable in separate ENV statement
ENV BAZ=${FOO}/baz

# Copy application code
COPY . .

# Precompile Rails assets
RUN RAILS_ENV=production SECRET_KEY_BASE=dummy bundle exec rails assets:precompile

# Production stage
FROM ruby:3.2-alpine

LABEL maintainer="ruby-team@example.com"
LABEL description="Production Ruby on Rails application"
LABEL version="1.2.0"

# Install runtime dependencies
RUN apk add --no-cache \
    postgresql-client \
    nodejs \
    tzdata \
    curl

WORKDIR /app

# Copy built application from builder
COPY --from=builder /usr/local/bundle /usr/local/bundle
COPY --from=builder /build /app

# Set production environment variables
ENV RAILS_ENV=production
ENV RAILS_SERVE_STATIC_FILES=true
ENV RAILS_LOG_TO_STDOUT=true
ENV PORT=3000

# Create application user with proper permissions
RUN addgroup -g 1000 rails && \
    adduser -D -u 1000 -G rails -s /sbin/nologin rails && \
    mkdir -p /app/tmp /app/log /app/storage && \
    chown -R rails:rails /app

# Expose application port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Switch to non-root user
USER rails

# Start Rails server
CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "3000"]

```
## Non-Compliant Code Examples
```dockerfile
FROM ruby:3.2-alpine

LABEL maintainer="ruby-team@example.com"
LABEL description="Ruby on Rails application with environment variable issues"

# Install system dependencies
RUN apk add --no-cache \
    build-base \
    postgresql-dev \
    nodejs \
    yarn \
    git

# Positive case 1: ENV referencing another variable in same statement with $
ENV FOO=bar \
    BAZ=$FOO/bar

WORKDIR /app

# Copy Gemfile
COPY Gemfile Gemfile.lock ./

# Install Ruby gems
RUN bundle config set --local deployment 'true' && \
    bundle config set --local without 'development test' && \
    bundle install --jobs 4

# Positive case 2: ENV referencing another variable in same statement with ${}
ENV FOO=bar \
    BAZ=${FOO}/baz

# Copy application code
COPY . .

# Precompile assets
RUN RAILS_ENV=production SECRET_KEY_BASE=dummy bundle exec rails assets:precompile

# Set additional environment variables
ENV RAILS_ENV=production \
    RAILS_SERVE_STATIC_FILES=true \
    RAILS_LOG_TO_STDOUT=true

# Create application user
RUN addgroup -g 1000 rails && \
    adduser -D -u 1000 -G rails rails && \
    chown -R rails:rails /app

# Expose port
EXPOSE 3000

USER rails

CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0"]

```
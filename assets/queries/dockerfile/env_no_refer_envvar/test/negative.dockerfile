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

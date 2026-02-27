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

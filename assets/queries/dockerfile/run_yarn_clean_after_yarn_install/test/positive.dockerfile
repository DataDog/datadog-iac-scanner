FROM node:18-alpine AS builder

LABEL maintainer="frontend-team@example.com"
LABEL description="React application builder without cache cleanup"

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++

WORKDIR /build

# Copy package files
COPY package.json yarn.lock ./

# Positive case: yarn install without cache clean (leaves cache, increases image size)
RUN yarn install

# Copy application source
COPY . .

# Build the application
RUN yarn build

# Production stage
FROM node:18-alpine

LABEL maintainer="frontend-team@example.com"
LABEL description="Production React application"

# Install serve to run the static site
RUN apk add --no-cache curl && \
    yarn global add serve

WORKDIR /app

# Copy built application from builder
COPY --from=builder /build/dist ./dist

# Create application user
RUN addgroup -g 1001 nodeapp && \
    adduser -D -u 1001 -G nodeapp nodeapp && \
    chown -R nodeapp:nodeapp /app

# Set environment variables
ENV NODE_ENV=production \
    PORT=3000

# Expose application port
EXPOSE 3000

USER nodeapp

CMD ["serve", "-s", "dist", "-l", "3000"]

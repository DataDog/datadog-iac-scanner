FROM node:18-alpine AS builder

LABEL maintainer="platform-team@example.com"
LABEL description="Node.js application with multiple healthchecks (incorrect)"

WORKDIR /build

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application source
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine

LABEL maintainer="platform-team@example.com"
LABEL description="Production Node.js application"

# Install curl for health checks
RUN apk add --no-cache curl

WORKDIR /app

# Copy built application from builder
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/package.json ./

# Create application user
RUN addgroup -g 1001 nodeapp && \
    adduser -D -u 1001 -G nodeapp nodeapp && \
    chown -R nodeapp:nodeapp /app

# Set environment variables
ENV NODE_ENV=production \
    PORT=3000

# Expose application port
EXPOSE 3000

HEALTHCHECK CMD foo

# Positive case 1: Second healthcheck for database (multiple HEALTHCHECKs - only last one applies)
HEALTHCHECK CMD bar

USER nodeapp

CMD ["node", "dist/server.js"]

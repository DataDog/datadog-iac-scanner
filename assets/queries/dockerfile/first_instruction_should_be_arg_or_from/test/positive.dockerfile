# Positive case 1: Starting with COPY instead of FROM or ARG (incorrect)
COPY foo bar

RUN command

FROM nginx:1.25-alpine

LABEL maintainer="web-team@example.com"
LABEL description="Nginx static site with incorrect first instruction"

# Install additional tools
RUN apk add --no-cache \
    curl \
    bash

WORKDIR /usr/share/nginx/html

ADD foo bar

# Copy website files
COPY --chown=nginx:nginx ./dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create cache directory
RUN mkdir -p /var/cache/nginx && \
    chown -R nginx:nginx /var/cache/nginx

# Expose HTTP and HTTPS ports
EXPOSE 80 443

USER nginx

CMD ["nginx", "-g", "daemon off;"]

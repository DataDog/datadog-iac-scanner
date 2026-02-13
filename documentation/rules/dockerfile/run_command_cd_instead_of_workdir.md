---
title: "RUN instruction using cd instead of WORKDIR"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/run_command_cd_instead_of_workdir"
  id: "f4a6bcd3-e231-4acf-993c-aa027be50d2e"
  display_name: "RUN instruction using cd instead of WORKDIR"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `f4a6bcd3-e231-4acf-993c-aa027be50d2e`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir)

### Description

Using relative paths with `cd` inside Dockerfile `RUN` instructions is fragile and can cause commands to execute in unintended directories, producing nondeterministic builds, accidental inclusion of build-context files, or incorrect file ownership and permissions that may expose sensitive data.

This rule inspects Dockerfile `RUN` instruction command strings and flags occurrences of `cd <path>` where `<path>` is not an absolute path (does not start with `/` or a Windows drive letter like `C:\`). Instead of changing directories with a relative `cd`, set the working directory with `WORKDIR /absolute/path` for subsequent instructions or use absolute paths in single `RUN` calls. Directory changes performed only within one `RUN` do not persist across layers and are error-prone.

Secure example using `WORKDIR`:

```dockerfile
FROM ubuntu:22.04
WORKDIR /app
COPY . .
RUN make build
```

## Compliant Code Examples
```dockerfile
FROM nginx
ENV AUTHOR=Docker
WORKDIR /usr/share/nginx/html
COPY Hello_docker.html /usr/share/nginx/html
CMD cd /usr/share/nginx/html && sed -e s/Docker/"$AUTHOR"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'
```

```dockerfile
FROM nginx
ENV AUTHOR=Docker
RUN cd /usr/share/nginx/html
COPY Hello_docker.html /usr/share/nginx/html
CMD cd /usr/share/nginx/html && sed -e s/Docker/"$AUTHOR"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'

```
## Non-Compliant Code Examples
```dockerfile
FROM nginx
ENV AUTHOR=Docker
RUN cd /../share/nginx/html
COPY Hello_docker.html /usr/share/nginx/html
CMD cd /usr/share/nginx/html && sed -e s/Docker/"$AUTHOR"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'

FROM nginx
ENV AUTHOR=Docker
RUN cd ../share/nginx/html
COPY Hello_docker.html /usr/share/nginx/html
CMD cd /usr/share/nginx/html && sed -e s/Docker/"$AUTHOR"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'

FROM nginx
ENV AUTHOR=Docker
RUN cd /usr/../share/nginx/html
COPY Hello_docker.html /usr/share/nginx/html
CMD cd /usr/share/nginx/html && sed -e s/Docker/"$AUTHOR"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'

```
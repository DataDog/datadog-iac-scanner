---
title: "WORKDIR path not absolute"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/workdir_path_not_absolute"
  id: "6b376af8-cfe8-49ab-a08d-f32de23661a4"
  display_name: "WORKDIR path not absolute"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `6b376af8-cfe8-49ab-a08d-f32de23661a4`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir)

### Description

Using a relative `WORKDIR` in a Dockerfile can create build-time and runtime ambiguity that leads to unpredictable behavior, accidental file writes or executions in the wrong location, and difficulty enforcing consistent file permissions and access boundaries.

Check Dockerfile `WORKDIR` instructions and require the argument to be an absolute path. Acceptable forms include Unix-style paths starting with `/`, Windows drive-letter paths like `C:\path`, or environment-variable-based paths such as `$APP_HOME` or `${APP_HOME}`. `WORKDIR` values that are relative (for example, `./app`, `../app`, or bare names) will be flagged. 

Secure examples:

```
WORKDIR /app
```

```
ENV APP_HOME=/srv/app
WORKDIR ${APP_HOME}
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN pip install --upgrade pip
WORKDIR /path/to/workdir
WORKDIR "/path/to/workdir"
WORKDIR /
WORKDIR c:\\windows
ENV DIRPATH=/path
ENV GLASSFISH_ARCHIVE glassfish5
WORKDIR $DIRPATH/$DIRNAME
WORKDIR ${GLASSFISH_HOME}/bin
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```
## Non-Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN pip install --upgrade pip
WORKDIR /path/to/workdir
WORKDIR workdir
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]
```
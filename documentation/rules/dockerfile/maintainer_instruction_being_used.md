---
title: "MAINTAINER instruction being used"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/maintainer_instruction_being_used"
  id: "99614418-f82b-4852-a9ae-5051402b741c"
  display_name: "MAINTAINER instruction being used"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `99614418-f82b-4852-a9ae-5051402b741c`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#maintainer-deprecated)

### Description

Using the deprecated `MAINTAINER` instruction can cause maintainer metadata to be lost or ignored by modern build systems and does not follow OCI image metadata conventions, which reduces image traceability and hinders incident response, patching, and supply chain automation. This rule flags Dockerfiles that contain a `MAINTAINER` instruction; instead, set maintainer information as a `LABEL` so metadata is preserved and machine-readable.

Update Dockerfiles by replacing `MAINTAINER` with a `LABEL` (for example, a simple `maintainer` label or the OCI-standard `org.opencontainers.image.authors`) and ensure the label value includes contact details or an identifier recognizable by your tooling.

Secure examples:

```dockerfile
# simple maintainer label
LABEL maintainer="Alice Example <alice@example.com>"

# OCI standard author label
LABEL org.opencontainers.image.authors="Alice Example <alice@example.com>"
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN pip install --upgrade pip
LABEL maintainer="SvenDowideit@home.org.au"
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
MAINTAINER "SvenDowideit@home.org.au"
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]
```
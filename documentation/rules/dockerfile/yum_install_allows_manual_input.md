---
title: "yum install allows manual input"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/yum_install_allows_manual_input"
  id: "6e19193a-8753-436d-8a09-76dcff91bb03"
  display_name: "yum install allows manual input"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `6e19193a-8753-436d-8a09-76dcff91bb03`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#run)

### Description

`RUN` instructions that invoke `yum install` without a non-interactive flag can prompt for user input during image builds, causing automated CI/CD pipelines to hang or produce inconsistent images when builds are completed manually.

Check Dockerfile `RUN` commands for invocations of `yum install` (including `groupinstall` or `localinstall`). The command must include a non-interactive flag such as `-y`, `yes`, or `--assumeyes`. This rule flags `RUN` entries where a `yum` install is detected but none of those flags are present. It applies to both single-string `RUN` commands and list-form `RUN` arguments. 

Secure example:

```dockerfile
RUN yum -y install curl
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN sudo yum install -y bundler
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
RUN sudo yum install bundler
RUN ["sudo yum", "install", "bundler"]
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```
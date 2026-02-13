---
title: "Unpinned package version in pip install"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/unpinned_package_version_in_pip_install"
  id: "02d9c71f-3ee8-4986-9c27-1a20d0d19bfc"
  display_name: "Unpinned package version in pip install"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `02d9c71f-3ee8-4986-9c27-1a20d0d19bfc`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)

### Description

Unpinned pip installs in Dockerfile `RUN` instructions allow dependency drift and unexpected upgrades, which can cause build non-determinism, breakages, or introduce vulnerable package versions. This rule examines Dockerfile `RUN` commands that invoke `pip` or `pip3` with the `install` subcommand and requires that each package specified directly on the command line include an explicit version specifier (for example, `package==1.2.3`).

Packages installed via requirement or constraint files (using `-r` or `-c`) are not validated by this check because versions should be managed inside those files. Only direct package arguments that start with a letter are flagged when no version is present. 

Secure example:

```dockerfile
RUN pip3 install flask==2.0.3 requests==2.26.0
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.4
RUN apk add --update py-pip=7.1.2-r0
RUN pip3 install -r pip_requirements.txt
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```

```dockerfile
FROM alpine:3.4
RUN apk add --update py-pip=7.1.2-r0
RUN sudo pip install --upgrade pip=20.3 connexion=2.7.0
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

FROM alpine:3.1
RUN apk add py-pip=7.1.2-r0
RUN sudo pip install --upgrade pip=20.3 connexion=2.7.0
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
RUN pip3 install requests=2.7.0
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```

```dockerfile
FROM alpine:3.4
RUN apk add --update py-pip=7.1.2-r0
RUN pip3 install -c constraints.txt
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]
```
## Non-Compliant Code Examples
```dockerfile
FROM alpine:3.9
RUN apk add --update py-pip=7.1.2-r0
RUN pip install --user pip
RUN ["pip", "install", "connexion"]
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
ENV TEST="test"
CMD ["python", "/usr/src/app/app.py"]

FROM alpine:3.7
RUN apk add --update py-pip=7.1.2-r0
RUN pip install connexion
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
RUN pip3 install requests
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python"]

```
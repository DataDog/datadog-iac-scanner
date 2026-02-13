---
title: "Changing default shell using RUN command"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/changing_default_shell_using_run_command"
  id: "8a301064-c291-4b20-adcb-403fe7fd95fd"
  display_name: "Changing default shell using RUN command"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `8a301064-c291-4b20-adcb-403fe7fd95fd`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#shell)

### Description

Changing the image's default shell by running shell binaries or user-modifying commands in a `RUN` instruction instead of using the Dockerfile `SHELL` instruction can produce inconsistent build vs. runtime behavior and cause subsequent instructions to be interpreted under unexpected shell parsing rules. This increases the risk of misinterpreted commands or injection vulnerabilities.

This rule flags Dockerfile `RUN` instructions where the invoked command is `mv`, `chsh`, `usermod`, or `ln` and their arguments reference common shell paths (for example, `/bin/bash`, `/bin/sh`, `/usr/bin/zsh`). It also flags `RUN` invocations that call `powershell` directly. The intended default shell should be defined with the `SHELL` instruction.

Resources that attempt to edit `/etc/passwd`, symlink shell binaries, or invoke PowerShell via `RUN` will be flagged. For Windows images, the JSON-array form of `SHELL` is preferred to ensure proper argument handling. 

Secure examples:

```Dockerfile
# Unix/Linux: set bash as the default shell for subsequent instructions
SHELL ["/bin/bash", "-lc"]
```

```Dockerfile
# Windows/PowerShell: set PowerShell as the default shell for subsequent instructions
SHELL ["powershell", "-Command"]
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN sudo yum install -y bundler
RUN yum install
SHELL ["cmd", "/S", "/C"]
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```

```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN sudo yum install -y bundler
RUN yum install
SHELL ["/bin/sh", "-c"]
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```

```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN sudo yum install -y bundler
RUN yum install
SHELL ["/bin/bash", "-c"]
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
RUN sudo yum install -y bundler
RUN yum install
RUN powershell -command
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```

```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN sudo yum install -y bundler
RUN yum install
RUN ln -sfv /bin/bash /bin/sh
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```
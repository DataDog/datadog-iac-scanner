---
title: "ADD instead of COPY"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/add_instead_of_copy"
  id: "9513a694-aa0d-41d8-be61-3271e056f36b"
  display_name: "ADD instead of COPY"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `9513a694-aa0d-41d8-be61-3271e056f36b`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#add)

### Description

Using the Dockerfile `ADD` instruction to pull or include non-archive files can introduce unverified remote content or unexpected file extraction into images. This increases the risk of supply-chain compromise and remote code execution.

Uses of `ADD` are flagged when the source does not appear to be a tar archive (no `.tar` or `.tar.*` extension). Replace `ADD` with `COPY` for local files and directories, and reserve `ADD` only for adding and auto-extracting tar archives. Resources using `ADD` with non-archive sources or remote URLs will be flagged.

Secure examples:

```dockerfile
# Use COPY for local files or directories
COPY ./install.sh /usr/local/bin/install.sh

# Use ADD only when intentionally extracting a tar archive
ADD archive.tar.gz /opt/app/
```

## Compliant Code Examples
```dockerfile
FROM openjdk:10-jdk
VOLUME /tmp
ARG JAR_FILE
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
ADD http://source.file/package.file.tar.gz /temp
RUN tar -xjf /temp/package.file.tar.gz \
  && make -C /tmp/package.file \
  && rm /tmp/ package.file.tar.gz
# trigger validation

```
## Non-Compliant Code Examples
```dockerfile
FROM openjdk:10-jdk
VOLUME /tmp
ADD http://source.file/package.file.tar.gz /temp
RUN tar -xjf /temp/package.file.tar.gz \
  && make -C /tmp/package.file \
  && rm /tmp/ package.file.tar.gz
ARG JAR_FILE
ADD ${JAR_FILE} app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]

```
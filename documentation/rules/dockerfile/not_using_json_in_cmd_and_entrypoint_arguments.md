---
title: "Not using JSON for CMD and ENTRYPOINT arguments"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/not_using_json_in_cmd_and_entrypoint_arguments"
  id: "b86987e1-6397-4619-81d5-8807f2387c79"
  display_name: "Not using JSON for CMD and ENTRYPOINT arguments"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Build Process"
---
## Metadata

**Id:** `b86987e1-6397-4619-81d5-8807f2387c79`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#entrypoint)

### Description

`CMD` and `ENTRYPOINT` should use the JSON (exec) form so commands are executed directly without invoking a shell. The shell/string form runs via `/bin/sh -c` which increases risk of command injection and can cause unpredictable argument parsing and improper signal forwarding (affecting graceful shutdown).

In Dockerfiles, check the `CMD` and `ENTRYPOINT` directives and require they be written as JSON arrays (exec form), for example, `CMD ["executable", "arg1"]` or `ENTRYPOINT ["executable", "arg"]`. If you need shell features, explicitly invoke a shell in the exec form (for example, `["sh","-c","..."]`) so the use of a shell is intentional.

Secure examples:

```Dockerfile
CMD ["nginx", "-g", "daemon off;"]
ENTRYPOINT ["java", "-jar", "app.jar"]
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN sudo yum install bundler
RUN yum install
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"] 
ENTRYPOINT ["top", "-b"]
```

```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
CMD [python, /usr/src/app/app.py] 
ENTRYPOINT [top, -b]

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /go/src/github.com/foo/href-counter/app ./
CMD ["./app"]
RUN useradd -ms /bin/bash patrick

USER patrick

```
## Non-Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN sudo yum install bundler
RUN yum install
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD [python, /usr/src/app/app.py] 
ENTRYPOINT [top, -b]
```
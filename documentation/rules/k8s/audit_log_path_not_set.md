---
title: "Audit log path not set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/audit_log_path_not_set"
  id: "73e251f0-363d-4e53-86e2-0a93592437eb"
  display_name: "Audit log path not set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `73e251f0-363d-4e53-86e2-0a93592437eb`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When `kube-apiserver` appears in a container command, the `--audit-log-path` flag should be set. This rule detects containers running `kube-apiserver` that do not include the `--audit-log-path` flag. Without `--audit-log-path`, the API server will not write audit logs to a file, preventing persistent audit records and hindering incident investigation and compliance.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: command-demo
  labels:
    purpose: demonstrate-command
spec:
  containers:
    - name: command-demo-container
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      command: ["kube-apiserver"]
      args: ["--audit-log-path=path/to/log"]
  restartPolicy: OnFailure

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: command-demo
  labels:
    purpose: demonstrate-command
spec:
  containers:
    - name: command-demo-container
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      command: ["kube-apiserver","--audit-log-path=path/to/log"]
      args: []
  restartPolicy: OnFailure

```
## Non-Compliant Code Examples
```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: dummy
  namespace: knative-sequence
spec:
  template:
    spec:
      containers:
      - name: command-demo-container
        image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
        command: ["kube-apiserver"]
        args: []
    restartPolicy: OnFailure
---
apiVersion: serving.knative.dev/v1
kind: Configuration
metadata:
  name: dummy-config
  namespace: knative-sequence
spec:
  template:
    spec:
      containers:
        - name: command-demo-container
          image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
          command: ["kube-apiserver"]
          args: []
      restartPolicy: OnFailure
---
apiVersion: serving.knative.dev/v1
kind: Revision
metadata:
  name: dummy-rev
  namespace: knative-sequence
spec:
  containers:
    - name: command-demo-container
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      command: ["kube-apiserver"]
      args: []
  restartPolicy: OnFailure
---
apiVersion: sources.knative.dev/v1
kind: ContainerSource
metadata:
  name: dummy-cs
  namespace: knative-sequence
spec:
  template:
    spec:
      containers:
        - name: command-demo-container
          image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
          command: ["kube-apiserver"]
          args: []
      restartPolicy: OnFailure

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: command-demo
  labels:
    purpose: demonstrate-command
spec:
  containers:
    - name: command-demo-container
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      command: ["kube-apiserver"]
      args: [""]
  restartPolicy: OnFailure

```
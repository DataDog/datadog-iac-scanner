---
title: "Audit log maxsize not properly set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/audit_log_maxsize_not_properly_set"
  id: "35c0a471-f7c8-4993-aa2c-503a3c712a66"
  display_name: "Audit log maxsize not properly set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `35c0a471-f7c8-4993-aa2c-503a3c712a66`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When a container runs `kube-apiserver`, the `--audit-log-maxsize` flag should be set to 100 megabytes or more.  
This rule inspects `containers` and `initContainers` and checks container commands for `kube-apiserver`; it verifies that `--audit-log-maxsize` is present and has a value of at least 100 megabytes.  
The rule reports `MissingAttribute` if the flag is absent and `IncorrectValue` if the flag is set to less than 100 megabytes.

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
      args: ["--audit-log-maxsize=150"]
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
      command: ["kube-apiserver","--audit-log-maxsize=100"]
      args: []
  restartPolicy: OnFailure

```
## Non-Compliant Code Examples
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
      args: []
  restartPolicy: OnFailure

```

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
        args: ["--audit-log-maxsize=50"]
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
          args: ["--audit-log-maxsize=50"]
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
      args: ["--audit-log-maxsize=50"]
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
          args: ["--audit-log-maxsize=50"]
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
      args: ["--audit-log-maxsize=50"]
  restartPolicy: OnFailure

```
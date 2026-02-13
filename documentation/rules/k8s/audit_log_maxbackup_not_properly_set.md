---
title: "Audit log maxbackup not properly set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/audit_log_maxbackup_not_properly_set"
  id: "768aab52-2504-4a2f-a3e3-329d5a679848"
  display_name: "Audit log maxbackup not properly set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `768aab52-2504-4a2f-a3e3-329d5a679848`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When a container or initContainer runs `kube-apiserver`, the `--audit-log-maxbackup` flag should be set to 10 or more. The rule reports a MissingAttribute when the flag is not defined and an IncorrectValue when the flag is defined with a value less than 10. Setting the flag to at least 10 helps retain rotated audit logs for a longer period.

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
      args: ["--audit-log-maxbackup=10"]
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
      command: ["kube-apiserver","--audit-log-maxbackup=15"]
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
        args: ["--audit-log-maxbackup=5"]
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
          args: ["--audit-log-maxbackup=5"]
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
      args: ["--audit-log-maxbackup=5"]
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
          args: ["--audit-log-maxbackup=5"]
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
      args: ["--audit-log-maxbackup=5"]
  restartPolicy: OnFailure

```
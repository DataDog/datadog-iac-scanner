---
title: "Insecure port not properly set"
group_id: "Kubernetes"
meta:
  name: "insecure_port_not_properly_set"
  id: "kubernetes-insecure-port-not-properly-set"
  display_name: "Insecure port not properly set"
  cloud_provider: ""
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-insecure-port-not-properly-set{{< /copyable-code >}}

**Platform:** Kubernetes

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When a container runs `kube-apiserver`, the `--insecure-port` flag should be set to `0`. If the flag is missing, the rule reports a MissingAttribute; if present but not set to `0`, the rule reports an IncorrectValue. This check applies to `containers` and `initContainers` within the resource spec.

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
      command: ["kube-apiserver","--insecure-port=0"]
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
      args: ["--insecure-port=0"]
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
      command: ["kube-apiserver", "--insecure-port=1143"]
  restartPolicy: OnFailure

```
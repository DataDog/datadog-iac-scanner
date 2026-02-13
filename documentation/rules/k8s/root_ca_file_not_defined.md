---
title: "Root CA file not defined"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/root_ca_file_not_defined"
  id: "05fb986f-ac73-4ebb-a5b2-7faafa93d882"
  display_name: "Root CA file not defined"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `05fb986f-ac73-4ebb-a5b2-7faafa93d882`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)

### Description

 Containers (including `initContainers`) that run `kube-controller-manager` should include the `--root-ca-file` flag. This flag specifies the path to the root CA certificate used to validate TLS certificates; without it the controller manager may not validate certificates correctly. The rule reports a MissingAttribute when the `--root-ca-file` flag is not present in the container's command.


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
      image: gcr.io/google_containers/kube-controller-manager-amd64:v1.6.0
      command: ["kube-controller-manager"]
      args: ["--root-ca-file=/path/to/ca/file.pem"]
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
      image: gcr.io/google_containers/kube-controller-manager-amd64:v1.6.0
      command: ["kube-controller-manager","--root-ca-file=/path/to/ca/file.pem"]
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
      image: gcr.io/google_containers/kube-controller-manager-amd64:v1.6.0
      command: ["kube-controller-manager"]
      args: []
  restartPolicy: OnFailure

```
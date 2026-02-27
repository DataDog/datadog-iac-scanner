---
title: "Client certificate authentication not set up properly"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/client_certificate_authentication_not_setup_properly"
  id: "e0e00aba-5f1c-4981-a542-9a9563c0ee20"
  display_name: "Client certificate authentication not set up properly"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `e0e00aba-5f1c-4981-a542-9a9563c0ee20`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)

### Description

Client certificate authentication must be configured using a `.pem` or `.crt` file. Containers running `kube-apiserver` or `kubelet` must include the `--client-ca-file` flag that references a `.pem` or `.crt` certificate. For KubeletConfiguration, the `authentication.x509.clientCAFile` field must reference a `.pem` or `.crt` file.

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
      image: foo/bar
      command: ["kubelet"]
      args: ["--client-ca-file=/var/lib/ca.pem"]
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
      args: ["--client-ca-file=/var/lib/ca.crt"]
  restartPolicy: OnFailure

```

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: "192.168.0.8"
port: 20250
protectKernelDefaults: false
serializeImagePulls: false
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: "/var/lib/kubernetes/ca.crt"
authorization:
evictionHard:
    memory.available:  "200Mi"

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
      args: ["--client-ca-file=/var/lib/ca.txt"]
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
      args: []
  restartPolicy: OnFailure

```

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: "192.168.0.8"
port: 20250
protectKernelDefaults: false
serializeImagePulls: false
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: "/var/lib/kubernetes/ca.txt"
authorization:
evictionHard:
    memory.available:  "200Mi"

```
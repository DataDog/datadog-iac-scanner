---
title: "Rotate Kubelet server certificate not active"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/rotate_kubelet_server_certificate_not_active"
  id: "1c621b8e-2c6a-44f5-bd6a-fb0fb7ba33e2"
  display_name: "Rotate Kubelet server certificate not active"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `1c621b8e-2c6a-44f5-bd6a-fb0fb7ba33e2`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/)

### Description

 The `RotateKubeletServerCertificate` feature gate must be set to `true`. It must be enabled either by including `RotateKubeletServerCertificate=true` in the `--feature-gates=` flag for kube components (for example `kubelet` or `kube-controller-manager`) or by setting `featureGates.RotateKubeletServerCertificate` to `true` in `KubeletConfiguration`. This rule reports an `IncorrectValue` when the feature gate is `false`.


## Compliant Code Examples
```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: "192.168.0.8"
port: 20250
serializeImagePulls: false
evictionHard:
    memory.available:  "200Mi"
featureGates:
    RotateKubeletServerCertificate: true

```

```json
{
    "kind": "KubeletConfiguration",
    "address": "192.168.0.8",
    "apiVersion": "kubelet.config.k8s.io/v1beta1",
    "evictionHard": {
        "memory.available": "200Mi"
    },
    "port": 20250,
    "serializeImagePulls": false
}

```

```json
{
    "kind": "KubeletConfiguration",
    "address": "192.168.0.8",
    "apiVersion": "kubelet.config.k8s.io/v1beta1",
    "evictionHard": {
        "memory.available": "200Mi"
    },
    "featureGates": {
        "RotateKubeletServerCertificate": true
    },
    "port": 20250,
    "serializeImagePulls": false
}

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
      image: foo/bar
      command: ["kubelet"]
      args: ["--feature-gates=RotateKubeletServerCertificate=false"]
  restartPolicy: OnFailure

```

```json
{
    "kind": "KubeletConfiguration",
    "address": "192.168.0.8",
    "apiVersion": "kubelet.config.k8s.io/v1beta1",
    "evictionHard": {
        "memory.available": "200Mi"
    },
    "featureGates": {
        "RotateKubeletServerCertificate": false
    },
    "port": 20250,
    "serializeImagePulls": false
}

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
    - name: command-demo-container7
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      command: ["kube-controller-manager"]
      args: ["--feature-gates=RotateKubeletServerCertificate=false"]
  restartPolicy: OnFailure

```
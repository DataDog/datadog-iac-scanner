---
title: "Kubelet protect-kernel-defaults set to false"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/kubelet_protect_kernel_defaults_set_to_false"
  id: "6cf42c97-facd-4fda-b8af-ea4529123355"
  display_name: "Kubelet protect-kernel-defaults set to false"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `6cf42c97-facd-4fda-b8af-ea4529123355`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)

### Description

 The `--protect-kernel-defaults` flag must be set to `true`.  
If kubelet is started via a container command, the command must not include `--protect-kernel-defaults=false`.  
For `KubeletConfiguration` resources, the `protectKernelDefaults` field must be defined and set to `true`.


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
      args: ["--protect-kernel-defaults=true"]
  restartPolicy: OnFailure

```

```json
{
    "kind": "KubeletConfiguration",
    "apiVersion": "kubelet.config.k8s.io/v1beta1",
    "port": 10250,
    "readOnlyPort": 10255,
    "cgroupDriver": "cgroupfs",
    "protectKernelDefaults": true,
    "hairpinMode": "promiscuous-bridge",
    "serializeImagePulls": false,
    "featureGates": {
      "RotateKubeletClientCertificate": true,
      "RotateKubeletServerCertificate": true
    }
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
    - name: command-demo-container
      image: foo/bar
      command: ["kubelet"]
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
      image: foo/bar
      command: ["kubelet","--protect-kernel-defaults=false"]
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
tlsCertFile: "someFile.txt"
tlsPrivateKeyFile: "someFile.txt"
evictionHard:
    memory.available:  "200Mi"

```

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: "192.168.0.8"
port: 20250
serializeImagePulls: false
tlsCertFile: "someFile.txt"
tlsPrivateKeyFile: "someFile.txt"
evictionHard:
    memory.available:  "200Mi"

```
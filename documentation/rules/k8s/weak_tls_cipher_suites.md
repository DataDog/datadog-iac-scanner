---
title: "Weak TLS cipher suites"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/weak_tls_cipher_suites"
  id: "510d5810-9a30-443a-817d-5c1fa527b110"
  display_name: "Weak TLS cipher suites"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `510d5810-9a30-443a-817d-5c1fa527b110`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)

### Description

 TLS connections should use strong cipher suites. Containers running `kube-apiserver` or `kubelet` should define the `--tls-cipher-suites` flag and restrict it to strong cipher suite names. The KubeletConfiguration `tlsCipherSuites` field should be present and contain only strong cipher suites.


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
      args: ["--tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
  restartPolicy: OnFailure

```

```json
{
    "kind": "KubeletConfiguration",
    "apiVersion": "kubelet.config.k8s.io/v1beta1",
    "port": 10250,
    "readOnlyPort": 10255,
    "cgroupDriver": "cgroupfs",
    "hairpinMode": "promiscuous-bridge",
    "serializeImagePulls": false,
    "tlsCipherSuites": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
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
      args: ["--tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"]
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
      args: ["--tls-cipher-suites=TLS_RSA_WITH_RC4_128_SHA"]
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
tlsCipherSuites: ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"]
evictionHard:
    memory.available:  "200Mi"

```

```json
{
    "kind": "KubeletConfiguration",
    "apiVersion": "kubelet.config.k8s.io/v1beta1",
    "port": 10250,
    "readOnlyPort": 10255,
    "cgroupDriver": "cgroupfs",
    "hairpinMode": "promiscuous-bridge",
    "serializeImagePulls": false,
    "featureGates": {
      "RotateKubeletClientCertificate": true,
      "RotateKubeletServerCertificate": true
    }
  }

```
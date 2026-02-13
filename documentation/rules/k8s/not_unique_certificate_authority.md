---
title: "Certificate authority is not unique"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/not_unique_certificate_authority"
  id: "cb7e695d-6a85-495c-b15f-23aed2519303"
  display_name: "Certificate authority is not unique"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `cb7e695d-6a85-495c-b15f-23aed2519303`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/)

### Description

The trusted certificate authority file used by etcd must be different from the client certificate authority file used by the API server. Do not set `--trusted-ca-file` for etcd to the same path as the API server's `--client-ca-file`. Sharing the same CA file can allow clients authenticated to the API server to be implicitly trusted by etcd, weakening isolation and increasing risk.

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
      args: ["--client-ca-file=/etc/env/valid.pem"]
  restartPolicy: OnFailure
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: database
spec:
  selector:
    matchLabels:
      app: database
      version: v1
  replicas: 1
  template:
    metadata:
      labels:
        app: database
        version: v1
    spec:
      serviceAccountName: database
      containers:
      - name: database
        image: gcr.io/google_containers/kube-apiserver:certification
        imagePullPolicy: IfNotPresent
        command: ["etcd"]
        args: ["--trusted-ca-file=/etc/env/valid2.pem"]
      nodeSelector:
        kubernetes.io/hostname: worker02  
    restartPolicy: OnFailure

```
## Non-Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: database
spec:
  selector:
    matchLabels:
      app: database
      version: v1
  replicas: 1
  template:
    metadata:
      labels:
        app: database
        version: v1
    spec:
      serviceAccountName: database
      containers:
      - name: database
        image: gcr.io/google_containers/kube-apiserver:certification
        imagePullPolicy: IfNotPresent
        command: ["etcd"]
        args: ["--trusted-ca-file=/etc/env/valid3.pem"]
      nodeSelector:
        kubernetes.io/hostname: worker02  
    restartPolicy: OnFailure
---
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
      args: ["--client-ca-file=/etc/env/valid3.pem"]
  restartPolicy: OnFailure

```
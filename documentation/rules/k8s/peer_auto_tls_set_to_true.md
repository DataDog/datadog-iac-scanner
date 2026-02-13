---
title: "Peer auto TLS set to true"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/peer_auto_tls_set_to_true"
  id: "ae8827e2-4af9-4baa-9998-87539ae0d6f0"
  display_name: "Peer auto TLS set to true"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ae8827e2-4af9-4baa-9998-87539ae0d6f0`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://etcd.io/docs/v3.4/op-guide/security/)

### Description

 When running `etcd`, the `--peer-auto-tls` flag must not be set to `true`; it should be set to `false` or omitted. This rule inspects `containers` and `initContainers` for `etcd` commands and flags set to `--peer-auto-tls=true`. Enabling peer auto TLS can cause certificates to be automatically accepted or generated for peers, potentially weakening cluster security, so explicit TLS configuration is required.


## Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-etcd-deployment
spec:
  selector:
    matchLabels:
      app: app
  replicas: 1
  template:
    metadata:
      labels:
        app: app
        version: v1
    spec:
      serviceAccountName: database
      containers:
      - name: database
        image: gcr.io/google_containers/etcd:v3.2.18
        imagePullPolicy: IfNotPresent
        command: ["etcd"]
        args: []
      nodeSelector:
        kubernetes.io/hostname: worker02  
    restartPolicy: OnFailure

```

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-etcd-deployment
spec:
  selector:
    matchLabels:
      app: app
  replicas: 1
  template:
    metadata:
      labels:
        app: app
        version: v1
    spec:
      serviceAccountName: database
      containers:
      - name: database
        image: gcr.io/google_containers/etcd:v3.2.18
        imagePullPolicy: IfNotPresent
        command: ["etcd", "--peer-auto-tls=false"]
        args: []
      nodeSelector:
        kubernetes.io/hostname: worker02  
    restartPolicy: OnFailure

```
## Non-Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-etcd-deployment
spec:
  selector:
    matchLabels:
      app: app
  replicas: 1
  template:
    metadata:
      labels:
        app: app
        version: v1
    spec:
      serviceAccountName: database
      containers:
      - name: database
        image: gcr.io/google_containers/etcd:v3.2.18
        imagePullPolicy: IfNotPresent
        command: ["etcd"]
        args: ["--peer-auto-tls=true"]
      nodeSelector:
        kubernetes.io/hostname: worker02  
    restartPolicy: OnFailure

```
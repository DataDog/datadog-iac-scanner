---
title: "etcd peer TLS certificate files not properly set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/etcd_peer_tls_certificate_files_not_properly_set"
  id: "09bb9e96-8da3-4736-b89a-b36814acca60"
  display_name: "etcd peer TLS certificate files not properly set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `09bb9e96-8da3-4736-b89a-b36814acca60`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://etcd.io/docs/v3.4/op-guide/security/)

### Description

 When a container command includes `etcd`, the `--peer-cert-file` and `--peer-key-file` flags should be set. The rule inspects both initContainers and containers and reports a MissingAttribute when any required flag is not present in the container's command. The result identifies the resource and the command position where the missing flag was detected.


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
        args: ["--peer-cert-file=/etc/env/file.crt", "--peer-key-file=/etc/env/file2.key"]
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
        command: ["etcd", "--peer-cert-file=/etc/env/file.crt", "--peer-key-file=/etc/env/file2.key"]
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
        args: ["--peer-key-file=/etc/env/file2.key"]
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
        command: ["etcd"]
        args: ["--peer-cert-file=/etc/env/file.crt"]
      nodeSelector:
        kubernetes.io/hostname: worker02  
    restartPolicy: OnFailure

```
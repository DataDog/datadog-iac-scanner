---
title: "etcd client certificate authentication set to false"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/etcd_client_certificate_authentication_set_to_false"
  id: "9391103a-d8d7-4671-ac5d-606ba7ccb0ac"
  display_name: "etcd client certificate authentication set to false"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `9391103a-d8d7-4671-ac5d-606ba7ccb0ac`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://etcd.io/docs/v3.4/op-guide/security/)

### Description

 When containers run `etcd`, the `--client-cert-auth` flag must be set to `true`. This enforces client certificate authentication to prevent unauthenticated access to the etcd server. The rule reports `IncorrectValue` when the flag is explicitly set to `false`, and `MissingAttribute` when the flag is not defined.


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
        args: ["--client-cert-auth=true"]
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
        command: ["etcd"]
        args: ["--client-cert-auth=false"]
      nodeSelector:
        kubernetes.io/hostname: worker02  
    restartPolicy: OnFailure

```
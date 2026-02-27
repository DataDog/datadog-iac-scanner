---
title: "Invalid metadata label"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/metadata_label_is_invalid"
  id: "1123031a-f921-4c5b-bd86-ef354ecfd37a"
  display_name: "Invalid metadata label"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `1123031a-f921-4c5b-bd86-ef354ecfd37a`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)

### Description

Metadata labels must be valid and conform to the pattern `^(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?$`.
This requires label values to start and end with an alphanumeric character and may include dashes, underscores, or dots in the middle; labels that do not match this pattern are reported as `IncorrectValue` with the resource and label details.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: goproxy
  labels:
    app: goproxy
spec:
  containers:
  - name: goproxy
    image: k8s.gcr.io/goproxy:0.1
    ports:
    - containerPort: 8080
    readinessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
    livenessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 20

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: goproxy
  labels:
    app: g**dy.l+bel.
spec:
  containers:
  - name: goproxy
    image: k8s.gcr.io/goproxy:0.1
    ports:
    - containerPort: 8080
    livenessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 20

```
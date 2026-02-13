---
title: "Invalid image tag"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/invalid_image"
  id: "583053b7-e632-46f0-b989-f81ff8045385"
  display_name: "Invalid image tag"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `583053b7-e632-46f0-b989-f81ff8045385`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/containers/images/#updating-images)

### Description

The image tag must be provided and must not be empty or `latest`. Image digests (using `@`, e.g., `image@sha256:...`) are preferred and will satisfy this rule. Omitting a tag or using the `latest` tag is considered invalid.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: private-image-test-1
spec:
  containers:
    - name: uses-private-image
      image: nginx:1.21
      imagePullPolicy: Always
      command: [ "echo", "SUCCESS" ]

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: private-image-test-3
spec:
  containers:
    - name: uses-private-image-container
      image: nginx
      imagePullPolicy: Always
      command: [ "echo", "SUCCESS" ]
---
apiVersion: v1
kind: Pod
metadata:
  name: private-image-test-33
spec:
  containers:
    - name: uses-private-image-container
      image: nginx:latest
      imagePullPolicy: Always
      command: [ "echo", "SUCCESS" ]

```
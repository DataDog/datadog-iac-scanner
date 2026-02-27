---
title: "Image without digest"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/image_without_digest"
  id: "7c81d34c-8e5a-402b-9798-9f442630e678"
  display_name: "Image without digest"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `7c81d34c-8e5a-402b-9798-9f442630e678`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/containers/images/#updating-images)

### Description

Images should be specified with their digests to ensure integrity. The policy checks `containers` and `initContainers` entries in the resource spec and flags any image value that does not include a digest (i.e., missing the '@' separator). Specifying images by digest enforces immutability and helps ensure consistent, repeatable, and trusted deployments.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: private-image-test-1
spec:
  containers:
    - name: uses-private-image
      image: image@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb
      imagePullPolicy: Always
      command: [ "echo", "SUCCESS" ]
```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: private-image-test-1
spec:
  containers:
    - name: uses-private-image
      image: $PRIVATE_IMAGE_NAME
      imagePullPolicy: Always
      command: [ "echo", "SUCCESS" ]

```
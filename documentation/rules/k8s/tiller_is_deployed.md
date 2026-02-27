---
title: "Tiller (Helm v2) deployed"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/tiller_is_deployed"
  id: "6d173be7-545a-46c6-a81d-2ae52ed1605d"
  display_name: "Tiller (Helm v2) deployed"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `6d173be7-545a-46c6-a81d-2ae52ed1605d`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/containers/images/)

### Description

Tiller (Helm v2) must not be deployed because it is deprecated and no longer supported. This rule detects resources that reference Tiller by resource name or labels (for example, `metadata.name`, `metadata.labels.app == "helm"`, or a `metadata.labels.name` containing "tiller"). It also detects Tiller container images by name in `containers` or `initContainers`, including within pod templates (`spec.template`).

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  volumes:
    - name: sec-ctx-vol
  containers:
    - name: sec-ctx-demo
      image: busybox
      command: [ "sh", "-c", "sleep 1h" ]
      volumeMounts:
        - name: sec-ctx-vol
          mountPath: /data/demo
      securityContext:
        allowPrivilegeEscalation: false
```
## Non-Compliant Code Examples
```yaml
--- 
apiVersion: extensions/v1beta1
kind: Deployment
metadata: 
  labels: 
    app: helm
    name: tiller
  name: tiller-deploy
spec: 
  containers: 
    - 
      image: tiller-image
      name: tiller-v1
  template: 
    metadata: 
      labels: 
        app: helm
        name: tiller
    spec: 
      containers: 
        - 
          args: 
            - "--listen=10.7.2.8:44134"
          image: tiller-image
          name: tiller-v2
          ports: 
            - 
              containerPort: 44134
              name: tiller
              protocol: TCP
            - 
              containerPort: 44135
              name: http
              protocol: TCP
      serviceAccountName: tiller

```
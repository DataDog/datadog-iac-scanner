---
title: "Containers missing drop capabilities"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/no_drop_capabilities_for_containers"
  id: "268ca686-7fb7-4ae9-b129-955a2a89064e"
  display_name: "Containers missing drop capabilities"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `268ca686-7fb7-4ae9-b129-955a2a89064e`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/)

### Description

 Containers and initContainers should configure drop capabilities in their `securityContext`. The rule requires that each container defines `securityContext.capabilities` with a `drop` attribute; missing `securityContext`, `capabilities`, or `drop` is reported. This enforces least-privilege by removing unnecessary Linux capabilities.


## Compliant Code Examples
```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: payment
        image: nginx
        securityContext:
          capabilities:
            drop:
              - all
            add:
              - NET_BIND_SERVICE
```
## Non-Compliant Code Examples
```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: payment
        image: nginx
        securityContext:
          capabilities:
            add:
              - NET_BIND_SERVICE
      - name: payment2
        image: nginx
        securityContext:
          allowPrivilegeEscalation: false
      - name: payment3
        image: nginx

```
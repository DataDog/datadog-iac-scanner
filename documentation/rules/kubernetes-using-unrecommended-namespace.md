---
title: "Using unrecommended namespace"
group_id: "Kubernetes"
meta:
  name: "using_unrecommended_namespace"
  id: "kubernetes-using-unrecommended-namespace"
  display_name: "Using unrecommended namespace"
  cloud_provider: ""
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-using-unrecommended-namespace{{< /copyable-code >}}

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/overview/working-with-objects/kubernetes-objects/)

### Description

Resources must include a non-null `metadata.namespace`. Namespaces such as `default`, `kube-system`, and `kube-public` must not be used; choose an appropriate non-system namespace instead.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
  namespace: cosmicPod
spec:
  securityContext:
    runAsUser: 1000
  containers:
  - name: app
    image: images.my-company.example/app:v4
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"

  - name: log-aggregator
    image: images.my-company.example/log-aggregator:v6
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"

---
apiVersion: v1
kind: CustomResourceDefinition
metadata:
  name: mongo.db.collection.com

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend2
spec:
  containers:
  - name: app
    image: images.my-company.example/app:v4
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"

  - name: log-aggregator
    image: images.my-company.example/log-aggregator:v6
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mongo.db.collection.com
  namespace: kube-public

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mongo.db.collection.com
  namespace: kube-system

```
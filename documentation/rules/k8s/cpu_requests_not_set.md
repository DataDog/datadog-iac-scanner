---
title: "CPU requests not set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/cpu_requests_not_set"
  id: "ca469dd4-c736-448f-8ac1-30a642705e0a"
  display_name: "CPU requests not set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `ca469dd4-c736-448f-8ac1-30a642705e0a`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#)

### Description

CPU requests should be set to ensure the total resource requests of scheduled containers are less than the node's capacity. This rule checks both `initContainers` and `containers` for the presence of a `resources` field, a `resources.requests` map, and a `cpu` entry within `requests`. It reports a MissingAttribute issue when any container is missing `resources`, missing `requests`, or missing CPU requests to help enforce proper schedulability and capacity planning.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
spec:
  containers:
    - name: app
      image: images.my-company.example/app:v4
      resources:
        requests:
          memory: "64Mi"
          cpu: "250m"
        limits:
          memory: "128Mi"
          cpu: "500m"
    - name: log-aggregator
      image: images.my-company.example/log-aggregator:v6
      resources:
        requests:
          memory: "64Mi"
          cpu: "250m"
        limits:
          memory: "128Mi"
          cpu: "500m"
---
apiVersion: serving.knative.dev/v1
kind: Configuration
metadata:
  name: dummy-config
  namespace: knative-sequence
spec:
  template:
    spec:
      containers:
        - name: app
          image: images.my-company.example/app:v4
          resources:
            requests:
              memory: "64Mi"
              cpu: "250m"
            limits:
              memory: "128Mi"
              cpu: "500m"
        - name: log-aggregator
          image: images.my-company.example/log-aggregator:v6
          resources:
            requests:
              memory: "64Mi"
              cpu: "250m"
            limits:
              memory: "128Mi"
              cpu: "500m"

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
spec:
  containers:
    - name: app
      image: images.my-company.example/app:v4
      resources:
        requests:
          memory: "64Mi"
        limits:
          memory: "128Mi"
          cpu: "500m"
    - name: log-aggregator
      image: images.my-company.example/log-aggregator:v6
      resources:
        limits:
          memory: "128Mi"
          cpu: "500m"
---
apiVersion: serving.knative.dev/v1
kind: Configuration
metadata:
  name: dummy-config
  namespace: knative-sequence
spec:
  template:
    spec:
      containers:
        - name: app
          image: images.my-company.example/app:v4
          resources:
            requests:
              memory: "64Mi"
            limits:
              memory: "128Mi"
              cpu: "500m"
        - name: log-aggregator
          image: images.my-company.example/log-aggregator:v6
          resources:
            limits:
              memory: "128Mi"
              cpu: "500m"

```
---
title: "Deployment without PodDisruptionBudget"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/deployment_without_pod_disruption_budget"
  id: "b23e9b98-0cb6-4fc9-b257-1f3270442678"
  display_name: "Deployment without PodDisruptionBudget"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** `b23e9b98-0cb6-4fc9-b257-1f3270442678`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/run-application/configure-pdb/)

### Description

Deployments with more than one replica should be targeted by a PodDisruptionBudget to ensure high availability during voluntary disruptions. This rule flags Deployment resources that have replicas > 1 but are not selected by any PodDisruptionBudget. A PodDisruptionBudget helps maintain the desired number of available pods during node drains or other disruptions.

## Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodDisruptionBudget
metadata:
  name: nginx-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: nginx32
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx32
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80

```
## Non-Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodDisruptionBudget
metadata:
  name: nginx-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: xpto
---
apiVersion: apps/v1
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
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80

```
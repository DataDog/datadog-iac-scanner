---
title: "HPA targeted deployments with configured replica count"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/hpa_targeted_deployments_with_configured_replica_count"
  id: "5744cbb8-5946-4b75-a196-ade44449525b"
  display_name: "HPA targeted deployments with configured replica count"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** `5744cbb8-5946-4b75-a196-ade44449525b`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale-walkthrough/)

### Description

 Deployments targeted by HorizontalPodAutoscaler should not include a statically configured replica count. This rule flags Deployments referenced by an HPA via the `scaleTargetRef` when the Deployment's `spec.replicas` field is defined. A defined `spec.replicas` can conflict with the HPA's scaling decisions and should be undefined so the HorizontalPodAutoscaler can manage replica count.


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
apiVersion: apps/v1
kind: Deployment
metadata:
  name: php-apache
spec:
  selector:
    matchLabels:
      run: php-apache
  template:
    metadata:
      labels:
        run: php-apache
    spec:
      containers:
      - name: php-apache
        image: k8s.gcr.io/hpa-example
        ports:
        - containerPort: 80
        resources:
          limits:
            cpu: 500m
          requests:
            cpu: 200m
```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: php-apache-1
spec:
  selector:
    matchLabels:
      run: php-apache
  replicas: 1
  template:
    metadata:
      labels:
        run: php-apache
    spec:
      containers:
      - name: php-apache
        image: k8s.gcr.io/hpa-example
        ports:
        - containerPort: 80
        resources:
          limits:
            cpu: 500m
          requests:
            cpu: 200m
---
apiVersion: autoscaling/v2beta2
kind: HorizontalPodAutoscaler
metadata:
  name: php-apache
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: php-apache-1
  minReplicas: 1
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 50
```
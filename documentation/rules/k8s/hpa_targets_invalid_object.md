---
title: "HPA targets invalid object"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/hpa_targets_invalid_object"
  id: "2f652c42-619d-4361-b361-9f599688f8ca"
  display_name: "HPA targets invalid object"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** `2f652c42-619d-4361-b361-9f599688f8ca`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale-walkthrough/)

### Description

 The `HorizontalPodAutoscaler` must target a valid object. This rule verifies each entry in `spec.metrics` with `type: "Object"` includes the required fields: `object.metric`, `object.target`, and `object.describedObject` with `name`, `apiVersion`, and `kind`. If any of these fields are missing, the metric is considered invalid.


## Compliant Code Examples
```yaml
apiVersion: autoscaling/v2beta2
kind: HorizontalPodAutoscaler
metadata:
  name: php-apache
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: php-apache
  minReplicas: 1
  maxReplicas: 10
  metrics:
  - type: Object
    object:
      metric:
        name: requests-per-second
      describedObject:
        apiVersion: networking.k8s.io/v1beta1
        kind: Ingress
        name: main-route
      target:
        type: Value
        value: 10k

```

```yaml
apiVersion: autoscaling/v2beta2
kind: HorizontalPodAutoscaler
metadata:
  name: matching-svc
  namespace: default
spec:
  metrics:
    - resource:
        name: cpu
        target:
          averageUtilization: 50
          type: Utilization
      type: Resource
  minReplicas: 1
  maxReplicas: 5
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: matching-svc

```
## Non-Compliant Code Examples
```yaml
apiVersion: autoscaling/v2beta2
kind: HorizontalPodAutoscaler
metadata:
  name: php-apache
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: php-apache
  minReplicas: 1
  maxReplicas: 10
  metrics:
  - type: Object
    object:
      metric:
        name: requests-per-second
      target:
        type: Value
        value: 10k
      describedObject:
        apiVersion: networking.k8s.io/v1beta1
        kind: Ingress

```
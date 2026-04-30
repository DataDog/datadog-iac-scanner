---
title: "Tiller Service present"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/tiller_service_is_not_deleted"
  id: "kubernetes-tiller-service-present"
  display_name: "Tiller Service present"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `kubernetes-tiller-service-present`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/services-networking/service)

### Description

Tiller services should be removed because Helm v2 is deprecated and no longer supported. This rule flags resources that reference 'tiller' in their metadata.name, in values of metadata.labels, or in values under spec.selector. These references should be removed or replaced to ensure compatibility with Helm v3.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Service
metadata:
  name: some-service
  labels:
    name: some-label
spec:
  ports:
    - protocol: TCP
      port: 80
      targetPort: 9376
```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Service
metadata:
  name: tiller-deploy
  labels:
    app: helm
    name: tiller
spec:
  type: ClusterIP
  selector:
    app: helm
    name: tiller
  ports:
  - name: tiller
    port: 44134
    protocol: TCP
    targetPort: tiller
```
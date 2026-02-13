---
title: "Service type is NodePort"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/service_type_is_nodeport"
  id: "845acfbe-3e10-4b8e-b656-3b404d36dfb2"
  display_name: "Service type is NodePort"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `845acfbe-3e10-4b8e-b656-3b404d36dfb2`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/services-networking/service/)

### Description

 Service resources should not have `spec.type` set to `NodePort`. A `NodePort` service exposes pods on each node and can create security and accessibility concerns; prefer `ClusterIP` or `LoadBalancer` where appropriate.


## Compliant Code Examples
```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  selector:
    app: MyApp
  ports:
    - protocol: TCP
      port: 80
      targetPort: 9376
  clusterIP: 10.0.171.239
  type: LoadBalancer
status:
  loadBalancer:
    ingress:
    - ip: 192.0.2.127
```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: NodePort
  selector:
    app: MyApp
  ports:
    - port: 80
      targetPort: 80
      nodePort: 30007
```
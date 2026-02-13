---
title: "Service with external load balancer"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/service_with_external_load_balancer"
  id: "26763a1c-5dda-4772-b507-5fca7fb5f165"
  display_name: "Service with external load balancer"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `26763a1c-5dda-4772-b507-5fca7fb5f165`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/)

### Description

 This Service uses a LoadBalancer and therefore creates an external load balancer, which may allow access from other networks and the internet. Annotations must be set to indicate an internal load balancer for supported cloud providers (for example, `networking.gke.io/load-balancer-type=Internal`, `cloud.google.com/load-balancer-type=Internal`, `service.beta.kubernetes.io/aws-load-balancer-internal=true`, `service.beta.kubernetes.io/azure-load-balancer-internal=true`) to avoid external exposure.


## Compliant Code Examples
```yaml
apiVersion: v1
kind: Service
metadata:
  name: sample-service 01
  annotations:
    cloud.google.com/load-balancer-type: 'Internal'
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: LoadBalancer
  selector:
    app: nginx
---
apiVersion: v1
kind: Service
metadata:
  name: sample-service 02
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-internal: 'true'
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: LoadBalancer
  selector:
    app: nginx
---
apiVersion: v1
kind: Service
metadata:
  name: sample-service 03
  annotations:
    service.beta.kubernetes.io/azure-load-balancer-internal: 'true'
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: LoadBalancer
  selector:
    app: nginx
---
apiVersion: v1
kind: Service
metadata:
  name: sample-service 04
  annotations:
    networking.gke.io/load-balancer-type: 'Internal'
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: LoadBalancer
  selector:
    app: nginx

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Service
metadata:
  name: sample-service 05
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: LoadBalancer
  selector:
    app: nginx
---
apiVersion: v1
kind: Service
metadata:
  name: sample-service 05334443
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-internal: 'false'
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: LoadBalancer
  selector:
    app: nginx
---
apiVersion: v1
kind: Service
metadata:
  name: sample-service 07
  annotations:
    service.beta.kubernetes.io/azure-load-balancer-internal: 'false'
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: LoadBalancer
  selector:
    app: nginx
---
apiVersion: v1
kind: Service
metadata:
  name: sample-service 08
  annotations:
    networking.gke.io/load-balancer-type: 'External'
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: LoadBalancer
  selector:
    app: nginx
---
apiVersion: v1
kind: Service
metadata:
  name: sample-service 09
  annotations:
    cloud.google.com/load-balancer-type: 'External'
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: LoadBalancer
  selector:
    app: nginx


```
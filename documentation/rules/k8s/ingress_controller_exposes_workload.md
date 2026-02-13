---
title: "Ingress controller exposes workload"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/ingress_controller_exposes_workload"
  id: "69bbc5e3-0818-4150-89cc-1e989b48f23b"
  display_name: "Ingress controller exposes workload"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `69bbc5e3-0818-4150-89cc-1e989b48f23b`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)

### Description

 Ingress controllers should not expose workloads, as this can create vulnerabilities and enable denial-of-service (DoS) attacks. This rule detects Ingress entries that route traffic to Services whose ports map directly to pod targetPorts, indicating direct exposure of workload ports. When such mappings are found, the rule flags the Ingress resource with an IncorrectValue issue identifying the resource and offending backend path.


## Compliant Code Examples
```yaml
apiVersion: v1
kind: Service
metadata:
  name: app
  labels:
    app: app
spec:
  type: ClusterIP
  ports:
  - port: 3000
    targetPort: 3000
  selector:
    app: app


---

apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: app-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx"
  labels:
    app: app
spec:
  rules:
  - host: app.acme.org
    http:
      paths:
      - backend:
          serviceName: app2
          servicePort: 3000

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Service
metadata:
  name: app
  labels:
    app: app
spec:
  type: ClusterIP
  ports:
  - port: 3000
    targetPort: 3000
  selector:
    app: app


---

apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: app-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx"
  labels:
    app: app
spec:
  rules:
  - host: app.acme.org
    http:
      paths:
      - backend:
          serviceName: app
          servicePort: 3000

```
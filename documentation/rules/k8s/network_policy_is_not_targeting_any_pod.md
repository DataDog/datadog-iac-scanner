---
title: "Network policy without Pod target"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/network_policy_is_not_targeting_any_pod"
  id: "85ab1c5b-014e-4352-b5f8-d7dea3bb4fd3"
  display_name: "Network policy without Pod target"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `85ab1c5b-014e-4352-b5f8-d7dea3bb4fd3`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

### Description

Each NetworkPolicy should target at least one Pod.
This rule verifies that the `spec.podSelector.matchLabels` entries match the `metadata.labels` of at least one Pod present in the input documents.
If no Pod matches the selector, the NetworkPolicy is reported as not targeting any Pod.

## Compliant Code Examples
```yaml
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
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: nginx
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 172.17.0.0/16
        except:
        - 172.17.1.0/24
    - namespaceSelector:
        matchLabels:
          project: myproject
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - protocol: TCP
      port: 6379
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
    ports:
    - protocol: TCP
      port: 5978
```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nopolicy
  labels:
    app: easy
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: rarelabel
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 172.17.0.0/16
        except:
        - 172.17.1.0/24
    - namespaceSelector:
        matchLabels:
          project: myproject
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - protocol: TCP
      port: 6379
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
    ports:
    - protocol: TCP
      port: 5978
---
apiVersion: v1
kind: Pod
metadata:
  name: partialpolicy
  labels:
    app: easy
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80

```
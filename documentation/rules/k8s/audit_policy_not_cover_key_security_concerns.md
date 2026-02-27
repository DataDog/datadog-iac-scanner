---
title: "Audit policy does not cover key security concerns"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/audit_policy_not_cover_key_security_concerns"
  id: "1828a670-5957-4bc5-9974-47da228f75e2"
  display_name: "Audit policy does not cover key security concerns"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `1828a670-5957-4bc5-9974-47da228f75e2`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)

### Description

The audit policy should cover key security concerns about sensitive data logged in Kubernetes audit logs.
The policy requires rules for specific resources to be defined at the required audit levels (Metadata, Request, RequestResponse). These resources include: secrets, tokenreviews, configmaps, pods, deployments, and pod/service sub-resources (pods/exec, pods/portforward, pods/proxy, services/proxy).
Missing any required level for a listed resource indicates the policy may not adequately prevent sensitive information from being recorded or exposed via audit events.

## Compliant Code Examples
```yaml
apiVersion: audit.k8s.io/v1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets","configmaps","tokenreviews"]
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods","deployments"]
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods/exec", "pods/portforward", "pods/proxy", "services/proxy"]

```
## Non-Compliant Code Examples
```yaml
apiVersion: audit.k8s.io/v1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
rules:
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets","configmaps","tokenreviews"]
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods","deployments"]
  - level: None
    resources:
    - group: ""
      resources: ["pods/exec", "pods/portforward", "pods/proxy", "services/proxy"]

```

```yaml
apiVersion: audit.k8s.io/v1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets","configmaps","tokenreviews"]
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods"]
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods/exec", "pods/portforward", "pods/proxy", "services/proxy"]

```

```yaml
apiVersion: audit.k8s.io/v1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:

```
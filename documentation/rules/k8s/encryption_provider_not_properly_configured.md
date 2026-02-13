---
title: "Encryption provider not properly configured"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/encryption_provider_not_properly_configured"
  id: "10efce34-5af6-4d83-b414-9e096d5a06a9"
  display_name: "Encryption provider not properly configured"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `10efce34-5af6-4d83-b414-9e096d5a06a9`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/#understanding-the-encryption-at-rest-configuration)

### Description

The `EncryptionConfiguration` must include at least one provider: `aescbc`, `kms`, or `secretbox`. This rule inspects `EncryptionConfiguration` documents and checks the `providers` entries in each resource to find one of these provider names. If none of the expected providers is present, the rule reports a `MissingAttribute` issue and records the expected and actual values. The check iterates the resource's `resources` elements and validates provider keys.

## Compliant Code Examples
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - identity: {}
      - aesgcm:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==
      - aescbc:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==
      - secretbox:
          keys:
            - name: key1
              secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=

```
## Non-Compliant Code Examples
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - identity: {}
      - aesgcm:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==

```
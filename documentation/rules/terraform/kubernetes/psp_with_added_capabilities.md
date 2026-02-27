---
title: "PSP with added capabilities"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/psp_with_added_capabilities"
  id: "48388bd2-7201-4dcc-b56d-e8a9efa58fad"
  display_name: "PSP with added capabilities"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `48388bd2-7201-4dcc-b56d-e8a9efa58fad`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod_security_policy#allowed_capabilities)

### Description

Pod Security Policy should not include allowed capabilities.

This rule inspects `kubernetes_pod_security_policy` resources and flags any presence of `spec.allowed_capabilities`. When triggered, the rule returns `documentId`, `resourceType`, `resourceName`, `searchKey`, `issueType`, `keyExpectedValue`, and `keyActualValue` to describe the finding. The `issueType` for these findings is `IncorrectValue`.

## Compliant Code Examples
```terraform
resource "kubernetes_pod_security_policy" "example2" {
  metadata {
    name = "terraform-example"
  }
  spec {
    privileged                 = false
    allow_privilege_escalation = false

    volumes = [
      "configMap",
      "emptyDir",
      "projected",
      "secret",
      "downwardAPI",
      "persistentVolumeClaim",
    ]

    run_as_user {
      rule = "MustRunAsNonRoot"
    }

    se_linux {
      rule = "RunAsAny"
    }

    supplemental_groups {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }

    fs_group {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }

    read_only_root_filesystem = true
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "kubernetes_pod_security_policy" "example" {
  metadata {
    name = "terraform-example"
  }
  spec {
    allowed_capabilities = ["NET_BIND_SERVICE"]
    privileged                 = false
    allow_privilege_escalation = false

    volumes = [
      "configMap",
      "emptyDir",
      "projected",
      "secret",
      "downwardAPI",
      "persistentVolumeClaim",
    ]

    run_as_user {
      rule = "MustRunAsNonRoot"
    }

    se_linux {
      rule = "RunAsAny"
    }

    supplemental_groups {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }

    fs_group {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }

    read_only_root_filesystem = true
  }
}

```
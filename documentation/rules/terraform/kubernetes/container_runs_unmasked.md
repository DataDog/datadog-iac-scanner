---
title: "Container runs unmasked"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/container_runs_unmasked"
  id: "0ad60203-c050-4115-83b6-b94bde92541d"
  display_name: "Container runs unmasked"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `0ad60203-c050-4115-83b6-b94bde92541d`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod_security_policy#allowed_proc_mount_types)

### Description

Checks whether a container has unmasked access to the host's `/proc` filesystem, which allows retrieval of sensitive information and could permit changing kernel parameters at runtime. The rule verifies that `kubernetes_pod_security_policy.spec.allowed_proc_mount_types` does not contain the value `Unmasked` and that `allowed_proc_mount_types` includes `Default` as the expected value. Unmasked access to `/proc` increases the attack surface and can enable privilege escalation or other runtime compromises.

## Compliant Code Examples
```terraform
resource "kubernetes_pod_security_policy" "example" {
  metadata {
    name = "terraform-example"
  }
  spec {
    privileged                 = false
    allow_privilege_escalation = false
    allowed_proc_mount_types   = ["Default"]

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
    privileged                 = false
    allow_privilege_escalation = false
    allowed_proc_mount_types   = ["Unmasked"]

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
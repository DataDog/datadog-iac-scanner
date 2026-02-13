---
title: "PSP allows privilege escalation"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/psp_allows_privilege_escalation"
  id: "2bff9906-4e9b-4f71-9346-8ebedfdf43ef"
  display_name: "PSP allows privilege escalation"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `2bff9906-4e9b-4f71-9346-8ebedfdf43ef`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod_security_policy#allow_privilege_escalation)

### Description

 `PodSecurityPolicy` should not allow privilege escalation. The `kubernetes_pod_security_policy` resource must include the `spec.allow_privilege_escalation` attribute and set it to `false`. If `spec.allow_privilege_escalation` is missing or set to `true`, this rule reports a `MissingAttribute` or `IncorrectValue` issue and recommends setting `spec.allow_privilege_escalation = false` as the remediation. The rule inspects `resource.kubernetes_pod_security_policy[name].spec` to determine the presence and value of `allow_privilege_escalation`.


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
    privileged                 = false
    allow_privilege_escalation = true

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

resource "kubernetes_pod_security_policy" "example2" {
  metadata {
    name = "terraform-example"
  }
  spec {
    privileged                 = false

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
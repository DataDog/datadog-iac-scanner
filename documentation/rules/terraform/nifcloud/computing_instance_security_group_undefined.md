---
title: "Beta - Nifcloud computing undefined security group to instance"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/computing_instance_security_group_undefined"
  id: "89218b48-75c9-4cb3-aaba-5299e852e8bc"
  display_name: "Beta - Nifcloud computing undefined security group to instance"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `89218b48-75c9-4cb3-aaba-5299e852e8bc`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/instance#security_group)

### Description

 Missing `security_group` on `nifcloud_instance` resources.
The `nifcloud_instance` resource should include a `security_group` to enforce network-level access controls.
Instances that do not set a `security_group` are flagged as `MissingAttribute`.


## Compliant Code Examples
```terraform
resource "nifcloud_instance" "negative" {
  image_id        = data.nifcloud_image.ubuntu.id
  security_group  = nifcloud_security_group.example.group_name
  network_interface {
    network_id = "net-COMMON_GLOBAL"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_instance" "positive" {
  image_id        = data.nifcloud_image.ubuntu.id
  network_interface {
    network_id = "net-COMMON_GLOBAL"
  }
}

```
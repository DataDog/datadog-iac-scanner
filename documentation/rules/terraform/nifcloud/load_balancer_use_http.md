---
title: "Beta - Nifcloud LB use HTTP port"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/load_balancer_use_http"
  id: "94e47f3f-b90b-43a1-a36d-521580bae863"
  display_name: "Beta - Nifcloud LB use HTTP port"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `94e47f3f-b90b-43a1-a36d-521580bae863`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#load_balancer_port)

### Description

 The `nifcloud_load_balancer` is configured to use the HTTP port (`load_balancer_port` is set to `80`).
It should be switched to HTTPS to benefit from TLS security features.
The rule reports an `IncorrectValue` issue when `load_balancer_port` equals `80`.


## Compliant Code Examples
```terraform
resource "nifcloud_load_balancer" "negative" {
  load_balancer_name = "example"
  instance_port      = 443
  load_balancer_port = 443
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_load_balancer" "positive" {
  load_balancer_name = "example"
  instance_port      = 80
  load_balancer_port = 80
}

```
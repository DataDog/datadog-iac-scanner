---
title: "Beta - Nifcloud LB listener use HTTP port"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/load_balancer_listener_use_http"
  id: "9f751a80-31f0-43a3-926c-20772791a038"
  display_name: "Beta - Nifcloud LB listener use HTTP port"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `9f751a80-31f0-43a3-926c-20772791a038`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer_listener#load_balancer_port)

### Description

The `nifcloud_load_balancer_listener` is configured to use the HTTP port: `load_balancer_port` is set to `80`, so the listener uses unencrypted HTTP rather than HTTPS. This configuration does not provide TLS encryption; the listener is expected to use HTTPS to benefit from TLS security features.

## Compliant Code Examples
```terraform
resource "nifcloud_load_balancer_listener" "negative" {
  load_balancer_name = "example"
  instance_port = 443
  load_balancer_port = 443
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_load_balancer_listener" "positive" {
  load_balancer_name = "example"
  instance_port = 80
  load_balancer_port = 80
}

```
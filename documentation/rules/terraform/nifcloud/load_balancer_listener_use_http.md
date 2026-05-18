---
title: "NIFCLOUD LB listener using HTTP port"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/load_balancer_listener_use_http"
  id: "terraform-nifcloud-load-balancer-listener-use-http"
  display_name: "NIFCLOUD LB listener using HTTP port"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-nifcloud-load-balancer-listener-use-http{{< /copyable-code >}}

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

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
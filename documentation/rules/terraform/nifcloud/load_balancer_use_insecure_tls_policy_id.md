---
title: "NIFCLOUD LB using insecure TLS policy ID"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/load_balancer_use_insecure_tls_policy_id"
  id: "terraform-nifcloud-load-balancer-use-insecure-tls-policy-id"
  display_name: "NIFCLOUD LB using insecure TLS policy ID"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-nifcloud-load-balancer-use-insecure-tls-policy-id{{< /copyable-code >}}

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#ssl_policy_id)

### Description

The load balancer uses an insecure TLS policy. This rule flags `nifcloud_load_balancer` resources that either omit `ssl_policy_id` or set `ssl_policy_id` to an outdated policy identifier (`1`, `2`, `3`, `5`, `8`). Resources must use `TLS v1.2+` for secure encryption.

## Compliant Code Examples
```terraform
resource "nifcloud_load_balancer" "negative" {
  load_balancer_name = "example"
  instance_port      = 443
  load_balancer_port = 443
  ssl_policy_id      = "4"
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_load_balancer" "positive" {
  load_balancer_name = "example"
  instance_port      = 443
  load_balancer_port = 443
  ssl_policy_name    = "1"
}

```

```terraform
resource "nifcloud_load_balancer" "positive" {
  load_balancer_name = "example"
  instance_port      = 443
  load_balancer_port = 443
}

```
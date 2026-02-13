---
title: "Beta - Nifcloud LB use insecure TLS policy name"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/load_balancer_use_insecure_tls_policy_name"
  id: "675e8eaa-2754-42b7-bf33-bfa295d1601d"
  display_name: "Beta - Nifcloud LB use insecure TLS policy name"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `675e8eaa-2754-42b7-bf33-bfa295d1601d`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#ssl_policy_name)

### Description

 The `lb` uses an insecure TLS policy. The `nifcloud_load_balancer` resource either omits the `ssl_policy_name` attribute or sets it to an outdated SSL policy. Configure `ssl_policy_name` to use a modern TLS policy (TLS v1.2 or newer) and avoid legacy SSL policies.


## Compliant Code Examples
```terraform
resource "nifcloud_load_balancer" "negative" {
  load_balancer_name = "example"
  instance_port      = 443
  load_balancer_port = 443
  ssl_policy_name    = "Standard Ciphers D ver1"
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_load_balancer" "positive" {
  load_balancer_name = "example"
  instance_port      = 443
  load_balancer_port = 443
  ssl_policy_name    = "Standard Ciphers A ver1"
}

```

```terraform
resource "nifcloud_load_balancer" "positive" {
  load_balancer_name = "example"
  instance_port      = 443
  load_balancer_port = 443
}

```
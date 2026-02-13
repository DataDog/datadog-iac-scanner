---
title: "Beta - CLB listener using insecure protocols"
group_id: "Terraform / TencentCloud"
meta:
  name: "tencentcloud/clb_listener_using_insecure_protocols"
  id: "fe08b81c-12e9-4b5e-9006-4218fca750fd"
  display_name: "Beta - CLB listener using insecure protocols"
  cloud_provider: "TencentCloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `fe08b81c-12e9-4b5e-9006-4218fca750fd`

**Cloud Provider:** TencentCloud

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/tencentcloudstack/tencentcloud/latest/docs/resources/clb_listener#protocol)

### Description

 The CLB listener `protocol` must not be set to insecure protocols such as `TCP`, `UDP`, or `HTTP`.
This rule checks `tencentcloud_clb_listener` resources and flags any instance where the `protocol` is one of these insecure values.
Resources configured with these protocols are considered insecure and are reported.


## Compliant Code Examples
```terraform
resource "tencentcloud_clb_listener" "listener" {
  clb_id        = "lb-0lh5au7v"
  listener_name = "test_listener"
  protocol      = "HTTPS"
  port          = 443
}

```
## Non-Compliant Code Examples
```terraform
resource "tencentcloud_clb_listener" "listener" {
  clb_id        = "lb-0lh5au7v"
  listener_name = "test_listener"
  protocol      = "TCP"
  port          = 8080
}

```

```terraform
resource "tencentcloud_clb_listener" "listener" {
  clb_id        = "lb-0lh5au7v"
  listener_name = "test_listener"
  protocol      = "UDP"
  port          = 8090
}

```

```terraform
resource "tencentcloud_clb_listener" "listener" {
  clb_id        = "lb-0lh5au7v"
  listener_name = "test_listener"
  protocol      = "HTTP"
  port          = 80
}

```
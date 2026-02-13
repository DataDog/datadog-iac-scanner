---
title: "ALB listening on HTTP"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/alb_listening_on_http"
  id: "ee3b1557-9fb5-4685-a95d-93f1edf2a0d7"
  display_name: "ALB listening on HTTP"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ee3b1557-9fb5-4685-a95d-93f1edf2a0d7`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/alb_listener)

### Description

 Application Load Balancer (`alb`) listeners should not use `HTTP`.
Listeners configured with `listener_protocol = "HTTP"` expose unencrypted traffic. In Terraform, set `listener_protocol = "HTTPS"` for `alicloud_alb_listener` resources to enforce TLS termination and secure data in transit.


## Compliant Code Examples
```terraform
resource "alicloud_alb_listener" "negative" {
  load_balancer_id     = alicloud_alb_load_balancer.default_3.id
  listener_protocol    = "HTTPS"
  listener_port        = 443
  listener_description = "createdByTerraform"
  default_actions {
    type = "ForwardGroup"
    forward_group_config {
      server_group_tuples {
        server_group_id = alicloud_alb_server_group.default.id
      }
    }
  }
  certificates {
    certificate_id = join("", [alicloud_ssl_certificates_service_certificate.default.id, "-cn-hangzhou"])
  }
  acl_config {
    acl_type = "White"
    acl_relations {
      acl_id = alicloud_alb_acl.example.id
    }
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_alb_listener" "positive" {
  load_balancer_id     = alicloud_alb_load_balancer.default_3.id
  listener_protocol    = "HTTP"
  listener_port        = 443
  listener_description = "createdByTerraform"
  default_actions {
    type = "ForwardGroup"
    forward_group_config {
      server_group_tuples {
        server_group_id = alicloud_alb_server_group.default.id
      }
    }
  }
  certificates {
    certificate_id = join("", [alicloud_ssl_certificates_service_certificate.default.id, "-cn-hangzhou"])
  }
  acl_config {
    acl_type = "White"
    acl_relations {
      acl_id = alicloud_alb_acl.example.id
    }
  }
}

```
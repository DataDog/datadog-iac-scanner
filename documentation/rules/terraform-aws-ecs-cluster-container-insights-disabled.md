---
title: "ECS cluster with container insights disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/ecs_cluster_container_insights_disabled"
  id: "terraform-aws-ecs-cluster-container-insights-disabled"
  display_name: "ECS cluster with container insights disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-aws-ecs-cluster-container-insights-disabled{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster#setting)

### Description

ECS clusters should have the `containerInsights` setting enabled to provide enhanced monitoring and observability for container workloads. Without enabling container insights, as in the configuration below, critical metrics and logs about cluster and task performance will not be collected, making it more difficult to detect anomalies, troubleshoot issues, and ensure operational health:

```
resource "aws_ecs_cluster" "foo" {
  name = "white-hart"
}
```

Enabling container insights by specifying the following helps provide visibility into resource utilization, failures, and capacity planning, reducing operational risk:

```
setting {
  name  = "containerInsights"
  value = "enabled"
}
```

## Compliant Code Examples
```terraform
resource "aws_ecs_cluster" "foo" {
  name = "white-hart"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_ecs_cluster" "foo" {
  name = "white-hart"

#  setting {
#    name  = "containerInsights"
#    value = "enabled"
#  }
}

```
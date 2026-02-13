---
title: "ECS task definition network mode not recommended"
group_id: "Terraform / AWS"
meta:
  name: "aws/ecs_task_definition_network_mode_not_recommended"
  id: "9f4a9409-9c60-4671-be96-9716dbf63db1"
  display_name: "ECS task definition network mode not recommended"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `9f4a9409-9c60-4671-be96-9716dbf63db1`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#network_mode)

### Description

This check ensures that the `network_mode` attribute in an AWS ECS task definition is set to `awsvpc`. When `network_mode` is set to any value other than `awsvpc`, such as `none`, the tasks do not leverage the enhanced network security and isolation features provided by AWS VPCs. Without `awsvpc`, the container tasks may lack granular control over network traffic, security group assignment, and enforcement of network policies, making them more exposed to lateral movement and attacks within the cluster. If left unaddressed, this misconfiguration could lead to unauthorized access or unintended network exposure of container workloads, increasing the risk of compromise.

## Compliant Code Examples
```terraform
resource "aws_ecs_task_definition" "negative1" {
  family                = "service"
  network_mode = "awsvpc"

  volume {
    name      = "service-storage"
    host_path = "/ecs/service-storage"
  }

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:ecs.availability-zone in [us-west-2a, us-west-2b]"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_ecs_task_definition" "positive1" {
  family                = "service"
  network_mode = "none"

  volume {
    name      = "service-storage"
    host_path = "/ecs/service-storage"
  }

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:ecs.availability-zone in [us-west-2a, us-west-2b]"
  }
}
```
---
title: "ECS service admin role is present"
group_id: "Terraform / AWS"
meta:
  name: "aws/ecs_service_admin_role_is_present"
  id: "3206240f-2e87-4e58-8d24-3e19e7c83d7c"
  display_name: "ECS service admin role is present"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `3206240f-2e87-4e58-8d24-3e19e7c83d7c`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service)

### Description

 This check ensures that Amazon ECS services are not configured with administrative roles, which could grant excessive permissions and violate the principle of least privilege. When an ECS service has an admin role, it can perform any action within AWS, potentially allowing attackers to escalate privileges if the service is compromised. Instead of using an admin role like `iam_role = "admin"`, you should create a specific role with only the necessary permissions and reference it using its ARN, as shown in this example: `iam_role = aws_iam_role.foo.arn`.


## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "aws_ecs_service" "negative1" {
  name            = "mongodb"
  cluster         = aws_ecs_cluster.foo.id
  task_definition = aws_ecs_task_definition.mongo.arn
  desired_count   = 3
  iam_role        = aws_iam_role.foo.arn
  depends_on      = [aws_iam_role_policy.foo]

  ordered_placement_strategy {
    type  = "binpack"
    field = "cpu"
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.foo.arn
    container_name   = "mongo"
    container_port   = 8080
  }

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:ecs.availability-zone in [us-west-2a, us-west-2b]"
  }
}
```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
resource "aws_ecs_service" "positive1" {
  name            = "mongodb"
  cluster         = aws_ecs_cluster.foo.id
  task_definition = aws_ecs_task_definition.mongo.arn
  desired_count   = 3
  iam_role        = "admin"
  depends_on      = [aws_iam_role_policy.foo]

  ordered_placement_strategy {
    type  = "binpack"
    field = "cpu"
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.foo.arn
    container_name   = "mongo"
    container_port   = 8080
  }

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:ecs.availability-zone in [us-west-2a, us-west-2b]"
  }
}
```
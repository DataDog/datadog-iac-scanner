---
title: "ECS service without running tasks"
group_id: "Terraform / AWS"
meta:
  name: "aws/ecs_service_without_running_tasks"
  id: "91f16d09-689e-4926-aca7-155157f634ed"
  display_name: "ECS service without running tasks"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** `91f16d09-689e-4926-aca7-155157f634ed`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service)

### Description

 The ECS service should have at least one task running, which is defined by the `desired_count` attribute in the Terraform configuration. An unsafe configuration, such as shown below, leaves the service without any running tasks, meaning the application will be unavailable and unable to process user requests:

```
resource "aws_ecs_service" "positive1" {
  name    = "positive1"
  cluster = aws_ecs_cluster.example.id
  desired_count   = 0
}
```

Failure to set an appropriate value for `desired_count` can lead to outages and an inability to meet service availability or business requirements.


## Compliant Code Examples
```terraform
resource "aws_ecs_service" "negative1" {
  name    = "negative1"
  cluster = aws_ecs_cluster.example.id

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100
}

resource "aws_ecs_service" "km_ecs_service" {
  name            = "km_ecs_service_${var.environment}"
  cluster         = aws_ecs_cluster.km_ecs_cluster.id
  task_definition = aws_ecs_task_definition.km_ecs_task.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  load_balancer {
    target_group_arn = var.elb_target_group_arn
    container_name   = "km-frontend"
    container_port   = 80
  }
  network_configuration {
    assign_public_ip = true
    subnets          = var.private_subnet
    security_groups  = [ var.elb_sg ]
  }
  tags = merge(var.default_tags, {
  })
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_ecs_service" "positive1" {
  name    = "positive1"
  cluster = aws_ecs_cluster.example.id
  desired_count   = 0
}

```
---
title: "ECS service without running tasks"
group_id: "Ansible / AWS"
meta:
  name: "aws/ecs_service_without_running_tasks"
  id: "ansible-aws-ecs-service-without-running-tasks"
  display_name: "ECS service without running tasks"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-ecs-service-without-running-tasks{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/ecs_service_module.html#ansible-collections-community-aws-ecs-service-module)

### Description

ECS services must define a deployment configuration to avoid deployments or scaling events from temporarily leaving zero tasks running, which can cause application downtime and loss of availability.

For Ansible ECS tasks using the `community.aws.ecs_service` or `ecs_service` modules, the `deployment_configuration` property must be present and include the `minimum_healthy_percent` and `maximum_percent` keys. Resources missing `deployment_configuration` or missing either `minimum_healthy_percent` or `maximum_percent` are flagged. This rule checks for the presence of those keys and does not validate numeric ranges. Ensure `minimum_healthy_percent` is set so at least one task remains running during deployments according to your desired task count.

Secure example (Ansible task):

```yaml
- name: my-ecs-service
  community.aws.ecs_service:
    name: my-service
    cluster: my-cluster
    task_definition: my-task:1
    desired_count: 2
    deployment_configuration:
      maximum_percent: 200
      minimum_healthy_percent: 50
```

## Compliant Code Examples
```yaml
- name: ECS Service
  community.aws.ecs_service:
    state: present
    name: test-service
    cluster: test-cluster
    task_definition: test-task-definition
    desired_count: 3
    deployment_configuration:
      minimum_healthy_percent: 75
      maximum_percent: 150
    placement_constraints:
      - type: memberOf
        expression: 'attribute:flavor==test'
    placement_strategy:
      - type: binpack
        field: memory

```
## Non-Compliant Code Examples
```yaml
- name: ECS Service
  community.aws.ecs_service:
    state: present
    name: test-service
    cluster: test-cluster
    task_definition: test-task-definition
    desired_count: 3
    placement_constraints:
      - type: memberOf
        expression: 'attribute:flavor==test'
    placement_strategy:
      - type: binpack
        field: memory

```
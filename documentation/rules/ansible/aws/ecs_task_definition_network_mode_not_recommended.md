---
title: "ECS task definition network mode not recommended"
group_id: "Ansible / AWS"
meta:
  name: "aws/ecs_task_definition_network_mode_not_recommended"
  id: "ansible-aws-ecs-task-definition-network-mode-not-recommended"
  display_name: "ECS task definition network mode not recommended"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `ansible-aws-ecs-task-definition-network-mode-not-recommended`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/ecs_taskdefinition_module.html#parameter-network_mode)

### Description

ECS task definitions must use the `awsvpc` network mode so each task receives its own ENI and can be isolated with security groups and VPC controls. Without `awsvpc`, tasks may share the host network namespace or lack per-task security group enforcement, increasing exposure to lateral movement and unintended network access.

The `network_mode` property in Ansible `community.aws.ecs_taskdefinition` or `ecs_taskdefinition` resources must be set to `"awsvpc"`. Resources missing `network_mode` or with values such as `"host"`, `"bridge"`, or `"none"` are flagged. AWS Fargate requires `awsvpc`, and using legacy modes causes tasks to share host networking and bypass per-task security group rules.

Secure configuration example:

```yaml
- name: Register ECS task definition with awsvpc
  community.aws.ecs_taskdefinition:
    family: my-task
    network_mode: awsvpc
    container_definitions: "{{ lookup('file', 'containers.json') }}"
```

## Compliant Code Examples
```yaml
- name: Create task definition
  community.aws.ecs_taskdefinition:
    family: nginx
    containers:
    - name: nginx
      essential: true
      image: nginx
      portMappings:
      - containerPort: 8080
        hostPort: 8080
    launch_type: FARGATE
    cpu: 512
    memory: 1024
    state: present
    network_mode: awsvpc

```
## Non-Compliant Code Examples
```yaml
---
- name: Create task definition
  community.aws.ecs_taskdefinition:
    family: nginx
    containers:
    - name: nginx
      essential: true
      image: "nginx"
      portMappings:
      - containerPort: 8080
        hostPort: 8080
      cpu: 512
      memory: 1024
    state: present
    network_mode: default

- name: Create task definition2
  community.aws.ecs_taskdefinition:
    family: nginx
    containers:
    - name: nginx
      essential: true
      image: "nginx"
      portMappings:
      - containerPort: 8080
        hostPort: 8080
    launch_type: FARGATE
    cpu: 512
    memory: 1024
    state: present
    network_mode: none

```
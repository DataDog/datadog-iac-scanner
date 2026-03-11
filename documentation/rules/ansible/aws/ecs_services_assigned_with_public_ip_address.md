---
title: "ECS Services assigned with public IP address"
group_id: "Ansible / AWS"
meta:
  name: "aws/ecs_services_assigned_with_public_ip_address"
  id: "560f256b-0b45-4496-bcb5-733681e7d38d"
  display_name: "ECS Services assigned with public IP address"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `560f256b-0b45-4496-bcb5-733681e7d38d`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/ecs_service_module.html)

### Description

Amazon ECS services should not be assigned public IP addresses because attaching public IPs exposes tasks directly to the internet, increasing the attack surface and the risk of unauthorized access. For Ansible tasks using the `community.aws.ecs_service` or `ecs_service` modules, the `network_configuration.assign_public_ip` property must be defined and set to `false`. Tasks with `assign_public_ip: true` will be flagged; if services require outbound internet access, use private subnets with a NAT gateway or expose services via a load balancer instead of assigning public IPs.

Secure configuration example:

```yaml
- name: Create ECS service with no public IP
  community.aws.ecs_service:
    name: my-service
    cluster: my-cluster
    task_definition: my-task:1
    network_configuration:
      subnets:
        - subnet-0123456789abcdef0
      security_groups:
        - sg-0123456789abcdef0
      assign_public_ip: false
```

## Compliant Code Examples
```yaml
- name: negative1
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Create ECS service with network configuration
      community.aws.ecs_service:
        state: present
        name: example-public-ip-service
        cluster: my-ecs-cluster
        task_definition: my-task-def:1
        desired_count: 2
        launch_type: FARGATE
        network_configuration:
          subnets:
            - subnet-aaaa1111
            - subnet-bbbb2222
          security_groups:
            - sg-cccc3333
          assign_public_ip: false

```
## Non-Compliant Code Examples
```yaml
- name: positive1
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Create ECS service with network configuration
      community.aws.ecs_service:
        state: present
        name: example-public-ip-service
        cluster: my-ecs-cluster
        task_definition: my-task-def:1
        desired_count: 2
        launch_type: FARGATE
        network_configuration:
          subnets:
            - subnet-aaaa1111
            - subnet-bbbb2222
          security_groups:
            - sg-cccc3333
          assign_public_ip: true

```
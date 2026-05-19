---
title: "ECS service admin role is present"
group_id: "Ansible / AWS"
meta:
  name: ""aws/ecs_service_admin_role_is_present""
  id: "ansible-aws-ecs-service-admin-role-is-present"
  display_name: "ECS service admin role is present"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-ecs-service-admin-role-is-present{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/ecs_service_module.html)

### Description

ECS services must not be assigned administrative IAM roles. Admin-level privileges grant containers broad account-wide access and increase the risk of privilege escalation and lateral movement if the service is compromised. In Ansible tasks using `community.aws.ecs_service` or `ecs_service`, the `role` property must reference a least-privilege IAM role or ARN and must not contain the substring "admin" (case-insensitive). This rule flags tasks where `role` is a string that includes "admin". Roles omitted or defined via non-string constructs may not be detected and should be reviewed to ensure they do not attach the `AdministratorAccess` policy.

Secure example referencing a non-admin role:

```yaml
- name: my-ecs-service
  community.aws.ecs_service:
    name: my-service
    cluster: my-cluster
    task_definition: my-task:1
    role: arn:aws:iam::123456789012:role/ecsTaskRole
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: ECS Service
  community.aws.ecs_service:
    state: present
    name: console-test-service
    cluster: new_cluster
    task_definition: new_cluster-task:1
    desired_count: 0

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: ECS Service
  community.aws.ecs_service:
    state: present
    name: console-test-service
    cluster: new_cluster
    task_definition: 'new_cluster-task:1'
    desired_count: 0
    role: admin

```
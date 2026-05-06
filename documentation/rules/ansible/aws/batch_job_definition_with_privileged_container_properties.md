---
title: "Batch job definition with privileged container properties"
group_id: "Ansible / AWS"
meta:
  name: "aws/batch_job_definition_with_privileged_container_properties"
  id: "defe5b18-978d-4722-9325-4d1975d3699f"
  display_name: "Batch job definition with privileged container properties"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}defe5b18-978d-4722-9325-4d1975d3699f{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/batch_job_definition_module.html)

### Description

Batch job definitions must not enable privileged containers. Privileged mode weakens container isolation and can allow containers to access host resources or escalate privileges, increasing the risk of host compromise and lateral movement.

For Ansible, tasks using the `community.aws.batch_job_definition` or `aws_batch_job_definition` modules must not set the `privileged` parameter to `true`. The `privileged` setting should be omitted or explicitly set to `false` in the job definition's container properties. Resources with `privileged: true` are flagged. Only enable privileged mode when absolutely required and after applying additional host hardening, access controls, and justification.

Secure example:

```yaml
- name: Register Batch job definition without privileged mode
  community.aws.batch_job_definition:
    name: my-batch-job
    container_properties:
      image: my-image:latest
      vcpus: 1
      memory: 1024
      privileged: false
```

## Compliant Code Examples
```yaml
- name: My Batch Job Definition
  community.aws.batch_job_definition:
    job_definition_name: My Batch Job Definition without privilege
    state: present
    type: container
    parameters:
      Param1: Val1
      Param2: Val2
    privileged: false
    image: <Docker Image URL>
    vcpus: 1
    memory: 512
    command:
      - python
      - run_my_script.py
      - arg1
    job_role_arn: <Job Role ARN>
    attempts: 3
  register: job_definition_create_result
- name: My Batch Job Definition without explicit privilege
  community.aws.batch_job_definition:
    job_definition_name: My Batch Job Definition
    state: present
    type: container
    parameters:
      Param1: Val1
      Param2: Val2
    image: <Docker Image URL>
    vcpus: 1
    memory: 512
    command:
      - python
      - run_my_script.py
      - arg1
    job_role_arn: <Job Role ARN>
    attempts: 3
  register: job_definition_create_result

```
## Non-Compliant Code Examples
```yaml
- name: My Batch Job Definition
  community.aws.batch_job_definition:
    job_definition_name: My Batch Job Definition
    state: present
    type: container
    parameters:
      Param1: Val1
      Param2: Val2
    privileged: true
    image: <Docker Image URL>
    vcpus: 1
    memory: 512
    command:
      - python
      - run_my_script.py
      - arg1
    job_role_arn: <Job Role ARN>
    attempts: 3
  register: job_definition_create_result

```
---
title: "Hardcoded AWS access key"
group_id: "Ansible / AWS"
meta:
  name: ""aws/hardcoded_aws_access_key""
  id: "ansible-aws-hardcoded-aws-access-key"
  display_name: "Hardcoded AWS access key"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-hardcoded-aws-access-key{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_instance_module.html)

### Description

Embedding AWS access keys in EC2 user data exposes credentials to source control, logs, and anyone with access to the instance. Attackers can use these credentials to access or escalate privileges in your AWS account.

This rule checks Ansible tasks using the `amazon.aws.ec2_instance` or `ec2_instance` modules and flags the `user_data` property when it contains patterns matching AWS Access Key IDs (20 uppercase alphanumeric characters) or Secret Access Keys (40-character base64-like strings). Resources whose `user_data` contains sequences matching those key patterns are flagged.

Do not hardcode credentials. Assign an IAM instance profile to the instance or retrieve secrets at runtime from AWS Secrets Manager or AWS Systems Manager Parameter Store and inject them securely.

Secure example using an instance profile and avoiding embedded keys:

```yaml
- name: Launch EC2 without hardcoded keys
  amazon.aws.ec2_instance:
    name: my-instance
    image_id: ami-0123456789abcdef0
    instance_type: t3.micro
    instance_profile_name: my-iam-instance-profile
    user_data: |
      #!/bin/bash
      # No hardcoded AWS keys here; fetch secrets from SSM or Secrets Manager at runtime
```

## Compliant Code Examples
```yaml
- name: start an instance with a cpu_options
  amazon.aws.ec2_instance:
    name: public-cpuoption-instance
    vpc_subnet_id: subnet-5ca1ab1e
    tags:
      Environment: Testing
    instance_type: c4.large
    volumes:
      - device_name: /dev/sda1
        ebs:
          delete_on_termination: true
    cpu_options:
      core_count: 1
      threads_per_core: 1

```
## Non-Compliant Code Examples
```yaml
- name: start an instance with a cpu_options
  amazon.aws.ec2_instance:
    name: "public-cpuoption-instance"
    vpc_subnet_id: subnet-5ca1ab1e
    tags:
      Environment: Testing
    user_data: "1234567890123456789012345678901234567890$"

```
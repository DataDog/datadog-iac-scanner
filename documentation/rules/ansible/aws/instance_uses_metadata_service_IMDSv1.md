---
title: "Instance uses metadata service IMDSv1"
group_id: "Ansible / AWS"
meta:
  name: "aws/instance_uses_metadata_service_IMDSv1"
  id: "b9ef8c0e-1392-4df4-aa84-2e0f95681c75"
  display_name: "Instance uses metadata service IMDSv1"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `b9ef8c0e-1392-4df4-aa84-2e0f95681c75`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_instance_module.html)

### Description

The EC2 instance metadata service should require IMDSv2 session tokens to reduce the risk of metadata and credential exposure via SSRF or from compromised instances.

For Ansible-managed EC2 resources (`amazon.aws.ec2_instance`, `community.aws.autoscaling_launch_config`), the `metadata_options.http_tokens` property must be set to `required` to enforce IMDSv2. Resources missing `metadata_options`, missing `metadata_options.http_tokens`, or where `http_tokens` is not `required` are flagged as insecure.

Secure configuration example:

```yaml
- name: Launch EC2 instance with IMDSv2 required
  amazon.aws.ec2_instance:
    name: my-instance
    image_id: ami-0123456789abcdef0
    instance_type: t3.micro
    metadata_options:
      http_tokens: required
```

## Compliant Code Examples
```yaml
- name: start an instance with metadata options
  amazon.aws.ec2_instance:
    name: "public-metadataoptions-instance"
    vpc_subnet_id: subnet-5calable
    instance_type: t3.small
    image_id: ami-123456
    tags:
      Environment: Testing
    metadata_options:
      http_endpoint: enabled
      http_tokens: required

- name: start an instance with legacy naming and metadata options
  amazon.aws.ec2_instance:
    name: "public-metadataoptions-instance"
    vpc_subnet_id: subnet-5calable
    instance_type: t3.small
    image_id: ami-123456
    tags:
      Environment: Testing
    metadata_options:
      http_endpoint: enabled
      http_tokens: required

```
## Non-Compliant Code Examples
```yaml
- name: start an instance with metadata options
  amazon.aws.ec2_instance:
    name: "public-metadataoptions-instance"
    vpc_subnet_id: subnet-5calable
    instance_type: t3.small
    image_id: ami-123456
    tags:
      Environment: Testing
    metadata_options:
      http_tokens: optional

- name: start an instance with legacy naming and metadata options
  amazon.aws.ec2_instance:
    name: "public-metadataoptions-instance-legacy"
    vpc_subnet_id: subnet-5calable
    instance_type: t3.small
    image_id: ami-123456
    tags:
      Environment: Testing
    metadata_options:
      http_tokens: optional

```
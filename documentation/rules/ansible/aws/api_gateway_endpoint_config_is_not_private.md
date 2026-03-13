---
title: "API Gateway endpoint config is not private"
group_id: "Ansible / AWS"
meta:
  name: "aws/api_gateway_endpoint_config_is_not_private"
  id: "559439b2-3e9c-4739-ac46-17e3b24ec215"
  display_name: "API Gateway endpoint config is not private"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `559439b2-3e9c-4739-ac46-17e3b24ec215`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/aws_api_gateway_module.html)

### Description

API Gateway endpoint type must be set to `PRIVATE` to prevent the API from being exposed to the public internet, which increases attack surface and can enable unauthorized access or data exfiltration.

For Ansible tasks using the `community.aws.aws_api_gateway` or `aws_api_gateway` modules, the `endpoint_type` property must be defined and set to `PRIVATE`. Tasks missing this property or with `endpoint_type` not set to `PRIVATE` are flagged. A `PRIVATE` endpoint restricts access to VPC endpoints, so ensure the required VPC endpoint and networking is configured to allow authorized clients to reach the API.

Secure Ansible task example:

```yaml
- name: Create private API Gateway
  community.aws.aws_api_gateway:
    name: my-private-api
    endpoint_type: PRIVATE
    state: present
```

## Compliant Code Examples
```yaml
- name: Setup AWS API Gateway setup on AWS and deploy API definition
  community.aws.aws_api_gateway:
    swagger_file: my_api.yml
    stage: production
    cache_enabled: true
    cache_size: '1.6'
    tracing_enabled: true
    endpoint_type: PRIVATE
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: Setup AWS API Gateway setup on AWS and deploy API definition
  community.aws.aws_api_gateway:
    swagger_file: my_api.yml
    stage: production
    cache_enabled: true
    cache_size: '1.6'
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```
---
title: "API Gateway without SSL certificate"
group_id: "Ansible / AWS"
meta:
  name: ""aws/api_gateway_without_ssl_certificate""
  id: "ansible-aws-api-gateway-without-ssl-certificate"
  display_name: "API Gateway without SSL certificate"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-api-gateway-without-ssl-certificate{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/api_gateway_module.html)

### Description

API Gateway integrations must validate TLS/SSL certificates to ensure backend endpoints are authentic and prevent man-in-the-middle attacks that can expose credentials or sensitive data.

The `validate_certs` property in Ansible `community.aws.api_gateway` and `api_gateway` tasks must be defined and set to a truthy value (Ansible `yes` or `true`). Resources missing this property or with `validate_certs` set to `no` or `false` are flagged.

If your backend uses self-signed certificates, prefer adding the CA to a trusted store or using proper certificate management rather than disabling certificate validation.

Secure example Ansible task:

```yaml
- name: Create API Gateway with TLS validation
  community.aws.api_gateway:
    name: my-api
    state: present
    validate_certs: yes
```

## Compliant Code Examples
```yaml
- name: update API v2
  community.aws.api_gateway:
    name: my-api
    api_id: abc123321cba
    state: present
    swagger_file: my_api.yml
    validate_certs: yes
- name: Setup AWS API Gateway setup on AWS and deploy API definition v2
  community.aws.api_gateway:
    name: my-api-v2
    swagger_file: my_api.yml
    stage: production
    cache_enabled: true
    cache_size: '1.6'
    tracing_enabled: true
    endpoint_type: EDGE
    state: present
    validate_certs: yes

```
## Non-Compliant Code Examples
```yaml
- name: update API
  community.aws.api_gateway:
    name: my-api
    api_id: 'abc123321cba'
    state: present
    swagger_file: my_api.yml
    validate_certs: no
- name: update API v1
  community.aws.api_gateway:
    name: my-api-v1
    api_id: 'abc123321cba'
    state: present
    swagger_file: my_api.yml
- name: Setup AWS API Gateway setup on AWS and deploy API definition
  community.aws.api_gateway:
    name: my-api-v2
    swagger_file: my_api.yml
    stage: production
    cache_enabled: true
    cache_size: '1.6'
    tracing_enabled: true
    endpoint_type: EDGE
    state: present
    validate_certs: no
- name: Setup AWS API Gateway setup on AWS and deploy API definition v1
  community.aws.api_gateway:
    name: my-api-v3
    swagger_file: my_api.yml
    stage: production
    cache_enabled: true
    cache_size: '1.6'
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```
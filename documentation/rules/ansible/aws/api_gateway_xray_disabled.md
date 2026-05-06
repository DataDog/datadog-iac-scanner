---
title: "API Gateway X-Ray disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/api_gateway_xray_disabled"
  id: "2059155b-27fd-441e-b616-6966c468561f"
  display_name: "API Gateway X-Ray disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}2059155b-27fd-441e-b616-6966c468561f{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/api_gateway_module.html#parameter-tracing_enabled)

### Description

API Gateway resources should have AWS X-Ray tracing enabled to provide end-to-end request visibility and support detection of anomalous or malicious activity. For Ansible tasks that use the `community.aws.api_gateway` or `api_gateway` modules, set the `tracing_enabled` property to `true`. Tasks missing `tracing_enabled` or with `tracing_enabled: false` are flagged because they disable observability needed for effective incident response and root-cause analysis.

Secure Ansible task example:

```yaml
- name: Configure API Gateway with X-Ray tracing
  community.aws.api_gateway:
    name: my-api
    tracing_enabled: true
```

## Compliant Code Examples
```yaml
- name: Setup AWS API Gateway setup on AWS and deploy API definition
  community.aws.api_gateway:
    name: my-api
    swagger_file: my_api.yml
    stage: production
    cache_enabled: true
    cache_size: '1.6'
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```
## Non-Compliant Code Examples
```yaml
---
- name: Setup AWS API Gateway setup on AWS and deploy API definition
  community.aws.api_gateway:
    name: my-api
    swagger_file: my_api.yml
    stage: production
    cache_enabled: true
    cache_size: '1.6'
    tracing_enabled: false
    endpoint_type: EDGE
    state: present
- name: Update API definition to deploy new version
  community.aws.api_gateway:
    name: my-api-v2
    api_id: 'abc123321cba'
    swagger_file: my_api.yml
    deploy_desc: Make auth fix available.
    cache_enabled: true
    cache_size: '1.6'
    endpoint_type: EDGE
    state: present

```
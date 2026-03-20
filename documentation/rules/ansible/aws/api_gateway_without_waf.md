---
title: "API Gateway without WAF"
group_id: "Ansible / AWS"
meta:
  name: "aws/api_gateway_without_waf"
  id: "f5f38943-664b-4acc-ab11-f292fa10ed0b"
  display_name: "API gateway without WAF"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `f5f38943-664b-4acc-ab11-f292fa10ed0b`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/wafv2_resources_module.html#parameter-arn)

### Description

API Gateway stages should be protected by an AWS WAF Web ACL to block common web threats (for example SQL injection, XSS, and malicious request patterns) before they reach backend services. Ensure your IaC defines a WAFv2 WebACLAssociation that links a Web ACL to the API Gateway stage. The association's `ResourceArn` (or Terraform `resource_arn`) must reference the API Gateway stage ARN (for REST APIs: arn:aws:apigateway:<region>::/restapis/<api-id>/stages/<stage-name>).

This rule checks Ansible API Gateway resources (modules `community.aws.api_gateway` or `api_gateway`) and expects a corresponding WAFv2 association (for example, `community.aws.wafv2_resources`/`wafv2_resources`) that targets the same stage. Resources missing a WebACLAssociation or where `ResourceArn` does not point to the stage are flagged.

Secure CloudFormation example:

```yaml
WebACLAssociation:
  Type: AWS::WAFv2::WebACLAssociation
  Properties:
    ResourceArn: !Sub "arn:aws:apigateway:${AWS::Region}::/restapis/${ApiId}/stages/${StageName}"
    WebACLArn: !Ref MyWebACL
```

## Compliant Code Examples
```yaml
- name: add test alb to waf string03
  community.aws.wafv2_resources:
    name: string03
    scope: REGIONAL
    state: present
    arn: "arn:aws:apigateway:region::/restapis/api-id/stages/produ"
- name: Setup AWS API Gateway setup on AWS and deploy API definition
  community.aws.api_gateway:
    swagger_file: my_api.yml
    stage: produ
    cache_enabled: true
    cache_size: '1.6'
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: add test alb to waf string032
  community.aws.wafv2_resources:
    name: string03
    scope: REGIONAL
    state: present
    arn: "arn:aws:apigateway:region::/restapis/api-id/stages/prod"
- name: Setup AWS API Gateway setup on AWS and deploy API definition2
  community.aws.api_gateway:
    swagger_file: my_api.yml
    stage: production
    cache_enabled: true
    cache_size: '1.6'
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```
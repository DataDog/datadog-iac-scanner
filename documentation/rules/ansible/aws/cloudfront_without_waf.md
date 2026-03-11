---
title: "CloudFront Without WAF"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudfront_without_waf"
  id: "22c80725-e390-4055-8d14-a872230f6607"
  display_name: "CloudFront Without WAF"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `22c80725-e390-4055-8d14-a872230f6607`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/cloudfront_distribution_module.html)

### Description

CloudFront distributions must be associated with an AWS WAF Web ACL to filter malicious HTTP traffic and reduce the risk of application‑layer attacks such as SQL injection, cross‑site scripting, and automated bot abuse. For Ansible tasks using the `community.aws.cloudfront_distribution` or `cloudfront_distribution` module, the `web_acl_id` property must be defined and set to the ARN of a WAFv2 Web ACL (global scope) to enable protection for the distribution. This rule flags distributions where `web_acl_id` is missing or undefined; ensure you attach a WAFv2 Web ACL ARN that is compatible with CloudFront.

Secure example (Ansible):

```yaml
- name: create cloudfront distribution with WAF
  community.aws.cloudfront_distribution:
    state: present
    alias:
      - example.com
    web_acl_id: arn:aws:wafv2:global:123456789012:regional/webacl/example-web-acl/abcd1234-ef56-7890-gh12-ijklmnopqrst
    # other required distribution properties...
```

## Compliant Code Examples
```yaml
- name: create a basic distribution with defaults and tags
  community.aws.cloudfront_distribution:
    state: present
    default_origin_domain_name: www.my-cloudfront-origin.com
    tags:
      Name: example distribution
      Project: example project
      Priority: '1'
    web_acl_id: my-web-acl-id

```
## Non-Compliant Code Examples
```yaml
- name: create a basic distribution with defaults and tags
  community.aws.cloudfront_distribution:
    state: present
    default_origin_domain_name: www.my-cloudfront-origin.com
    tags:
      Name: example distribution
      Project: example project
      Priority: '1'

```
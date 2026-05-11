---
title: "CloudFront viewer protocol policy allows HTTP"
group_id: "Ansible / AWS"
meta:
  name: "aws/viewer_protocol_policy_allows_http"
  id: "ansible-aws-viewer-protocol-policy-allows-http"
  display_name: "CloudFront viewer protocol policy allows HTTP"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-viewer-protocol-policy-allows-http{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/cloudfront_distribution_module.html)

### Description

CloudFront distributions must enforce HTTPS for viewer connections to prevent sensitive data from being transmitted in plaintext and reduce the risk of downgrade or man-in-the-middle attacks.

For Ansible CloudFront resources (modules `community.aws.cloudfront_distribution` or `cloudfront_distribution`), the `viewer_protocol_policy` property in `default_cache_behavior` and in each `cache_behaviors` entry must be set to `https-only` or `redirect-to-https`. Tasks with `viewer_protocol_policy` set to `allow-all` or without an explicit secure setting are flagged. Ensure every cache behavior explicitly specifies a secure policy.

Secure configuration example:

```yaml
- name: Create CloudFront distribution
  community.aws.cloudfront_distribution:
    origin:
      - id: origin1
        domain_name: example.com
    default_cache_behavior:
      viewer_protocol_policy: https-only
    cache_behaviors:
      - path_pattern: /images/*
        viewer_protocol_policy: redirect-to-https
```

## Compliant Code Examples
```yaml
- name: example1
  community.aws.cloudfront_distribution:
    state: present
    caller_reference: unique test distribution ID
    origins:
    - id: my test origin-000111
      domain_name: www.example.com
      origin_path: /production
      custom_headers:
      - header_name: MyCustomHeaderName
        header_value: MyCustomHeaderValue
    default_cache_behavior:
      target_origin_id: my test origin-000111
      forwarded_values:
        query_string: true
        cookies:
          forward: all
        headers:
        - '*'
      viewer_protocol_policy: https-only
      smooth_streaming: true
      compress: true
      allowed_methods:
        items:
        - GET
        - HEAD
        cached_methods:
        - GET
        - HEAD

- name: example2
  community.aws.cloudfront_distribution:
    state: present
    caller_reference: unique test distribution ID
    origins:
    - id: my test origin-000111
      domain_name: www.example.com
      origin_path: /production
      custom_headers:
      - header_name: MyCustomHeaderName
        header_value: MyCustomHeaderValue
    cache_behaviors:
      target_origin_id: my test origin-000111
      forwarded_values:
        query_string: true
        cookies:
          forward: all
        headers:
        - '*'
      viewer_protocol_policy: https-only
      smooth_streaming: true
      compress: true
      allowed_methods:
        items:
        - GET
        - HEAD
        cached_methods:
        - GET
        - HEAD

```
## Non-Compliant Code Examples
```yaml
- name: example1
  community.aws.cloudfront_distribution:
    state: present
    caller_reference: unique test distribution ID
    origins:
      - id: 'my test origin-000111'
        domain_name: www.example.com
        origin_path: /production
        custom_headers:
          - header_name: MyCustomHeaderName
            header_value: MyCustomHeaderValue
    default_cache_behavior:
      target_origin_id: 'my test origin-000111'
      forwarded_values:
        query_string: true
        cookies:
          forward: all
        headers:
          - '*'
      viewer_protocol_policy: allow-all
      smooth_streaming: true
      compress: true
      allowed_methods:
        items:
          - GET
          - HEAD
        cached_methods:
          - GET
          - HEAD

- name: example2
  community.aws.cloudfront_distribution:
    state: present
    caller_reference: unique test distribution ID
    origins:
      - id: 'my test origin-000111'
        domain_name: www.example.com
        origin_path: /production
        custom_headers:
          - header_name: MyCustomHeaderName
            header_value: MyCustomHeaderValue
    cache_behaviors:
      target_origin_id: 'my test origin-000111'
      forwarded_values:
        query_string: true
        cookies:
          forward: all
        headers:
          - '*'
      viewer_protocol_policy: allow-all
      smooth_streaming: true
      compress: true
      allowed_methods:
        items:
          - GET
          - HEAD
        cached_methods:
          - GET
          - HEAD

```
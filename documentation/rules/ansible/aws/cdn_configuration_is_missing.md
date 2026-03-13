---
title: "CDN configuration is missing"
group_id: "Ansible / AWS"
meta:
  name: "aws/cdn_configuration_is_missing"
  id: "b25398a2-0625-4e61-8e4d-a1bb23905bf6"
  display_name: "CDN configuration is missing"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `b25398a2-0625-4e61-8e4d-a1bb23905bf6`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/cloudfront_distribution_module.html)

### Description

CloudFront distributions must be enabled and include at least one origin so traffic is routed through the CDN. This ensures requests benefit from CloudFront protections such as caching, TLS termination, WAF rules, and DDoS mitigation. A disabled or origin-less distribution can cause traffic to bypass the CDN and expose origin servers.

This rule inspects Ansible tasks using the `community.aws.cloudfront_distribution` or `cloudfront_distribution` modules. It requires the `enabled` property to be present and set to `true`, and the `origins` property to be defined with at least one origin entry. Tasks missing `enabled` or `origins`, or with `enabled: false`, are flagged as misconfigured.

Secure example:

```yaml
- name: create cloudfront distribution
  community.aws.cloudfront_distribution:
    enabled: true
    comment: "Secure distribution"
    origins:
      - id: my-origin
        domain_name: origin.example.com
        custom_origin_config:
          origin_protocol_policy: https-only
          http_port: 80
          https_port: 443
```

## Compliant Code Examples
```yaml
- name: create a distribution with an origin, logging and default cache behavior
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
    logging:
      enabled: true
      include_cookies: false
      bucket: mylogbucket.s3.amazonaws.com
      prefix: myprefix/
    enabled: true
    comment: this is a CloudFront distribution with logging

```
## Non-Compliant Code Examples
```yaml
- name: create a distribution without an origin and with enabled=false
  community.aws.cloudfront_distribution:
    state: present
    caller_reference: unique test distribution ID
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
    enabled: false
    logging:
      enabled: true
      include_cookies: false
      bucket: mylogbucket.s3.amazonaws.com
      prefix: myprefix/

```
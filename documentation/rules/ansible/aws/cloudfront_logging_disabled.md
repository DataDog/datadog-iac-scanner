---
title: "CloudFront logging disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudfront_logging_disabled"
  id: "d31cb911-bf5b-4eb6-9fc3-16780c77c7bd"
  display_name: "CloudFront logging disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** {{</* copyable-code */>}}d31cb911-bf5b-4eb6-9fc3-16780c77c7bd{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/cloudfront_distribution_module.html)

### Description

CloudFront distributions must have access logging enabled to record viewer requests for incident investigation and auditing. Without logs, you cannot reliably detect abuse, investigate incidents, or meet audit requirements.

For Ansible CloudFront distribution resources (modules `community.aws.cloudfront_distribution` and `cloudfront_distribution`), the `logging` property must be defined and `logging.enabled` set to `true`. Tasks missing `logging` or with `logging.enabled: false` are flagged. Ensure a valid S3 bucket is specified in `logging.bucket` as the log destination.

Secure configuration example:

```yaml
- name: Create CloudFront distribution with logging enabled
  community.aws.cloudfront_distribution:
    origin:
      - id: my-origin
        domain_name: origin.example.com
    enabled: yes
    logging:
      enabled: true
      bucket: my-log-bucket.s3.amazonaws.com
      include_cookies: false
```

## Compliant Code Examples
```yaml
- name: create a distribution with an origin, logging and default cache behavior
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
    enabled: false
    comment: this is a CloudFront distribution with logging

```
## Non-Compliant Code Examples
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
    enabled: false
    comment: this is a CloudFront distribution with logging
- name: create a second distribution with an origin, logging and default cache behavior
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
      enabled: false
      include_cookies: false
      bucket: mylogbucket.s3.amazonaws.com
      prefix: myprefix/
    enabled: false
    comment: this is a CloudFront distribution with logging

```
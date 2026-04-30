---
title: "CloudFront without minimum protocol TLS 1.2"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudfront_without_minimum_protocol_tls_1.2"
  id: "ansible-aws-cloudfront-without-minimum-protocol-tls-1-2"
  display_name: "CloudFront without minimum protocol TLS 1.2"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `ansible-aws-cloudfront-without-minimum-protocol-tls-1-2`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/cloudfront_distribution_module.html#parameter-viewer_certificate/minimum_protocol_version)

### Description

CloudFront distributions must enforce modern TLS for viewer connections to prevent interception and protocol downgrades. The Ansible `community.aws.cloudfront_distribution` (or `cloudfront_distribution`) resource must include a `viewer_certificate` block with `minimum_protocol_version` set to a TLS 1.2 variant (for example, `TLSv1.2_2018` or `TLSv1.2_2019`).

Tasks that omit `viewer_certificate` or specify a `minimum_protocol_version` that is not a TLS 1.2 variant are flagged.

Secure configuration example:

```yaml
- name: Create CloudFront distribution with TLS 1.2 minimum
  community.aws.cloudfront_distribution:
    state: present
    enabled: yes
    origins:
      - id: myOrigin
        domain_name: origin.example.com
    viewer_certificate:
      acm_certificate_arn: arn:aws:acm:us-east-1:123456789012:certificate/abcd-ef01-2345-6789
      ssl_support_method: sni-only
      minimum_protocol_version: TLSv1.2_2018
```

## Compliant Code Examples
```yaml
- name: create a distribution with an origin and logging
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
    logging:
      enabled: true
      include_cookies: false
      bucket: mylogbucket.s3.amazonaws.com
      prefix: myprefix/
    viewer_certificate:
      minimum_protocol_version: TLSv1.2_2018
    comment: this is a CloudFront distribution with logging

```
## Non-Compliant Code Examples
```yaml
- name: create a distribution with an origin and logging
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
    logging:
      enabled: true
      include_cookies: false
      bucket: mylogbucket.s3.amazonaws.com
      prefix: myprefix/
    viewer_certificate:
      minimum_protocol_version: TLSv1
    comment: this is a CloudFront distribution with logging
- name: create another distribution with an origin and logging
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
    logging:
      enabled: true
      include_cookies: false
      bucket: mylogbucket.s3.amazonaws.com
      prefix: myprefix/
    viewer_certificate:
      minimum_protocol_version: TLSv1.1_2016
    comment: this is a CloudFront distribution with logging
- name: create a third distribution
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
    logging:
      enabled: true
      include_cookies: false
      bucket: mylogbucket.s3.amazonaws.com
      prefix: myprefix/
    comment: this is a CloudFront distribution with logging

```
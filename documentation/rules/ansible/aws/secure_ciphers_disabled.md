---
title: "Secure ciphers disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/secure_ciphers_disabled"
  id: "ansible-aws-secure-ciphers-disabled"
  display_name: "Secure ciphers disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `ansible-aws-secure-ciphers-disabled`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/cloudfront_distribution_module.html)

### Description

CloudFront distributions that do not enforce a modern minimum TLS protocol version can allow legacy TLS/SSL versions, increasing the risk of downgrade attacks and interception of data in transit.

For Ansible CloudFront resources (modules `community.aws.cloudfront_distribution` and `cloudfront_distribution`), the `viewer_certificate.minimum_protocol_version` property must be defined and set to `TLSv1.1` or `TLSv1.2` (preferably `TLSv1.2`) when using a custom certificate (`viewer_certificate.cloudfront_default_certificate` set to `false`). Resources that omit `minimum_protocol_version` or specify any other value are flagged. 

Secure configuration example for Ansible:

```yaml
- name: Create CloudFront distribution with secure TLS
  community.aws.cloudfront_distribution:
    name: my-distribution
    viewer_certificate:
      cloudfront_default_certificate: false
      acm_certificate_arn: arn:aws:acm:region:acct:certificate/your-cert-id
      minimum_protocol_version: TLSv1.2
```

## Compliant Code Examples
```yaml
- name: example
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
    viewer_certificate:
      cloudfront_default_certificate: true

```
## Non-Compliant Code Examples
```yaml
- name: example
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
    viewer_certificate:
      cloudfront_default_certificate: false
      minimum_protocol_version: 'SSLv3'

```
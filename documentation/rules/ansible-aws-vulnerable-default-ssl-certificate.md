---
title: "Vulnerable default SSL certificate"
group_id: "Ansible / AWS"
meta:
  name: ""aws/vulnerable_default_ssl_certificate""
  id: "ansible-aws-vulnerable-default-ssl-certificate"
  display_name: "Vulnerable default SSL certificate"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Defaults"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-vulnerable-default-ssl-certificate{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/cloudfront_distribution_module.html)

### Description

CloudFront distributions should use custom SSL certificates rather than the default CloudFront certificate. Custom certificates enable serving content on custom domain names and enforce strong, managed TLS settings for data in transit.

For Ansible tasks using `community.aws.cloudfront_distribution` or `cloudfront_distribution`, the `viewer_certificate.cloudfront_default_certificate` property must be `false` or not defined. If `viewer_certificate.acm_certificate_arn` or `viewer_certificate.iam_certificate_id` is provided, then `viewer_certificate.ssl_support_method` and `viewer_certificate.minimum_protocol_version` must also be defined.

Resources with `cloudfront_default_certificate` set to `true`, or with a custom certificate but missing `ssl_support_method` or `minimum_protocol_version`, are flagged. Use a secure `viewer_certificate` block that references a custom ACM or IAM certificate and explicitly sets the SSL support method and a modern minimum protocol version.

Secure example for an Ansible CloudFront distribution:

```yaml
- name: Create CloudFront distribution with custom certificate
  community.aws.cloudfront_distribution:
    name: my-distribution
    viewer_certificate:
      acm_certificate_arn: arn:aws:acm:us-east-1:123456789012:certificate/abcd-ef01-2345
      ssl_support_method: sni-only
      minimum_protocol_version: TLSv1.2_2019
```

## Compliant Code Examples
```yaml
- name: create a basic distribution with defaults, tags and custom SSL certificate
  community.aws.cloudfront_distribution:
    state: present
    caller_reference: my-distribution-ssl-negative
    default_origin_domain_name: www.my-cloudfront-origin.com
    viewer_certificate:
      acm_certificate_arn: arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012
      ssl_support_method: sni-only
      minimum_protocol_version: TLS1.2_2018
    tags:
      Name: example distribution
      Project: example project
      Priority: '1'

```
## Non-Compliant Code Examples
```yaml
- name: create a basic distribution with defaults, tags and default SSL certificate
  community.aws.cloudfront_distribution:
    state: present
    caller_reference: my-distribution-ssl-default
    default_origin_domain_name: www.my-cloudfront-origin.com
    viewer_certificate:
      cloudfront_default_certificate: true
    tags:
      Name: example distribution
      Project: example project
      Priority: '1'
- name: create a basic distribution with defaults, tags and misconfigured custom SSL certificate
  community.aws.cloudfront_distribution:
    state: present
    caller_reference: my-distribution-ssl-misconfigured
    default_origin_domain_name: www.my-cloudfront-origin.com
    viewer_certificate:
      acm_certificate_arn: arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012
    tags:
      Name: example distribution
      Project: example project
      Priority: '1'

```
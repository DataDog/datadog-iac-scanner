---
title: "Certificate has expired"
group_id: "Ansible / AWS"
meta:
  name: ""aws/certificate_has_expired""
  id: "ansible-aws-certificate-has-expired"
  display_name: "Certificate has expired"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-certificate-has-expired{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/acm_certificate_module.html)

### Description

Expired SSL/TLS certificates cause service outages by breaking TLS handshakes and undermine trust in encrypted connections. This can result in failed client connections and compliance or security issues. In Ansible, tasks using the `community.aws.acm_certificate` module must reference a certificate whose `certificate.expiration_date` is a future date. This rule flags `community.aws.acm_certificate` tasks where `certificate.expiration_date` is in the past. Renew or replace any expired certificates—for example, request a new ACM certificate or update the task to point to a renewed certificate—so `certificate.expiration_date` reflects a valid future date.

## Compliant Code Examples
```yaml
- name: upload a self-signed certificate2
  community.aws.acm_certificate:
    certificate: "{{ lookup('file', 'validCertificate.pem' ) }}"
    privateKey: "{{ lookup('file', 'key.pem' ) }}"
    name_tag: my_cert
    region: ap-southeast-2

```
## Non-Compliant Code Examples
```yaml
- name: upload a self-signed certificate
  community.aws.acm_certificate:
    certificate: "{{ lookup('file', 'expiredCertificate.pem' ) }}"
    privateKey: "{{ lookup('file', 'key.pem' ) }}"
    name_tag: my_cert
    region: ap-southeast-2

```
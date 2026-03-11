---
title: "Certificate Has Expired"
group_id: "Ansible / AWS"
meta:
  name: "aws/certificate_has_expired"
  id: "5a443297-19d4-4381-9e5b-24faf947ec22"
  display_name: "Certificate Has Expired"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `5a443297-19d4-4381-9e5b-24faf947ec22`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/2.10/collections/community/aws/aws_acm_module.html)

### Description

Expired SSL/TLS certificates cause service outages by breaking TLS handshakes and undermine trust in encrypted connections, which can result in failed client connections and compliance or security issues. In Ansible, tasks using the `community.aws.aws_acm` module must reference a certificate whose `certificate.expiration_date` is a future date; this rule flags `community.aws.aws_acm` tasks where `certificate.expiration_date` is in the past. Renew or replace any expired certificates—e.g., request a new ACM certificate or update the task to point to a renewed certificate—so `certificate.expiration_date` reflects a valid future date.

## Compliant Code Examples
```yaml
- name: upload a self-signed certificate2
  community.aws.aws_acm:
    certificate: "{{ lookup('file', 'validCertificate.pem' ) }}"
    privateKey: "{{ lookup('file', 'key.pem' ) }}"
    name_tag: my_cert
    region: ap-southeast-2

```
## Non-Compliant Code Examples
```yaml
- name: upload a self-signed certificate
  community.aws.aws_acm:
    certificate: "{{ lookup('file', 'expiredCertificate.pem' ) }}"
    privateKey: "{{ lookup('file', 'key.pem' ) }}"
    name_tag: my_cert
    region: ap-southeast-2

```
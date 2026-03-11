---
title: "Certificate RSA Key Bytes Lower Than 256"
group_id: "Ansible / AWS"
meta:
  name: "aws/certificate_rsa_key_bytes_lower_than_256"
  id: "d5ec2080-340a-4259-b885-f833c4ea6a31"
  display_name: "Certificate RSA Key Bytes Lower Than 256"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `d5ec2080-340a-4259-b885-f833c4ea6a31`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/2.10/collections/community/aws/aws_acm_module.html)

### Description

Certificates must use sufficiently strong RSA keys to prevent cryptographic compromise; RSA keys smaller than 2048 bits can be factored with modern compute, enabling certificate impersonation and decryption of TLS traffic. For Ansible tasks using the `community.aws.aws_acm` module, ensure the `certificate.rsa_key_bytes` property is defined and set to at least `256` (bytes), which corresponds to 2048 bits. Resources missing this property or with `rsa_key_bytes < 256` will be flagged as insecure; larger values (for example, `rsa_key_bytes: 512` for 4096-bit keys) are acceptable.

Secure example:

```yaml
- name: Request ACM certificate with 2048-bit RSA key
  community.aws.aws_acm:
    name: example-cert
    certificate:
      rsa_key_bytes: 256
    state: present
```

## Compliant Code Examples
```yaml
- name: upload a self-signed certificate2
  community.aws.aws_acm:
    certificate: "{{ lookup('file', 'rsa4096.pem' ) }}"
    privateKey: "{{ lookup('file', 'key.pem' ) }}"
    name_tag: my_cert
    region: ap-southeast-2

```
## Non-Compliant Code Examples
```yaml
- name: upload a self-signed certificate
  community.aws.aws_acm:
    certificate: "{{ lookup('file', 'rsa1024.pem' ) }}"
    privateKey: "{{ lookup('file', 'key.pem' ) }}"
    name_tag: my_cert
    region: ap-southeast-2

```
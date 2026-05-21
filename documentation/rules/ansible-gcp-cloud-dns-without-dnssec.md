---
title: "Cloud DNS without DNSSEC"
group_id: "Ansible / GCP"
meta:
  name: "gcp/cloud_dns_without_dnssec"
  id: "ansible-gcp-cloud-dns-without-dnssec"
  display_name: "Cloud DNS without DNSSEC"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-cloud-dns-without-dnssec{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_dns_managed_zone_module.html#return-dnssecConfig/state)

### Description

DNS zones must have DNSSEC enabled to protect DNS responses from tampering, spoofing, and cache poisoning and to ensure the authenticity and integrity of name resolution.

For Ansible-managed Google Cloud DNS zones using `google.cloud.gcp_dns_managed_zone` or `gcp_dns_managed_zone`, the `dnssec_config.state` property must be defined and set to `"on"`. Resources missing `dnssec_config`, missing `dnssec_config.state`, or with `dnssec_config.state` not equal to `"on"` are flagged. 

Secure configuration example:

```yaml
- name: Create DNS managed zone with DNSSEC enabled
  google.cloud.gcp_dns_managed_zone:
    name: my-managed-zone
    dns_name: example.com.
    dnssec_config:
      state: "on"
```

## Compliant Code Examples
```yaml
- name: create a managed zone
  google.cloud.gcp_dns_managed_zone:
    name: test_object
    dns_name: test.somewild2.example.com.
    description: test zone
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present
    dnssec_config:
      kind: some_kind
      state: on

```
## Non-Compliant Code Examples
```yaml
---
- name: create a managed zone
  google.cloud.gcp_dns_managed_zone:
    name: test_object
    dns_name: test.somewild2.example.com.
    description: test zone
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a second managed zone
  google.cloud.gcp_dns_managed_zone:
    name: test_object
    dns_name: test.somewild2.example.com.
    description: test zone
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    dnssec_config:
      kind: some_kind
- name: create a third managed zone
  google.cloud.gcp_dns_managed_zone:
    name: test_object
    dns_name: test.somewild2.example.com.
    description: test zone
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    dnssec_config:
      kind: some_kind
      state: off

```
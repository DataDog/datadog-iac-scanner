---
title: "DNSSEC using RSASHA1"
group_id: "Ansible / GCP"
meta:
  name: ""gcp/dnssec_using_rsasha1""
  id: "ansible-gcp-dnssec-using-rsasha1"
  display_name: "DNSSEC using RSASHA1"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-dnssec-using-rsasha1{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_dns_managed_zone_module.html#return-dnssecConfig/defaultKeySpecs/algorithm)

### Description

Using the RSASHA1 algorithm for DNSSEC weakens DNS integrity because SHA-1 is deprecated and vulnerable to collision attacks, increasing the risk of forged or tampered DNS responses.

For Ansible-managed Google Cloud DNS zones (modules `google.cloud.gcp_dns_managed_zone` and `gcp_dns_managed_zone`), the `dnssec_config.defaultKeySpecs.algorithm` property must not be set to `rsasha1` (checked case-insensitively). Resources with `dnssec_config.defaultKeySpecs.algorithm` set to `rsasha1` are flagged. Update the property to a stronger algorithm such as `RSASHA256`, `RSASHA512`, or an ECDSA option like `ECDSAP256SHA256`. 

Secure configuration example:

```yaml
- name: Create managed zone with secure DNSSEC algorithm
  google.cloud.gcp_dns_managed_zone:
    name: my-zone
    dnssec_config:
      defaultKeySpecs:
        - algorithm: RSASHA256
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
      defaultKeySpecs:
        algorithm: RSASHA256
      state: off

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
    dnssec_config:
      defaultKeySpecs:
        algorithm: RSASHA1
      state: off

```
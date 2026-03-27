---
title: "Route 53 record undefined"
group_id: "Ansible / AWS"
meta:
  name: "aws/route53_record_undefined"
  id: "445dce51-7e53-4e50-80ef-7f94f14169e4"
  display_name: "Route 53 record undefined"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `445dce51-7e53-4e50-80ef-7f94f14169e4`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/route53_module.html#parameter-value)

### Description

Route 53 record resources must include one or more record values so DNS entries are created and resolve correctly. Missing values can lead to service disruption, broken name resolution, or unintended traffic routing. For Ansible tasks using the `amazon.aws.route53` or `route53` modules, the `value` parameter must be present and non-null, typically as a list of one or more string values. Tasks missing the `value` parameter, with `value: null`, or with an empty list are flagged.

Secure example Ansible task:

```yaml
- name: Create A record for app.example.com
  amazon.aws.route53:
    zone: example.com
    record: app
    type: A
    ttl: 300
    value:
      - "203.0.113.10"
```

## Compliant Code Examples
```yaml
- name: Use a routing policy to distribute traffic
  amazon.aws.route53:
    state: present
    zone: foo.com
    record: www.foo.com
    type: CNAME
    value: host1.foo.com
    ttl: 30
    identifier: host1@www
    weight: 100
    health_check: d994b780-3150-49fd-9205-356abdd42e75

```
## Non-Compliant Code Examples
```yaml
---
- name: Use a routing policy to distribute traffic02
  amazon.aws.route53:
    state: present
    zone: foo.com
    record: www.foo.com
    type: CNAME
    value:
    ttl: 30
    identifier: "host1@www"
    weight: 100
    health_check: "d994b780-3150-49fd-9205-356abdd42e75"
- name: Use a routing policy to distribute traffic03
  amazon.aws.route53:
    state: present
    zone: foo.com
    record: www.foo.com
    type: CNAME
    ttl: 30
    identifier: "host1@www"
    weight: 100
    health_check: "d994b780-3150-49fd-9205-356abdd42e75"

```
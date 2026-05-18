---
title: "Redis not compliant"
group_id: "Ansible / AWS"
meta:
  name: "aws/redis_not_compliant"
  id: "ansible-aws-redis-not-compliant"
  display_name: "Redis not compliant"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-redis-not-compliant{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/elasticache_module.html#parameter-cache_engine_version)

### Description

ElastiCache Redis engine versions must meet the AWS PCI DSS baseline. Running outdated Redis releases can expose known vulnerabilities and lead to non-compliance. In Ansible, tasks using the `community.aws.elasticache` or `elasticache` modules must define `cache_engine_version` and set it to a version equal to or newer than `4.0.10`. Resources missing `cache_engine_version` or specifying a lower version are flagged as non-compliant. Update to a maintained Redis release that satisfies PCI DSS requirements.

Secure example for Ansible:

```yaml
- name: Create ElastiCache Redis cluster
  community.aws.elasticache:
    name: my-redis-cluster
    engine: redis
    cache_engine_version: "4.0.10"
    node_type: cache.t3.small
    num_cache_nodes: 1
```

## Compliant Code Examples
```yaml
- name: Basic example
  community.aws.elasticache:
    name: test-please-delete
    state: present
    engine: memcached
    cache_engine_version: 5.1.10
    node_type: cache.m1.small
    num_nodes: 1

```
## Non-Compliant Code Examples
```yaml
- name: Basic example
  community.aws.elasticache:
    name: "test-please-delete"
    state: present
    engine: memcached
    cache_engine_version: 1.4.14
    node_type: cache.m1.small
    num_nodes: 1

```
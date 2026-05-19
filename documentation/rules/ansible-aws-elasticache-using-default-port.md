---
title: "ElastiCache using default port"
group_id: "Ansible / AWS"
meta:
  name: ""aws/elasticache_using_default_port""
  id: "ansible-aws-elasticache-using-default-port"
  display_name: "ElastiCache using default port"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-elasticache-using-default-port{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/elasticache_module.html#parameter-cache_port)

### Description

ElastiCache instances using engine default ports are easy for attackers and automated scanners to discover and target, increasing the risk of unauthorized access and automated exploitation.

In Ansible, tasks that use the `community.aws.elasticache` or `elasticache` module must not set the `cache_port` property to the engine defaults: `6379` when `engine: redis` and `11211` when `engine: memcached`. Resources with `cache_port` equal to these default values are flagged. Choose a non-standard port and enforce network access controls (security groups/subnets) to limit exposure.

Secure example changing the default port:

```yaml
- name: Create Redis ElastiCache cluster with non-default port
  community.aws.elasticache:
    name: my-redis-cluster
    engine: redis
    cache_port: 6380
    # other required properties...
```

## Compliant Code Examples
```yaml
- name: Basic example2
  community.aws.elasticache:
    name: "test-please-delete"
    state: present
    engine: memcached
    cache_engine_version: 1.4.14
    node_type: cache.m1.small
    num_nodes: 1
    cache_port: 11212
    cache_subnet_group: default
    zone: us-east-1d

```

```yaml
- name: Basic example2
  community.aws.elasticache:
    name: "test-please-delete"
    state: present
    engine: redis
    cache_engine_version: 1.4.14
    node_type: cache.m1.small
    num_nodes: 1
    cache_port: 6380
    cache_subnet_group: default
    zone: us-east-1d

```
## Non-Compliant Code Examples
```yaml
- name: Basic example2
  community.aws.elasticache:
    name: "test-please-delete"
    state: present
    engine: redis
    cache_engine_version: 1.4.14
    node_type: cache.m1.small
    num_nodes: 1
    cache_port: 6379
    cache_subnet_group: default
    zone: us-east-1d

```

```yaml
- name: Basic example
  community.aws.elasticache:
    name: "test-please-delete"
    state: present
    engine: memcached
    cache_engine_version: 1.4.14
    node_type: cache.m1.small
    num_nodes: 1
    cache_port: 11211
    cache_subnet_group: default
    zone: us-east-1d

```
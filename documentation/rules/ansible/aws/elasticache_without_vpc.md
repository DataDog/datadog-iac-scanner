---
title: "ElastiCache without VPC"
group_id: "Ansible / AWS"
meta:
  name: "aws/elasticache_without_vpc"
  id: "ansible-aws-elasticache-without-vpc"
  display_name: "ElastiCache without VPC"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ansible-aws-elasticache-without-vpc`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/elasticache_module.html#parameter-cache_subnet_group)

### Description

ElastiCache clusters must be launched in a VPC to provide network isolation and reduce the risk of unauthorized access to cached data or lateral movement within your environment.

In Ansible playbooks, tasks using the `community.aws.elasticache` or `elasticache` modules must set the `cache_subnet_group` property to the name of an existing ElastiCache subnet group. A task where `cache_subnet_group` is undefined or null is flagged because omission typically results in resources being created outside a VPC or without the intended subnet isolation.

Secure Ansible example:

```yaml
- name: Create ElastiCache cluster in VPC
  community.aws.elasticache:
    name: my-cache
    engine: redis
    cache_subnet_group: my-cache-subnet-group
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
    cache_port: 11211
    cache_subnet_group: default
    zone: us-east-1d

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
    cache_port: 11211
    cache_security_groups:
      - default
    zone: us-east-1d

```
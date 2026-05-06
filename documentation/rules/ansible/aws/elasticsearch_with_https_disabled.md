---
title: "Elasticsearch with HTTPS disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/elasticsearch_with_https_disabled"
  id: "d6c2d06f-43c1-488a-9ba1-8d75b40fc62d"
  display_name: "Elasticsearch with HTTPS disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}d6c2d06f-43c1-488a-9ba1-8d75b40fc62d{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/devel/collections/community/aws/opensearch_module.html)

### Description

OpenSearch domain endpoints must enforce HTTPS to ensure client connections use TLS and prevent interception or tampering of sensitive data such as queries and credentials. In Ansible tasks using the `community.aws.opensearch` or `opensearch` modules, the `domain_endpoint_options.enforce_https` property must be set to `true`. Tasks that omit `domain_endpoint_options` or `enforce_https`, or that set `enforce_https: false`, are flagged.

Secure Ansible task example:

```yaml
- name: create opensearch domain with HTTPS enforced
  community.aws.opensearch:
    domain_name: my-domain
    domain_endpoint_options:
      enforce_https: true
```

## Compliant Code Examples
```yaml
- name: Create OpenSearch domain with dedicated masters
  community.aws.opensearch:
    domain_name: "my-domain"
    engine_version: OpenSearch_1.1
    cluster_config:
      instance_type: "t2.small.search"
      instance_count: 12
      dedicated_master: true
      zone_awareness: true
      availability_zone_count: 2
      dedicated_master_instance_type: "t2.small.search"
      dedicated_master_instance_count: 3
      warm_enabled: true
      warm_type: "ultrawarm1.medium.search"
      warm_count: 1
      cold_storage_options:
        enabled: false
    domain_endpoint_options:
      enforce_https: true
    ebs_options:
      ebs_enabled: true
      volume_type: "io1"
      volume_size: 10
      iops: 1000
    vpc_options:
      subnets:
        - "subnet-e537d64a"
        - "subnet-e537d64b"
      security_groups:
        - "sg-dd2f13cb"
        - "sg-dd2f13cc"
    snapshot_options:
      automated_snapshot_start_hour: 13
    access_policies: "{{ lookup('file', 'policy.json') | from_json }}"
    encryption_at_rest_options:
      enabled: false
    node_to_node_encryption_options:
      enabled: false
    tags:
      Environment: Development
      Application: Search
    wait: true

```
## Non-Compliant Code Examples
```yaml
- name: Create OpenSearch domain for dev environment, no zone awareness, no dedicated masters
  community.aws.opensearch:
    domain_name: "dev-cluster"
    engine_version: Elasticsearch_1.1
    cluster_config:
      instance_type: "t2.small.search"
      instance_count: 2
      zone_awareness: false
      dedicated_master: false
    domain_endpoint_options:
      custom_endpoint_enabled: false
    ebs_options:
      ebs_enabled: true
      volume_type: "gp2"
      volume_size: 10
    access_policies: "{{ lookup('file', 'policy.json') | from_json }}"

```

```yaml
- name: Create OpenSearch domain for dev environment, no zone awareness, no dedicated masters
  community.aws.opensearch:
    domain_name: "dev-cluster"
    engine_version: Elasticsearch_1.1
    cluster_config:
      instance_type: "t2.small.search"
      instance_count: 2
      zone_awareness: false
      dedicated_master: false
    ebs_options:
      ebs_enabled: true
      volume_type: "gp2"
      volume_size: 10
    access_policies: "{{ lookup('file', 'policy.json') | from_json }}"

```

```yaml
- name: Create OpenSearch domain for dev environment, no zone awareness, no dedicated masters
  community.aws.opensearch:
    domain_name: "dev-cluster"
    engine_version: Elasticsearch_1.1
    cluster_config:
      instance_type: "t2.small.search"
      instance_count: 2
      zone_awareness: false
      dedicated_master: false
    domain_endpoint_options:
      enforce_https: false
    ebs_options:
      ebs_enabled: true
      volume_type: "gp2"
      volume_size: 10
    access_policies: "{{ lookup('file', 'policy.json') | from_json }}"

```
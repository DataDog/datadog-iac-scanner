---
title: "Configuration aggregator to all regions disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/config_configuration_aggregator_to_all_regions_disabled"
  id: "ansible-aws-config-configuration-aggregator-to-all-regions-disabled"
  display_name: "Configuration aggregator to all regions disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-config-configuration-aggregator-to-all-regions-disabled{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/config_aggregator_module.html#parameter-organization_source)

### Description

AWS Config aggregators must collect configuration data from all AWS Regions to provide centralized, complete visibility of resource state. This ensures cross-region misconfigurations and compliance violations are detected.

For Ansible tasks using the `community.aws.config_aggregator` or `aws_config_aggregator` modules, set the `all_aws_regions` property to `true` under the relevant `account_sources` entries or the `organization_source` block. Resources that omit `all_aws_regions` or have it set to `false` are flagged, as they do not provide full regional coverage.

Secure examples for Ansible (account and organization sources):

```yaml
- name: Create AWS Config Aggregator (account sources)
  community.aws.config_aggregator:
    name: my-config-aggregator
    account_sources:
      - account_ids: ['123456789012']
        all_aws_regions: true

- name: Create AWS Config Aggregator (organization source)
  community.aws.config_aggregator:
    name: org-config-aggregator
    organization_source:
      role_arn: arn:aws:iam::111122223333:role/ConfigAggregatorRole
      all_aws_regions: true
```

## Compliant Code Examples
```yaml
- name: Create cross-account aggregator
  community.aws.config_aggregator:
    name: test_config_rule
    state: present
    account_sources:
      account_ids:
      - 1234567890
      - 0123456789
      - 9012345678
      all_aws_regions: yes
    organization_source:
      all_aws_regions: yes

```
## Non-Compliant Code Examples
```yaml
- name: Create cross-account aggregator
  community.aws.config_aggregator:
    name: test_config_rule
    state: present
    account_sources:
      account_ids:
      - 1234567890
      - 0123456789
      - 9012345678
      all_aws_regions: no
    organization_source:
      all_aws_regions: yes
- name: Create cross-account aggregator2
  community.aws.config_aggregator:
    name: test_config_rule
    state: present
    account_sources:
      account_ids:
      - 1234567890
      - 0123456789
      - 9012345678
      all_aws_regions: yes
    organization_source:
      all_aws_regions: no

```
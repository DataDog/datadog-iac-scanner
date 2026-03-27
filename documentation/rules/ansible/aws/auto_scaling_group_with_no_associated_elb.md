---
title: "Auto Scaling Group with no associated ELB"
group_id: "Ansible / AWS"
meta:
  name: "aws/auto_scaling_group_with_no_associated_elb"
  id: "050f085f-a8db-4072-9010-2cca235cc02f"
  display_name: "Auto Scaling Group with no associated ELB"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Availability"
---
## Metadata

**Id:** `050f085f-a8db-4072-9010-2cca235cc02f`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Availability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/autoscaling_group_module.html#parameter-load_balancers)

### Description

Auto Scaling Groups must be associated with a load balancer so new instances receive traffic and health checks can detect and replace unhealthy instances. Without a load balancer, instances may not serve requests, and application availability and scaling behavior can be impacted.

For Ansible `autoscaling_group` tasks (modules `amazon.aws.autoscaling_group` and `autoscaling_group`), the `load_balancers` property must be defined and set to a non-empty list of Classic ELB names. Tasks missing the `load_balancers` property or with `load_balancers: []` are flagged. If you use Application Load Balancers with target groups instead of Classic ELBs, configure `target_group_arns` accordingly—this rule only validates the `load_balancers` attribute.

Secure example:

```yaml
- name: Create Auto Scaling Group with ELB
  amazon.aws.autoscaling_group:
    name: my-asg
    launch_template: my-launch-template
    min_size: 2
    max_size: 5
    load_balancers:
      - my-classic-elb
```

## Compliant Code Examples
```yaml
- name: elb12
  amazon.aws.autoscaling_group:
    name: special
    load_balancers: [ 'lb1', 'lb2' ]
    availability_zones: [ 'eu-west-1a', 'eu-west-1b' ]
    launch_config_name: 'lc-1'
    min_size: 1
    max_size: 10
    desired_capacity: 5
    vpc_zone_identifier: [ 'subnet-abcd1234', 'subnet-1a2b3c4d' ]
    tags:
      - environment: production
        propagate_at_launch: no

```

```yaml
- name: elb22
  amazon.aws.autoscaling_group:
    name: special
    load_balancers: [ 'lb1', 'lb2' ]
    availability_zones: [ 'eu-west-1a', 'eu-west-1b' ]
    launch_config_name: 'lc-1'
    min_size: 1
    max_size: 10
    desired_capacity: 5
    vpc_zone_identifier: [ 'subnet-abcd1234', 'subnet-1a2b3c4d' ]
    tags:
      - environment: production
        propagate_at_launch: no

```
## Non-Compliant Code Examples
```yaml
- name: elb2
  amazon.aws.autoscaling_group:
    name: special
    availability_zones: [ 'eu-west-1a', 'eu-west-1b' ]
    launch_config_name: 'lc-1'
    min_size: 1
    max_size: 10
    desired_capacity: 5
    vpc_zone_identifier: [ 'subnet-abcd1234', 'subnet-1a2b3c4d' ]
    tags:
      - environment: production
        propagate_at_launch: no

```

```yaml
- name: elb1
  amazon.aws.autoscaling_group:
    name: special
    load_balancers: []
    availability_zones: [ 'eu-west-1a', 'eu-west-1b' ]
    launch_config_name: 'lc-1'
    min_size: 1
    max_size: 10
    desired_capacity: 5
    vpc_zone_identifier: [ 'subnet-abcd1234', 'subnet-1a2b3c4d' ]
    tags:
      - environment: production
        propagate_at_launch: no

```
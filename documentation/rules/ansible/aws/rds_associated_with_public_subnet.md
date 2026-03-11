---
title: "RDS Associated with Public Subnet"
group_id: "Ansible / AWS"
meta:
  name: "aws/rds_associated_with_public_subnet"
  id: "16732649-4ff6-4cd2-8746-e72c13fae4b8"
  display_name: "RDS Associated with Public Subnet"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `16732649-4ff6-4cd2-8746-e72c13fae4b8`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/rds_instance_module.html#parameter-db_subnet_group_name)

### Description

RDS instances must not be placed in public subnets because an internet-routable subnet exposes the database endpoint to the internet, increasing the risk of unauthorized access and data exfiltration. This rule inspects Ansible tasks that create RDS instances (resource types `community.aws.rds_instance` or `rds_instance`) and requires the subnet group property (`db_subnet_group_name` or `subnet_group`) to reference a subnet group composed only of private subnets. It verifies the referenced subnet group tasks (`community.aws.rds_subnet_group` or `rds_subnet_group`) and the subnet tasks (`amazon.aws.ec2_vpc_subnet` or `ec2_vpc_subnet`); any subnet with `cidr` equal to `0.0.0.0/0` or `ipv6_cidr` equal to `::/0` is treated as public and will trigger a finding. Resources missing the subnet-group property or where the subnet group includes any public subnet will be flagged; ensure subnet groups list subnets using private CIDR ranges and that registered subnet task names match the entries in the subnet group.

Secure example with private subnet CIDRs:

```yaml
- name: Create private subnet
  amazon.aws.ec2_vpc_subnet:
    vpc_id: vpc-123
    cidr: 10.0.1.0/24
  register: private_subnet_a

- name: Create RDS subnet group using private subnets
  community.aws.rds_subnet_group:
    name: my-db-subnet-group
    subnets:
      - "{{ private_subnet_a }}"

- name: Create RDS instance in private subnet group
  community.aws.rds_instance:
    db_subnet_group_name: my-db-subnet-group
    # other RDS properties...
```

## Compliant Code Examples
```yaml
- name: create minimal aurora instance in default VPC and default subnet group2
  community.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster
    db_subnet_group_name: my_subnet_group2
- name: Add or change a subnet group2
  community.aws.rds_subnet_group:
    state: present
    name: my_subnet_group2
    description: My Fancy Ex Parrot Subnet Group
    subnets:
    - "{{ subnet22.subnet.id }}"
  register: my_subnet_group2
- name: Create subnet for database servers22
  amazon.aws.ec2_vpc_subnet:
    state: present
    vpc_id: vpc-123456
    cidr: 10.0.1.16/28
    tags:
      Name: Database Subnet
  register: subnet22

```
## Non-Compliant Code Examples
```yaml
- name: create minimal aurora instance in default VPC and default subnet group
  community.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster
    db_subnet_group_name: my_subnet_group
- name: Add or change a subnet group
  community.aws.rds_subnet_group:
    state: present
    name: my_subnet_group
    description: My Fancy Ex Parrot Subnet Group
    subnets:
      - "{{ subnet1.subnet.id }}"
      - "{{ subnet2.subnet.id }}"
  register: my_subnet_group
- name: Create subnet for database servers
  amazon.aws.ec2_vpc_subnet:
    state: present
    vpc_id: vpc-123456
    cidr: 0.0.0.0/0
    tags:
      Name: Database Subnet
  register: subnet1
- name: Create subnet for database servers2
  amazon.aws.ec2_vpc_subnet:
    state: present
    vpc_id: vpc-123456
    cidr: 10.0.1.16/28
    tags:
      Name: Database Subnet
  register: subnet2

```
---
title: "EC2 instance using default VPC"
group_id: "Ansible / AWS"
meta:
  name: "aws/ec2_instance_using_default_vpc"
  id: "8833f180-96f1-46f4-9147-849aafa56029"
  display_name: "EC2 instance using default VPC"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `8833f180-96f1-46f4-9147-849aafa56029`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_instance_module.html#parameter-vpc_subnet_id)

### Description

Launching EC2 instances into a default VPC increases exposure because default VPCs often have permissive networking defaults that are not tailored with least-privilege network controls. This makes it harder to enforce isolation and audit access. In Ansible playbooks using the `amazon.aws.ec2_instance` or `ec2_instance` module, the `vpc_subnet_id` parameter must not reference a subnet that belongs to a default VPC. This rule flags EC2 tasks where `vpc_subnet_id` is templated to a registered `amazon.aws.ec2_vpc_subnet`/`ec2_vpc_subnet` and the corresponding subnet's `vpc_id` contains the string "default". Ensure subnets referenced by `vpc_subnet_id` are created in a non-default VPC (for example, `vpc-0abc1234`) rather than a value containing "default".

Secure example with a subnet in a non-default VPC:

```yaml
- name: create subnet in custom VPC
  amazon.aws.ec2_vpc_subnet:
    vpc_id: vpc-0abc1234
    cidr: 10.0.1.0/24
    state: present
  register: my_subnet

- name: launch instance in the custom subnet
  amazon.aws.ec2_instance:
    name: my-instance
    image_id: ami-0123456789abcdef0
    instance_type: t3.micro
    vpc_subnet_id: "{{ my_subnet.subnet.id }}"
    wait: true
    network:
      assign_public_ip: false
```

## Compliant Code Examples
```yaml
- name: Launch instance in subnet from custom VPC
  amazon.aws.ec2_instance:
    name: db-instance
    key_name: mykey
    instance_type: t2.micro
    image_id: ami-123456
    wait: yes
    vpc_subnet_id: "{{ my_subnet2.subnet.id }}"
    network:
      assign_public_ip: false
- name: Create subnet for database server2
  amazon.aws.ec2_vpc_subnet:
    state: present
    vpc_id: "{{ myVPC.vpcs.0.id }}"
    cidr: 10.0.1.16/28
    tags:
      Name: Database Subnet
  register: my_subnet2

```
## Non-Compliant Code Examples
```yaml
- name: Launch instance in subnet from default VPC
  amazon.aws.ec2_instance:
    name: db-instance
    key_name: mykey
    instance_type: t2.micro
    image_id: ami-123456
    wait: yes
    vpc_subnet_id: "{{ my_subnet.subnet.id }}"
    network:
      assign_public_ip: false
- name: Create subnet for database server
  amazon.aws.ec2_vpc_subnet:
    state: present
    vpc_id: "{{ defaultVPC.vpcs.0.id }}"
    cidr: 10.0.1.16/28
    tags:
      Name: Database Subnet
  register: my_subnet

```
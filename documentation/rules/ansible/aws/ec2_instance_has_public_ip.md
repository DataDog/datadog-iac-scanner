---
title: "EC2 instance has public IP"
group_id: "Ansible / AWS"
meta:
  name: "aws/ec2_instance_has_public_ip"
  id: "a8b0c58b-cd25-4b53-9ad0-55bca0be0bc1"
  display_name: "EC2 instance has public IP"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `a8b0c58b-cd25-4b53-9ad0-55bca0be0bc1`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_instance_module.html)

### Description

EC2 instances and launch templates that automatically receive a public IPv4 address are exposed directly to the internet, increasing the attack surface and the risk of unauthorized access or exploitation.

For Ansible tasks, check the following module properties:

- For `amazon.aws.ec2_launch_template` / `ec2_launch_template`: `network_interfaces.associate_public_ip_address`
- For `amazon.aws.ec2_instance` / `ec2_instance`: `network.assign_public_ip`

Each property must be explicitly set to `false` (or `'no'`) or omitted. The rule flags resources where the property is truthy (for example, `true`, `yes`) because there is no safe default. 

Secure examples:

```yaml
- name: Launch instance without public IP (ec2_instance)
  amazon.aws.ec2_instance:
    name: my-instance
    network:
      assign_public_ip: false

- name: Create launch template without public IP
  amazon.aws.ec2_launch_template:
    name: my-template
    network_interfaces:
      - device_index: 0
        associate_public_ip_address: false
```

## Compliant Code Examples
```yaml
- amazon.aws.ec2:
    key_name: mykey
    instance_type: t2.micro
    count: 3
    vpc_subnet_id: subnet-29e63245
    assign_public_ip: false
- name: Create an ec2 launch template
  amazon.aws.ec2_launch_template:
    name: my_template
    image_id: ami-04b762b4289fba92b
    key_name: my_ssh_key
    instance_type: t2.micro
- name: Create an ec2 launch template
  amazon.aws.ec2_launch_template:
    name: "my_template"
    image_id: "ami-04b762b4289fba92b"
    key_name: my_ssh_key
    instance_type: t2.micro
    network_interfaces:
      - interface_type: interface
        ipv6_addresses: []
        mac_address: '0 e: 0 e: 36: 60: 67: cf'
        network_interface_id: eni - 061 dee20eba3b445a
        owner_id: '721066863947'
        source_dest_check: true
        status: " in -use"

```
## Non-Compliant Code Examples
```yaml
- name: Create an ec2 launch template
  amazon.aws.ec2_launch_template:
    name: "my_template"
    image_id: "ami-04b762b4289fba92b"
    key_name: my_ssh_key
    instance_type: t2.micro
    network_interfaces:
      associate_public_ip_address: true
- name: start an instance with a public IP address
  amazon.aws.ec2_instance:
    name: "public-compute-instance"
    key_name: "prod-ssh-key"
    vpc_subnet_id: subnet-5ca1ab1e
    instance_type: c5.large
    security_group: default
    network:
      assign_public_ip: true

```
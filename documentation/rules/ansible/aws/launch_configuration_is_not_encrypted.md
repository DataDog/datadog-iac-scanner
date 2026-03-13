---
title: "Launch configuration is not encrypted"
group_id: "Ansible / AWS"
meta:
  name: "aws/launch_configuration_is_not_encrypted"
  id: "66477506-6abb-49ed-803d-3fa174cd5f6a"
  display_name: "Launch configuration is not encrypted"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `66477506-6abb-49ed-803d-3fa174cd5f6a`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/ec2_lc_module.html)

### Description

Block device volumes in EC2 launch configurations must be encrypted to protect data at rest and prevent exposure of snapshots or AMIs if storage media is compromised.

For Ansible tasks using the `community.aws.ec2_lc` or `ec2_lc` modules, ensure the `volumes` list is defined and each volume entry sets `encrypted: true` (Ansible `yes` is also acceptable) under `ec2_lc.volumes`. Ephemeral (instance-store) volumes do not support encryption and are excluded. This rule flags launch configurations missing the `volumes` property, any volume entries without an `encrypted` property, or volumes where `encrypted` is explicitly false.

Example secure configuration for an Ansible `ec2_lc` task:

```yaml
- name: Create launch configuration with encrypted volumes
  community.aws.ec2_lc:
    name: my-launch-config
    image_id: ami-0123456789abcdef0
    instance_type: t3.medium
    volumes:
      - device_name: /dev/xvda
        volume_size: 50
        volume_type: gp2
        encrypted: true
        delete_on_termination: yes
```

## Compliant Code Examples
```yaml
- name: note that encrypted volumes are only supported in >= Ansible 2.4 v4
  ec2_lc:
    name: special
    image_id: ami-XXX
    key_name: default
    security_groups: [group, group2]
    instance_type: t1.micro
    volumes:
    - device_name: /dev/sda1
      volume_size: 100
      volume_type: io1
      iops: 3000
      delete_on_termination: true
      encrypted: yes
- name: note that encrypted volumes are only supported in >= Ansible 2.4 v5
  community.aws.ec2_lc:
    name: special
    image_id: ami-XXX
    key_name: default
    security_groups: [group, group2]
    instance_type: t1.micro
    volumes:
    - device_name: /dev/sda1
      volume_size: 100
      volume_type: io1
      iops: 3000
      delete_on_termination: true
      encrypted: yes

```
## Non-Compliant Code Examples
```yaml
- name: note that encrypted volumes are only supported in >= Ansible 2.4
  community.aws.ec2_lc:
    name: special
    image_id: ami-XXX
    key_name: default
    security_groups: ['group', 'group2' ]
    instance_type: t1.micro
    volumes:
    - device_name: /dev/sda1
      volume_size: 100
      volume_type: io1
      iops: 3000
      delete_on_termination: true
      encrypted: no
- name: note that encrypted volumes are only supported in >= Ansible 2.4 v2
  ec2_lc:
    name: special
    image_id: ami-XXX
    key_name: default
    security_groups: ['group', 'group2' ]
    instance_type: t1.micro
    volumes:
    - device_name: /dev/sda1
      volume_size: 100
      volume_type: io1
      iops: 3000
      delete_on_termination: true
- name: note that encrypted volumes are only supported in >= Ansible 2.4 v3
  ec2_lc:
    name: special
    image_id: ami-XXX
    key_name: default
    security_groups: ['group', 'group2' ]
    instance_type: t1.micro

```
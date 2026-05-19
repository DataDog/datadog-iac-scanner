---
title: "Default security groups with unrestricted traffic"
group_id: "Ansible / AWS"
meta:
  name: ""aws/default_security_groups_with_unrestricted_traffic""
  id: "ansible-aws-default-security-groups-with-unrestricted-traffic"
  display_name: "Default security groups with unrestricted traffic"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-default-security-groups-with-unrestricted-traffic{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html)

### Description

Security groups that allow inbound or outbound CIDR ranges of `0.0.0.0/0` or `::/0` expose resources to the entire internet, increasing the risk of unauthorized access, brute-force attacks, and data exfiltration.

For Ansible `amazon.aws.ec2_group` or `ec2_group` tasks, inspect the `rules` and `rules_egress` entries and ensure the `cidr_ip` and `cidr_ipv6` properties are not set to `0.0.0.0/0` or `::/0`. Tasks containing `cidr_ip: 0.0.0.0/0` or `cidr_ipv6: ::/0` are flagged. Restrict access to specific CIDR ranges or reference other security groups instead of using global open CIDRs.

Secure configuration example:

```yaml
my_security_group:
  amazon.aws.ec2_group:
    name: my-sg
    rules:
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 203.0.113.0/24
    rules_egress:
      - proto: -1
        from_port: 0
        to_port: 0
        cidr_ip: 10.0.0.0/16
```

## Compliant Code Examples
```yaml
- name: example ec2 group
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: all
        # in the 'proto' attribute, if you specify -1, all, or a protocol number other than tcp, udp, icmp, or 58 (ICMPv6),
        # traffic on all ports is allowed, regardless of any ports you specify
      from_port: 10050   # this value is ignored
      to_port: 10050   # this value is ignored
      cidr_ip: 10.1.0.0/16
      cidr_ipv6: 64:ff9b::/96
    rules_egress:
    - proto: tcp
      from_port: 80
      to_port: 80
      cidr_ip: 10.1.0.0/16
      cidr_ipv6: 64:ff9b::/96
      group_name: example-other
        # description to use if example-other needs to be created
      group_desc: other example EC2 group

```
## Non-Compliant Code Examples
```yaml
---
- name: example ec2 group
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: all
        # in the 'proto' attribute, if you specify -1, all, or a protocol number other than tcp, udp, icmp, or 58 (ICMPv6),
        # traffic on all ports is allowed, regardless of any ports you specify
        from_port: 10050 # this value is ignored
        to_port: 10050 # this value is ignored
        cidr_ip:
          - 0.0.0.0/0
- name: example2 ec2 group
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules_egress:
      - proto: tcp
        from_port: 80
        to_port: 80
        cidr_ip: 0.0.0.0/0
        group_name: example-other
        # description to use if example-other needs to be created
        group_desc: other example EC2 group
- name: example3 ec2 group
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: all
        # in the 'proto' attribute, if you specify -1, all, or a protocol number other than tcp, udp, icmp, or 58 (ICMPv6),
        # traffic on all ports is allowed, regardless of any ports you specify
        from_port: 10050 # this value is ignored
        to_port: 10050 # this value is ignored
        cidr_ipv6: ::/0
- name: example4 ec2 group
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules_egress:
      - proto: tcp
        from_port: 80
        to_port: 80
        cidr_ipv6: ::/0
        group_name: example-other
        # description to use if example-other needs to be created
        group_desc: other example EC2 group
- name: example5 ec2 group
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      # 'ports' rule keyword was introduced in version 2.4. It accepts a single port value or a list of values including ranges (from_port-to_port).
      - proto: tcp
        ports: 22
        group_name: example-vpn
    rules_egress:
      - proto: tcp
        from_port: 80
        to_port: 80
        cidr_ipv6:
          - ::/0
        group_name: example-other
        # description to use if example-other needs to be created
        group_desc: other example EC2 group

```
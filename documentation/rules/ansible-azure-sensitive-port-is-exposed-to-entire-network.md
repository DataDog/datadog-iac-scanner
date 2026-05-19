---
title: "Sensitive port is exposed to entire network"
group_id: "Ansible / Azure"
meta:
  name: ""azure/sensitive_port_is_exposed_to_entire_network""
  id: "ansible-azure-sensitive-port-is-exposed-to-entire-network"
  display_name: "Sensitive port is exposed to entire network"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-azure-sensitive-port-is-exposed-to-entire-network{{< /copyable-code >}}

**Provider:** Azure

**Platform:** Ansible

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_securitygroup_module.html#parameter-rules)

### Description

Inbound network security group rules that allow TCP or UDP access to sensitive service ports from anywhere (for example, 0.0.0.0/0 or ::/0) expose services such as Telnet or POP3 to the public internet, increasing the risk of unauthorized access and exploitation.

In Ansible tasks using `azure.azcollection.azure_rm_securitygroup` or `azure_rm_securitygroup`, inspect each entry in `rules[]`. A rule is flagged when `access` is `"Allow"`, `direction` is `"Inbound"` (or absent), `source_address_prefix` ends with `"/0"`, `protocol` is TCP/UDP (or `"*"`, which expands to include TCP/UDP), and `destination_port_range` contains a sensitive TCP port.

The check handles `destination_port_range` as either a string or an array and supports single ports, comma-separated lists, and ranges. Resources missing the `direction` property are treated as inbound and are evaluated.

Remediate by restricting `source_address_prefix` to specific CIDR ranges or internal/service endpoints, or by removing or denying public Allow rules for those ports. For example, allow only from a trusted management CIDR:

```yaml
- name: Create NSG with restricted rule
  azure_rm_securitygroup:
    name: myNSG
    resource_group: myRG
    rules:
      - name: AllowSSHFromMgmt
        protocol: Tcp
        destination_port_range: 22
        source_address_prefix: 10.0.0.0/24
        access: Allow
        direction: Inbound
        priority: 1000
```

## Compliant Code Examples
```yaml
- name: foo1
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
    - name: example1
      priority: 100
      direction: Inbound
      access: Deny
      protocol: TCP
      source_port_range: '*'
      destination_port_range: 23
      source_address_prefix: '*'
      destination_address_prefix: '*'
- name: foo2
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
    - name: example2
      priority: 100
      direction: Inbound
      access: Allow
      protocol: Icmp
      source_port_range: '*'
      destination_port_range: 23-24
      source_address_prefix: '*'
      destination_address_prefix: '*'
- name: foo3
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
    - name: example3
      priority: 100
      direction: Inbound
      access: Allow
      protocol: TCP
      source_port_range: '*'
      destination_port_range: 8-174
      source_address_prefix: 0.0.0.0
      destination_address_prefix: '*'
- name: foo4
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
    - name: example4
      priority: 100
      direction: Inbound
      access: Allow
      protocol: TCP
      source_port_range: '*'
      destination_port_range: 23-196
      source_address_prefix: 192.168.0.0
      destination_address_prefix: '*'
- name: foo5
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
    - name: example5
      priority: 100
      direction: Inbound
      access: Allow
      protocol: TCP
      source_port_range: '*'
      destination_port_range: 23
      source_address_prefix: /1
      destination_address_prefix: '*'
- name: foo6
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
    - name: example6
      priority: 100
      direction: Inbound
      access: Allow
      protocol: '*'
      source_port_range: '*'
      destination_port_range: 43
      source_address_prefix: /0
      destination_address_prefix: '*'
- name: foo7
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
    - name: example7
      priority: 100
      direction: Inbound
      access: Allow
      protocol: Icmp
      source_port_range: '*'
      destination_port_range: 23
      source_address_prefix: internet
      destination_address_prefix: '*'
- name: foo8
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
    - name: example8
      priority: 100
      direction: Inbound
      access: Allow
      protocol: '*'
      source_port_range: '*'
      destination_port_range: 22, 24,49-67
      source_address_prefix: any
      destination_address_prefix: '*'
- name: foo9
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
    - name: example9
      priority: 100
      direction: Inbound
      access: Allow
      protocol: Icmp
      source_port_range: '*'
      destination_port_range: 23
      source_address_prefix: /0
      destination_address_prefix: '*'
- name: foo10
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
    - name: example10
      priority: 100
      direction: Inbound
      access: Allow
      protocol: TCP
      source_port_range: '*'
      destination_port_range:
      - 23
      - 69
      source_address_prefix: 0.0.1.0
      destination_address_prefix: '*'
    - name: example11
      priority: 100
      direction: Inbound
      access: Allow
      protocol: TCP
      source_port_range: '*'
      destination_port_range:
      - 2
      - 310
      source_address_prefix: 0.0.0.0
      destination_address_prefix: '*'

```
## Non-Compliant Code Examples
```yaml
---
- name: foo1
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
      - name: example1
        priority: 100
        direction: Inbound
        access: Allow
        protocol: UDP
        source_port_range: "*"
        destination_port_range: "61621"
        source_address_prefix: "/0"
        destination_address_prefix: "*"
- name: foo2
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
      - name: example2
        priority: 100
        direction: Inbound
        access: Allow
        protocol: TCP
        source_port_range: "*"
        destination_port_range: "23-34"
        source_address_prefix: "1.1.1.1/0"
        destination_address_prefix: "*"
- name: foo3
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
      - name: example3
        priority: 100
        direction: Inbound
        access: Allow
        protocol: "*"
        source_port_range: "*"
        destination_port_range: "21-23"
        source_address_prefix: "/0"
        destination_address_prefix: "*"
- name: foo4
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
      - name: example4
        priority: 100
        direction: Inbound
        access: Allow
        protocol: "*"
        source_port_range: "*"
        destination_port_range: "23"
        source_address_prefix: "0.0.0.0/0"
        destination_address_prefix: "*"
- name: foo5
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
      - name: example5
        priority: 100
        direction: Inbound
        access: Allow
        protocol: "UDP"
        source_port_range: "*"
        destination_port_range:
          - "23"
          - "245"
        source_address_prefix: "34.15.11.3/0"
        destination_address_prefix: "*"
- name: foo6
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
      - name: example6
        priority: 100
        direction: Inbound
        access: Allow
        protocol: "TCP"
        source_port_range: "*"
        destination_port_range: "23"
        source_address_prefix: "/0"
        destination_address_prefix: "*"
- name: foo7
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
      - name: example7
        priority: 100
        direction: Inbound
        access: Allow
        protocol: "UDP"
        source_port_range: "*"
        destination_port_range: "22-64, 94"
        source_address_prefix: "10.0.0.0/0"
        destination_address_prefix: "*"
- name: foo8
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
      - name: example8
        priority: 100
        direction: Inbound
        access: Allow
        protocol: "TCP"
        source_port_range: "*"
        destination_port_range:
          - "14"
          - "23"
          - "48"
        source_address_prefix: "12.12.12.12/0"
        destination_address_prefix: "*"
- name: foo9
  azure_rm_securitygroup:
    resource_group: myResourceGroup
    name: mysecgroup
    rules:
      - name: example9
        priority: 100
        direction: Inbound
        access: Allow
        protocol: "*"
        source_port_range: "*"
        destination_port_range:
          - "12"
          - "23-24"
          - "46"
        source_address_prefix: "/0"
        destination_address_prefix: "*"
      - name: example10
        priority: 100
        direction: Inbound
        access: Allow
        protocol: "*"
        source_port_range: "*"
        destination_port_range: 46-146, 18-36, 1-2, 3
        source_address_prefix: "1.2.3.4/0"
        destination_address_prefix: "*"

```
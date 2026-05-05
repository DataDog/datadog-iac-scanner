---
title: "Ansible Tower exposed to the internet"
group_id: "Ansible / Ansible Inventory"
meta:
  name: "hosts/ansible_tower_exposed_to_internet"
  id: "ansible-common-ansible-tower-exposed-to-internet"
  display_name: "Ansible Tower exposed to the internet"
  cloud_provider: "Ansible Inventory"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `ansible-common-ansible-tower-exposed-to-internet`

**Cloud Provider:** Ansible Inventory

**Platform:** Ansible

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible-tower/latest/html/administration/security_best_practices.html#understand-the-architecture-of-ansible-and-tower)

### Description

Ansible Tower hosts must not be assigned public IP addresses. Exposing Tower to the public internet increases the risk of unauthorized access and credential compromise of your automation infrastructure. Check the Ansible inventory resource (`ansible_inventory`) for entries under `all.children.tower.hosts` and ensure each host value is a private IP address (RFC1918) or an internal DNS name rather than a public IP. Resources with hosts set to public IPs are flagged.

Use private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or internal hostnames, and place Tower behind a VPN, bastion host, or firewall/security-group restrictions to limit exposure.

Secure inventory example with a private IP:

```yaml
all:
  children:
    tower:
      hosts:
        tower.internal.example.com:
          ansible_host: 10.0.1.5
```

## Compliant Code Examples
```yaml
all:
  children:
    automationhub:
      hosts:
        automationhub.acme.org:
          admin_password: <password>
          pg_database: awx
          pg_host: database-01.acme.org
          pg_password: <password>
          pg_port: '5432'
          pg_sslmode: prefer
          pg_username: awx
    database:
      hosts:
        database-01.acme.org:
          admin_password: <password>
          pg_database: awx
          pg_host: database-01.acme.org
          pg_password: <password>
          pg_port: '5432'
          pg_sslmode: prefer
          pg_username: awx
    tower:
      hosts:
        172.27.0.5:
          admin_password: <password>
          pg_database: awx
          pg_host: database-01.acme.org
          pg_password: <password>
          pg_port: '5432'
          pg_sslmode: prefer
          pg_username: awx
    ungrouped: {}

```

```ini
[tower]
172.27.0.2
172.27.0.3
172.27.0.4
```
## Non-Compliant Code Examples
```yaml
all:
  children:
    automationhub:
      hosts:
        automationhub.acme.org:
          admin_password: <password>
          pg_database: awx
          pg_host: database-01.acme.org
          pg_password: <password>
          pg_port: '5432'
          pg_sslmode: prefer
          pg_username: awx
    database:
      hosts:
        database-01.acme.org:
          admin_password: <password>
          pg_database: awx
          pg_host: database-01.acme.org
          pg_password: <password>
          pg_port: '5432'
          pg_sslmode: prefer
          pg_username: awx
    tower:
      hosts:
        139.50.1.1:
          admin_password: <password>
          pg_database: awx
          pg_host: database-01.acme.org
          pg_password: <password>
          pg_port: '5432'
          pg_sslmode: prefer
          pg_username: awx
    ungrouped: {}

```

```ini
[tower]
150.50.1.1
[automationhub]
automationhub.acme.org
[database]
database-01.acme.org
[all:vars]
admin_password='<password>'
pg_host='database-01.acme.org'
pg_port='5432'
pg_database='awx'
pg_username='awx'
pg_password='<password>'
pg_sslmode='prefer'
```
---
title: "Communication over HTTP"
group_id: "Ansible / Common"
meta:
  name: "general/communication_over_http"
  id: "2e8d4922-8362-4606-8c14-aa10466a1ce3"
  display_name: "Communication over HTTP"
  cloud_provider: "Common"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{</* copyable-code */>}}2e8d4922-8362-4606-8c14-aa10466a1ce3{{</* copyable-code */>}}

**Cloud Provider:** Common

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/uri_module.html#parameter-url)

### Description

Using HTTP URLs in Ansible uri tasks exposes requests and any sensitive data (tokens, credentials, or cookies) to interception and tampering because traffic is sent in plaintext. Tasks that use the `ansible.builtin.uri` module should have a `url` property that begins with `https://`. Tasks whose `url` starts with `http://` are flagged and should be updated to use `https://` endpoints or other secure transport.

Secure example:

```yaml
- name: Call API over HTTPS
  ansible.builtin.uri:
    url: "https://api.example.com/endpoint"
    method: GET
```

## Compliant Code Examples
```yaml
- name: Verificar o status de um site usando o módulo uri
  hosts: localhost
  tasks:
    - name: Verificar o status do site
      ansible.builtin.uri:
        url: "https://www.example.com"
        method: GET
      register: site_response

    - name: Exibir resposta do site
      debug:
        var: site_response

```
## Non-Compliant Code Examples
```yaml
- name: Verificar o status de um site usando o módulo uri
  hosts: localhost
  tasks:
    - name: Verificar o status do site
      ansible.builtin.uri:
        url: "http://www.example.com"
        method: GET
      register: site_response

    - name: Exibir resposta do site
      debug:
        var: site_response

```
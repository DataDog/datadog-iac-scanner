---
title: "Ensure MySQL is using the latest version of TLS encryption"
group_id: "Terraform / Azure"
meta:
  name: "azure/mysql_not_using_latest_tls"
  id: "c2a1d4e6-f789-4b0c-9e12-3456789abcde"
  display_name: "Ensure MySQL is using the latest version of TLS encryption"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `c2a1d4e6-f789-4b0c-9e12-3456789abcde`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/3.117.1/docs/resources/mysql_server#ssl_minimal_tls_version_enforced-2)

### Description

 Outdated TLS versions (TLS 1.0/1.1) contain vulnerabilities that can be exploited by attackers to intercept sensitive data transmitted between the client and the MySQL server. When TLS 1.0/1.1 is used, your database traffic becomes vulnerable to man-in-the-middle attacks, potentially exposing usernames, passwords, and sensitive data. Using TLS 1.2 addresses these security weaknesses and provides stronger encryption algorithms and more secure cipher suites. To ensure proper configuration, replace `ssl_minimal_tls_version_enforced = ["TLS1_0"]` with `ssl_minimal_tls_version_enforced = ["TLS1_2"]` in your Azure MySQL server resource.


## Compliant Code Examples
```terraform
resource "azurerm_mysql_server" "good_example" {
  name                = "good-mysql-server"
  location            = "East US"
  resource_group_name = "example-rg"

  ssl_minimal_tls_version_enforced = ["TLS1_2"] # ✅ Correct TLS version
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_mysql_server" "bad_example" {
  name                = "bad-mysql-server"
  location            = "East US"
  resource_group_name = "example-rg"

  ssl_minimal_tls_version_enforced = ["TLS1_0"] # ❌ Outdated TLS version
}

```
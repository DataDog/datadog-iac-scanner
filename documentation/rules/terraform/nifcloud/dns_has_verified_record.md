---
title: "Beta - Nifcloud DNS has verified record"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/dns_has_verified_record"
  id: "a1defcb6-55e8-4511-8c2a-30b615b0e057"
  display_name: "Beta - Nifcloud DNS has verified record"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `a1defcb6-55e8-4511-8c2a-30b615b0e057`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/dns_record#record)

### Description

 Remove the verification TXT record used for DNS authentication (records containing `nifty-dns-verify=`) after verification is complete. If the authentication record remains, others could reuse it to claim or re-register the zone, exposing DNS control to unauthorized parties. This rule flags `nifcloud_dns_record` resources that include `nifty-dns-verify=` and returns attributes `documentId`, `resourceType`, `resourceName`, `searchKey`, `issueType`, `keyExpectedValue`, and `keyActualValue`.


## Compliant Code Examples
```terraform
resource "nifcloud_dns_record" "negative" {
  zone_id = nifcloud_dns_zone.example.id
  name    = "test.example.test"
  type    = "TXT"
  ttl     = 300
  record  = "negative"
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_dns_record" "positive" {
  zone_id = nifcloud_dns_zone.example.id
  name    = "test.example.test"
  type    = "TXT"
  ttl     = 300
  record  = "nifty-dns-verify=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
}

```
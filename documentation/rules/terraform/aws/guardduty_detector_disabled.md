---
title: "GuardDuty detector disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/guardduty_detector_disabled"
  id: "704dadd3-54fc-48ac-b6a0-02f170011473"
  display_name: "GuardDuty detector disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `704dadd3-54fc-48ac-b6a0-02f170011473`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_detector#example-usage)

### Description

 This check ensures that Amazon GuardDuty is enabled in your AWS environment by verifying that the `enable` attribute in the `aws_guardduty_detector` Terraform resource is set to `true`. GuardDuty is a threat detection service that continuously monitors for malicious or unauthorized behavior, helping identify and prioritize potential security risks. If GuardDuty is disabled, suspicious activities such as anomalous API calls, potentially unauthorized deployments, or account compromise may go undetected, leaving cloud resources vulnerable to attack. Enabling GuardDuty is a crucial security best practice to maintain visibility into potential threats and respond to incidents promptly.


## Compliant Code Examples
```terraform
resource "aws_guardduty_detector" "negative1" {
  enable = true
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_guardduty_detector" "positive1" {
  enable = false
}


```
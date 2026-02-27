---
title: "Stack notifications disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/stack_notifications_disabled"
  id: "b72d0026-f649-4c91-a9ea-15d8f681ac09"
  display_name: "Stack notifications disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `b72d0026-f649-4c91-a9ea-15d8f681ac09`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack)

### Description

Enabling stack notifications in AWS CloudFormation ensures that administrators are promptly informed about critical events such as stack creation, updates, or failures. Without specifying the `notification_arns` attribute in the Terraform resource, as shown below, important operational or security changes may go unnoticed, potentially delaying response to incidents or failures:

```
resource "aws_cloudformation_stack" "example" {
  name = "networking-stack"
  parameters = {
    VPCCidr = "10.0.0.0/16"
  }
  notification_arns = ["arn:aws:sns:us-east-1:123456789012:my-sns-topic"]
}
```

Missing notifications can lead to undetected application outages or misconfigurations, increasing the risk to your cloud infrastructure.

## Compliant Code Examples
```terraform
resource "aws_cloudformation_stack" "negative1" {

  name = "networking-stack"

  parameters = {
    VPCCidr = "10.0.0.0/16"
  }


  notification_arns = ["a","b"]

}
```
## Non-Compliant Code Examples
```terraform
resource "aws_cloudformation_stack" "positive1" {

  name = "networking-stack"

  parameters = {
    VPCCidr = "10.0.0.0/16"
  }


}
```
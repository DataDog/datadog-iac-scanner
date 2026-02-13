---
title: "No stack policy"
group_id: "Terraform / AWS"
meta:
  name: "aws/no_stack_policy"
  id: "2f01fb2d-828a-499d-b98e-b83747305052"
  display_name: "No stack policy"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `2f01fb2d-828a-499d-b98e-b83747305052`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack)

### Description

 AWS CloudFormation stacks should implement a stack policy, set using the `policy_body` or `policy_url` attributes in Terraform, to restrict which actions can modify or delete critical resources within the stack. Without a stack policy, any update operation could unintentionally overwrite, disrupt, or remove essential resources, increasing the risk of accidental outages or security issues. Properly configuring a stack policy helps enforce change management controls and reduces the attack surface for unauthorized or accidental actions.


## Compliant Code Examples
```terraform
resource "aws_cloudformation_stack" "negative1" {

     name = "networking-stack"

     parameters = {
     VPCCidr = "10.0.0.0/16"
     }

     policy_url = "somepolicyurl"
}



resource "aws_cloudformation_stack" "negative2" {

     name = "networking-stack"

     parameters = {
     VPCCidr = "10.0.0.0/16"
     }

     policy_body = "somepolicy"
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
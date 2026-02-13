---
title: "Stack without template"
group_id: "Terraform / AWS"
meta:
  name: "aws/stack_without_template"
  id: "91bea7b8-0c31-4863-adc9-93f6177266c4"
  display_name: "Stack without template"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `91bea7b8-0c31-4863-adc9-93f6177266c4`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack)

### Description

This check ensures that the `aws_cloudformation_stack` resource in Terraform includes either the `template_url` or `template_body` attribute, which defines the CloudFormation template to be deployed. Omitting both of these attributes results in stacks being created without an actual CloudFormation template, leaving the stack incomplete and potentially non-functional. If left unaddressed, this misconfiguration can lead to failed deployments and gaps in infrastructure automation, increasing operational risks.

A secure Terraform configuration is shown below:

```
resource "aws_cloudformation_stack" "example" {
  name = "networking-stack"

  parameters = {
    VPCCidr = "10.0.0.0/16"
  }

  template_url = "https://s3.amazonaws.com/example/cloudformation-template.yml"
}
```

## Compliant Code Examples
```terraform
resource "aws_cloudformation_stack" "negative1" {

     name = "networking-stack"

     parameters = {
     VPCCidr = "10.0.0.0/16"
     }

     template_url = "sometemplateurl"
}



resource "aws_cloudformation_stack" "negative2" {

     name = "networking-stack"

     parameters = {
     VPCCidr = "10.0.0.0/16"
     }

     template_body = "sometemplatebody"
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
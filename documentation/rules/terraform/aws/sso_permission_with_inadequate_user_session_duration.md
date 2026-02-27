---
title: "SSO permission with inadequate user session duration"
group_id: "Terraform / AWS"
meta:
  name: "aws/sso_permission_with_inadequate_user_session_duration"
  id: "ce9dfce0-5fc8-433b-944a-3b16153111a8"
  display_name: "SSO permission with inadequate user session duration"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `ce9dfce0-5fc8-433b-944a-3b16153111a8`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssoadmin_permission_set)

### Description

Single Sign-On (SSO) permission sets should restrict user session durations to a maximum of one hour to reduce the window of opportunity for unauthorized access and session hijacking. Allowing longer session durations by setting the `session_duration` attribute to values such as `"PT2H"` or `"PT1H1M"` in the `aws_ssoadmin_permission_set` resource increases the risk of attackers leveraging stale or stolen sessions. Configuring session durations to `session_duration = "PT1H"`, or omitting the duration in the configuration enforces this security best practice and helps limit potential exposure.

```
resource "aws_ssoadmin_permission_set" "example" {
  name             = "Example"
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  relay_state      = "https://s3.console.aws.amazon.com/s3/home?region=us-east-1//"
  session_duration = "PT1H"
}
```

## Compliant Code Examples
```terraform
resource "aws_ssoadmin_permission_set" "example" {
  name             = "Example"
  description      = "An example"
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  relay_state      = "https://s3.console.aws.amazon.com/s3/home?region=us-east-1#"
  session_duration = "PT1H"
}

resource "aws_ssoadmin_permission_set" "example2" {
  name             = "Example"
  description      = "An example"
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  relay_state      = "https://s3.console.aws.amazon.com/s3/home?region=us-east-1#"
}


```
## Non-Compliant Code Examples
```terraform
resource "aws_ssoadmin_permission_set" "example3" {
  name             = "Example"
  description      = "An example"
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  relay_state      = "https://s3.console.aws.amazon.com/s3/home?region=us-east-1#"
  session_duration = "PT1H1M"
}

resource "aws_ssoadmin_permission_set" "example4" {
  name             = "Example"
  description      = "An example"
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  relay_state      = "https://s3.console.aws.amazon.com/s3/home?region=us-east-1#"
  session_duration = "PT2H"
}

```
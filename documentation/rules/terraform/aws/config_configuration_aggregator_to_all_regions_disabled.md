---
title: "Configuration aggregator to all regions disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/config_configuration_aggregator_to_all_regions_disabled"
  id: "ac5a0bc0-a54c-45aa-90c3-15f7703b9132"
  display_name: "Configuration aggregator to all regions disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `ac5a0bc0-a54c-45aa-90c3-15f7703b9132`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator#all_regions)

### Description

This check ensures that the `all_regions` attribute is set to `true` in AWS Config configuration aggregators, either within `account_aggregation_source` or `organization_aggregation_source` blocks. If `all_regions = false` or specific regions are listed, AWS Config will not aggregate configuration data from all regions, potentially leaving gaps in compliance visibility and risk detection for resources deployed outside the specified regions. Without full regional aggregation, there is an increased risk that misconfigurations or security issues in unmonitored regions go undetected, undermining centralized auditing and governance across an AWS environment.

## Compliant Code Examples
```terraform
resource "aws_config_configuration_aggregator" "negative1" {
  name = "example"

  account_aggregation_source {
    all_regions = true

  }
}

resource "aws_config_configuration_aggregator" "negative2" {
  depends_on = [aws_iam_role_policy_attachment.organization]

  name = "example" # Required

  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.organization.arn
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_config_configuration_aggregator" "positive1" {
  name = "example"

  account_aggregation_source {
    account_ids = ["123456789012"]
    regions     = ["us-east-2", "us-east-1", "us-west-1", "us-west-2"]
  }
}

resource "aws_config_configuration_aggregator" "positive2" {
  depends_on = [aws_iam_role_policy_attachment.organization]

  name = "example" # Required

  organization_aggregation_source {
    all_regions = false
    role_arn    = aws_iam_role.organization.arn
  }
}

```
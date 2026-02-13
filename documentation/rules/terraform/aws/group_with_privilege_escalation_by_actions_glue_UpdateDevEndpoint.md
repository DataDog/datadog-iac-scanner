---
title: "Group with privilege escalation by actions 'glue:UpdateDevEndpoint'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_glue_UpdateDevEndpoint"
  id: "8f3c16b3-354d-45db-8ad5-5066778a9485"
  display_name: "Group with privilege escalation by actions 'glue:UpdateDevEndpoint'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `8f3c16b3-354d-45db-8ad5-5066778a9485`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

 This check identifies IAM group policies that grant the `glue:UpdateDevEndpoint` action with the resource set to `"*"`, as shown in the following insecure example:

```
policy = jsonencode({
  Version = "2012-10-17"
  Statement = [
    {
      Action = [
        "glue:UpdateDevEndpoint",
      ]
      Effect   = "Allow"
      Resource = "*"
    },
  ]
})
```

Allowing unrestricted access to `glue:UpdateDevEndpoint` enables users in the group to potentially attach arbitrary IAM roles to a Glue development endpoint, which can be leveraged for privilege escalation. If left unaddressed, attackers with this permission may exploit it to gain elevated permissions or access sensitive resources by executing malicious code or gaining unauthorized access to other AWS services. This misconfiguration can result in significant security risks, including compromise of AWS account resources and loss of sensitive information.


## Compliant Code Examples
```terraform
resource "aws_iam_user" "cosmic2" {
  name = "cosmic2"
}

resource "aws_iam_user_policy" "inline_policy_run_instances2" {
  name = "inline_policy_run_instances"
  user = aws_iam_user.cosmic2.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_group" "cosmic" {
  name = "cosmic"
}

resource "aws_iam_group_policy" "test_inline_policy" {
  name = "test_inline_policy"
  group = aws_iam_group.cosmic.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "glue:UpdateDevEndpoint",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```
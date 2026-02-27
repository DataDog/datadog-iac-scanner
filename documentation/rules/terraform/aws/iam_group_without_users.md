---
title: "IAM group without users"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_group_without_users"
  id: "fc101ca7-c9dd-4198-a1eb-0fbe92e80044"
  display_name: "IAM group without users"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `fc101ca7-c9dd-4198-a1eb-0fbe92e80044`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_membership#users)

### Description

IAM Groups should have at least one user associated with them to ensure that group permissions are assigned with clear intent and are being utilized for access control. Leaving an IAM group without users—such as configuring `users = []` in an `aws_iam_group_membership` resource—can create ambiguity in access management, leaving unused privilege sets within the environment that may go unnoticed or be misused if users are later added without proper oversight. To address this, always specify one or more users in the `users` attribute, as shown below:

```
resource "aws_iam_group_membership" "team" {
  name = "tf-testing-group-membership"

  users = [
    aws_iam_user.user_one.name,
    aws_iam_user.user_two.name,
  ]

  group = aws_iam_group.group.name
}
```

## Compliant Code Examples
```terraform
resource "aws_iam_group_membership" "team" {
  name = "tf-testing-group-membership"

  users = [
    aws_iam_user.user_one.name,
    aws_iam_user.user_two.name,
  ]

  group = aws_iam_group.group.name
}

resource "aws_iam_group" "group" {
  name = "test-group"
}

resource "aws_iam_user" "user_one" {
  name = "test-user"
}

resource "aws_iam_user" "user_two" {
  name = "test-user-two"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_group_membership" "team2" {
  name = "tf-testing-group-membership"

  users = [
    aws_iam_user.user_one2.name,
    aws_iam_user.user_two2.name,
  ]

  group = aws_iam_group.group222.name
}

resource "aws_iam_group" "group2" {
  name = "test-group"
}

resource "aws_iam_user" "user_one2" {
  name = "test-user"
}

resource "aws_iam_user" "user_two2" {
  name = "test-user-two"
}

resource "aws_iam_group_membership" "team3" {
  name = "tf-testing-group-membership"

  users = [
  ]

  group = aws_iam_group.group3.name
}

resource "aws_iam_group" "group3" {
  name = "test-group"
}

```
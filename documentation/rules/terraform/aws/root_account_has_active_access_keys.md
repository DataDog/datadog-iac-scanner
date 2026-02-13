---
title: "Root account has active access keys"
group_id: "Terraform / AWS"
meta:
  name: "aws/root_account_has_active_access_keys"
  id: "970d224d-b42a-416b-81f9-8f4dfe70c4bc"
  display_name: "Root account has active access keys"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `970d224d-b42a-416b-81f9-8f4dfe70c4bc`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_access_key)

### Description

 The AWS root account has unrestricted access to all resources in an AWS account, making it a high-value target for attackers. Having active access keys for the root account creates a significant security risk, as compromised keys could lead to complete account takeover and unauthorized access to all AWS services and resources. Best security practice requires using IAM users with appropriate permissions instead of the root account for daily operations and programmatic access.

Insecure example:
```terraform
resource "aws_iam_access_key" "positive1" {
  user    = "root"
  pgp_key = "keybase:some_person_that_exists"
}
```

Secure example:
```terraform
resource "aws_iam_access_key" "negative1" {
  user    = aws_iam_user.lb.name
  pgp_key = "keybase:some_person_that_exists"
}
```


## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "aws_iam_access_key" "negative1" {
  user    = aws_iam_user.lb.name
  pgp_key = "keybase:some_person_that_exists"
}

resource "aws_iam_user" "negative2" {
  name = "loadbalancer"
  path = "/system/"
}

resource "aws_iam_user_policy" "negative3" {
  name = "test"
  user = aws_iam_user.lb.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

output "secret" {
  value = aws_iam_access_key.lb.encrypted_secret
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_access_key" "positive2" {
  user    = "root"
  pgp_key = "keybase:some_person_that_exists"
  status = "Active"
}

resource "aws_iam_user" "lb" {
  name = "loadbalancer"
  path = "/system/"
}

resource "aws_iam_user_policy" "positive5" {
  name = "test"
  user = aws_iam_user.lb.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

output "secret" {
  value = aws_iam_access_key.lb.encrypted_secret
}

```

```terraform
#this is a problematic code where the query should report a result(s)
resource "aws_iam_access_key" "positive1" {
  user    = "root"
  pgp_key = "keybase:some_person_that_exists"
}

resource "aws_iam_user" "positive3" {
  name = "loadbalancer"
  path = "/system/"
}

resource "aws_iam_user_policy" "positive4" {
  name = "test"
  user = aws_iam_user.lb.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

output "secret" {
  value = aws_iam_access_key.lb.encrypted_secret
}

```
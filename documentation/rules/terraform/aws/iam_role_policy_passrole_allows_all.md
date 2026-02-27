---
title: "IAM role policy passrole allows all"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_role_policy_passrole_allows_all"
  id: "e39bee8c-fe54-4a3f-824d-e5e2d1cca40a"
  display_name: "IAM role policy passrole allows all"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `e39bee8c-fe54-4a3f-824d-e5e2d1cca40a`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html#access-analyzer-reference-policy-checks-security-warning-pass-role-with-star-in-resource)

### Description

Granting the `iam:passrole` action with a resource value of `"*"` in Terraform (`"Resource": "*"`) is overly permissive, as it allows the user or role to pass any IAM role in the account to AWS services. This broad permission can lead to privilege escalation, enabling attackers or unauthorized users to assume highly-privileged roles they should not have access to. To mitigate this risk, the resource should be scoped to specific role ARNs (for example, `"Resource": "arn:aws:iam::account-id:role/RoleName"`) to enforce the principle of least privilege.

## Compliant Code Examples
```terraform
resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "iam:passrole"
        ],
        "Effect": "Allow",
        "Resource": "arn:aws:sqs:us-east-2:account-ID-without-hyphens:queue1"
      }
    ]
  }
  EOF
}


```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "iam:passrole"
        ],
        "Effect": "Allow",
        "Resource": "*"
      }
    ]
  }
  EOF
}




```
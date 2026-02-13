---
title: "Authentication without MFA"
group_id: "Terraform / AWS"
meta:
  name: "aws/authentication_without_mfa"
  id: "3ddfa124-6407-4845-a501-179f90c65097"
  display_name: "Authentication without MFA"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `3ddfa124-6407-4845-a501-179f90c65097`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user_policy)

### Description

 Requiring users to authenticate using Multi-Factor Authentication (MFA) provides an extra layer of security beyond just a password, reducing the risk of unauthorized access if credentials are compromised. In Terraform, this can be enforced by using an IAM policy with a condition such as `"aws:MultiFactorAuthPresent": "true"`, which restricts permissions such as `sts:AssumeRole` to only those sessions where MFA has been verified. Without this condition, as shown in the following policy snippet, the user may be able to access sensitive AWS resources without MFA: 

```
"Condition": {
  "BoolIfExists": {
    "aws:MultiFactorAuthPresent": "false"
  }
}
```

If left unaddressed, this misconfiguration could allow attackers with access to the user's credentials to escalate privileges or access critical resources without needing a second authentication factor, significantly increasing the risk of account compromise or data breach.


## Compliant Code Examples
```terraform
provider "aws" {
  region  = "us-east-1"
}

resource "aws_iam_user" "negative1" {
  name = "aws-foundations-benchmark-1-4-0-terraform-user"
  path = "/"
}

resource "aws_iam_user_login_profile" "negative1" {
  user = aws_iam_user.negative1.name
  pgp_key = "gpgkeybase64gpgkeybase64gpgkeybase64gpgkeybase64"
}

resource "aws_iam_access_key" "negative1" {
  user = aws_iam_user.negative1.name
}

resource "aws_iam_user_policy" "negative1" {
  name = "aws-foundations-benchmark-1-4-0-terraform-user"
  user = aws_iam_user.negative1.name

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
     {
       "Effect": "Allow",
       "Resource": ${aws_iam_user.negative1.arn},
       "Action": "sts:AssumeRole",
       "Condition": {
         "BoolIfExists": {
           "aws:MultiFactorAuthPresent" : "true"
         }
       }
     }
   ]
}
EOF
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region  = "us-east-1"
}

resource "aws_iam_user" "positive1" {
  name = "aws-foundations-benchmark-1-4-0-terraform-user"
  path = "/"
}

resource "aws_iam_user_login_profile" "positive2" {
  user = aws_iam_user.positive2.name
  pgp_key = "gpgkeybase64gpgkeybase64gpgkeybase64gpgkeybase64"
}

resource "aws_iam_user_policy" "positive2" {
  name = "aws-foundations-benchmark-1-4-0-terraform-user"
  user = aws_iam_user.positive2.name

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
     {
       "Effect": "Allow",
       "Resource": "${aws_iam_user.positive2.arn}",
       "Action": "sts:AssumeRole"
     }
   ]
}
EOF
}

```

```terraform
provider "aws" {
  region  = "us-east-1"
}

resource "aws_iam_user" "positive1" {
  name = "aws-foundations-benchmark-1-4-0-terraform-user"
  path = "/"
}

resource "aws_iam_user_login_profile" "positive1" {
  user = aws_iam_user.positive1.name
  pgp_key = "gpgkeybase64gpgkeybase64gpgkeybase64gpgkeybase64"
}

resource "aws_iam_access_key" "positive1" {
  user = aws_iam_user.positive1.name
}

resource "aws_iam_user_policy" "positive1" {
  name = "aws-foundations-benchmark-1-4-0-terraform-user"
  user = aws_iam_user.positive1.name

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
     {
       "Effect": "Allow",
       "Resource": "${aws_iam_user.positive1.arn}",
       "Action": "sts:AssumeRole",
       "Condition": {
         "BoolIfExists": {
           "aws:MultiFactorAuthPresent" : "false"
         }
       }
     }
   ]
}
EOF
}

```
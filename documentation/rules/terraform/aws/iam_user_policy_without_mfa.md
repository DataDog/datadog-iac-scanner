---
title: "IAM user policy without MFA"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_user_policy_without_mfa"
  id: "b5681959-6c09-4f55-b42b-c40fa12d03ec"
  display_name: "IAM user policy without MFA"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `b5681959-6c09-4f55-b42b-c40fa12d03ec`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html)

### Description

This check verifies that the AWS root user is required to authenticate using Multi-Factor Authentication (MFA). If the root user is not protected with MFA, as in a policy lacking a condition on `"aws:MultiFactorAuthPresent"`, unauthorized users with access to the root credentials could compromise the entire AWS account. Enforcing MFA by adding a policy condition, such as the following, significantly reduces the risk of credential theft, unauthorized privilege escalation, and account takeovers.

```
"Condition": {
  "BoolIfExists": {
    "aws:MultiFactorAuthPresent": "true"
  }
}
```

## Compliant Code Examples
```terraform
resource "aws_iam_user" "negative1" {
  name = "root"
  path = "/system/"

  tags = {
    tag-key = "tag-value"
  }
}

resource "aws_iam_access_key" "negative2" {
  user = aws_iam_user.lb.name
}

resource "aws_iam_user_policy" "negative3" {
  name = "test"
  user = aws_iam_user.lb.name

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": {
         "AWS": "arn:aws:iam::111122223333:root"
       },
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

resource "aws_iam_user_policy" "negative4" {
  name = "test"
  user = aws_iam_user.lb.name

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": {
         "AWS": "arn:aws:iam::mfa/111122223333:root"
       },
       "Action": "sts:AssumeRole"
     }
   ]
}
EOF
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_user" "positive1" {
  name = "root"
  path = "/system/"

  tags = {
    tag-key = "tag-value"
  }
}

resource "aws_iam_access_key" "positive2" {
  user = aws_iam_user.lb.name
}

resource "aws_iam_user_policy" "positive3" {
  name = "test"
  user = aws_iam_user.lb.name

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": {
         "AWS": "arn:aws:iam::111122223333:root"
       },
       "Action": "sts:AssumeRole"
     }
   ]
}
EOF
}
```
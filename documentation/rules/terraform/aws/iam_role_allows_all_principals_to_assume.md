---
title: "IAM role allows all principals to assume"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_role_allows_all_principals_to_assume"
  id: "12b7e704-37f0-4d1e-911a-44bf60c48c21"
  display_name: "IAM role allows all principals to assume"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `12b7e704-37f0-4d1e-911a-44bf60c48c21`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role)

### Description

 IAM roles should restrict which services or principals can assume them by using tightly scoped `assume_role_policy` statements. If an IAM role's `Principal` in the assume role policy allows all services (for example, `"Principal": {"AWS": "arn:aws:iam::root"}`) or is overly broad, it can be assumed by unintended AWS accounts or resources, leading to privilege escalation or unauthorized actions in your environment. To mitigate this, always specify the minimum required services or principals in the `assume_role_policy`. For example, restrict access by defining `"Principal": {"Service": "ec2.amazonaws.com"}` instead of allowing `"arn:aws:iam::root"`. Leaving this unchecked could result in a critical security vulnerability where any AWS principal could leverage the role's permissions, increasing the risk of data exposure or account compromise.


## Compliant Code Examples
```terraform
//  Create a role which OpenShift instances will assume.
//  This role has a policy saying it can be assumed by ec2
//  instances.
resource "aws_iam_role" "negative1" {
  name = "${var.name_tag_prefix}-openshift-instance-role"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

//  This policy allows an instance to forward logs to CloudWatch, and
//  create the Log Stream or Log Group if it doesn't exist.
resource "aws_iam_policy" "negative2" {
  name        = "${var.name_tag_prefix}-openshift-instance-forward-logs"
  path        = "/"
  description = "Allows an instance to forward logs to CloudWatch"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Principal": {
        "AWS": "arn:aws:iam::some_role"
      },
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
    ],
      "Resource": [
        "arn:aws:iam::*:*:*"
    ]
  }
 ]
}
EOF
}


//  Attach the policies to the role.
resource "aws_iam_policy_attachment" "negative3" {
  name       = "${var.name_tag_prefix}-openshift-attachment-forward-logs"
  roles      = ["${aws_iam_role.openshift-instance-role.name}"]
  policy_arn = "${aws_iam_policy.openshift-policy-forward-logs.arn}"
}

//  Create a instance profile for the role.
resource "aws_iam_instance_profile" "negative4" {
  name  = "${var.name_tag_prefix}-openshift-instance-profile"
  role = "${aws_iam_role.openshift-instance-role.name}"
}

```
## Non-Compliant Code Examples
```terraform
//  Create a role which OpenShift instances will assume.
//  This role has a policy saying it can be assumed by ec2
//  instances.
resource "aws_iam_role" "positive1" {
  name = "${var.name_tag_prefix}-openshift-instance-role"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

//  This policy allows an instance to forward logs to CloudWatch, and
//  create the Log Stream or Log Group if it doesn't exist.
resource "aws_iam_role" "positive2" {
  name        = "${var.name_tag_prefix}-openshift-instance-forward-logs"
  path        = "/"
  description = "Allows an instance to forward logs to CloudWatch"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Principal": {
        "AWS": "arn:aws:iam::root"
      },
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
    ],
      "Resource": [
        "arn:aws:iam::*:*:*"
    ]
  }
 ]
}
EOF
}


//  Attach the policies to the role.
resource "aws_iam_policy_attachment" "positive3" {
  name       = "${var.name_tag_prefix}-openshift-attachment-forward-logs"
  roles      = ["${aws_iam_role.openshift-instance-role.name}"]
  policy_arn = "${aws_iam_policy.openshift-policy-forward-logs.arn}"
}

//  Create a instance profile for the role.
resource "aws_iam_instance_profile" "positive4" {
  name  = "${var.name_tag_prefix}-openshift-instance-profile"
  role = "${aws_iam_role.openshift-instance-role.name}"
}

```
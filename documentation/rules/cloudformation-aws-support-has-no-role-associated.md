---
title: "Support has no role associated"
group_id: "CloudFormation / AWS"
meta:
  name: ""aws/support_has_no_role_associated""
  id: "cloudformation-aws-support-has-no-role-associated"
  display_name: "Support has no role associated"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}cloudformation-aws-support-has-no-role-associated{{< /copyable-code >}}

**Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html)

### Description

IAM policies named `AWSSupportAccess` should be attached to explicit principals so support permissions are intentionally granted and controlled. An `AWS::IAM::Policy` with `PolicyName: "AWSSupportAccess"` that has no `Roles`, `Users`, or `Groups` defined is unmanaged or orphaned, which can lead to configuration drift or accidental future attachment that grants broad support privileges.

Check `AWS::IAM::Policy` resources where `PolicyName` equals `AWSSupportAccess` and ensure at least one of the `Roles`, `Users`, or `Groups` properties is present and contains one or more principals. Resources with these properties missing or empty will be flagged. Attach the policy to designated principals (for example, a support role) to make intent explicit and maintain least privilege.

Secure configuration example with a role attachment:

```yaml
MySupportPolicy:
  Type: AWS::IAM::Policy
  Properties:
    PolicyName: AWSSupportAccess
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action: "support:*"
          Resource: "*"
    Roles:
      - !Ref SupportRole
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  MyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: mygrouppolicy
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - s3:GetObject
              - s3:PutObject
              - s3:PutObjectAcl
            Resource: arn:aws:s3:::myAWSBucket/*
      Groups:
        - myexistinggroup1
        - !Ref mygroup

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "MyPolicy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "mygrouppolicy",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:PutObjectAcl"
              ],
              "Resource": "arn:aws:s3:::myAWSBucket/*",
              "Effect": "Allow"
            }
          ]
        },
        "Groups": [
          "myexistinggroup1",
          "mygroup"
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "noRoles": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "AWSSupportAccess",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "*"
              ],
              "Resource": "*"
            }
          ]
        },
        "Users": [
          "SomeUser"
        ],
        "Groups": [
          "SomeGroup"
        ]
      }
    },
    "noUsers": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "AWSSupportAccess",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "*"
              ],
              "Resource": "*"
            }
          ]
        },
        "Roles": [
          "SomeRole"
        ],
        "Groups": [
          "SomeGroup"
        ]
      }
    },
    "noGroups": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "AWSSupportAccess",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "*"
              ],
              "Resource": "*"
            }
          ]
        },
        "Roles": [
          "SomeRole"
        ],
        "Users": [
          "SomeUser"
        ]
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  noRoles:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: AWSSupportAccess
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Action: ["*"]
          Resource: "*"
      Users: ["SomeUser"]
      Groups: ["SomeGroup"]
  noUsers:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: AWSSupportAccess
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Action: ["*"]
          Resource: "*"
      Roles: ["SomeRole"]
      Groups: ["SomeGroup"]
  noGroups:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: AWSSupportAccess
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Action: ["*"]
          Resource: "*"
      Roles: ["SomeRole"]
      Users: ["SomeUser"]



```
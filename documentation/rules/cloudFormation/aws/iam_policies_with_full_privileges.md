---
title: "IAM policies with full privileges"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_policies_with_full_privileges"
  id: "953b3cdb-ce13-428a-aa12-318726506661"
  display_name: "IAM policies with full privileges"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `953b3cdb-ce13-428a-aa12-318726506661`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html)

### Description

 IAM policy statements that allow `Action: '*'` on `Resource: '*'` grant full administrative privileges across the account and enable privilege escalation, data exfiltration, and account takeover. This rule checks `AWS::IAM::Policy` resources' `Properties.PolicyDocument.Statement` entries and flags statements where `Effect` is `Allow` and both `Action` and `Resource` are the wildcard `'*'` (either as a single string or contained in an array). Replace full wildcards with explicit action lists and scoped resource ARNs, or apply IAM condition keys to restrict the policy to the minimum required scope. Statements that do not include both wildcards will not be flagged. 
 
 Secure example limiting S3 access to a single bucket:

```yaml
MyS3Policy:
  Type: AWS::IAM::Policy
  Properties:
    PolicyName: ReadOnlyS3
    PolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Action:
            - s3:GetObject
            - s3:ListBucket
          Resource:
            - arn:aws:s3:::my-bucket
            - arn:aws:s3:::my-bucket/*
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
      "Properties": {
        "PolicyName": "mygrouppolicy",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:PutObjectAcl"
              ],
              "Resource": "arn:aws:s3:::myAWSBucket/*"
            }
          ]
        },
        "Groups": [
          "myexistinggroup1",
          "mygroup"
        ]
      },
      "Type": "AWS::IAM::Policy"
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
    "mypolicy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "mygrouppolicy",
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
        "Groups": [
          "myexistinggroup1",
          "mygroup"
        ]
      }
    },
    "mypolicy2": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "mygrouppolicy",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"
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

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  mypolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: mygrouppolicy
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Action: ["*"]
          Resource: "*"
      Groups:
      - myexistinggroup1
      - !Ref mygroup
  mypolicy2:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: mygrouppolicy
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Action: "*"
          Resource: "*"
      Groups:
      - myexistinggroup1
      - !Ref mygroup




```
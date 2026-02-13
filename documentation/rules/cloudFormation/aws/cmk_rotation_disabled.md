---
title: "CMK rotation disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cmk_rotation_disabled"
  id: "1c07bfaf-663c-4f6f-b22b-8e2d481e4df5"
  display_name: "CMK rotation disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `1c07bfaf-663c-4f6f-b22b-8e2d481e4df5`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html)

### Description

 AWS KMS Customer Master Keys (CMKs) must have automatic key rotation enabled to limit the exposure of long-lived cryptographic keys and reduce the impact if a key is compromised.

 This rule applies to `AWS::KMS::Key` resources that are enabled (`Properties.Enabled` set to `true`) and not pending deletion. Such keys must define `Properties.EnableKeyRotation` set to `true`. Resources missing `EnableKeyRotation` or with `EnableKeyRotation` set to `false` will be flagged. Keys that have `Properties.PendingWindowInDays` defined (indicating pending deletion) are excluded from this requirement.

Secure configuration example:

```yaml
MyKey:
  Type: AWS::KMS::Key
  Properties:
    Enabled: true
    EnableKeyRotation: true
```


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
Resources:
  myKey:
    Type: AWS::KMS::Key
    Properties:
      Enabled: true
      EnableKeyRotation: true
      KeyPolicy:
        Version: '2012-10-17'
        Id: key-default-1
        Statement:
        - Sid: Enable IAM User Permissions
          Effect: Allow
          Principal:
            AWS:
              Fn::Join:
              - ''
              - - 'arn:aws:iam::'
                - Ref: AWS::AccountId
                - :root
          Action: kms:*
          Resource: '*'
      Tags:
      - Key:
          Ref: Key
        Value:
          Ref: Value
Parameters:
  Key:
    Type: String
  Value:
    Type: String
```

```json
{
  "Resources": {
    "myKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Enabled": true,
        "EnableKeyRotation": true,
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Id": "key-default-1",
          "Statement": [
            {
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": {
                  "Fn::Join": [
                    "",
                    [
                      "arn:aws:iam::",
                      {
                        "Ref": "AWS::AccountId"
                      },
                      ":root"
                    ]
                  ]
                }
              },
              "Action": "kms:*",
              "Resource": "*"
            }
          ]
        },
        "Tags": [
          {
            "Key": {
              "Ref": "Key"
            },
            "Value": {
              "Ref": "Value"
            }
          }
        ]
      }
    }
  },
  "Parameters": {
    "Key": {
      "Type": "String"
    },
    "Value": {
      "Type": "String"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "myKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Enabled": true,
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Id": "key-default-1",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": {
                  "Fn::Join": [
                    "",
                    [
                      "arn:aws:iam::",
                      {
                        "Ref": "AWS::AccountId"
                      },
                      ":root"
                    ]
                  ]
                }
              },
              "Action": "kms:*",
              "Resource": "*",
              "Sid": "Enable IAM User Permissions"
            }
          ]
        },
        "Tags": [
          {
            "Key": {
              "Ref": "Key"
            },
            "Value": {
              "Ref": "Value"
            }
          }
        ]
      }
    },
    "myKey2": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Enabled": true,
        "EnableKeyRotation": false,
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Id": "key-default-1",
          "Statement": [
            {
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": {
                  "Fn::Join": [
                    "",
                    [
                      "arn:aws:iam::",
                      {
                        "Ref": "AWS::AccountId"
                      },
                      ":root"
                    ]
                  ]
                }
              },
              "Action": "kms:*",
              "Resource": "*"
            }
          ]
        },
        "Tags": [
          {
            "Key": {
              "Ref": "Key"
            },
            "Value": {
              "Ref": "Value"
            }
          }
        ]
      }
    }
  },
  "Parameters": {
    "Key": {
      "Type": "String"
    },
    "Value": {
      "Type": "String"
    }
  }
}

```

```yaml
#this is a problematic code where the query should report a result(s)
Resources:
  myKey:
    Type: AWS::KMS::Key
    Properties:
      Enabled: true
      KeyPolicy:
        Version: '2012-10-17'
        Id: key-default-1
        Statement:
        - Sid: Enable IAM User Permissions
          Effect: Allow
          Principal:
            AWS:
              Fn::Join:
              - ''
              - - 'arn:aws:iam::'
                - Ref: AWS::AccountId
                - :root
          Action: kms:*
          Resource: '*'
      Tags:
      - Key:
          Ref: Key
        Value:
          Ref: Value
  myKey2:
    Type: AWS::KMS::Key
    Properties:
      Enabled: true
      EnableKeyRotation: false
      KeyPolicy:
        Version: '2012-10-17'
        Id: key-default-1
        Statement:
        - Sid: Enable IAM User Permissions
          Effect: Allow
          Principal:
            AWS:
              Fn::Join:
              - ''
              - - 'arn:aws:iam::'
                - Ref: AWS::AccountId
                - :root
          Action: kms:*
          Resource: '*'
      Tags:
      - Key:
          Ref: Key
        Value:
          Ref: Value
Parameters:
  Key:
    Type: String
  Value:
    Type: String
```
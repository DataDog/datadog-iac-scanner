---
title: "SQS policy with public access"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/sqs_policy_with_public_access"
  id: "9b6a3f5b-5fd6-40ee-9bc0-ed604911212d"
  display_name: "SQS policy with public access"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `9b6a3f5b-5fd6-40ee-9bc0-ed604911212d`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-policy.html)

### Description

 Allowing sensitive SQS management actions to wildcard principals lets any actor modify, delete, or change permissions on queues. This can enable resource takeover, data loss, or privilege escalation.

This rule inspects `AWS::SQS::QueuePolicy` resources and flags `PolicyDocument.Statement` entries where `Effect: "Allow"` and `Action` contains any of `SQS:AddPermission`, `SQS:CreateQueue`, `SQS:DeleteQueue`, `SQS:RemovePermission`, `SQS:TagQueue`, or `SQS:UnTagQueue`, if the `Principal` includes a wildcard (for example, `*` or patterns like `arn:aws:iam::*`). Statements that include a restrictive `Condition` are excluded from this flag. 

To remediate, specify explicit principals (account ARNs or role ARNs) or add tight conditions (for example, `aws:SourceAccount`) to limit who can perform these actions.

Secure configuration example with an explicit principal:

```yaml
MyQueuePolicy:
  Type: AWS::SQS::QueuePolicy
  Properties:
    PolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Sid: AllowSpecificAccountManageQueue
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:root
          Action:
            - SQS:RemovePermission
            - SQS:TagQueue
          Resource: arn:aws:sqs:us-east-1:123456789012:my-queue
```


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
Resources:
  SampleSQSPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - "https://sqs:us-east-2.amazonaws.com/444455556666/queue2"
      PolicyDocument:
        Statement:
          -
            Action:
              - "SQS:SendMessage"
              - "SQS:ReceiveMessage"
            Effect: "Allow"
            Resource: "arn:aws:sqs:us-east-2:444455556666:queue2"
            Principal:
              AWS:
                - "111122223333"
                - "*"

```

```json
{
  "Resources": {
    "SampleSQSPolicy3": {
      "Properties": {
        "Queues": [
          "https://sqs:us-east-2.amazonaws.com/444455556666/queue2"
        ],
        "PolicyDocument": {
          "Statement": [
            {
              "Action": [
                "SQS:SendMessage",
                "SQS:CreateQueue"
              ],
              "Effect": "Deny",
              "Resource": "arn:aws:sqs:us-east-2:444455556666:queue2",
              "Principal": {
                "AWS": [
                  "111122223333",
                  "*"
                ]
              }
            }
          ]
        }
      },
      "Type": "AWS::SQS::QueuePolicy"
    }
  }
}

```

```json
{
  "Resources": {
    "SampleSQSPolicy2": {
      "Type": "AWS::SQS::QueuePolicy",
      "Properties": {
        "Queues": [
          "https://sqs:us-east-2.amazonaws.com/444455556666/queue2"
        ],
        "PolicyDocument": {
          "Statement": [
            {
              "Action": [
                "SQS:SendMessage",
                "SQS:CreateQueue"
              ],
              "Effect": "Allow",
              "Resource": "arn:aws:sqs:us-east-2:444455556666:queue2",
              "Principal": {
                "AWS": [
                  "111122223333"
                ]
              }
            }
          ]
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
Resources:
  SampleSQSPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - "https://sqs:us-east-2.amazonaws.com/444455556666/queue2"
      PolicyDocument:
        Statement:
          -
            Action:
              - "SQS:SendMessage"
              - "SQS:AddPermission"
            Effect: "Allow"
            Resource: "arn:aws:sqs:us-east-2:444455556666:queue2"
            Principal:
              AWS:
                - "111122223333"
                - "arn:aws:iam::437628376:*"

```

```json
{
  "Resources": {
    "SampleSQSPolicy": {
      "Type": "AWS::SQS::QueuePolicy",
      "Properties": {
        "Queues": [
          "https://sqs:us-east-2.amazonaws.com/444455556666/queue2"
        ],
        "PolicyDocument": {
          "Statement": [
            {
              "Action": [
                "SQS:SendMessage",
                "SQS:CreateQueue"
              ],
              "Effect": "Allow",
              "Resource": "arn:aws:sqs:us-east-2:444455556666:queue2",
              "Principal": {
                "AWS": [
                  "111122223333",
                  "*"
                ]
              }
            }
          ]
        }
      }
    }
  }
}

```

```json
{
  "Resources": {
    "SampleSQSPolicy": {
      "Type": "AWS::SQS::QueuePolicy",
      "Properties": {
        "Queues": [
          "https://sqs:us-east-2.amazonaws.com/444455556666/queue2"
        ],
        "PolicyDocument": {
          "Statement": [
            {
              "Principal": {
                "AWS": [
                  "111122223333",
                  "arn:aws:iam::437628376:*"
                ]
              },
              "Action": [
                "SQS:SendMessage",
                "SQS:AddPermission"
              ],
              "Effect": "Allow",
              "Resource": "arn:aws:sqs:us-east-2:444455556666:queue2"
            }
          ]
        }
      }
    }
  }
}

```
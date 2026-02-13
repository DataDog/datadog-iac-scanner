---
title: "DynamoDB with AWS-owned CMK"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/dynamodb_with_aws_owned_cmk"
  id: "c8dee387-a2e6-4a73-a942-183c975549ac"
  display_name: "DynamoDB with AWS-owned CMK"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `c8dee387-a2e6-4a73-a942-183c975549ac`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dynamodb-table-ssespecification.html)

### Description

DynamoDB tables must use AWS KMS-managed encryption rather than the default AWS-owned key so you can control key lifecycle, rotation, and access auditing. Relying on the AWS-owned key can limit your ability to revoke or monitor key use.
 
 In CloudFormation, ensure `AWS::DynamoDB::Table` resources include the `SSESpecification` property with `SSEType` set to `KMS` and `SSEEnabled` set to `true`. Resources missing `SSESpecification` or `SSEEnabled`, or with `SSEEnabled` set to `false` while `SSEType` is `KMS`, will be flagged.
 
 If you want the AWS-managed service key, set `SSEType` to `KMS`, set `SSEEnabled` to `true`, and omit `KMSMasterKeyId`. To use a customer-managed CMK, also set `KMSMasterKeyId` to the CMK ARN or alias.

Secure configuration example:

```yaml
MyDynamoTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: my-table
    AttributeDefinitions:
      - AttributeName: id
        AttributeType: S
    KeySchema:
      - AttributeName: id
        KeyType: HASH
    SSESpecification:
      SSEEnabled: true
      SSEType: KMS
      # Optional: specify a customer-managed CMK
      # KMSMasterKeyId: arn:aws:kms:region:account-id:key/key-id
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Sample CloudFormation template for DynamoDB with customer managed CMK
Resources:
  dynamodbKMSKey:
    Type: AWS::KMS::Key
    Properties:
      Description: "An example CMK"
      KeyPolicy:
        Version: "2012-10-17"
        Id: "key-default-1"
        Statement:
          - Sid: "Allow administration of the key"
            Effect: "Allow"
            Principal:
              AWS: "arn:aws:iam::123456789012:user/ana"
            Action:
              - "kms:Create*"
              - "kms:Describe*"
              - "kms:Enable*"
              - "kms:List*"
              - "kms:Put*"
              - "kms:Update*"
              - "kms:Revoke*"
              - "kms:Disable*"
              - "kms:Get*"
              - "kms:Delete*"
              - "kms:ScheduleKeyDeletion"
              - "kms:CancelKeyDeletion"
            Resource: "*"
          - Sid: "Allow use of the key"
            Effect: "Allow"
            Principal:
              AWS: "arn:aws:iam::123456789012:user/ana"
            Action:
              - "kms:DescribeKey"
              - "kms:Encrypt"
              - "kms:Decrypt"
              - "kms:ReEncrypt*"
              - "kms:GenerateDataKey"
              - "kms:GenerateDataKeyWithoutPlaintext"
            Resource: "*"

  DynamoDBOnDemandTable1:
    Type: "AWS::DynamoDB::Table"
    Properties:
      TableName: "dynamodb-kms"
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST
      SSESpecification:
        KMSMasterKeyId: !Ref dynamodbKMSKey
        SSEEnabled: true
        SSEType: "KMS"

```

```json
{
  "Resources": {
    "dynamodbKMSKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "An example CMK",
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Id": "key-default-1",
          "Statement": [
            {
              "Sid": "Allow administration of the key",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/ana"
              },
              "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
              ],
              "Resource": "*"
            },
            {
              "Sid": "Allow use of the key",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/ana"
              },
              "Action": [
                "kms:DescribeKey",
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyWithoutPlaintext"
              ],
              "Resource": "*"
            }
          ]
        }
      }
    },
    "DynamoDBOnDemandTable1": {
      "Type": "AWS::DynamoDB::Table",
      "Properties": {
        "BillingMode": "PAY_PER_REQUEST",
        "SSESpecification": {
          "KMSMasterKeyId": "dynamodbKMSKey",
          "SSEEnabled": true,
          "SSEType": "KMS"
        },
        "TableName": "dynamodb-kms",
        "AttributeDefinitions": [
          {
            "AttributeName": "pk",
            "AttributeType": "S"
          }
        ],
        "KeySchema": [
          {
            "AttributeName": "pk",
            "KeyType": "HASH"
          }
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Sample CloudFormation template for DynamoDB with customer managed CMK"
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-11"
Description: Sample CloudFormation template for DynamoDB with AWS-Owned CMK
Resources:
  DynamoDBOnDemandTable4:
    Type: "AWS::DynamoDB::Table"
    Properties:
      TableName: "dynamodb-kms-2"
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST
      SSESpecification:
        SSEType: "KMS"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Sample CloudFormation template for DynamoDB with AWS-Owned CMK",
  "Resources": {
    "DynamoDBOnDemandTable2": {
      "Type": "AWS::DynamoDB::Table",
      "Properties": {
        "TableName": "dynamodb-kms-0",
        "AttributeDefinitions": [
          {
            "AttributeName": "pk",
            "AttributeType": "S"
          }
        ],
        "KeySchema": [
          {
            "AttributeName": "pk",
            "KeyType": "HASH"
          }
        ],
        "BillingMode": "PAY_PER_REQUEST",
        "SSESpecification": {
          "SSEEnabled": false,
          "SSEType": "KMS"
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-10"
Description: Sample CloudFormation template for DynamoDB with AWS-Owned CMK
Resources:
  DynamoDBOnDemandTable5:
    Type: "AWS::DynamoDB::Table"
    Properties:
      TableName: "dynamodb-kms-3"
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST

```
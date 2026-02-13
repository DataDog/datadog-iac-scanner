---
title: "DynamoDB table point-in-time recovery disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/dynamodb_table_point_in_time_recovery_disabled"
  id: "0f04217d-488f-4e7a-bec8-f16159686cd6"
  display_name: "DynamoDB table point-in-time recovery disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `0f04217d-488f-4e7a-bec8-f16159686cd6`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dynamodb-table-pointintimerecoveryspecification.html)

### Description

 DynamoDB tables must have point-in-time recovery (PITR) enabled to allow restoration to a prior consistent state after accidental deletes, overwrites, or data corruption. Without PITR, you cannot restore to recent points in time, increasing the risk of permanent data loss and extended recovery time. Check `AWS::DynamoDB::Table` resources and ensure the `Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled` property is defined and set to `true`. Resources missing `PointInTimeRecoverySpecification`, missing the `PointInTimeRecoveryEnabled` field, or with `PointInTimeRecoveryEnabled` set to `false` will be flagged.

Secure configuration example:

```yaml
MyDynamoTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: MyTable
    AttributeDefinitions:
      - AttributeName: id
        AttributeType: S
    KeySchema:
      - AttributeName: id
        KeyType: HASH
    BillingMode: PAY_PER_REQUEST
    PointInTimeRecoverySpecification:
      PointInTimeRecoveryEnabled: true
```


## Compliant Code Examples
```yaml
Resources:
  MyDynamoDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      PointInTimeRecoverySpecification: 
        PointInTimeRecoveryEnabled: true

```

```json
{
  "Resources": {
    "DynamoDBOnDemandTable1": {
      "Type": "AWS::DynamoDB::Table",
      "Properties": {
        "BillingMode": "PAY_PER_REQUEST",
        "PointInTimeRecoverySpecification" : {
          "PointInTimeRecoveryEnabled" : true
        }
      }
    },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Sample CloudFormation template for DynamoDB with customer managed CMK"
  }
}

```
## Non-Compliant Code Examples
```yaml
Resources:
  MyDynamoDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: my-table

```

```json
{
  "Resources": {
    "DynamoDBOnDemandTable1": {
      "Type": "AWS::DynamoDB::Table",
      "Properties": {
        "BillingMode": "PAY_PER_REQUEST",
        "PointInTimeRecoverySpecification" : {
          "PointInTimeRecoveryEnabled" : false
        }
      }
    },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Sample CloudFormation template for DynamoDB with customer managed CMK"
  }
}

```

```yaml
Resources:
  MyDynamoDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      PointInTimeRecoverySpecification: {}
```
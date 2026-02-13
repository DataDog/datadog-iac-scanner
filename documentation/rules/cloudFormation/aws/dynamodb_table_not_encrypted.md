---
title: "DynamoDB table not encrypted"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/dynamodb_table_not_encrypted"
  id: "4bd21e68-38c1-4d58-acdc-6a14b203237f"
  display_name: "DynamoDB table not encrypted"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `4bd21e68-38c1-4d58-acdc-6a14b203237f`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dynamodb-table-ssespecification.html)

### Description

 DynamoDB tables must have server-side encryption enabled to protect data at rest and prevent unauthorized access to table contents, backups, and snapshots. In CloudFormation, the `AWS::DynamoDB::Table` resource must set `Properties.SSESpecification.SSEEnabled` to `true`. Resources that omit `SSESpecification.SSEEnabled` or have `SSEEnabled` set to `false` will be flagged.

Secure configuration example:

```yaml
MyDynamoTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: my-table
    SSESpecification:
      SSEEnabled: true
      SSEType: AES256
```


## Compliant Code Examples
```yaml
Resources:
  MyDynamoDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: my-table
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: N
        - AttributeName: name
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH
      ProvisionedThroughput:
        ReadCapacityUnits: 5
        WriteCapacityUnits: 5
      SSESpecification:
        SSEEnabled: true

```
## Non-Compliant Code Examples
```yaml
Resources:
  MyDynamoDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: my-table
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: N
        - AttributeName: name
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH
      ProvisionedThroughput:
        ReadCapacityUnits: 5
        WriteCapacityUnits: 5
      SSESpecification:
        SSEType: KMS
```

```yaml
Resources:
  MyDynamoDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: my-table
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: N
        - AttributeName: name
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH
      ProvisionedThroughput:
        ReadCapacityUnits: 5
        WriteCapacityUnits: 5
      SSESpecification:
        SSEEnabled: false

```
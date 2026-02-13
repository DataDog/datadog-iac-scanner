---
title: "DynamoDB with non-recommended table billing mode"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/dynamodb_with_table_billing_mode_not_recommended"
  id: "c333e906-8d8b-4275-b999-78b6318f8dc6"
  display_name: "DynamoDB with non-recommended table billing mode"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `c333e906-8d8b-4275-b999-78b6318f8dc6`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html#cfn-dynamodb-table-attributedef)

### Description

 DynamoDB tables must explicitly specify a valid billing mode to ensure predictable capacity behavior and to avoid deploying tables with undefined or unexpected throughput that can impact availability. In CloudFormation, the `BillingMode` property on `AWS::DynamoDB::Table` must be set to either `PROVISIONED` or `PAY_PER_REQUEST`. Resources missing the `BillingMode` property or using any other value will be flagged. If you choose `PROVISIONED`, also configure appropriate provisioned throughput or auto-scaling. If you choose `PAY_PER_REQUEST`, do not define `ProvisionedThroughput`.

Secure example using on-demand (PAY_PER_REQUEST):

```yaml
MyDynamoTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: my-table
    BillingMode: PAY_PER_REQUEST
```

Secure example using provisioned capacity:

```yaml
MyDynamoTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: my-table
    BillingMode: PROVISIONED
    ProvisionedThroughput:
      ReadCapacityUnits: 5
      WriteCapacityUnits: 5
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  myDynamoDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      AttributeDefinitions:
        -
          AttributeName: "Album"
          AttributeType: "S"
        -
          AttributeName: "Artist"
          AttributeType: "S"
      KeySchema:
        -
          AttributeName: "Album"
          KeyType: "HASH"
        -
          AttributeName: "Artist"
          KeyType: "RANGE"
      ProvisionedThroughput:
        ReadCapacityUnits: "5"
        WriteCapacityUnits: "5"
      TableName: "myTableName"
  myDynamoDBTable2:
    Type: AWS::DynamoDB::Table
    Properties:
      AttributeDefinitions:
        -
          AttributeName: "Album"
          AttributeType: "S"
        -
          AttributeName: "Artist"
          AttributeType: "S"
      BillingMode: "PAY_PER_REQUEST"
      KeySchema:
        -
          AttributeName: "Album"
          KeyType: "HASH"
        -
          AttributeName: "Artist"
          KeyType: "RANGE"
      TableName: "myTableName"
  myDynamoDBTable3:
    Type: AWS::DynamoDB::Table
    Properties:
      AttributeDefinitions:
        -
          AttributeName: "Album"
          AttributeType: "S"
        -
          AttributeName: "Artist"
          AttributeType: "S"
      BillingMode: "PROVISIONED"
      KeySchema:
        -
          AttributeName: "Album"
          KeyType: "HASH"
        -
          AttributeName: "Artist"
          KeyType: "RANGE"
      ProvisionedThroughput:
        ReadCapacityUnits: "5"
        WriteCapacityUnits: "5"
      TableName: "myTableName"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myDynamoDBTable": {
      "Type": "AWS::DynamoDB::Table",
      "Properties": {
        "TableName": "myTableName",
        "AttributeDefinitions": [
          {
            "AttributeName": "Album",
            "AttributeType": "S"
          },
          {
            "AttributeType": "S",
            "AttributeName": "Artist"
          }
        ],
        "KeySchema": [
          {
            "AttributeName": "Album",
            "KeyType": "HASH"
          },
          {
            "AttributeName": "Artist",
            "KeyType": "RANGE"
          }
        ],
        "ProvisionedThroughput": {
          "ReadCapacityUnits": "5",
          "WriteCapacityUnits": "5"
        }
      }
    },
    "myDynamoDBTable2": {
      "Type": "AWS::DynamoDB::Table",
      "Properties": {
        "TableName": "myTableName",
        "AttributeDefinitions": [
          {
            "AttributeType": "S",
            "AttributeName": "Album"
          },
          {
            "AttributeName": "Artist",
            "AttributeType": "S"
          }
        ],
        "BillingMode": "PAY_PER_REQUEST",
        "KeySchema": [
          {
            "AttributeName": "Album",
            "KeyType": "HASH"
          },
          {
            "AttributeName": "Artist",
            "KeyType": "RANGE"
          }
        ]
      }
    },
    "myDynamoDBTable3": {
      "Type": "AWS::DynamoDB::Table",
      "Properties": {
        "AttributeDefinitions": [
          {
            "AttributeName": "Album",
            "AttributeType": "S"
          },
          {
            "AttributeName": "Artist",
            "AttributeType": "S"
          }
        ],
        "BillingMode": "PROVISIONED",
        "KeySchema": [
          {
            "KeyType": "HASH",
            "AttributeName": "Album"
          },
          {
            "AttributeName": "Artist",
            "KeyType": "RANGE"
          }
        ],
        "ProvisionedThroughput": {
          "ReadCapacityUnits": "5",
          "WriteCapacityUnits": "5"
        },
        "TableName": "myTableName"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "myDynamoDBTable": {
      "Type": "AWS::DynamoDB::Table",
      "Properties": {
        "AttributeDefinitions": [
          {
            "AttributeName": "Album",
            "AttributeType": "S"
          },
          {
            "AttributeName": "Artist",
            "AttributeType": "S"
          }
        ],
        "BillingMode": "PayPal",
        "KeySchema": [
          {
            "AttributeName": "Album",
            "KeyType": "HASH"
          },
          {
            "AttributeName": "Artist",
            "KeyType": "RANGE"
          }
        ],
        "TableName": "myTableName"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  myDynamoDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      AttributeDefinitions:
        -
          AttributeName: "Album"
          AttributeType: "S"
        -
          AttributeName: "Artist"
          AttributeType: "S"
      BillingMode: "PayPal"
      KeySchema:
        -
          AttributeName: "Album"
          KeyType: "HASH"
        -
          AttributeName: "Artist"
          KeyType: "RANGE"
      TableName: "myTableName"

```
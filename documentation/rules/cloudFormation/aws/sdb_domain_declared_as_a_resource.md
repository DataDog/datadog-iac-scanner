---
title: "SDB domain declared as a resource"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/sdb_domain_declared_as_a_resource"
  id: "6ea57c8b-f9c0-4ec7-bae3-bd75a9dee27d"
  display_name: "SDB domain declared as a resource"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `6ea57c8b-f9c0-4ec7-bae3-bd75a9dee27d`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-simpledb.html)

### Description

Declaring an AWS SimpleDB domain is discouraged because SimpleDB is a legacy service that lacks many modern security and operational controls. This increases the risk of data exposure and creates maintenance and compliance challenges.

CloudFormation resources with `Type: "AWS::SDB::Domain"` must not be defined. Any resource of that type will be flagged by this rule. Use supported services such as Amazon DynamoDB, Amazon RDS, or Amazon S3 with server-side encryption and appropriate IAM controls as secure alternatives.

Secure alternative (DynamoDB instead of SimpleDB):

```yaml
MyTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: my-table
    AttributeDefinitions:
      - AttributeName: id
        AttributeType: S
    KeySchema:
      - AttributeName: id
        KeyType: HASH
    BillingMode: PAY_PER_REQUEST
    SSESpecification:
      SSEEnabled: true
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "SDB Domain declared"
Resources:
  HostedZone:
    Type: AWS::Route53::HostedZone
    Properties:
      Name: "HostedZone"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "SDB Domain declared",
  "Resources": {
    "HostedZone": {
      "Type": "AWS::Route53::HostedZone",
      "Properties": {
        "Name": "HostedZone"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "SDB Domain declared",
  "Resources": {
    "HostedZone": {
      "Type": "AWS::Route53::HostedZone",
      "Properties": {
        "Name": "HostedZone"
      }
    },
    "SBDDomain": {
      "Type": "AWS::SDB::Domain",
      "Properties": {
        "Description": "Some information"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "SDB Domain declared"
Resources:
  HostedZone:
    Type: AWS::Route53::HostedZone
    Properties:
      Name: "HostedZone"
  SBDDomain:
    Type: AWS::SDB::Domain
    Properties:
      Description: "Some information"

```
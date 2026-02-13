---
title: "RDS DB instance publicly accessible"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/rds_db_instance_publicly_accessible"
  id: "de38e1d5-54cb-4111-a868-6f7722695007"
  display_name: "RDS DB instance publicly accessible"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "CRITICAL"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `de38e1d5-54cb-4111-a868-6f7722695007`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Critical

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html)

### Description

 RDS DB instances must not be publicly accessible because exposing a database endpoint to the internet increases the attack surface and can enable unauthorized access, credential-guessing attacks, and data exfiltration. In AWS CloudFormation, the `PubliclyAccessible` property on `AWS::RDS::DBInstance` resources must be set to `false`. Resources with `PubliclyAccessible` set to `true` will be flagged. If the property is omitted, ensure the instance is deployed to private subnets and protected by restrictive security groups so it cannot receive a public IP or accept traffic from the internet.

Secure configuration example:

```yaml
MyDBInstance:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceIdentifier: my-db-instance
    Engine: postgres
    EngineVersion: '14.7'
    DBInstanceClass: db.t3.micro
    AllocatedStorage: 20
    MasterUsername: admin
    MasterUserPassword: !Ref DBPassword
    PubliclyAccessible: false
    DBSubnetGroupName: !Ref MyDBSubnetGroup
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: >-
  Description": "AWS CloudFormation Sample Template for creating an Amazon RDS DB instance:
  Sample template showing how to create a DB instance with Enhanced Monitoring enabled.
  **WARNING** This template creates an RDS DB instance. You will be billed for the AWS
  resources used if you create a stack from this template.
Parameters:
  DBInstanceID:
    Default: mydbinstance
    Description: My database instance
    Type: String
    MinLength: '1'
    MaxLength: '63'
    AllowedPattern: '[a-zA-Z][a-zA-Z0-9]*'
    ConstraintDescription: >-
      Must begin with a letter and must not end with a hyphen or contain two
      consecutive hyphens.
  DBName:
    Default: mydb
    Description: My database
    Type: String
    MinLength: '1'
    MaxLength: '64'
    AllowedPattern: '[a-zA-Z][a-zA-Z0-9]*'
    ConstraintDescription: Must begin with a letter and contain only alphanumeric characters.
  DBInstanceClass:
    Default: db.m5.large
    Description: DB instance class
    Type: String
    ConstraintDescription: Must select a valid DB instance type.
  DBAllocatedStorage:
    Default: '50'
    Description: The size of the database (GiB)
    Type: Number
    MinValue: '5'
    MaxValue: '1024'
    ConstraintDescription: must be between 20 and 65536 GiB.
  DBUsername:
    NoEcho: 'true'
    Description: Username for MySQL database access
    Type: String
    MinLength: '1'
    MaxLength: '16'
    AllowedPattern: '[a-zA-Z][a-zA-Z0-9]*'
    ConstraintDescription: must begin with a letter and contain only alphanumeric characters.
  DBPassword:
    NoEcho: 'true'
    Description: Password MySQL database access
    Type: String
    MinLength: '8'
    MaxLength: '41'
    AllowedPattern: '[a-zA-Z0-9]*'
    ConstraintDescription: must contain only alphanumeric characters.
Resources:
  MyDB:
    Type: 'AWS::RDS::DBInstance'
    Properties:
      DBInstanceIdentifier: !Ref DBInstanceID
      DBName: !Ref DBName
      DBInstanceClass: !Ref DBInstanceClass
      AllocatedStorage: !Ref DBAllocatedStorage
      Engine: MySQL
      EngineVersion: 8.0.16
      MasterUsername: !Ref DBUsername
      MasterUserPassword: !Ref DBPassword
      MonitoringInterval: '60'
      MonitoringRoleArn: 'arn:aws:iam::123456789012:role/rds-monitoring-role'
      PubliclyAccessible: false

```

```json
{
  "Resources": {
    "MyDB": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "AllocatedStorage": "DBAllocatedStorage",
        "EngineVersion": "8.0.16",
        "MasterUserPassword": "DBPassword",
        "MonitoringInterval": "60",
        "DBInstanceIdentifier": "DBInstanceID",
        "DBName": "DBName",
        "DBInstanceClass": "DBInstanceClass",
        "Engine": "MySQL",
        "MasterUsername": "DBUsername",
        "MonitoringRoleArn": "arn:aws:iam::123456789012:role/rds-monitoring-role",
        "PubliclyAccessible": false
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Description\": \"AWS CloudFormation Sample Template for creating an Amazon RDS DB instance: Sample template showing how to create a DB instance with Enhanced Monitoring enabled. **WARNING** This template creates an RDS DB instance. You will be billed for the AWS resources used if you create a stack from this template.",
  "Parameters": {
    "DBPassword": {
      "NoEcho": "true",
      "Description": "Password MySQL database access",
      "Type": "String",
      "MinLength": "8",
      "MaxLength": "41",
      "AllowedPattern": "[a-zA-Z0-9]*",
      "ConstraintDescription": "must contain only alphanumeric characters."
    },
    "DBInstanceID": {
      "MinLength": "1",
      "MaxLength": "63",
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*",
      "ConstraintDescription": "Must begin with a letter and must not end with a hyphen or contain two consecutive hyphens.",
      "Default": "mydbinstance",
      "Description": "My database instance",
      "Type": "String"
    },
    "DBName": {
      "Default": "mydb",
      "Description": "My database",
      "Type": "String",
      "MinLength": "1",
      "MaxLength": "64",
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*",
      "ConstraintDescription": "Must begin with a letter and contain only alphanumeric characters."
    },
    "DBInstanceClass": {
      "Default": "db.m5.large",
      "Description": "DB instance class",
      "Type": "String",
      "ConstraintDescription": "Must select a valid DB instance type."
    },
    "DBAllocatedStorage": {
      "Description": "The size of the database (GiB)",
      "Type": "Number",
      "MinValue": "5",
      "MaxValue": "1024",
      "ConstraintDescription": "must be between 20 and 65536 GiB.",
      "Default": "50"
    },
    "DBUsername": {
      "MinLength": "1",
      "MaxLength": "16",
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*",
      "ConstraintDescription": "must begin with a letter and contain only alphanumeric characters.",
      "NoEcho": "true",
      "Description": "Username for MySQL database access",
      "Type": "String"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Description": "Description\": \"AWS CloudFormation Sample Template for creating an Amazon RDS DB instance: Sample template showing how to create a DB instance with Enhanced Monitoring enabled. **WARNING** This template creates an RDS DB instance. You will be billed for the AWS resources used if you create a stack from this template.",
  "Parameters": {
    "DBInstanceClass": {
      "Description": "DB instance class",
      "Type": "String",
      "ConstraintDescription": "Must select a valid DB instance type.",
      "Default": "db.m5.large"
    },
    "DBAllocatedStorage": {
      "ConstraintDescription": "must be between 20 and 65536 GiB.",
      "Default": "50",
      "Description": "The size of the database (GiB)",
      "Type": "Number",
      "MinValue": "5",
      "MaxValue": "1024"
    },
    "DBUsername": {
      "MinLength": "1",
      "MaxLength": "16",
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*",
      "ConstraintDescription": "must begin with a letter and contain only alphanumeric characters.",
      "NoEcho": "true",
      "Description": "Username for MySQL database access",
      "Type": "String"
    },
    "DBPassword": {
      "Type": "String",
      "MinLength": "8",
      "MaxLength": "41",
      "AllowedPattern": "[a-zA-Z0-9]*",
      "ConstraintDescription": "must contain only alphanumeric characters.",
      "NoEcho": "true",
      "Description": "Password MySQL database access"
    },
    "DBInstanceID": {
      "Default": "mydbinstance",
      "Description": "My database instance",
      "Type": "String",
      "MinLength": "1",
      "MaxLength": "63",
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*",
      "ConstraintDescription": "Must begin with a letter and must not end with a hyphen or contain two consecutive hyphens."
    },
    "DBName": {
      "ConstraintDescription": "Must begin with a letter and contain only alphanumeric characters.",
      "Default": "mydb",
      "Description": "My database",
      "Type": "String",
      "MinLength": "1",
      "MaxLength": "64",
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*"
    }
  },
  "Resources": {
    "MyDB": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "MasterUsername": "DBUsername",
        "MasterUserPassword": "DBPassword",
        "PubliclyAccessible": true,
        "DBInstanceIdentifier": "DBInstanceID",
        "DBName": "DBName",
        "AllocatedStorage": "DBAllocatedStorage",
        "MonitoringInterval": "60",
        "MonitoringRoleArn": "arn:aws:iam::123456789012:role/rds-monitoring-role",
        "DBInstanceClass": "DBInstanceClass",
        "Engine": "MySQL",
        "EngineVersion": "8.0.16"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z"
}

```

```yaml
#this is a problematic code where the query should report a result(s)
AWSTemplateFormatVersion: 2010-09-09
Description: >-
  Description": "AWS CloudFormation Sample Template for creating an Amazon RDS DB instance:
  Sample template showing how to create a DB instance with Enhanced Monitoring enabled.
  **WARNING** This template creates an RDS DB instance. You will be billed for the AWS
  resources used if you create a stack from this template.
Parameters:
  DBInstanceID:
    Default: mydbinstance
    Description: My database instance
    Type: String
    MinLength: '1'
    MaxLength: '63'
    AllowedPattern: '[a-zA-Z][a-zA-Z0-9]*'
    ConstraintDescription: >-
      Must begin with a letter and must not end with a hyphen or contain two
      consecutive hyphens.
  DBName:
    Default: mydb
    Description: My database
    Type: String
    MinLength: '1'
    MaxLength: '64'
    AllowedPattern: '[a-zA-Z][a-zA-Z0-9]*'
    ConstraintDescription: Must begin with a letter and contain only alphanumeric characters.
  DBInstanceClass:
    Default: db.m5.large
    Description: DB instance class
    Type: String
    ConstraintDescription: Must select a valid DB instance type.
  DBAllocatedStorage:
    Default: '50'
    Description: The size of the database (GiB)
    Type: Number
    MinValue: '5'
    MaxValue: '1024'
    ConstraintDescription: must be between 20 and 65536 GiB.
  DBUsername:
    NoEcho: 'true'
    Description: Username for MySQL database access
    Type: String
    MinLength: '1'
    MaxLength: '16'
    AllowedPattern: '[a-zA-Z][a-zA-Z0-9]*'
    ConstraintDescription: must begin with a letter and contain only alphanumeric characters.
  DBPassword:
    NoEcho: 'true'
    Description: Password MySQL database access
    Type: String
    MinLength: '8'
    MaxLength: '41'
    AllowedPattern: '[a-zA-Z0-9]*'
    ConstraintDescription: must contain only alphanumeric characters.
Resources:
  MyDB:
    Type: 'AWS::RDS::DBInstance'
    Properties:
      DBInstanceIdentifier: !Ref DBInstanceID
      DBName: !Ref DBName
      DBInstanceClass: !Ref DBInstanceClass
      AllocatedStorage: !Ref DBAllocatedStorage
      Engine: MySQL
      EngineVersion: 8.0.16
      MasterUsername: !Ref DBUsername
      MasterUserPassword: !Ref DBPassword
      MonitoringInterval: '60'
      MonitoringRoleArn: 'arn:aws:iam::123456789012:role/rds-monitoring-role'
      PubliclyAccessible: true
```
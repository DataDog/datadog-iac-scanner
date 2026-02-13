---
title: "Automatic minor upgrades disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/automatic_minor_upgrades_disabled"
  id: "f0104061-8bfc-4b45-8a7d-630eb502f281"
  display_name: "Automatic minor upgrades disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `f0104061-8bfc-4b45-8a7d-630eb502f281`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html)

### Description

 Amazon RDS instances must have automatic minor version upgrades enabled so vendor patches and security fixes are applied promptly, reducing exposure to known database vulnerabilities and helping meet patching and compliance requirements. The `AutoMinorVersionUpgrade` property on `AWS::RDS::DBInstance` resources must be defined and set to `true`. Resources missing this property or explicitly set to `false` will be flagged. Note that minor upgrades may require a brief database restart during the maintenance window, so configure `PreferredMaintenanceWindow` to control timing.

```yaml
MyDB:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceIdentifier: mydb
    Engine: mysql
    EngineVersion: "8.0.28"
    AutoMinorVersionUpgrade: true
```


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
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
      AutoMinorVersionUpgrade: true
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Description\": \"AWS CloudFormation Sample Template for creating an Amazon RDS DB instance: Sample template showing how to create a DB instance with Enhanced Monitoring enabled. **WARNING** This template creates an RDS DB instance. You will be billed for the AWS resources used if you create a stack from this template.",
  "Parameters": {
    "DBInstanceClass": {
      "Type": "String",
      "ConstraintDescription": "Must select a valid DB instance type.",
      "Default": "db.m5.large",
      "Description": "DB instance class"
    },
    "DBAllocatedStorage": {
      "Default": "50",
      "Description": "The size of the database (GiB)",
      "Type": "Number",
      "MinValue": "5",
      "MaxValue": "1024",
      "ConstraintDescription": "must be between 20 and 65536 GiB."
    },
    "DBUsername": {
      "NoEcho": "true",
      "Description": "Username for MySQL database access",
      "Type": "String",
      "MinLength": "1",
      "MaxLength": "16",
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*",
      "ConstraintDescription": "must begin with a letter and contain only alphanumeric characters."
    },
    "DBPassword": {
      "ConstraintDescription": "must contain only alphanumeric characters.",
      "NoEcho": "true",
      "Description": "Password MySQL database access",
      "Type": "String",
      "MinLength": "8",
      "MaxLength": "41",
      "AllowedPattern": "[a-zA-Z0-9]*"
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
      "Properties": {
        "EngineVersion": "8.0.16",
        "MasterUsername": "DBUsername",
        "MonitoringInterval": "60",
        "MonitoringRoleArn": "arn:aws:iam::123456789012:role/rds-monitoring-role",
        "AutoMinorVersionUpgrade": true,
        "DBInstanceIdentifier": "DBInstanceID",
        "DBInstanceClass": "DBInstanceClass",
        "Engine": "MySQL",
        "MasterUserPassword": "DBPassword",
        "DBName": "DBName",
        "AllocatedStorage": "DBAllocatedStorage"
      },
      "Type": "AWS::RDS::DBInstance"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Description\": \"AWS CloudFormation Sample Template for creating an Amazon RDS DB instance: Sample template showing how to create a DB instance with Enhanced Monitoring enabled. **WARNING** This template creates an RDS DB instance. You will be billed for the AWS resources used if you create a stack from this template.",
  "Parameters": {
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
      "NoEcho": "true",
      "Description": "Username for MySQL database access",
      "Type": "String",
      "MinLength": "1",
      "MaxLength": "16",
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*",
      "ConstraintDescription": "must begin with a letter and contain only alphanumeric characters."
    },
    "DBPassword": {
      "NoEcho": "true",
      "Description": "Password MySQL database access",
      "Type": "String",
      "MinLength": "8",
      "MaxLength": "41",
      "AllowedPattern": "[a-zA-Z0-9]*",
      "ConstraintDescription": "must contain only alphanumeric characters."
    }
  },
  "Resources": {
    "MyDB": {
      "Properties": {
        "DBInstanceIdentifier": "DBInstanceID",
        "DBInstanceClass": "DBInstanceClass",
        "Engine": "MySQL",
        "MasterUserPassword": "DBPassword",
        "MonitoringInterval": "60",
        "MonitoringRoleArn": "arn:aws:iam::123456789012:role/rds-monitoring-role",
        "DBName": "DBName",
        "AllocatedStorage": "DBAllocatedStorage",
        "EngineVersion": "8.0.16",
        "MasterUsername": "DBUsername"
      },
      "Type": "AWS::RDS::DBInstance"
    },
    "MyDB2": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "DBInstanceIdentifier": "DBInstanceID",
        "DBInstanceClass": "DBInstanceClass",
        "EngineVersion": "8.0.16",
        "MasterUserPassword": "DBPassword",
        "MonitoringRoleArn": "arn:aws:iam::123456789012:role/rds-monitoring-role",
        "DBName": "DBName",
        "AllocatedStorage": "DBAllocatedStorage",
        "Engine": "MySQL",
        "MasterUsername": "DBUsername",
        "MonitoringInterval": "60",
        "AutoMinorVersionUpgrade": false
      }
    }
  }
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
  MyDB2:
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
      AutoMinorVersionUpgrade: false
```
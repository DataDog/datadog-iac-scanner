---
title: "Low RDS backup retention period"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/low_rds_backup_retention_period"
  id: "e649a218-d099-4550-86a4-1231e1fcb60d"
  display_name: "Low RDS backup retention period"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Backup"
---
## Metadata

**Id:** `e649a218-d099-4550-86a4-1231e1fcb60d`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Backup

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html)

### Description

 RDS clusters and standalone instances must retain automated backups for at least `7` days to ensure recoverability and limit data loss from accidental deletion, corruption, or operational errors. In AWS CloudFormation, the `BackupRetentionPeriod` property on `AWS::RDS::DBCluster` (and on standalone `AWS::RDS::DBInstance` resources) must be defined and set to `7` or greater. This rule flags `AWS::RDS::DBCluster` resources that omit `BackupRetentionPeriod` or set it to a value less than `7`. For `AWS::RDS::DBInstance` resources, the check is enforced only when no `AWS::RDS::DBCluster` resources are defined in the template because cluster-level backup retention may govern recovery for clustered deployments. Resources missing the property or with `BackupRetentionPeriod` less than `7` will be reported.

Secure configuration examples:

```yaml
MyDBCluster:
  Type: AWS::RDS::DBCluster
  Properties:
    Engine: aurora-mysql
    BackupRetentionPeriod: 7
```

```yaml
MyDBInstance:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceClass: db.t3.medium
    Engine: mysql
    BackupRetentionPeriod: 7
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Creates RDS Cluster
Parameters:
  PMDatabaseEngine:
    Type: String
    Default: "MySQL"
    Description: "Database engine, Aurora, MySQL or PostgreSQL"
  PMRDSSG:
    Description: "Select the Security Group to use for the ELB"
    Type: "AWS::EC2::SecurityGroup::Id"
  PMDatabaseEngineVer:
    Type: String
    Description: "Database engine ver"
  PMDatabaseUsername:
    NoEcho: 'true'
    Type: String
    Description: "Database admin account name"
  PMDatabasePassword:
    NoEcho: 'true'
    Type: String
    Description: "Database admin account password"
  PMDBClusterParameterGroupName:
    Description: "Db Parameter Groupname"
    Type: String
  PMDatabaseInstanceClass:
    Type: String
    Default: "db.t2.micro"
    Description: "Database instance class"
  PMPrivateSubnets:
    Description: "Subnets to launch instances into"
    Type: "List<AWS::EC2::Subnet::Id>"
  PMServerEnv:
    Description: "Server Environment name."
    ConstraintDescription: "Choose an Environment from the drop down"
    Type: String
  PMDBClusterIdentifier:
    Description: "Db Cluster Name."
    Type: String

Resources:
  DatabaseCluster:
    Type: "AWS::RDS::DBCluster"
    Properties:
      VpcSecurityGroupIds:
      - Ref: "PMRDSSG"
      Engine: !Ref "PMDatabaseEngine"
      EngineVersion: !Ref "PMDatabaseEngineVer"
      MasterUsername: !Ref "PMDatabaseUsername"
      MasterUserPassword: !Ref "PMDatabasePassword"
      DBClusterParameterGroupName: !Ref "RDSDBClusterParameterGroup"
      StorageEncrypted: true
      BackupRetentionPeriod: 16
      PreferredBackupWindow: '12:00-13:00'
      PreferredMaintenanceWindow: 'mon:13:00-mon:14:00'

  Database1:
    Type: "AWS::RDS::DBInstance"
    Properties:
      Engine: !Ref "PMDatabaseEngine"
      DBClusterIdentifier: !Ref "DatabaseCluster"
      DBInstanceClass: !Ref "PMDatabaseInstanceClass"
      DBSubnetGroupName: !Ref "DbSubnetGroup"
      DBInstanceIdentifier: !Sub "${PMDBClusterIdentifier}-db1"

  Database2:
    Type: "AWS::RDS::DBInstance"
    Properties:
      Engine: !Ref "PMDatabaseEngine"
      DBClusterIdentifier: !Ref "DatabaseCluster"
      DBInstanceClass: !Ref "PMDatabaseInstanceClass"
      DBSubnetGroupName: !Ref "DbSubnetGroup"
      DBInstanceIdentifier: !Sub "${PMDBClusterIdentifier}-db2"

  DbSubnetGroup:
    Type: "AWS::RDS::DBSubnetGroup"
    Properties:
      DBSubnetGroupDescription: !Sub "${PMServerEnv} RDS DB subnet group"
      SubnetIds:
        Ref: "PMPrivateSubnets"

  RDSDBClusterParameterGroup:
    Type: "AWS::RDS::DBClusterParameterGroup"
    Properties:
      Description: "CloudFormation Sample Aurora Cluster Parameter Group"
      Family: !Ref "PMDBClusterParameterGroupName"
      Parameters:
        time_zone: "UTC"
        collation_connection: "utf8_general_ci"
        character_set_database: "utf8"

Outputs:
  RdsDbId:
    Description: "RDS Database Cluster ID"
    Value: !Ref "DatabaseCluster"
  RdsEndpointAdd:
    Description: "RDS Database Endpoint"
    Value: !GetAtt "DatabaseCluster.Endpoint.Address"
  RdsReadEndpointAdd:
    Description: "RDS Read Database Endpoint"
    Value: !GetAtt "DatabaseCluster.ReadEndpoint.Address"
  RdsEndpointPort:
    Description: "RDS Database Port"
    Value: !GetAtt "DatabaseCluster.Endpoint.Port"
  DbUser:
    Description: "RDS Database admin account user"
    Value: !Ref "PMDatabaseUsername"
  DbPassword:
    Description: "RDS Database admin account password"
    Value: !Ref "PMDatabasePassword"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "DBUser": {
      "MinLength": 1,
      "MaxLength": 16,
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*",
      "ConstraintDescription": "must begin with a letter and contain only alphanumeric characters.",
      "NoEcho": true,
      "Description": "The database admin account username",
      "Type": "String"
    },
    "DBPassword": {
      "MinLength": 1,
      "MaxLength": 41,
      "AllowedPattern": "[a-zA-Z0-9]*",
      "ConstraintDescription": "must contain only alphanumeric characters.",
      "NoEcho": true,
      "Description": "The database admin account password",
      "Type": "String"
    }
  },
  "Resources": {
    "MyDB": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "EngineVersion": "5.5",
        "MasterUsername": "DBUser",
        "MasterUserPassword": "DBPassword",
        "DBParameterGroupName": "MyRDSParamGroup",
        "BackupRetentionPeriod": 10,
        "AllocatedStorage": "5",
        "DBInstanceClass": "db.t2.small",
        "Engine": "MySQL"
      }
    },
    "MyRDSParamGroup": {
      "Type": "AWS::RDS::DBParameterGroup",
      "Properties": {
        "Family": "MySQL5.5",
        "Description": "CloudFormation Sample Database Parameter Group",
        "Parameters": {
          "autocommit": "1",
          "general_log": "1",
          "old_passwords": "0"
        }
      }
    }
  }
}

```

```json
{
  "Parameters": {
    "SourceDBInstanceIdentifier": {
      "Type": "String"
    },
    "DBInstanceType": {
      "Type": "String"
    },
    "SourceRegion": {
      "Type": "String"
    }
  },
  "Resources": {
    "MyKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "KeyPolicy": {
          "Version": "2012-10-17T00:00:00Z",
          "Id": "key-default-1",
          "Statement": [
            {
              "Principal": {
                "AWS": [
                  "",
                  [
                    "arn:aws:iam::",
                    "AWS::AccountId",
                    ":root"
                  ]
                ]
              },
              "Action": "kms:*",
              "Resource": "*",
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow"
            }
          ]
        }
      }
    },
    "MyDBSmall": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "SourceDBInstanceIdentifier": "SourceDBInstanceIdentifier",
        "SourceRegion": "SourceRegion",
        "KmsKeyId": "MyKey",
        "BackupRetentionPeriod": 7,
        "DBInstanceClass": "DBInstanceType"
      }
    }
  },
  "Outputs": {
    "InstanceId": {
      "Description": "InstanceId of the newly created RDS Instance",
      "Value": "MyDBSmall"
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "RDS Storage Encrypted"
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: RDS Storage Encrypted
Parameters:
  SourceDBInstanceIdentifier:
    Type: String
  DBInstanceType:
    Type: String
  SourceRegion:
    Type: String
Resources:
  MyKey:
    Type: "AWS::KMS::Key"
    Properties:
      KeyPolicy:
        Version: 2012-10-17
        Id: key-default-1
        Statement:
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !Join
                - ""
                - - "arn:aws:iam::"
                  - !Ref "AWS::AccountId"
                  - ":root"
            Action: "kms:*"
            Resource: "*"
  MyDBSmall:
    Type: "AWS::RDS::DBInstance"
    Properties:
      DBInstanceClass: !Ref DBInstanceType
      SourceDBInstanceIdentifier: !Ref SourceDBInstanceIdentifier
      SourceRegion: !Ref SourceRegion
      KmsKeyId: !Ref MyKey
      BackupRetentionPeriod: 6
Outputs:
  InstanceId:
    Description: InstanceId of the newly created RDS Instance
    Value: !Ref MyDBSmall

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  DBUser:
    NoEcho: true
    Description: The database admin account username
    Type: String
    MinLength: 1
    MaxLength: 16
    AllowedPattern: "[a-zA-Z][a-zA-Z0-9]*"
    ConstraintDescription: must begin with a letter and contain only alphanumeric characters.
  DBPassword:
    NoEcho: true
    Description: The database admin account password
    Type: String
    MinLength: 1
    MaxLength: 41
    AllowedPattern: "[a-zA-Z0-9]*"
    ConstraintDescription: must contain only alphanumeric characters.
Resources:
  MyDB:
    Type: "AWS::RDS::DBInstance"
    Properties:
      AllocatedStorage: '5'
      DBInstanceClass: db.t2.small
      Engine: MySQL
      EngineVersion: '5.5'
      MasterUsername: !Ref DBUser
      MasterUserPassword: !Ref DBPassword
      DBParameterGroupName: !Ref MyRDSParamGroup
  MyRDSParamGroup:
    Type: "AWS::RDS::DBParameterGroup"
    Properties:
      Family: MySQL5.5
      Description: CloudFormation Sample Database Parameter Group
      Parameters:
        autocommit: '1'
        general_log: '1'
        old_passwords: '0'

```

```json
{
  "Outputs": {
    "RdsDbId": {
      "Description": "RDS Database Cluster ID",
      "Value": "DatabaseCluster"
    },
    "RdsEndpointAdd": {
      "Description": "RDS Database Endpoint",
      "Value": "DatabaseCluster.Endpoint.Address"
    },
    "RdsReadEndpointAdd": {
      "Description": "RDS Read Database Endpoint",
      "Value": "DatabaseCluster.ReadEndpoint.Address"
    },
    "RdsEndpointPort": {
      "Description": "RDS Database Port",
      "Value": "DatabaseCluster.Endpoint.Port"
    },
    "DbUser": {
      "Description": "RDS Database admin account user",
      "Value": "PMDatabaseUsername"
    },
    "DbPassword": {
      "Description": "RDS Database admin account password",
      "Value": "PMDatabasePassword"
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Creates RDS Cluster",
  "Parameters": {
    "PMRDSSG": {
      "Description": "Select the Security Group to use for the ELB",
      "Type": "AWS::EC2::SecurityGroup::Id"
    },
    "PMPrivateSubnets": {
      "Description": "Subnets to launch instances into",
      "Type": "List\u003cAWS::EC2::Subnet::Id\u003e"
    },
    "PMServerEnv": {
      "Description": "Server Environment name.",
      "ConstraintDescription": "Choose an Environment from the drop down",
      "Type": "String"
    },
    "PMDBClusterIdentifier": {
      "Type": "String",
      "Description": "Db Cluster Name."
    },
    "PMDBClusterParameterGroupName": {
      "Description": "Db Parameter Groupname",
      "Type": "String"
    },
    "PMDatabaseInstanceClass": {
      "Type": "String",
      "Default": "db.t2.micro",
      "Description": "Database instance class"
    },
    "PMDatabaseEngine": {
      "Type": "String",
      "Default": "MySQL",
      "Description": "Database engine, Aurora, MySQL or PostgreSQL"
    },
    "PMDatabaseEngineVer": {
      "Type": "String",
      "Description": "Database engine ver"
    },
    "PMDatabaseUsername": {
      "NoEcho": "true",
      "Type": "String",
      "Description": "Database admin account name"
    },
    "PMDatabasePassword": {
      "Description": "Database admin account password",
      "NoEcho": "true",
      "Type": "String"
    }
  },
  "Resources": {
    "Database2": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "Engine": "PMDatabaseEngine",
        "DBClusterIdentifier": "DatabaseCluster",
        "DBInstanceClass": "PMDatabaseInstanceClass",
        "DBSubnetGroupName": "DbSubnetGroup",
        "DBInstanceIdentifier": "${PMDBClusterIdentifier}-db2"
      }
    },
    "DbSubnetGroup": {
      "Type": "AWS::RDS::DBSubnetGroup",
      "Properties": {
        "DBSubnetGroupDescription": "${PMServerEnv} RDS DB subnet group",
        "SubnetIds": {
          "Ref": "PMPrivateSubnets"
        }
      }
    },
    "RDSDBClusterParameterGroup": {
      "Properties": {
        "Description": "CloudFormation Sample Aurora Cluster Parameter Group",
        "Family": "PMDBClusterParameterGroupName",
        "Parameters": {
          "time_zone": "UTC",
          "collation_connection": "utf8_general_ci",
          "character_set_database": "utf8"
        }
      },
      "Type": "AWS::RDS::DBClusterParameterGroup"
    },
    "DatabaseCluster": {
      "Type": "AWS::RDS::DBCluster",
      "Properties": {
        "StorageEncrypted": true,
        "BackupRetentionPeriod": 3,
        "MasterUsername": "PMDatabaseUsername",
        "MasterUserPassword": "PMDatabasePassword",
        "DBClusterParameterGroupName": "RDSDBClusterParameterGroup",
        "PreferredBackupWindow": "12:00-13:00",
        "PreferredMaintenanceWindow": "mon:13:00-mon:14:00",
        "VpcSecurityGroupIds": [
          {
            "Ref": "PMRDSSG"
          }
        ],
        "Engine": "PMDatabaseEngine",
        "EngineVersion": "PMDatabaseEngineVer"
      }
    },
    "Database1": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "DBInstanceIdentifier": "${PMDBClusterIdentifier}-db1",
        "Engine": "PMDatabaseEngine",
        "DBClusterIdentifier": "DatabaseCluster",
        "DBInstanceClass": "PMDatabaseInstanceClass",
        "DBSubnetGroupName": "DbSubnetGroup"
      }
    }
  }
}

```
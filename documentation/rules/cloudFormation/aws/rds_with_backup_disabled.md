---
title: "RDS with backup disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/rds_with_backup_disabled"
  id: "8c415f6f-7b90-4a27-a44a-51047e1506f9"
  display_name: "RDS with backup disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `8c415f6f-7b90-4a27-a44a-51047e1506f9`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html)

### Description

Disabling automated backups for an RDS instance removes point-in-time recovery and increases the risk of permanent data loss and compliance violations. In AWS CloudFormation, check `AWS::RDS::DBInstance` resources. The `Properties.BackupRetentionPeriod` must be a positive integer (greater than or equal to `1`) representing the number of days to retain automated backups. This rule flags resources where `BackupRetentionPeriod` is set to `0`. Ensure the property is defined and set to at least `1` to enable automated backups and point-in-time recovery.

Secure configuration example:

```yaml
MyDB:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceIdentifier: my-db
    Engine: mysql
    BackupRetentionPeriod: 7
```

## Compliant Code Examples
```yaml
Resources:
 MyDB:
  Type: AWS::RDS::DBInstance
  Properties:
    DBSecurityGroups:
    - Ref: MyDbSecurityByEC2SecurityGroup
    - Ref: MyDbSecurityByCIDRIPGroup
    AllocatedStorage: '5'
    DBInstanceClass: db.t2.small
    Engine: oracle-ee
    LicenseModel: bring-your-own-license
    MasterUsername: master
    MasterUserPassword: SecretPassword01
    BackupRetentionPeriod: 7
  DeletionPolicy: Snapshot
```

```json
{
  "Resources": {
    "MyDB": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "BackupRetentionPeriod": 7,
        "DBSecurityGroups": [
          {
            "Ref": "MyDbSecurityByEC2SecurityGroup"
          },
          {
            "Ref": "MyDbSecurityByCIDRIPGroup"
          }
        ],
        "AllocatedStorage": "5",
        "DBInstanceClass": "db.t2.small",
        "Engine": "oracle-ee",
        "LicenseModel": "bring-your-own-license",
        "MasterUsername": "master",
        "MasterUserPassword": "SecretPassword01"
      },
      "DeletionPolicy": "Snapshot"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "MyDB": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "BackupRetentionPeriod": 0,
        "DBSecurityGroups": [
          {
            "Ref": "MyDbSecurityByEC2SecurityGroup"
          },
          {
            "Ref": "MyDbSecurityByCIDRIPGroup"
          }
        ],
        "AllocatedStorage": "5",
        "DBInstanceClass": "db.t2.small",
        "Engine": "oracle-ee",
        "LicenseModel": "bring-your-own-license",
        "MasterUsername": "master",
        "MasterUserPassword": "SecretPassword01"
      },
      "DeletionPolicy": "Snapshot"
    }
  }
}

```

```yaml
Resources:
 MyDB:
  Type: AWS::RDS::DBInstance
  Properties:
    DBSecurityGroups:
    - Ref: MyDbSecurityByEC2SecurityGroup
    - Ref: MyDbSecurityByCIDRIPGroup
    AllocatedStorage: '5'
    DBInstanceClass: db.t2.small
    Engine: oracle-ee
    LicenseModel: bring-your-own-license
    MasterUsername: master
    MasterUserPassword: SecretPassword01
    BackupRetentionPeriod: 0
  DeletionPolicy: Snapshot
```
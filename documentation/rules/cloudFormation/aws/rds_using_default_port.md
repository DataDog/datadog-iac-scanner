---
title: "RDS using default port"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/rds_using_default_port"
  id: "1fe9d958-ddce-4228-a124-05265a959a8b"
  display_name: "RDS using default port"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `1fe9d958-ddce-4228-a124-05265a959a8b`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-port)

### Description

Using an RDS instance's default database port makes the service easy for attackers to discover and target with automated scanners, brute-force attempts, and opportunistic exploits. Instances should not listen on the engine's well-known port. This rule checks `AWS::RDS::DBInstance` resources and flags `Properties.Port` when it is explicitly set to the engine's default value. Default ports checked include Aurora, MariaDB, and MySQL (`3306`), PostgreSQL (`5432`), Oracle (`1521`), and SQL Server (`1433`). If you must use a common port for compatibility, restrict access with tight security group, subnet, and network controls rather than relying on port obscurity.

Secure configuration example (PostgreSQL on non-default port):

```yaml
MyDBInstance:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceIdentifier: my-db
    Engine: postgres
    EngineVersion: '14.7'
    DBInstanceClass: db.t3.micro
    AllocatedStorage: 20
    Port: 5433
    MasterUsername: admin
    MasterUserPassword: !Ref DBPassword
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
    Port: 1522
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
        "Engine": "mysql",
        "LicenseModel": "bring-your-own-license",
        "MasterUsername": "master",
        "MasterUserPassword": "SecretPassword01",
        "Port": 3307
      },
      "DeletionPolicy": "Snapshot"
    }
  }
}

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
        "MasterUserPassword": "SecretPassword01",
        "Port": 1522
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
        "MasterUserPassword": "SecretPassword01",
        "Port": 1521
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
    Engine: mysql
    LicenseModel: bring-your-own-license
    MasterUsername: master
    MasterUserPassword: SecretPassword01
    BackupRetentionPeriod: 7
    Port: 3306
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
        "Engine": "mysql",
        "LicenseModel": "bring-your-own-license",
        "MasterUsername": "master",
        "MasterUserPassword": "SecretPassword01",
        "Port": 3306
      },
      "DeletionPolicy": "Snapshot"
    }
  }
}

```
---
title: "DocDB cluster master password in plaintext"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/docdb_cluster_master_password_in_plaintext"
  id: "39423ce4-9011-46cd-b6b1-009edcd9385d"
  display_name: "DocDB cluster master password in plaintext"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `39423ce4-9011-46cd-b6b1-009edcd9385d`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html)

### Description

Amazon DocumentDB (`AWS::DocDB::DBCluster`) master user passwords must not be embedded as plaintext in the template or stored as parameter `Default` values. Exposed credentials in IaC or parameter defaults can be checked into source control or viewed in consoles and lead to unauthorized database access.

 For `AWS::DocDB::DBCluster` resources, validate `Resources.<name>.Properties.MasterUserPassword`. It must reference an AWS Secrets Manager secret or a parameter that does not define a `Default`. When using a parameter for passwords, set `NoEcho: true` and omit `Default`. Alternatively, use a Secrets Manager dynamic reference or an `AWS::SecretsManager::Secret` resource and reference its secret value.

 Resources with `MasterUserPassword` set to a literal string, or parameters that include a password-like `Default`, will be flagged.

Secure examples:

```yaml
Parameters:
  DBPassword:
    Type: String
    NoEcho: true

Resources:
  MyDBCluster:
    Type: AWS::DocDB::DBCluster
    Properties:
      MasterUsername: admin
      MasterUserPassword: !Ref DBPassword
```

```yaml
Resources:
  MyDBCluster:
    Type: AWS::DocDB::DBCluster
    Properties:
      MasterUsername: admin
      MasterUserPassword: '{{resolve:secretsmanager:my-db-secret:SecretString:password}}'
```

## Compliant Code Examples
```json
{
  "Parameters": {
    "ParentAccessToken": {
      "Description": "Access Token",
      "Type": "String",
      "Default": ""
    }
  },
  "Resources": {
    "NewAmpApp4": {
      "Type": "AWS::Amplify::App",
      "Properties": {
        "AccessToken": "ParentAccessToken",
        "Description": "String",
        "Repository": "String",
        "OauthToken": "String",
        "BuildSpec": "String",
        "CustomHeaders": "String",
        "EnableBranchAutoDeletion": true,
        "IAMServiceRole": "String",
        "Name": "NewAmpApp"
      }
    }
  }
}

```

```yaml
Parameters:
  ParentMasterPassword:
    Description: 'Password'
    Type: String
    Default: ''
Resources:
  NewAmpApp1:
    Type: AWS::DocDB::DBCluster
    Properties:
      BackupRetentionPeriod: 8
      DBClusterIdentifier: "sample-cluster"
      DBClusterParameterGroupName: "default.docdb3.6"
      DBSubnetGroupName: "default"
      DeletionProtection: true
      KmsKeyId: "your-kms-key-id"
      MasterUsername: "your-master-username"
      MasterUserPassword: !Ref ParentMasterPassword
      Port: 27017
      PreferredBackupWindow: "07:34-08:04"
      PreferredMaintenanceWindow: "sat:04:51-sat:05:21"
      SnapshotIdentifier: "sample-cluster-snapshot-id"
      StorageEncrypted: true

```

```json
{
  "Parameters": {
    "ParentMasterPassword": {
      "Description": "Password",
      "Type": "String"
    }
  },
  "Resources": {
    "NewAmpApp1": {
      "Type": "AWS::DocDB::DBCluster",
      "Properties": {
        "DBClusterIdentifier": "sample-cluster",
        "DBSubnetGroupName": "default",
        "DeletionProtection": true,
        "MasterUserPassword": "ParentMasterPassword",
        "Port": 27017,
        "PreferredBackupWindow": "07:34-08:04",
        "PreferredMaintenanceWindow": "sat:04:51-sat:05:21",
        "BackupRetentionPeriod": 8,
        "SnapshotIdentifier": "sample-cluster-snapshot-id",
        "KmsKeyId": "your-kms-key-id",
        "MasterUsername": "your-master-username",
        "StorageEncrypted": true,
        "DBClusterParameterGroupName": "default.docdb3.6"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
Parameters:
  ParentMasterPassword:
    Description: 'Password'
    Type: String
    Default: 'asDjskjs73!'
Resources:
  NewAmpApp1:
    Type: AWS::DocDB::DBCluster
    Properties:
      BackupRetentionPeriod: 8
      DBClusterIdentifier: "sample-cluster"
      DBClusterParameterGroupName: "default.docdb3.6"
      DBSubnetGroupName: "default"
      DeletionProtection: true
      KmsKeyId: "your-kms-key-id"
      MasterUsername: "your-master-username"
      MasterUserPassword: !Ref ParentMasterPassword
      Port: 27017
      PreferredBackupWindow: "07:34-08:04"
      PreferredMaintenanceWindow: "sat:04:51-sat:05:21"
      SnapshotIdentifier: "sample-cluster-snapshot-id"
      StorageEncrypted: true

```

```yaml
Resources:
  NewAmpApp03:
    Type:  AWS::DocDB::DBCluster
    Properties:
      BackupRetentionPeriod: 8
      DBClusterIdentifier: "sample-cluster"
      DBClusterParameterGroupName: "default.docdb3.6"
      DBSubnetGroupName: "default"
      DeletionProtection: true
      KmsKeyId: "your-kms-key-id"
      MasterUsername: "your-master-username"
      MasterUserPassword: 'asDjskjs73!!'
      Port: 27017
      PreferredBackupWindow: "07:34-08:04"
      PreferredMaintenanceWindow: "sat:04:51-sat:05:21"
      SnapshotIdentifier: "sample-cluster-snapshot-id"
      StorageEncrypted: true

```

```json
{
  "Parameters": {
    "ParentMasterPassword": {
      "Description": "Password",
      "Type": "String",
      "Default": "asDjskjs73!"
    }
  },
  "Resources": {
    "NewAmpApp1": {
      "Type": "AWS::DocDB::DBCluster",
      "Properties": {
        "KmsKeyId": "your-kms-key-id",
        "MasterUsername": "your-master-username",
        "PreferredBackupWindow": "07:34-08:04",
        "BackupRetentionPeriod": 8,
        "DBClusterIdentifier": "sample-cluster",
        "DeletionProtection": true,
        "MasterUserPassword": "ParentMasterPassword",
        "Port": 27017,
        "PreferredMaintenanceWindow": "sat:04:51-sat:05:21",
        "SnapshotIdentifier": "sample-cluster-snapshot-id",
        "StorageEncrypted": true,
        "DBClusterParameterGroupName": "default.docdb3.6",
        "DBSubnetGroupName": "default"
      }
    }
  }
}

```
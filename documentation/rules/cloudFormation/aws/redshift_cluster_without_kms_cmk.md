---
title: "Redshift cluster without a KMS CMK"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/redshift_cluster_without_kms_cmk"
  id: "de76a0d6-66d5-45c9-9022-f05545b85c78"
  display_name: "Redshift cluster without a KMS CMK"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `de76a0d6-66d5-45c9-9022-f05545b85c78`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html)

### Description

 Redshift clusters should specify a customer-managed AWS KMS key (`KmsKeyId`) to maintain control over encryption of data at rest and snapshots. Without a customer-managed CMK, you lose control over key rotation, access policies, and the ability to revoke or share keys. In AWS CloudFormation, the `KmsKeyId` property must be defined on `AWS::Redshift::Cluster` resources and set to the ARN or key ID of a customer-managed KMS key. Resources missing this property will be flagged because they may rely on AWS-managed keys or lack explicit encryption controls. Secure configuration example (CloudFormation YAML):

```yaml
MyRedshiftCluster:
  Type: AWS::Redshift::Cluster
  Properties:
    ClusterType: single-node
    NodeType: dc2.large
    DBName: dev
    MasterUsername: masteruser
    MasterUserPassword: ReplaceWithSecurePassword
    KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/abcd1234-ef56-7890-abcd-ef1234567890
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Redshift Stack
Resources:
  RedshiftCluster:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: !Ref RedshiftClusterSubnetGroup
      ClusterType: !If [ SingleNode, single-node, multi-node ]
      NumberOfNodes: !If [ SingleNode, !Ref 'AWS::NoValue', !Ref RedshiftNodeCount ] #'
      DBName: !Sub ${DatabaseName}
      IamRoles:
        - !GetAtt RawDataBucketAccessRole.Arn
      MasterUserPassword: !Ref MasterUserPassword
      MasterUsername: !Ref MasterUsername
      PubliclyAccessible: true
      NodeType: dc1.large
      Port: 5439
      VpcSecurityGroupIds:
        - !Sub ${RedshiftSecurityGroup}
      PreferredMaintenanceWindow: Sun:09:15-Sun:09:45
      KmsKeyId: wewewewewefsa
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub ${DataBucketName}
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Redshift Stack",
  "Resources": {
    "RedshiftCluster": {
      "Type": "AWS::Redshift::Cluster",
      "Properties": {
        "IamRoles": [
          "RawDataBucketAccessRole.Arn"
        ],
        "PubliclyAccessible": true,
        "NodeType": "dc1.large",
        "Port": 5439,
        "VpcSecurityGroupIds": [
          "${RedshiftSecurityGroup}"
        ],
        "PreferredMaintenanceWindow": "Sun:09:15-Sun:09:45",
        "ClusterType": [
          "SingleNode",
          "single-node",
          "multi-node"
        ],
        "NumberOfNodes": [
          "SingleNode",
          "AWS::NoValue",
          "RedshiftNodeCount"
        ],
        "DBName": "${DatabaseName}",
        "MasterUserPassword": "MasterUserPassword",
        "MasterUsername": "MasterUsername",
        "KmsKeyId": "wewewewewefsa",
        "ClusterSubnetGroupName": "RedshiftClusterSubnetGroup"
      }
    },
    "DataBucket": {
      "Properties": {
        "BucketName": "${DataBucketName}"
      },
      "Type": "AWS::S3::Bucket"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Redshift Stack",
  "Resources": {
    "DataBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "${DataBucketName}"
      }
    },
    "RedshiftCluster": {
      "Properties": {
        "NodeType": "dc1.large",
        "Port": 5439,
        "VpcSecurityGroupIds": [
          "${RedshiftSecurityGroup}"
        ],
        "ClusterSubnetGroupName": "RedshiftClusterSubnetGroup",
        "ClusterType": [
          "SingleNode",
          "single-node",
          "multi-node"
        ],
        "MasterUserPassword": "MasterUserPassword",
        "MasterUsername": "MasterUsername",
        "PreferredMaintenanceWindow": "Sun:09:15-Sun:09:45",
        "NumberOfNodes": [
          "SingleNode",
          "AWS::NoValue",
          "RedshiftNodeCount"
        ],
        "DBName": "${DatabaseName}",
        "IamRoles": [
          "RawDataBucketAccessRole.Arn"
        ],
        "PubliclyAccessible": true
      },
      "Type": "AWS::Redshift::Cluster"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Redshift Stack
Resources:
  RedshiftCluster:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: !Ref RedshiftClusterSubnetGroup
      ClusterType: !If [ SingleNode, single-node, multi-node ]
      NumberOfNodes: !If [ SingleNode, !Ref 'AWS::NoValue', !Ref RedshiftNodeCount ] #'
      DBName: !Sub ${DatabaseName}
      IamRoles:
        - !GetAtt RawDataBucketAccessRole.Arn
      MasterUserPassword: !Ref MasterUserPassword
      MasterUsername: !Ref MasterUsername
      PubliclyAccessible: true
      NodeType: dc1.large
      Port: 5439
      VpcSecurityGroupIds:
        - !Sub ${RedshiftSecurityGroup}
      PreferredMaintenanceWindow: Sun:09:15-Sun:09:45
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub ${DataBucketName}
```
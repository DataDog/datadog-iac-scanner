---
title: "Elasticsearch not encrypted at rest"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elasticsearch_not_encrypted_at_rest"
  id: "86a248ab-0e01-4564-a82a-878303e253bb"
  display_name: "Elasticsearch not encrypted at rest"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `86a248ab-0e01-4564-a82a-878303e253bb`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-encryptionatrestoptions)

### Description

 Elasticsearch (OpenSearch) domains must have encryption at rest enabled to protect index data, snapshots, and backups from unauthorized access if storage media or backups are compromised.
 
 In CloudFormation, the `AWS::Elasticsearch::Domain` resource must include `EncryptionAtRestOptions` with `Enabled` set to `true`. Resources missing `EncryptionAtRestOptions` or with `Enabled` set to `false` will be flagged. If you require a customer-managed key, also set `KmsKeyId` under `EncryptionAtRestOptions`. Omitting `KmsKeyId` uses the AWS-managed key.

Secure configuration example:

```yaml
MyDomain:
  Type: AWS::Elasticsearch::Domain
  Properties:
    DomainName: my-domain
    EncryptionAtRestOptions:
      Enabled: true
      KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/abcd-ef01-2345-6789
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Creates RDS Cluster
Resources:
  ElasticsearchDomain:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: "test"
      ElasticsearchClusterConfig:
        DedicatedMasterEnabled: "true"
        InstanceCount: "2"
        ZoneAwarenessEnabled: "true"
        InstanceType: "m3.medium.elasticsearch"
        DedicatedMasterType: "m3.medium.elasticsearch"
        DedicatedMasterCount: "3"
      EncryptionAtRestOptions:
        Enabled: true
      EBSOptions:
        EBSEnabled: true
        Iops: 0
        VolumeSize: 20
        VolumeType: "gp2"
      SnapshotOptions:
        AutomatedSnapshotStartHour: "0"
      AccessPolicies:
        Version: "2012-10-17"
        Statement:
          -
            Effect: "Allow"
            Principal:
              AWS: "arn:aws:iam::123456789012:user/es-user"
            Action: "es:*"
            Resource: "arn:aws:es:us-east-1:846973539254:domain/test/*"
      AdvancedOptions:
        rest.action.multi.allow_explicit_index: "true"

```

```json
{
  "Resources": {
    "ElasticsearchDomain": {
      "Type": "AWS::Elasticsearch::Domain",
      "Properties": {
        "AccessPolicies": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/es-user"
              },
              "Action": "es:*",
              "Resource": "arn:aws:es:us-east-1:846973539254:domain/test/*"
            }
          ]
        },
        "AdvancedOptions": {
          "rest.action.multi.allow_explicit_index": "true"
        },
        "DomainName": "test",
        "ElasticsearchClusterConfig": {
          "DedicatedMasterCount": "3",
          "DedicatedMasterEnabled": "true",
          "InstanceCount": "2",
          "ZoneAwarenessEnabled": "true",
          "InstanceType": "m3.medium.elasticsearch",
          "DedicatedMasterType": "m3.medium.elasticsearch"
        },
        "EncryptionAtRestOptions": {
          "Enabled": true
        },
        "EBSOptions": {
          "EBSEnabled": true,
          "Iops": 0,
          "VolumeSize": 20,
          "VolumeType": "gp2"
        },
        "SnapshotOptions": {
          "AutomatedSnapshotStartHour": "0"
        }
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Creates RDS Cluster"
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Creates RDS Cluster
Resources:
  ElasticsearchDomain1:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: "test"
      ElasticsearchClusterConfig:
        DedicatedMasterEnabled: "true"
        InstanceCount: "2"
        ZoneAwarenessEnabled: "true"
        InstanceType: "m3.medium.elasticsearch"
        DedicatedMasterType: "m3.medium.elasticsearch"
        DedicatedMasterCount: "3"
      EBSOptions:
        EBSEnabled: true
        Iops: 0
        VolumeSize: 20
        VolumeType: "gp2"
      SnapshotOptions:
        AutomatedSnapshotStartHour: "0"
      AccessPolicies:
        Version: "2012-10-17"
        Statement:
          -
            Effect: "Allow"
            Principal:
              AWS: "arn:aws:iam::123456789012:user/es-user"
            Action: "es:*"
            Resource: "arn:aws:es:us-east-1:846973539254:domain/test/*"
      AdvancedOptions:
        rest.action.multi.allow_explicit_index: "true"

```

```json
{
  "Description": "Creates RDS Cluster",
  "Resources": {
    "ElasticsearchDomain": {
      "Type": "AWS::Elasticsearch::Domain",
      "Properties": {
        "EncryptionAtRestOptions": {
          "Enabled": false
        },
        "EBSOptions": {
          "EBSEnabled": true,
          "Iops": 0,
          "VolumeSize": 20,
          "VolumeType": "gp2"
        },
        "SnapshotOptions": {
          "AutomatedSnapshotStartHour": "0"
        },
        "AccessPolicies": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/es-user"
              },
              "Action": "es:*",
              "Resource": "arn:aws:es:us-east-1:846973539254:domain/test/*"
            }
          ]
        },
        "AdvancedOptions": {
          "rest.action.multi.allow_explicit_index": "true"
        },
        "DomainName": "test",
        "ElasticsearchClusterConfig": {
          "DedicatedMasterType": "m3.medium.elasticsearch",
          "DedicatedMasterCount": "3",
          "DedicatedMasterEnabled": "true",
          "InstanceCount": "2",
          "ZoneAwarenessEnabled": "true",
          "InstanceType": "m3.medium.elasticsearch"
        }
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```

```json
{
  "Resources": {
    "ElasticsearchDomain1": {
      "Type": "AWS::Elasticsearch::Domain",
      "Properties": {
        "DomainName": "test",
        "ElasticsearchClusterConfig": {
          "InstanceCount": "2",
          "ZoneAwarenessEnabled": "true",
          "InstanceType": "m3.medium.elasticsearch",
          "DedicatedMasterType": "m3.medium.elasticsearch",
          "DedicatedMasterCount": "3",
          "DedicatedMasterEnabled": "true"
        },
        "EBSOptions": {
          "EBSEnabled": true,
          "Iops": 0,
          "VolumeSize": 20,
          "VolumeType": "gp2"
        },
        "SnapshotOptions": {
          "AutomatedSnapshotStartHour": "0"
        },
        "AccessPolicies": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/es-user"
              },
              "Action": "es:*",
              "Resource": "arn:aws:es:us-east-1:846973539254:domain/test/*"
            }
          ]
        },
        "AdvancedOptions": {
          "rest.action.multi.allow_explicit_index": "true"
        }
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Creates RDS Cluster"
}

```
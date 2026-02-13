---
title: "Elasticsearch encryption with KMS disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elasticsearch_domain_encryption_with_kms_disabled"
  id: "d926aa95-0a04-4abc-b20c-acf54afe38a1"
  display_name: "Elasticsearch encryption with KMS disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `d926aa95-0a04-4abc-b20c-acf54afe38a1`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-encryptionatrestoptions)

### Description

 Elasticsearch domains must use AWS KMS-backed encryption at rest to protect indexed data, snapshots, and backups from unauthorized access and to provide customer control and auditability of encryption keys.
 
 In CloudFormation, the `AWS::Elasticsearch::Domain` resource must include the `EncryptionAtRestOptions` property with `KmsKeyId` defined and not `null`. Resources missing `EncryptionAtRestOptions` or with `EncryptionAtRestOptions.KmsKeyId` undefined will be flagged. The `KmsKeyId` value should reference a customer-managed AWS KMS key ARN or a `Ref` to an `AWS::KMS::Key`, rather than relying solely on the service default key.

Secure configuration example:

```yaml
MyDomain:
  Type: AWS::Elasticsearch::Domain
  Properties:
    DomainName: my-domain
    EncryptionAtRestOptions:
      Enabled: true
      KmsKeyId: !Ref MyKmsKey

MyKmsKey:
  Type: AWS::KMS::Key
  Properties:
    Description: KMS key for Elasticsearch encryption
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
        KmsKeyId: "some-kms-key-id"
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
          "Enabled": true,
          "KmsKeyId": "some-kms-key-id"
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
```json
{
  "Description": "Creates RDS Cluster",
  "Resources": {
    "ElasticsearchDomain": {
      "Type": "AWS::Elasticsearch::Domain",
      "Properties": {
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

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Creates RDS Cluster2
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
  "Description": "Creates RDS Cluster2",
  "Resources": {
    "ElasticsearchDomain": {
      "Type": "AWS::Elasticsearch::Domain",
      "Properties": {
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
---
title: "MSK cluster encryption disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/msk_cluster_encryption_disabled"
  id: "a976d63f-af0e-46e8-b714-8c1a9c4bf768"
  display_name: "MSK cluster encryption disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `a976d63f-af0e-46e8-b714-8c1a9c4bf768`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html)

### Description

 MSK clusters must have encryption enabled for data at rest and in transit to prevent unauthorized access, eavesdropping, and tampering of Kafka messages and backups. In AWS CloudFormation, `AWS::MSK::Cluster` resources must define `EncryptionInfo`. `EncryptionInfo.EncryptionInTransit.ClientBroker` must be set to `TLS` and `EncryptionInfo.EncryptionInTransit.InCluster` must be set to `true`. Resources missing `EncryptionInfo`, with `ClientBroker` set to other values (for example, `PLAINTEXT` or `TLS_PLAINTEXT`), or with `InCluster` set to `false` will be flagged as insecure. 
 
 Secure configuration example:

```yaml
MyMSKCluster:
  Type: AWS::MSK::Cluster
  Properties:
    ClusterName: my-msk-cluster
    EncryptionInfo:
      EncryptionInTransit:
        ClientBroker: TLS
        InCluster: true
```


## Compliant Code Examples
```yaml
Description: MSK Cluster with all properties
Resources:
  TestCluster:
    Type: 'AWS::MSK::Cluster'
    Properties:
      ClusterName: ClusterWithAllProperties
      KafkaVersion: 2.2.1
      NumberOfBrokerNodes: 3
      EnhancedMonitoring: PER_BROKER
      EncryptionInfo:
        EncryptionAtRest:
          DataVolumeKMSKeyId: ReplaceWithKmsKeyArn
        EncryptionInTransit:
          ClientBroker: TLS
          InCluster: true
      OpenMonitoring:
        Prometheus:
          JmxExporter:
            EnabledInBroker: "true"
          NodeExporter:
            EnabledInBroker: "true"
      ConfigurationInfo:
        Arn: ReplaceWithConfigurationArn
        Revision: 1
      ClientAuthentication:
        Tls:
          CertificateAuthorityArnList:
            - ReplaceWithCAArn
      Tags:
        Environment: Test
        Owner: QATeam
      BrokerNodeGroupInfo:
        BrokerAZDistribution: DEFAULT
        InstanceType: kafka.m5.large
        SecurityGroups:
          - ReplaceWithSecurityGroupId
        StorageInfo:
          EBSStorageInfo:
            VolumeSize: 100
        ClientSubnets:
          - ReplaceWithSubnetId1
          - ReplaceWithSubnetId2
          - ReplaceWithSubnetId3

```

```json
{
  "Description": "MSK Cluster with all properties",
  "Resources": {
    "TestCluster4": {
      "Type": "AWS::MSK::Cluster",
      "Properties": {
        "ClusterName": "ClusterWithAllProperties",
        "KafkaVersion": "2.2.1",
        "NumberOfBrokerNodes": 3,
        "EnhancedMonitoring": "PER_BROKER",
        "EncryptionInfo": {
          "EncryptionAtRest": {
            "DataVolumeKMSKeyId": "ReplaceWithKmsKeyArn"
          },
          "EncryptionInTransit": {
            "ClientBroker": "TLS"
          }
        },
        "OpenMonitoring": {
          "Prometheus": {
            "JmxExporter": {
              "EnabledInBroker": "true"
            },
            "NodeExporter": {
              "EnabledInBroker": "true"
            }
          }
        },
        "ConfigurationInfo": {
          "Arn": "ReplaceWithConfigurationArn",
          "Revision": 1
        },
        "ClientAuthentication": {
          "Tls": {
            "CertificateAuthorityArnList": [
              "ReplaceWithCAArn"
            ]
          }
        },
        "Tags": {
          "Environment": "Test",
          "Owner": "QATeam"
        },
        "BrokerNodeGroupInfo": {
          "BrokerAZDistribution": "DEFAULT",
          "InstanceType": "kafka.m5.large",
          "SecurityGroups": [
            "ReplaceWithSecurityGroupId"
          ],
          "StorageInfo": {
            "EBSStorageInfo": {
              "VolumeSize": 100
            }
          },
          "ClientSubnets": [
            "ReplaceWithSubnetId1",
            "ReplaceWithSubnetId2",
            "ReplaceWithSubnetId3"
          ]
        }
      }
    }
  }
}

```

```yaml
Description: MSK Cluster with all properties
Resources:
  TestCluster2:
    Type: 'AWS::MSK::Cluster'
    Properties:
      ClusterName: ClusterWithAllProperties
      KafkaVersion: 2.2.1
      NumberOfBrokerNodes: 3
      EnhancedMonitoring: PER_BROKER
      EncryptionInfo:
        EncryptionAtRest:
          DataVolumeKMSKeyId: ReplaceWithKmsKeyArn
        EncryptionInTransit:
          ClientBroker: TLS
      OpenMonitoring:
        Prometheus:
          JmxExporter:
            EnabledInBroker: "true"
          NodeExporter:
            EnabledInBroker: "true"
      ConfigurationInfo:
        Arn: ReplaceWithConfigurationArn
        Revision: 1
      ClientAuthentication:
        Tls:
          CertificateAuthorityArnList:
            - ReplaceWithCAArn
      Tags:
        Environment: Test
        Owner: QATeam
      BrokerNodeGroupInfo:
        BrokerAZDistribution: DEFAULT
        InstanceType: kafka.m5.large
        SecurityGroups:
          - ReplaceWithSecurityGroupId
        StorageInfo:
          EBSStorageInfo:
            VolumeSize: 100
        ClientSubnets:
          - ReplaceWithSubnetId1
          - ReplaceWithSubnetId2
          - ReplaceWithSubnetId3

```
## Non-Compliant Code Examples
```yaml
Description: MSK Cluster with all properties
Resources:
  TestCluster6:
    Type: 'AWS::MSK::Cluster'
    Properties:
      ClusterName: ClusterWithAllProperties
      KafkaVersion: 2.2.1
      NumberOfBrokerNodes: 3
      EnhancedMonitoring: PER_BROKER
      EncryptionInfo:
        EncryptionAtRest:
          DataVolumeKMSKeyId: ReplaceWithKmsKeyArn
        EncryptionInTransit:
          ClientBroker: PLAINTEXT
      OpenMonitoring:
        Prometheus:
          JmxExporter:
            EnabledInBroker: "true"
          NodeExporter:
            EnabledInBroker: "true"
      ConfigurationInfo:
        Arn: ReplaceWithConfigurationArn
        Revision: 1
      ClientAuthentication:
        Tls:
          CertificateAuthorityArnList:
            - ReplaceWithCAArn
      Tags:
        Environment: Test
        Owner: QATeam
      BrokerNodeGroupInfo:
        BrokerAZDistribution: DEFAULT
        InstanceType: kafka.m5.large
        SecurityGroups:
          - ReplaceWithSecurityGroupId
        StorageInfo:
          EBSStorageInfo:
            VolumeSize: 100
        ClientSubnets:
          - ReplaceWithSubnetId1
          - ReplaceWithSubnetId2
          - ReplaceWithSubnetId3

```

```yaml
Description: MSK Cluster with all properties
Resources:
  TestCluster7:
    Type: 'AWS::MSK::Cluster'
    Properties:
      ClusterName: ClusterWithAllProperties
      KafkaVersion: 2.2.1
      NumberOfBrokerNodes: 3
      EnhancedMonitoring: PER_BROKER
      EncryptionInfo:
        EncryptionAtRest:
          DataVolumeKMSKeyId: ReplaceWithKmsKeyArn
        EncryptionInTransit:
          InCluster: false
      OpenMonitoring:
        Prometheus:
          JmxExporter:
            EnabledInBroker: "true"
          NodeExporter:
            EnabledInBroker: "true"
      ConfigurationInfo:
        Arn: ReplaceWithConfigurationArn
        Revision: 1
      ClientAuthentication:
        Tls:
          CertificateAuthorityArnList:
            - ReplaceWithCAArn
      Tags:
        Environment: Test
        Owner: QATeam
      BrokerNodeGroupInfo:
        BrokerAZDistribution: DEFAULT
        InstanceType: kafka.m5.large
        SecurityGroups:
          - ReplaceWithSecurityGroupId
        StorageInfo:
          EBSStorageInfo:
            VolumeSize: 100
        ClientSubnets:
          - ReplaceWithSubnetId1
          - ReplaceWithSubnetId2
          - ReplaceWithSubnetId3

```

```json
{
  "Description": "MSK Cluster with all properties",
  "Resources": {
    "TestCluster9": {
      "Type": "AWS::MSK::Cluster",
      "Properties": {
        "ClusterName": "ClusterWithAllProperties",
        "KafkaVersion": "2.2.1",
        "NumberOfBrokerNodes": 3,
        "EnhancedMonitoring": "PER_BROKER",
        "EncryptionInfo": {
          "EncryptionAtRest": {
            "DataVolumeKMSKeyId": "ReplaceWithKmsKeyArn"
          },
          "EncryptionInTransit": {
            "ClientBroker": "PLAINTEXT"
          }
        },
        "OpenMonitoring": {
          "Prometheus": {
            "JmxExporter": {
              "EnabledInBroker": "true"
            },
            "NodeExporter": {
              "EnabledInBroker": "true"
            }
          }
        },
        "ConfigurationInfo": {
          "Arn": "ReplaceWithConfigurationArn",
          "Revision": 1
        },
        "ClientAuthentication": {
          "Tls": {
            "CertificateAuthorityArnList": [
              "ReplaceWithCAArn"
            ]
          }
        },
        "Tags": {
          "Environment": "Test",
          "Owner": "QATeam"
        },
        "BrokerNodeGroupInfo": {
          "BrokerAZDistribution": "DEFAULT",
          "InstanceType": "kafka.m5.large",
          "SecurityGroups": [
            "ReplaceWithSecurityGroupId"
          ],
          "StorageInfo": {
            "EBSStorageInfo": {
              "VolumeSize": 100
            }
          },
          "ClientSubnets": [
            "ReplaceWithSubnetId1",
            "ReplaceWithSubnetId2",
            "ReplaceWithSubnetId3"
          ]
        }
      }
    }
  }
}

```
---
title: "MSK broker is publicly accessible"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/msk_broker_is_publicly_accessible"
  id: "0ce1ba20-8ba8-4364-836f-40c24b8cb0ab"
  display_name: "MSK broker is publicly accessible"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `0ce1ba20-8ba8-4364-836f-40c24b8cb0ab`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-publicaccess.html)

### Description

 MSK clusters must not expose broker endpoints to the public internet because public broker endpoints allow any internet actor to connect, increasing the risk of data exfiltration and unauthorized access. In AWS CloudFormation, verify `AWS::MSK::Cluster` resources. The `BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type` property must be set to `DISABLED` or the `PublicAccess` block omitted. This rule flags resources where `PublicAccess.Type` is set to `SERVICE_PROVIDED_EIPS`, which provisions public EIPs for brokers and makes them reachable from the internet.

Secure configuration example:

```yaml
MyMSKCluster:
  Type: AWS::MSK::Cluster
  Properties:
    BrokerNodeGroupInfo:
      ConnectivityInfo:
        PublicAccess:
          Type: DISABLED
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: MSK Cluster with required properties.
Resources:
  TestCluster0:
    Type: "AWS::MSK::Cluster"
    Properties:
      ClusterName: ClusterWithRequiredProperties
      KafkaVersion: 2.2.1
      NumberOfBrokerNodes: 3
      BrokerNodeGroupInfo:
        InstanceType: kafka.m5.large
        ClientSubnets:
          - ReplaceWithSubnetId1
          - ReplaceWithSubnetId2
          - ReplaceWithSubnetId3

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "MSK Cluster with required properties.",
  "Resources": {
    "TestCluster": {
      "Properties": {
        "BrokerNodeGroupInfo": {
          "ClientSubnets": [
            "ReplaceWithSubnetId1",
            "ReplaceWithSubnetId2",
            "ReplaceWithSubnetId3"
          ],
          "ConnectivityInfo": {
            "PublicAccess": {
              "Type": "DISABLED"
            }
          },
          "InstanceType": "kafka.m5.large"
        },
        "ClusterName": "ClusterWithRequiredProperties",
        "KafkaVersion": "2.2.1",
        "NumberOfBrokerNodes": 3
      },
      "Type": "AWS::MSK::Cluster"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "MSK Cluster with required properties.",
  "Resources": {
    "TestCluster": {
      "Properties": {
        "BrokerNodeGroupInfo": {
          "ClientSubnets": [
            "ReplaceWithSubnetId1",
            "ReplaceWithSubnetId2",
            "ReplaceWithSubnetId3"
          ],
          "ConnectivityInfo": {
            "PublicAccess": {
              "Type": "SERVICE_PROVIDED_EIPS"
            }
          },
          "InstanceType": "kafka.m5.large"
        },
        "ClusterName": "ClusterWithRequiredProperties",
        "KafkaVersion": "2.2.1",
        "NumberOfBrokerNodes": 3
      },
      "Type": "AWS::MSK::Cluster"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: MSK Cluster with required properties.
Resources:
  TestCluster:
    Type: "AWS::MSK::Cluster"
    Properties:
      ClusterName: ClusterWithRequiredProperties
      KafkaVersion: 2.2.1
      NumberOfBrokerNodes: 3
      BrokerNodeGroupInfo:
        InstanceType: kafka.m5.large
        ClientSubnets:
          - ReplaceWithSubnetId1
          - ReplaceWithSubnetId2
          - ReplaceWithSubnetId3
        ConnectivityInfo:
          PublicAccess:
            Type: SERVICE_PROVIDED_EIPS

```
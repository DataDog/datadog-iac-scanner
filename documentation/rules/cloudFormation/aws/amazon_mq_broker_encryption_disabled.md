---
title: "Amazon MQ broker encryption disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/amazon_mq_broker_encryption_disabled"
  id: "316278b3-87ac-444c-8f8f-a733a28da60f"
  display_name: "Amazon MQ broker encryption disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `316278b3-87ac-444c-8f8f-a733a28da60f`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-encryptionoptions)

### Description

 Amazon MQ brokers must have encryption options defined so message data, broker storage, and snapshots are encrypted at rest and protected from unauthorized access if storage media or backups are compromised. In CloudFormation, the `AWS::AmazonMQ::Broker` resource must include the `EncryptionOptions` property configured to enable AWS KMS encryption. For example, set `KmsKeyId` to a customer-managed KMS key or setting `UseAwsOwnedKey` to `true` to rely on an AWS-owned key. Resources missing the `EncryptionOptions` property will be flagged. Use a customer-managed KMS key (`KmsKeyId`) when you need full control over key rotation and access policies.

Secure configuration example (CloudFormation YAML):

```yaml
MyBroker:
  Type: AWS::AmazonMQ::Broker
  Properties:
    BrokerName: my-broker
    EngineType: ActiveMQ
    EngineVersion: 5.15.0
    HostInstanceType: mq.t3.micro
    EncryptionOptions:
      KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/abcd-ef01-2345-6789
      UseAwsOwnedKey: false
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Create a basic ActiveMQ broker"
Resources:
  BasicBroker:
    Type: "AWS::AmazonMQ::Broker"
    Properties:
      AutoMinorVersionUpgrade: "false"
      BrokerName: MyBasicBroker
      DeploymentMode: SINGLE_INSTANCE
      EncryptionOptions:
        UseAwsOwnedKey: true
      EngineType: ActiveMQ
      EngineVersion: "5.15.0"
      HostInstanceType: mq.t2.micro
      PubliclyAccessible: "true"
      Users:
        -
          ConsoleAccess: "true"
          Groups:
            - MyGroup
          Password:
            Ref: "BrokerPassword"
          Username:
            Ref: "BrokerUsername"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Create a basic ActiveMQ broker",
  "Resources": {
    "BasicBroker": {
      "Type": "AWS::AmazonMQ::Broker",
      "Properties": {
        "BrokerName": "MyBasicBroker",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EncryptionOptions": {
          "UseAwsOwnedKey": true
        },
        "EngineType": "ActiveMQ",
        "EngineVersion": "5.15.0",
        "HostInstanceType": "mq.t2.micro",
        "Users": [
          {
            "ConsoleAccess": "true",
            "Groups": [
              "MyGroup"
            ],
            "Password": {
              "Ref": "BrokerPassword"
            },
            "Username": {
              "Ref": "BrokerUsername"
            }
          }
        ],
        "AutoMinorVersionUpgrade": "false",
        "PubliclyAccessible": "true"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Create a basic ActiveMQ broker",
  "Resources": {
    "BasicBroker": {
      "Type": "AWS::AmazonMQ::Broker",
      "Properties": {
        "HostInstanceType": "mq.t2.micro",
        "PubliclyAccessible": "true",
        "Users": [
          {
            "ConsoleAccess": "true",
            "Groups": [
              "MyGroup"
            ],
            "Password": {
              "Ref": "BrokerPassword"
            },
            "Username": {
              "Ref": "BrokerUsername"
            }
          }
        ],
        "AutoMinorVersionUpgrade": "false",
        "BrokerName": "MyBasicBroker",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EngineType": "ActiveMQ",
        "EngineVersion": "5.15.0"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Create a basic ActiveMQ broker"
Resources:
  BasicBroker:
    Type: "AWS::AmazonMQ::Broker"
    Properties:
      AutoMinorVersionUpgrade: "false"
      BrokerName: MyBasicBroker
      DeploymentMode: SINGLE_INSTANCE
      EngineType: ActiveMQ
      EngineVersion: "5.15.0"
      HostInstanceType: mq.t2.micro
      PubliclyAccessible: "true"
      Users:
        -
          ConsoleAccess: "true"
          Groups:
            - MyGroup
          Password:
            Ref: "BrokerPassword"
          Username:
            Ref: "BrokerUsername"

```
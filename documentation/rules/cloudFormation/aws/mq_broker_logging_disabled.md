---
title: "Amazon MQ broker logging disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/mq_broker_logging_disabled"
  id: "e519ed6a-8328-4b69-8eb7-8fa549ac3050"
  display_name: "Amazon MQ broker logging disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `e519ed6a-8328-4b69-8eb7-8fa549ac3050`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-logs)

### Description

Amazon MQ brokers must have audit and general logging enabled so broker activity and security events are recorded for detection and investigation, and to support compliance and forensic requirements. In AWS CloudFormation, the `AWS::AmazonMQ::Broker` resource must include the `Logs` property with both `Audit` and `General` defined and set to `true`. Resources missing `Logs`, missing either `Audit` or `General`, or with either value set to `false` will be flagged.

Secure configuration example:

```yaml
MyBroker:
  Type: AWS::AmazonMQ::Broker
  Properties:
    BrokerName: my-broker
    Logs:
      Audit: true
      General: true
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
      PubliclyAccessible: false
      Users:
        -
          ConsoleAccess: "true"
          Groups:
            - MyGroup
          Password:
            Ref: "BrokerPassword"
          Username:
            Ref: "BrokerUsername"
      Logs:
        General: true
        Audit: true

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Create a basic ActiveMQ broker",
  "Resources": {
    "BasicBroker2": {
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
        "Logs": {
          "General": true,
          "Audit": true
        }
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
    "BasicBroker8": {
      "Type": "AWS::AmazonMQ::Broker",
      "Properties": {
        "BrokerName": "MyBasicBroker",
        "DeploymentMode": "SINGLE_INSTANCE",
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
        "PubliclyAccessible": false,
        "Logs": {
          "General": true
        }
      }
    },
    "BasicBroker9": {
      "Type": "AWS::AmazonMQ::Broker",
      "Properties": {
        "BrokerName": "MyBasicBroker",
        "DeploymentMode": "SINGLE_INSTANCE",
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
        "PubliclyAccessible": false,
        "Logs": {
          "Audit": true
        }
      }
    },
    "BasicBroker10": {
      "Type": "AWS::AmazonMQ::Broker",
      "Properties": {
        "BrokerName": "MyBasicBroker",
        "DeploymentMode": "SINGLE_INSTANCE",
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
        "PubliclyAccessible": false,
        "Logs": {
          "General": false,
          "Audit": true
        }
      }
    },
    "BasicBroker11": {
      "Type": "AWS::AmazonMQ::Broker",
      "Properties": {
        "BrokerName": "MyBasicBroker",
        "DeploymentMode": "SINGLE_INSTANCE",
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
        "PubliclyAccessible": false,
        "Logs": {
          "General": true,
          "Audit": false
        }
      }
    },
    "BasicBroker12": {
      "Type": "AWS::AmazonMQ::Broker",
      "Properties": {
        "BrokerName": "MyBasicBroker",
        "DeploymentMode": "SINGLE_INSTANCE",
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
        "PubliclyAccessible": false
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Create a basic ActiveMQ broker"
Resources:
  BasicBroker3:
    Type: "AWS::AmazonMQ::Broker"
    Properties:
      BrokerName: MyBasicBroker
      DeploymentMode: SINGLE_INSTANCE
      EngineType: ActiveMQ
      EngineVersion: "5.15.0"
      HostInstanceType: mq.t2.micro
      PubliclyAccessible: false
      Users:
        -
          ConsoleAccess: "true"
          Groups:
            - MyGroup
          Password:
            Ref: "BrokerPassword"
          Username:
            Ref: "BrokerUsername"
      Logs:
        General: true
  BasicBroker4:
    Type: "AWS::AmazonMQ::Broker"
    Properties:
      BrokerName: MyBasicBroker
      DeploymentMode: SINGLE_INSTANCE
      EngineType: ActiveMQ
      EngineVersion: "5.15.0"
      HostInstanceType: mq.t2.micro
      PubliclyAccessible: false
      Users:
        -
          ConsoleAccess: "true"
          Groups:
            - MyGroup
          Password:
            Ref: "BrokerPassword"
          Username:
            Ref: "BrokerUsername"
      Logs:
        Audit: true
  BasicBroker5:
    Type: "AWS::AmazonMQ::Broker"
    Properties:
      BrokerName: MyBasicBroker
      DeploymentMode: SINGLE_INSTANCE
      EngineType: ActiveMQ
      EngineVersion: "5.15.0"
      HostInstanceType: mq.t2.micro
      PubliclyAccessible: false
      Users:
        -
          ConsoleAccess: "true"
          Groups:
            - MyGroup
          Password:
            Ref: "BrokerPassword"
          Username:
            Ref: "BrokerUsername"
      Logs:
        General: false
        Audit: true
  BasicBroker6:
    Type: "AWS::AmazonMQ::Broker"
    Properties:
      BrokerName: MyBasicBroker
      DeploymentMode: SINGLE_INSTANCE
      EngineType: ActiveMQ
      EngineVersion: "5.15.0"
      HostInstanceType: mq.t2.micro
      PubliclyAccessible: false
      Users:
        -
          ConsoleAccess: "true"
          Groups:
            - MyGroup
          Password:
            Ref: "BrokerPassword"
          Username:
            Ref: "BrokerUsername"
      Logs:
        Audit: false
        General: true
  BasicBroker7:
    Type: "AWS::AmazonMQ::Broker"
    Properties:
      BrokerName: MyBasicBroker
      DeploymentMode: SINGLE_INSTANCE
      EngineType: ActiveMQ
      EngineVersion: "5.15.0"
      HostInstanceType: mq.t2.micro
      PubliclyAccessible: false
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
---
title: "ECS task definition health check missing"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ecs_task_definition_healthcheck_missing"
  id: "d24389b4-b209-4ff0-8345-dc7a4569dcdd"
  display_name: "ECS task definition health check missing"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `d24389b4-b209-4ff0-8345-dc7a4569dcdd`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-taskdefinition-healthcheck.html)

### Description

Amazon ECS container definitions must include a `HealthCheck` so the orchestrator and any load balancers can detect unhealthy containers and replace them automatically. Without health checks, failing containers may continue to receive traffic or delay recovery, increasing downtime and operational risk.
 
 For `AWS::ECS::TaskDefinition` resources, each element of `Properties.ContainerDefinitions` must define the `HealthCheck` property. Resources missing `HealthCheck` will be flagged.
 
 The `HealthCheck` should, at minimum, include a `Command`. It can also include `Interval`, `Timeout`, `Retries`, and `StartPeriod` to tune detection and recovery behavior.

Secure example (CloudFormation YAML):

```yaml
MyTaskDefinition:
  Type: AWS::ECS::TaskDefinition
  Properties:
    ContainerDefinitions:
      - Name: my-container
        Image: my-image:latest
        HealthCheck:
          Command:
            - CMD-SHELL
            - curl -f http://localhost:8080/health || exit 1
          Interval: 30
          Timeout: 5
          Retries: 3
          StartPeriod: 10
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  MyEC2Instance:
    Type: "AWS::EC2::Instance"
    Properties:
      ImageId: "ami-0ff8a91507f77f867"
      InstanceType: t2.micro
      KeyName: testkey
      BlockDeviceMappings:
        - DeviceName: /dev/sdm
          Ebs:
            VolumeType: io1
            Iops: 200
            DeleteOnTermination: false
            VolumeSize: 20
  taskdefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - Name:
            Ref: "AppName"
          MountPoints:
            - SourceVolume: "my-vol"
              ContainerPath: "/var/www/my-vol"
          Image: "amazon/amazon-ecs-sample"
          Cpu: 256
          PortMappings:
            - ContainerPort:
                Ref: "AppContainerPort"
              HostPort:
                Ref: "AppHostPort"
          EntryPoint:
            - "/usr/sbin/apache2"
            - "-D"
            - "FOREGROUND"
          HealthCheck:
            Command:
              - CMD-SHELL
              - curl -f http://localhost:8080/ || exit 1
            Interval: 30
            Retries: 3
            StartPeriod: 1
            Timeout: 5
          Memory: 512
          Essential: true
      Volumes:
        - Host:
            SourcePath: "/var/lib/docker/vfs/dir/"
          Name: "my-vol"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "MyEC2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": "ami-0ff8a91507f77f867",
        "InstanceType": "t2.micro",
        "KeyName": "testkey",
        "BlockDeviceMappings": [
          {
            "Ebs": {
              "VolumeType": "io1",
              "Iops": 200,
              "DeleteOnTermination": false,
              "VolumeSize": 20
            },
            "DeviceName": "/dev/sdm"
          }
        ]
      }
    },
    "taskdefinition": {
      "Type": "AWS::ECS::TaskDefinition",
      "Properties": {
        "Volumes": [
          {
            "Host": {
              "SourcePath": "/var/lib/docker/vfs/dir/"
            },
            "Name": "my-vol"
          }
        ],
        "ContainerDefinitions": [
          {
            "EntryPoint": [
              "/usr/sbin/apache2",
              "-D",
              "FOREGROUND"
            ],
            "Memory": 512,
            "PortMappings": [
              {
                "ContainerPort": {
                  "Ref": "AppContainerPort"
                },
                "HostPort": {
                  "Ref": "AppHostPort"
                }
              }
            ],
            "MountPoints": [
              {
                "SourceVolume": "my-vol",
                "ContainerPath": "/var/www/my-vol"
              }
            ],
            "Image": "amazon/amazon-ecs-sample",
            "Cpu": 256,
            "HealthCheck": {
              "Command": [
                "CMD-SHELL",
                "curl -f http://localhost:8080/ || exit 1"
              ],
              "Interval": 30,
              "Retries": 3,
              "StartPeriod": 1,
              "Timeout": 5
            },
            "Essential": true,
            "Name": {
              "Ref": "AppName"
            }
          }
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "MyEC2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "BlockDeviceMappings": [
          {
            "DeviceName": "/dev/sdm",
            "Ebs": {
              "DeleteOnTermination": false,
              "VolumeSize": 20,
              "VolumeType": "io1",
              "Iops": 200
            }
          }
        ],
        "ImageId": "ami-0ff8a91507f77f867",
        "InstanceType": "t2.micro",
        "KeyName": "testkey"
      }
    },
    "taskdefinition": {
      "Type": "AWS::ECS::TaskDefinition",
      "Properties": {
        "ContainerDefinitions": [
          {
            "MountPoints": [
              {
                "SourceVolume": "my-vol",
                "ContainerPath": "/var/www/my-vol"
              }
            ],
            "Image": "amazon/amazon-ecs-sample",
            "Cpu": 256,
            "PortMappings": [
              {
                "HostPort": {
                  "Ref": "AppHostPort"
                },
                "ContainerPort": {
                  "Ref": "AppContainerPort"
                }
              }
            ],
            "EntryPoint": [
              "/usr/sbin/apache2",
              "-D",
              "FOREGROUND"
            ],
            "Memory": 512,
            "Essential": true,
            "Name": {
              "Ref": "AppName"
            }
          }
        ],
        "Volumes": [
          {
            "Host": {
              "SourcePath": "/var/lib/docker/vfs/dir/"
            },
            "Name": "my-vol"
          }
        ]
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  MyEC2Instance:
    Type: "AWS::EC2::Instance"
    Properties:
      ImageId: "ami-0ff8a91507f77f867"
      InstanceType: t2.micro
      KeyName: testkey
      BlockDeviceMappings:
        - DeviceName: /dev/sdm
          Ebs:
            VolumeType: io1
            Iops: 200
            DeleteOnTermination: false
            VolumeSize: 20
  taskdefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - Name:
            Ref: "AppName1"
          MountPoints:
            - SourceVolume: "my-vol"
              ContainerPath: "/var/www/my-vol"
          Image: "amazon/amazon-ecs-sample"
          Cpu: 256
          PortMappings:
            - ContainerPort:
                Ref: "AppContainerPort"
              HostPort:
                Ref: "AppHostPort"
          EntryPoint:
            - "/usr/sbin/apache2"
            - "-D"
            - "FOREGROUND"
          HealthCheck:
            Command:
              - CMD-SHELL
              - curl -f http://localhost:8080/ || exit 1
            Interval: 30
            Retries: 3
            StartPeriod: 1
            Timeout: 5
          Memory: 512
          Essential: true
        - Name:
            Ref: "AppName"
          MountPoints:
            - SourceVolume: "my-vol"
              ContainerPath: "/var/www/my-vol"
          Image: "amazon/amazon-ecs-sample"
          Cpu: 256
          PortMappings:
            - ContainerPort:
                Ref: "AppContainerPort"
              HostPort:
                Ref: "AppHostPort"
          EntryPoint:
            - "/usr/sbin/apache2"
            - "-D"
            - "FOREGROUND"
          Memory: 512
          Essential: true
      Volumes:
        - Host:
            SourcePath: "/var/lib/docker/vfs/dir/"
          Name: "my-vol"

```
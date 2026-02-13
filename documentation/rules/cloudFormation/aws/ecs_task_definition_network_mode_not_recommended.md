---
title: "ECS task definition network mode not recommended"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ecs_task_definition_network_mode_not_recommended"
  id: "027a4b7a-8a59-4938-a04f-ed532512cf45"
  display_name: "ECS task definition network mode not recommended"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `027a4b7a-8a59-4938-a04f-ed532512cf45`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#cfn-ecs-taskdefinition-networkmode)

### Description

 Amazon ECS task definitions should use `NetworkMode` set to `awsvpc` so each task receives its own elastic network interface and can be protected by VPC security groups. This enables per-task network isolation and reduces the blast radius of compromised containers.
 
 In CloudFormation, the `AWS::ECS::TaskDefinition` resource's `NetworkMode` property must be defined and set to `awsvpc`. If `NetworkMode` is undefined, it defaults to `bridge`. Resources missing the property or with any other value (for example, `bridge` or `host`) will be flagged because they cannot leverage task-level security groups. 
 
 Secure configuration example:

```yaml
MyTaskDefinition:
  Type: AWS::ECS::TaskDefinition
  Properties:
    Family: my-task
    NetworkMode: awsvpc
    ContainerDefinitions:
      - Name: my-container
        Image: nginx:latest
        Essential: true
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  taskdefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      NetworkMode: awsvpc
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

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
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
        "NetworkMode": "awsvpc",
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
  taskdefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      NetworkMode: none
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
          Memory: 512
          Essential: true

```
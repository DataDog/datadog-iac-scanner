---
title: "ECS task definition invalid CPU or memory"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ecs_task_definition_invalid_cpu_or_memory"
  id: "f4c9b5f5-68b8-491f-9e48-4f96644a1d51"
  display_name: "ECS task definition invalid CPU or memory"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `f4c9b5f5-68b8-491f-9e48-4f96644a1d51`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html)

### Description

Incorrect CPU or memory settings for AWS Fargate tasks can prevent containers from starting or cause insufficient or imbalanced resource allocation. This can lead to service downtime and degraded availability.
 
 This rule checks `AWS::ECS::Service` resources with `LaunchType` set to `FARGATE` and their associated `AWS::ECS::TaskDefinition` container definitions:
 - `ContainerDefinitions[].Cpu` must be one of `256`, `512`, `1024`, `2048`, or `4096`.
 - Memory must match allowed values per CPU:
   - For `Cpu=256`, memory must be `512`, `1024`, or `2048`.
   - For `Cpu=512`, memory must be in the range `1024`–`4095`.
   - For `Cpu=1024`, memory must be in the range `2048`–`8191`.
   - For `Cpu=2048`, memory must be in the range `4096`–`16383`.
   - For `Cpu=4096`, memory must be in the range `8192`–`30719`.
 
 Resources missing these properties, with `Cpu` outside the allowed set, with `Memory` outside the mapped values, or (for non-`256` CPU) with `Memory` not a multiple of `1024` will be flagged.

Secure example (valid Fargate task definition):

```yaml
MyTaskDef:
  Type: AWS::ECS::TaskDefinition
  Properties:
    Family: my-task
    ContainerDefinitions:
      - Name: my-container
        Cpu: 512
        Memory: 2048
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  ECSService:
    Type: AWS::ECS::Service
    DependsOn:
      - Listener
    Properties:
      Role:
        Ref: ECSServiceRole
      TaskDefinition:
        Ref: ECSTaskDefinition
      DesiredCount: 1
      LoadBalancers:
        - TargetGroupArn:
            Ref: TargetGroup
          ContainerPort: 80
          ContainerName: sample-app
      Cluster:
        Ref: ECSCluster
      LaunchType: FARGATE
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
    "ECSService": {
      "Properties": {
        "LoadBalancers": [
          {
            "TargetGroupArn": {
              "Ref": "TargetGroup"
            },
            "ContainerPort": 80,
            "ContainerName": "sample-app"
          }
        ],
        "Cluster": {
          "Ref": "ECSCluster"
        },
        "LaunchType": "FARGATE",
        "Role": {
          "Ref": "ECSServiceRole"
        },
        "TaskDefinition": {
          "Ref": "ECSTaskDefinition"
        },
        "DesiredCount": 1
      },
      "Type": "AWS::ECS::Service",
      "DependsOn": [
        "Listener"
      ]
    },
    "taskdefinition": {
      "Type": "AWS::ECS::TaskDefinition",
      "Properties": {
        "ContainerDefinitions": [
          {
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
            "EntryPoint": [
              "/usr/sbin/apache2",
              "-D",
              "FOREGROUND"
            ],
            "Memory": 512,
            "Essential": true,
            "Name": {
              "Ref": "AppName"
            },
            "MountPoints": [
              {
                "SourceVolume": "my-vol",
                "ContainerPath": "/var/www/my-vol"
              }
            ],
            "Image": "amazon/amazon-ecs-sample",
            "Cpu": 256
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
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "ECSService": {
      "DependsOn": [
        "Listener"
      ],
      "Properties": {
        "Role": {
          "Ref": "ECSServiceRole"
        },
        "TaskDefinition": {
          "Ref": "ECSTaskDefinition"
        },
        "DesiredCount": 1,
        "LoadBalancers": [
          {
            "TargetGroupArn": {
              "Ref": "TargetGroup"
            },
            "ContainerPort": 80,
            "ContainerName": "sample-app"
          }
        ],
        "Cluster": {
          "Ref": "ECSCluster"
        },
        "LaunchType": "FARGATE"
      },
      "Type": "AWS::ECS::Service"
    },
    "taskdefinition": {
      "Type": "AWS::ECS::TaskDefinition",
      "Properties": {
        "ContainerDefinitions": [
          {
            "Essential": true,
            "Name": {
              "Ref": "AppName"
            },
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
                "ContainerPort": {
                  "Ref": "AppContainerPort"
                },
                "HostPort": {
                  "Ref": "AppHostPort"
                }
              }
            ],
            "EntryPoint": [
              "/usr/sbin/apache2",
              "-D",
              "FOREGROUND"
            ],
            "Memory": 4096
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
    },
    "taskdefinition2": {
      "Type": "AWS::ECS::TaskDefinition",
      "Properties": {
        "ContainerDefinitions": [
          {
            "Memory": 4096,
            "Essential": true,
            "Name": {
              "Ref": "AppName2"
            },
            "MountPoints": [
              {
                "SourceVolume": "my-vol",
                "ContainerPath": "/var/www/my-vol"
              }
            ],
            "Image": "amazon/amazon-ecs-sample",
            "Cpu": 100,
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
            "EntryPoint": [
              "/usr/sbin/apache2",
              "-D",
              "FOREGROUND"
            ]
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
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template"
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  ECSService:
    Type: AWS::ECS::Service
    DependsOn:
      - Listener
    Properties:
      Role:
        Ref: ECSServiceRole
      TaskDefinition:
        Ref: ECSTaskDefinition
      DesiredCount: 1
      LoadBalancers:
        - TargetGroupArn:
            Ref: TargetGroup
          ContainerPort: 80
          ContainerName: sample-app
      Cluster:
        Ref: ECSCluster
      LaunchType: FARGATE
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
          Memory: 4096
          Essential: true
      Volumes:
        - Host:
            SourcePath: "/var/lib/docker/vfs/dir/"
          Name: "my-vol"
  taskdefinition2:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - Name:
            Ref: "AppName2"
          MountPoints:
            - SourceVolume: "my-vol"
              ContainerPath: "/var/www/my-vol"
          Image: "amazon/amazon-ecs-sample"
          Cpu: 100
          PortMappings:
            - ContainerPort:
                Ref: "AppContainerPort"
              HostPort:
                Ref: "AppHostPort"
          EntryPoint:
            - "/usr/sbin/apache2"
            - "-D"
            - "FOREGROUND"
          Memory: 4096
          Essential: true
      Volumes:
        - Host:
            SourcePath: "/var/lib/docker/vfs/dir/"
          Name: "my-vol"

```
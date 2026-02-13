---
title: "EFS volume with disabled transit encryption"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/efs_volume_with_disabled_transit_encryption"
  id: "c1282e03-b285-4637-aee7-eefe3a7bb658"
  display_name: "EFS volume with disabled transit encryption"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `c1282e03-b285-4637-aee7-eefe3a7bb658`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/efs-volumes.html)

### Description

Amazon ECS task definitions that mount Amazon EFS volumes must enable in-transit encryption to protect data transmitted between containers and the file system from interception or tampering.
 
 In CloudFormation, the `AWS::ECS::TaskDefinition` resource’s `Properties.volumes[*].efsVolumeConfiguration.TransitEncryption` property must be defined and set to `ENABLED`. Resources missing this property or with `TransitEncryption` set to any value other than `ENABLED` will be flagged.

Secure example:

```yaml
MyTaskDefinition:
  Type: AWS::ECS::TaskDefinition
  Properties:
    Family: my-task
    ContainerDefinitions: []
    Volumes:
      - Name: MyEfsVolume
        EFSVolumeConfiguration:
          FileSystemId: fs-0123456789abcdef0
          TransitEncryption: ENABLED
```

## Compliant Code Examples
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
                    "Name": "container-using-efs",
                    "Image": "amazonlinux:2",
                    "EntryPoint": [
                        "sh",
                        "-c"
                    ],
                    "Command": [
                        "ls -la /mount/efs"
                    ],
                    "MountPoints": [
                        {
                            "SourceVolume": "myEfsVolume",
                            "ContainerPath": "/mount/efs",
                            "ReadOnly": true
                        }
                    ]
                }
            ],
            "Volumes": [
                {
                    "Name": "myEfsVolume",
                    "EFSVolumeConfiguration": {
                        "FileSystemId": "fs-1234",
                        "RootDirectory": "/path/to/my/data",
                        "TransitEncryptionPort": 10,
                        "TransitEncryption": "ENABLED"
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
                    "Name": "container-using-efs",
                    "Image": "amazonlinux:2",
                    "EntryPoint": [
                        "sh",
                        "-c"
                    ],
                    "Command": [
                        "ls -la /mount/efs"
                    ],
                    "MountPoints": [
                        {
                            "SourceVolume": "myEfsVolume",
                            "ContainerPath": "/mount/efs",
                            "ReadOnly": true
                        }
                    ]
                }
            ],
            "Volumes": [
                {
                    "Name": "myEfsVolume",
                    "EFSVolumeConfiguration": {
                        "FileSystemId": "fs-1234",
                        "RootDirectory": "/path/to/my/data",
                        "TransitEncryptionPort": 10
                    }
                }
            ]
        }
      }
    }
  }

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
                    "Name": "container-using-efs",
                    "Image": "amazonlinux:2",
                    "EntryPoint": [
                        "sh",
                        "-c"
                    ],
                    "Command": [
                        "ls -la /mount/efs"
                    ],
                    "MountPoints": [
                        {
                            "SourceVolume": "myEfsVolume",
                            "ContainerPath": "/mount/efs",
                            "ReadOnly": true
                        }
                    ]
                }
            ],
            "Volumes": [
                {
                    "Name": "myEfsVolume",
                    "EFSVolumeConfiguration": {
                        "fileSystemId": "fs-1234",
                        "rootDirectory": "/path/to/my/data",
                        "TransitEncryptionPort": 10,
                        "TransitEncryption": "DISABLED"
                    }
                }
            ]
        }
      }
    }
  }

```
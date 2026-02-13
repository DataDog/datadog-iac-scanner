---
title: "ECS service without running tasks"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ecs_service_without_running_tasks"
  id: "79d745f0-d5f3-46db-9504-bef73e9fd528"
  display_name: "ECS service without running tasks"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** `79d745f0-d5f3-46db-9504-bef73e9fd528`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html#cfn-ecs-service-deploymentconfiguration)

### Description

Amazon ECS services must define deployment controls so deployments do not reduce the number of healthy tasks to zero and so failed deployments can be rolled back automatically.
 
 In CloudFormation, the `AWS::ECS::Service` resource must include a non-`null` `Properties.DeploymentConfiguration` object that contains one or more of the deployment control properties: `MinimumHealthyPercent`, `MaximumPercent`, or `DeploymentCircuitBreaker`. Resources missing `DeploymentConfiguration` or lacking all of these properties will be flagged.
 
 `MinimumHealthyPercent` ensures a minimum number of tasks remain healthy during updates, `MaximumPercent` limits how many tasks may run during deployments, and `DeploymentCircuitBreaker` can enable automatic rollback on failed deployments.

Secure configuration example:

```yaml
MyService:
  Type: AWS::ECS::Service
  Properties:
    ServiceName: my-service
    TaskDefinition: my-task
    DesiredCount: 2
    DeploymentConfiguration:
      MinimumHealthyPercent: 100
      MaximumPercent: 200
      DeploymentCircuitBreaker:
        Enable: true
        Rollback: true
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Creating ECS service
Parameters:
  AppName:
    Type: String
    Description: Name of app requiring ELB exposure
    Default: simple-app
  AppContainerPort:
    Type: Number
    Description: Container port of app requiring ELB exposure
    Default: '80'
  AppHostPort:
    Type: Number
    Description: Host port of app requiring ELB exposure
    Default: '80'
  ServiceName:
    Type: String
  LoadBalancerName:
    Type: String
  HealthCheckGracePeriodSeconds:
    Type: String
Resources:
  cluster:
    Type: AWS::ECS::Cluster
  taskdefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - Name: !Ref AppName
          MountPoints:
            - SourceVolume: my-vol
              ContainerPath: /var/www/my-vol
          Image: amazon/amazon-ecs-sample
          Cpu: '10'
          PortMappings:
            - ContainerPort: !Ref AppContainerPort
              HostPort: !Ref AppHostPort
          EntryPoint:
            - /usr/sbin/apache2
            - '-D'
            - FOREGROUND
          Memory: '500'
          Essential: true
        - Name: busybox
          Image: busybox
          Cpu: '10'
          EntryPoint:
            - sh
            - '-c'
          Memory: '500'
          Command:
            - >-
              /bin/sh -c "while true; do /bin/date > /var/www/my-vol/date; sleep
              1; done"
          Essential: false
          VolumesFrom:
            - SourceContainer: !Ref AppName
      Volumes:
        - Host:
            SourcePath: /var/lib/docker/vfs/dir/
          Name: my-vol
  service:
    Type: AWS::ECS::Service
    Properties:
      Cluster: !Ref cluster
      DeploymentConfiguration:
        MaximumPercent: 200
        MinimumHealthyPercent: 100
      DesiredCount: 0
      HealthCheckGracePeriodSeconds: !Ref HealthCheckGracePeriodSeconds
      LoadBalancers:
        - ContainerName: !Ref AppName
          ContainerPort: !Ref AppContainerPort
          LoadBalancerName: !Ref elb
      PlacementStrategies:
        - Type: binpack
          Field: memory
        - Type: spread
          Field: host
      PlacementConstraints:
        - Type: memberOf
          Expression: 'attribute:ecs.availability-zone != us-east-1d'
        - Type: distinctInstance
      TaskDefinition: !Ref taskdefinition
      ServiceName: !Ref ServiceName
      Role: !Ref Role
  elb:
    Type: AWS::ElasticLoadBalancing::LoadBalancer
    Properties:
      LoadBalancerName: !Ref LoadBalancerName
      Listeners:
        - InstancePort: !Ref AppHostPort
          LoadBalancerPort: '80'
          Protocol: HTTP
      Subnets:
        - !Ref Subnet1
    DependsOn: GatewayAttachment
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/24
  Subnet1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.0.0.0/25
  InternetGateway:
    Type: AWS::EC2::InternetGateway
  GatewayAttachment:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      InternetGatewayId: !Ref InternetGateway
      VpcId: !Ref VPC
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: 2008-10-17
        Statement:
          - Sid: ''
            Effect: Allow
            Principal:
              Service: ecs.amazonaws.com
            Action: 'sts:AssumeRole'
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole'
Outputs:
  Cluster:
    Value: !Ref cluster

```

```json
{
  "Description": "Creating ECS service",
  "Parameters": {
    "AppHostPort": {
      "Default": "80",
      "Type": "Number",
      "Description": "Host port of app requiring ELB exposure"
    },
    "ServiceName": {
      "Type": "String"
    },
    "LoadBalancerName": {
      "Type": "String"
    },
    "HealthCheckGracePeriodSeconds": {
      "Type": "String"
    },
    "AppName": {
      "Type": "String",
      "Description": "Name of app requiring ELB exposure",
      "Default": "simple-app"
    },
    "AppContainerPort": {
      "Type": "Number",
      "Description": "Container port of app requiring ELB exposure",
      "Default": "80"
    }
  },
  "Resources": {
    "taskdefinition": {
      "Type": "AWS::ECS::TaskDefinition",
      "Properties": {
        "ContainerDefinitions": [
          {
            "EntryPoint": [
              "/usr/sbin/apache2",
              "-D",
              "FOREGROUND"
            ],
            "Memory": "500",
            "Essential": true,
            "Name": "AppName",
            "MountPoints": [
              {
                "SourceVolume": "my-vol",
                "ContainerPath": "/var/www/my-vol"
              }
            ],
            "Image": "amazon/amazon-ecs-sample",
            "Cpu": "10",
            "PortMappings": [
              {
                "HostPort": "AppHostPort",
                "ContainerPort": "AppContainerPort"
              }
            ]
          },
          {
            "VolumesFrom": [
              {
                "SourceContainer": "AppName"
              }
            ],
            "Name": "busybox",
            "Image": "busybox",
            "Cpu": "10",
            "EntryPoint": [
              "sh",
              "-c"
            ],
            "Memory": "500",
            "Command": [
              "/bin/sh -c \"while true; do /bin/date \u003e /var/www/my-vol/date; sleep 1; done\""
            ],
            "Essential": false
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
    "Subnet1": {
      "Properties": {
        "VpcId": "VPC",
        "CidrBlock": "10.0.0.0/25"
      },
      "Type": "AWS::EC2::Subnet"
    },
    "InternetGateway": {
      "Type": "AWS::EC2::InternetGateway"
    },
    "Role": {
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17T00:00:00Z",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": "ecs.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "ManagedPolicyArns": [
          "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole"
        ]
      },
      "Type": "AWS::IAM::Role"
    },
    "cluster": {
      "Type": "AWS::ECS::Cluster"
    },
    "service": {
      "Type": "AWS::ECS::Service",
      "Properties": {
        "DesiredCount": 0,
        "HealthCheckGracePeriodSeconds": "HealthCheckGracePeriodSeconds",
        "LoadBalancers": [
          {
            "LoadBalancerName": "elb",
            "ContainerName": "AppName",
            "ContainerPort": "AppContainerPort"
          }
        ],
        "PlacementStrategies": [
          {
            "Type": "binpack",
            "Field": "memory"
          },
          {
            "Field": "host",
            "Type": "spread"
          }
        ],
        "ServiceName": "ServiceName",
        "Cluster": "cluster",
        "DeploymentConfiguration": {
          "MaximumPercent": 200,
          "MinimumHealthyPercent": 100
        },
        "PlacementConstraints": [
          {
            "Type": "memberOf",
            "Expression": "attribute:ecs.availability-zone != us-east-1d"
          },
          {
            "Type": "distinctInstance"
          }
        ],
        "TaskDefinition": "taskdefinition",
        "Role": "Role"
      }
    },
    "elb": {
      "DependsOn": "GatewayAttachment",
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
      "Properties": {
        "LoadBalancerName": "LoadBalancerName",
        "Listeners": [
          {
            "Protocol": "HTTP",
            "InstancePort": "AppHostPort",
            "LoadBalancerPort": "80"
          }
        ],
        "Subnets": [
          "Subnet1"
        ]
      }
    },
    "VPC": {
      "Properties": {
        "CidrBlock": "10.0.0.0/24"
      },
      "Type": "AWS::EC2::VPC"
    },
    "GatewayAttachment": {
      "Properties": {
        "InternetGatewayId": "InternetGateway",
        "VpcId": "VPC"
      },
      "Type": "AWS::EC2::VPCGatewayAttachment"
    }
  },
  "Outputs": {
    "Cluster": {
      "Value": "cluster"
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z"
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Creating ECS service",
  "Parameters": {
    "AppName": {
      "Type": "String",
      "Description": "Name of app requiring ELB exposure",
      "Default": "simple-app"
    },
    "AppContainerPort": {
      "Default": "80",
      "Type": "Number",
      "Description": "Container port of app requiring ELB exposure"
    },
    "AppHostPort": {
      "Type": "Number",
      "Description": "Host port of app requiring ELB exposure",
      "Default": "80"
    },
    "ServiceName": {
      "Type": "String"
    },
    "LoadBalancerName": {
      "Type": "String"
    },
    "HealthCheckGracePeriodSeconds": {
      "Type": "String"
    }
  },
  "Resources": {
    "cluster": {
      "Type": "AWS::ECS::Cluster"
    },
    "taskdefinition": {
      "Type": "AWS::ECS::TaskDefinition",
      "Properties": {
        "ContainerDefinitions": [
          {
            "Cpu": "10",
            "PortMappings": [
              {
                "ContainerPort": "AppContainerPort",
                "HostPort": "AppHostPort"
              }
            ],
            "EntryPoint": [
              "/usr/sbin/apache2",
              "-D",
              "FOREGROUND"
            ],
            "Memory": "500",
            "Essential": true,
            "Name": "AppName",
            "MountPoints": [
              {
                "SourceVolume": "my-vol",
                "ContainerPath": "/var/www/my-vol"
              }
            ],
            "Image": "amazon/amazon-ecs-sample"
          },
          {
            "Name": "busybox",
            "Image": "busybox",
            "Cpu": "10",
            "EntryPoint": [
              "sh",
              "-c"
            ],
            "Memory": "500",
            "Command": [
              "/bin/sh -c \"while true; do /bin/date \u003e /var/www/my-vol/date; sleep 1; done\""
            ],
            "Essential": false,
            "VolumesFrom": [
              {
                "SourceContainer": "AppName"
              }
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
    },
    "elb": {
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
      "Properties": {
        "Listeners": [
          {
            "InstancePort": "AppHostPort",
            "LoadBalancerPort": "80",
            "Protocol": "HTTP"
          }
        ],
        "Subnets": [
          "Subnet1"
        ],
        "LoadBalancerName": "LoadBalancerName"
      },
      "DependsOn": "GatewayAttachment"
    },
    "VPC": {
      "Type": "AWS::EC2::VPC",
      "Properties": {
        "CidrBlock": "10.0.0.0/24"
      }
    },
    "Subnet1": {
      "Type": "AWS::EC2::Subnet",
      "Properties": {
        "VpcId": "VPC",
        "CidrBlock": "10.0.0.0/25"
      }
    },
    "GatewayAttachment": {
      "Properties": {
        "InternetGatewayId": "InternetGateway",
        "VpcId": "VPC"
      },
      "Type": "AWS::EC2::VPCGatewayAttachment"
    },
    "Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17T00:00:00Z",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": "ecs.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "ManagedPolicyArns": [
          "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole"
        ]
      }
    },
    "service": {
      "Type": "AWS::ECS::Service",
      "Properties": {
        "LoadBalancers": [
          {
            "ContainerName": "AppName",
            "ContainerPort": "AppContainerPort",
            "LoadBalancerName": "elb"
          }
        ],
        "DesiredCount": 0,
        "HealthCheckGracePeriodSeconds": "HealthCheckGracePeriodSeconds",
        "PlacementStrategies": [
          {
            "Field": "memory",
            "Type": "binpack"
          },
          {
            "Type": "spread",
            "Field": "host"
          }
        ],
        "PlacementConstraints": [
          {
            "Type": "memberOf",
            "Expression": "attribute:ecs.availability-zone != us-east-1d"
          },
          {
            "Type": "distinctInstance"
          }
        ],
        "TaskDefinition": "taskdefinition",
        "ServiceName": "ServiceName",
        "Role": "Role",
        "Cluster": "cluster"
      }
    },
    "InternetGateway": {
      "Type": "AWS::EC2::InternetGateway"
    }
  },
  "Outputs": {
    "Cluster": {
      "Value": "cluster"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Creating ECS service
Parameters:
  AppName:
    Type: String
    Description: Name of app requiring ELB exposure
    Default: simple-app
  AppContainerPort:
    Type: Number
    Description: Container port of app requiring ELB exposure
    Default: '80'
  AppHostPort:
    Type: Number
    Description: Host port of app requiring ELB exposure
    Default: '80'
  ServiceName:
    Type: String
  LoadBalancerName:
    Type: String
  HealthCheckGracePeriodSeconds:
    Type: String
Resources:
  cluster:
    Type: AWS::ECS::Cluster
  taskdefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - Name: !Ref AppName
          MountPoints:
            - SourceVolume: my-vol
              ContainerPath: /var/www/my-vol
          Image: amazon/amazon-ecs-sample
          Cpu: '10'
          PortMappings:
            - ContainerPort: !Ref AppContainerPort
              HostPort: !Ref AppHostPort
          EntryPoint:
            - /usr/sbin/apache2
            - '-D'
            - FOREGROUND
          Memory: '500'
          Essential: true
        - Name: busybox
          Image: busybox
          Cpu: '10'
          EntryPoint:
            - sh
            - '-c'
          Memory: '500'
          Command:
            - >-
              /bin/sh -c "while true; do /bin/date > /var/www/my-vol/date; sleep
              1; done"
          Essential: false
          VolumesFrom:
            - SourceContainer: !Ref AppName
      Volumes:
        - Host:
            SourcePath: /var/lib/docker/vfs/dir/
          Name: my-vol
  service:
    Type: AWS::ECS::Service
    Properties:
      Cluster: !Ref cluster
      DesiredCount: 0
      HealthCheckGracePeriodSeconds: !Ref HealthCheckGracePeriodSeconds
      LoadBalancers:
        - ContainerName: !Ref AppName
          ContainerPort: !Ref AppContainerPort
          LoadBalancerName: !Ref elb
      PlacementStrategies:
        - Type: binpack
          Field: memory
        - Type: spread
          Field: host
      PlacementConstraints:
        - Type: memberOf
          Expression: 'attribute:ecs.availability-zone != us-east-1d'
        - Type: distinctInstance
      TaskDefinition: !Ref taskdefinition
      ServiceName: !Ref ServiceName
      Role: !Ref Role
  elb:
    Type: AWS::ElasticLoadBalancing::LoadBalancer
    Properties:
      LoadBalancerName: !Ref LoadBalancerName
      Listeners:
        - InstancePort: !Ref AppHostPort
          LoadBalancerPort: '80'
          Protocol: HTTP
      Subnets:
        - !Ref Subnet1
    DependsOn: GatewayAttachment
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/24
  Subnet1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.0.0.0/25
  InternetGateway:
    Type: AWS::EC2::InternetGateway
  GatewayAttachment:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      InternetGatewayId: !Ref InternetGateway
      VpcId: !Ref VPC
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: 2008-10-17
        Statement:
          - Sid: ''
            Effect: Allow
            Principal:
              Service: ecs.amazonaws.com
            Action: 'sts:AssumeRole'
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole'
Outputs:
  Cluster:
    Value: !Ref cluster

```
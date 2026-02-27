---
title: "ECS service admin role is present"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ecs_service_admin_role_is_present"
  id: "01986452-bdd8-4aaa-b5df-d6bf61d616ff"
  display_name: "ECS service admin role is present"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `01986452-bdd8-4aaa-b5df-d6bf61d616ff`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html)

### Description

Amazon ECS services must not be assigned administrative IAM roles because a service role with admin privileges lets containers or the ECS control plane perform broad, potentially destructive actions across your account. This increases the risk of privilege escalation and data exposure.
 
 This check targets `AWS::ECS::Service` resources with a `Role` property and load balancers configured. It flags cases where `Role` is provided as a literal string that contains `admin` (case-insensitive), which commonly indicates an admin role or admin ARN.
 
 The `Role` property should reference a least-privilege IAM role (for example, reference an `AWS::IAM::Role` resource by ARN) and must not be an admin role or include `AdministratorAccess` policies. Note that this rule specifically looks for literal role names/strings containing `admin` and will not flag roles supplied via CloudFormation `Ref`. 
 
 Secure example where the service references a dedicated, scoped IAM role:

```yaml
MyECSServiceRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Principal:
            Service: ecs.amazonaws.com
          Action: sts:AssumeRole
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole

MyService:
  Type: AWS::ECS::Service
  Properties:
    Role: !GetAtt MyECSServiceRole.Arn
    LoadBalancers:
      - ContainerName: myapp
        ContainerPort: 80
        TargetGroupArn: !Ref MyTargetGroup
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
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
      Role: Role
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
Outputs:
  Cluster:
    Value: !Ref cluster
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Creating ECS service",
  "Parameters": {
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
    },
    "AppHostPort": {
      "Type": "Number",
      "Description": "Host port of app requiring ELB exposure",
      "Default": "80"
    },
    "ServiceName": {
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
                "ContainerPort": "AppContainerPort",
                "HostPort": "AppHostPort"
              }
            ],
            "EntryPoint": [
              "/usr/sbin/apache2",
              "-D",
              "FOREGROUND"
            ],
            "Memory": "500"
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
    "service": {
      "Type": "AWS::ECS::Service",
      "Properties": {
        "Role": "Role",
        "HealthCheckGracePeriodSeconds": "HealthCheckGracePeriodSeconds",
        "LoadBalancers": [
          {
            "ContainerName": "AppName",
            "ContainerPort": "AppContainerPort",
            "LoadBalancerName": "elb"
          }
        ],
        "PlacementStrategies": [
          {
            "Type": "binpack",
            "Field": "memory"
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
        "Cluster": "cluster",
        "DeploymentConfiguration": {
          "MaximumPercent": 200,
          "MinimumHealthyPercent": 100
        },
        "DesiredCount": 0,
        "ServiceName": "ServiceName"
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
    "InternetGateway": {
      "Type": "AWS::EC2::InternetGateway"
    },
    "GatewayAttachment": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "InternetGatewayId": "InternetGateway",
        "VpcId": "VPC"
      }
    }
  },
  "Outputs": {
    "Cluster": {
      "Value": "cluster"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Parameters": {
    "HealthCheckGracePeriodSeconds": {
      "Type": "String"
    },
    "AppName": {
      "Default": "simple-app",
      "Type": "String",
      "Description": "Name of app requiring ELB exposure"
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
    }
  },
  "Resources": {
    "service": {
      "Properties": {
        "DeploymentConfiguration": {
          "MaximumPercent": 200,
          "MinimumHealthyPercent": 100
        },
        "DesiredCount": 0,
        "HealthCheckGracePeriodSeconds": "HealthCheckGracePeriodSeconds",
        "ServiceName": "ServiceName",
        "Cluster": "cluster",
        "LoadBalancers": [
          {
            "ContainerName": "AppName",
            "ContainerPort": "AppContainerPort",
            "LoadBalancerName": "elb"
          }
        ],
        "PlacementStrategies": [
          {
            "Type": "binpack",
            "Field": "memory"
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
        "Role": "AdminRole"
      },
      "Type": "AWS::ECS::Service"
    },
    "elb": {
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
      "Properties": {
        "LoadBalancerName": "LoadBalancerName",
        "Listeners": [
          {
            "InstancePort": "AppHostPort",
            "LoadBalancerPort": "80",
            "Protocol": "HTTP"
          }
        ],
        "Subnets": [
          "Subnet1"
        ]
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
    "InternetGateway": {
      "Type": "AWS::EC2::InternetGateway"
    },
    "GatewayAttachment": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "InternetGatewayId": "InternetGateway",
        "VpcId": "VPC"
      }
    },
    "cluster": {
      "Type": "AWS::ECS::Cluster"
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
            "Cpu": "10",
            "PortMappings": [
              {
                "HostPort": "AppHostPort",
                "ContainerPort": "AppContainerPort"
              }
            ],
            "EntryPoint": [
              "/usr/sbin/apache2",
              "-D",
              "FOREGROUND"
            ],
            "Memory": "500",
            "Essential": true,
            "Name": "AppName"
          },
          {
            "Command": [
              "/bin/sh -c \"while true; do /bin/date \u003e /var/www/my-vol/date; sleep 1; done\""
            ],
            "Essential": false,
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
            "Memory": "500"
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
  "Outputs": {
    "Cluster": {
      "Value": "cluster"
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Creating ECS service"
}

```

```yaml
#this is a problematic code where the query should report a result(s)
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
      Role: AdminRole
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
Outputs:
  Cluster:
    Value: !Ref cluster
```
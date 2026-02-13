---
title: "Auto Scaling group with no associated ELB"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/auto_scaling_group_with_no_associated_elb"
  id: "ad21e616-5026-4b9d-990d-5b007bfe679c"
  display_name: "Auto Scaling group with no associated ELB"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Availability"
---
## Metadata

**Id:** `ad21e616-5026-4b9d-990d-5b007bfe679c`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Availability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html)

### Description

Auto Scaling groups must be associated with a load balancer to distribute traffic and maintain availability during scaling and instance replacement. Without a load balancer, instances can become single points of failure and traffic may be routed unevenly.

 In CloudFormation, the `AWS::AutoScaling::AutoScalingGroup` resource must define the `LoadBalancerNames` property, and it must be a non-empty list of Classic ELB names. Resources missing `LoadBalancerNames` or where `LoadBalancerNames` is an empty array will be flagged.

 If your environment uses Application Load Balancers (ALBs) or Network Load Balancers (NLBs), attach the Auto Scaling group to target groups via the `TargetGroupARNs` property instead, since this rule only checks `LoadBalancerNames`.

Secure configuration example:

```yaml
MyAutoScalingGroup:
  Type: AWS::AutoScaling::AutoScalingGroup
  Properties:
    LaunchConfigurationName: myLaunchConfig
    MinSize: '1'
    MaxSize: '3'
    LoadBalancerNames:
      - my-classic-elb
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: !Sub ${AWS::StackName}-launch-template
      LaunchTemplateData:
        BlockDeviceMappings:
          - Ebs:
              VolumeSize: 22
              VolumeType: gp2
              DeleteOnTermination: true
              Encrypted: true
            DeviceName: /dev/xvdcz
        CreditSpecification:
          CpuCredits: Unlimited
        ImageId: ami-02354e95b39ca8dec
        InstanceType: t2.micro
        KeyName: my-key-pair-useast1
        Monitoring:
          Enabled: true
        SecurityGroupIds:
          - sg-7c227019
          - sg-903004f8
  myASG:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: myASG
      MinSize: "1"
      MaxSize: "6"
      DesiredCapacity: "2"
      HealthCheckGracePeriod: 300
      LoadBalancerNames:
        - elb_1
        - elb_2
      LaunchTemplate:
        LaunchTemplateId: !Ref myLaunchTemplate
        Version: !GetAtt myLaunchTemplate.LatestVersionNumber
      VPCZoneIdentifier:
        - !Ref myPublicSubnet1
        - !Ref myPublicSubnet2
      MetricsCollection:
        - Granularity: "1Minute"
          Metrics:
            - "GroupMinSize"
            - "GroupMaxSize"
      Tags:
        - Key: Environment
          Value: Production
          PropagateAtLaunch: "true"
        - Key: Purpose
          Value: WebServerGroup
          PropagateAtLaunch: "false"
```

```json
{
  "Resources": {
    "myLaunchTemplate": {
      "Type": "AWS::EC2::LaunchTemplate",
      "Properties": {
        "LaunchTemplateName": "${AWS::StackName}-launch-template",
        "LaunchTemplateData": {
          "ImageId": "ami-02354e95b39ca8dec",
          "InstanceType": "t2.micro",
          "KeyName": "my-key-pair-useast1",
          "Monitoring": {
            "Enabled": true
          },
          "SecurityGroupIds": [
            "sg-7c227019",
            "sg-903004f8"
          ],
          "BlockDeviceMappings": [
            {
              "Ebs": {
                "Encrypted": true,
                "VolumeSize": 22,
                "VolumeType": "gp2",
                "DeleteOnTermination": true
              },
              "DeviceName": "/dev/xvdcz"
            }
          ],
          "CreditSpecification": {
            "CpuCredits": "Unlimited"
          }
        }
      }
    },
    "myASG": {
      "Type": "AWS::AutoScaling::AutoScalingGroup",
      "Properties": {
        "Tags": [
          {
            "Key": "Environment",
            "Value": "Production",
            "PropagateAtLaunch": "true"
          },
          {
            "Key": "Purpose",
            "Value": "WebServerGroup",
            "PropagateAtLaunch": "false"
          }
        ],
        "AutoScalingGroupName": "myASG",
        "MaxSize": "6",
        "HealthCheckGracePeriod": 300,
        "LoadBalancerNames": [
          "elb_1",
          "elb_2"
        ],
        "LaunchTemplate": {
          "LaunchTemplateId": "myLaunchTemplate",
          "Version": "myLaunchTemplate.LatestVersionNumber"
        },
        "VPCZoneIdentifier": [
          "myPublicSubnet1",
          "myPublicSubnet2"
        ],
        "MetricsCollection": [
          {
            "Granularity": "1Minute",
            "Metrics": [
              "GroupMinSize",
              "GroupMaxSize"
            ]
          }
        ],
        "MinSize": "1",
        "DesiredCapacity": "2"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myLaunchTemplate": {
      "Type": "AWS::EC2::LaunchTemplate",
      "Properties": {
        "LaunchTemplateName": "${AWS::StackName}-launch-template",
        "LaunchTemplateData": {
          "InstanceType": "t2.micro",
          "KeyName": "my-key-pair-useast1",
          "Monitoring": {
            "Enabled": true
          },
          "SecurityGroupIds": [
            "sg-7c227019",
            "sg-903004f8"
          ],
          "BlockDeviceMappings": [
            {
              "Ebs": {
                "VolumeSize": 22,
                "VolumeType": "gp2",
                "DeleteOnTermination": true,
                "Encrypted": true
              },
              "DeviceName": "/dev/xvdcz"
            }
          ],
          "CreditSpecification": {
            "CpuCredits": "Unlimited"
          },
          "ImageId": "ami-02354e95b39ca8dec"
        }
      }
    },
    "myASG": {
      "Type": "AWS::AutoScaling::AutoScalingGroup",
      "Properties": {
        "HealthCheckGracePeriod": 300,
        "LaunchTemplate": {
          "LaunchTemplateId": "myLaunchTemplate",
          "Version": "myLaunchTemplate.LatestVersionNumber"
        },
        "VPCZoneIdentifier": [
          "myPublicSubnet1",
          "myPublicSubnet2"
        ],
        "MetricsCollection": [
          {
            "Granularity": "1Minute",
            "Metrics": [
              "GroupMinSize",
              "GroupMaxSize"
            ]
          }
        ],
        "AutoScalingGroupName": "myASG",
        "MaxSize": "6",
        "DesiredCapacity": "2",
        "MinSize": "1",
        "Tags": [
          {
            "Key": "Environment",
            "Value": "Production",
            "PropagateAtLaunch": "true"
          },
          {
            "Key": "Purpose",
            "Value": "WebServerGroup",
            "PropagateAtLaunch": "false"
          }
        ]
      }
    },
    "myASG2": {
      "Type": "AWS::AutoScaling::AutoScalingGroup",
      "Properties": {
        "LoadBalancerNames": [],
        "LaunchTemplate": {
          "Version": "myLaunchTemplate.LatestVersionNumber",
          "LaunchTemplateId": "myLaunchTemplate"
        },
        "VPCZoneIdentifier": [
          "myPublicSubnet1",
          "myPublicSubnet2"
        ],
        "MinSize": "1",
        "MaxSize": "6",
        "HealthCheckGracePeriod": 300,
        "Tags": [
          {
            "Value": "Production",
            "PropagateAtLaunch": "true",
            "Key": "Environment"
          },
          {
            "Key": "Purpose",
            "Value": "WebServerGroup",
            "PropagateAtLaunch": "false"
          }
        ],
        "AutoScalingGroupName": "myASG2",
        "DesiredCapacity": "2",
        "MetricsCollection": [
          {
            "Granularity": "1Minute",
            "Metrics": [
              "GroupMinSize",
              "GroupMaxSize"
            ]
          }
        ]
      }
    },
    "myASG3": {
      "Type": "AWS::AutoScaling::AutoScalingGroup",
      "Properties": {
        "VPCZoneIdentifier": [
          "myPublicSubnet1",
          "myPublicSubnet2"
        ],
        "MaxSize": "6",
        "MinSize": "1",
        "DesiredCapacity": "2",
        "HealthCheckGracePeriod": 300,
        "LoadBalancerNames": [],
        "LaunchTemplate": {
          "LaunchTemplateId": "myLaunchTemplate",
          "Version": "myLaunchTemplate.LatestVersionNumber"
        },
        "MetricsCollection": [
          {
            "Granularity": "1Minute",
            "Metrics": [
              "GroupMinSize",
              "GroupMaxSize"
            ]
          }
        ],
        "Tags": [
          {
            "Key": "Environment",
            "Value": "Production",
            "PropagateAtLaunch": "true"
          },
          {
            "Key": "Purpose",
            "Value": "WebServerGroup",
            "PropagateAtLaunch": "false"
          }
        ],
        "AutoScalingGroupName": "myASG"
      }
    }
  }
}

```

```yaml
#this is a problematic code where the query should report a result(s)
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: !Sub ${AWS::StackName}-launch-template
      LaunchTemplateData:
        BlockDeviceMappings:
          - Ebs:
              VolumeSize: 22
              VolumeType: gp2
              DeleteOnTermination: true
              Encrypted: true
            DeviceName: /dev/xvdcz
        CreditSpecification:
          CpuCredits: Unlimited
        ImageId: ami-02354e95b39ca8dec
        InstanceType: t2.micro
        KeyName: my-key-pair-useast1
        Monitoring:
          Enabled: true
        SecurityGroupIds:
          - sg-7c227019
          - sg-903004f8
  myASG:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: myASG
      MinSize: "1"
      MaxSize: "6"
      DesiredCapacity: "2"
      HealthCheckGracePeriod: 300
      LaunchTemplate:
        LaunchTemplateId: !Ref myLaunchTemplate
        Version: !GetAtt myLaunchTemplate.LatestVersionNumber
      VPCZoneIdentifier:
        - !Ref myPublicSubnet1
        - !Ref myPublicSubnet2
      MetricsCollection:
        - Granularity: "1Minute"
          Metrics:
            - "GroupMinSize"
            - "GroupMaxSize"
      Tags:
        - Key: Environment
          Value: Production
          PropagateAtLaunch: "true"
        - Key: Purpose
          Value: WebServerGroup
          PropagateAtLaunch: "false"
  myASG2:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: myASG2
      MinSize: "1"
      MaxSize: "6"
      DesiredCapacity: "2"
      HealthCheckGracePeriod: 300
      LoadBalancerNames: []
      LaunchTemplate:
        LaunchTemplateId: !Ref myLaunchTemplate
        Version: !GetAtt myLaunchTemplate.LatestVersionNumber
      VPCZoneIdentifier:
        - !Ref myPublicSubnet1
        - !Ref myPublicSubnet2
      MetricsCollection:
        - Granularity: "1Minute"
          Metrics:
            - "GroupMinSize"
            - "GroupMaxSize"
      Tags:
        - Key: Environment
          Value: Production
          PropagateAtLaunch: "true"
        - Key: Purpose
          Value: WebServerGroup
          PropagateAtLaunch: "false"
  myASG3:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: myASG
      MinSize: "1"
      MaxSize: "6"
      DesiredCapacity: "2"
      HealthCheckGracePeriod: 300
      LoadBalancerNames: []
      LaunchTemplate:
        LaunchTemplateId: !Ref myLaunchTemplate
        Version: !GetAtt myLaunchTemplate.LatestVersionNumber
      VPCZoneIdentifier:
        - !Ref myPublicSubnet1
        - !Ref myPublicSubnet2
      MetricsCollection:
        - Granularity: "1Minute"
          Metrics:
            - "GroupMinSize"
            - "GroupMaxSize"
      Tags:
        - Key: Environment
          Value: Production
          PropagateAtLaunch: "true"
        - Key: Purpose
          Value: WebServerGroup
          PropagateAtLaunch: "false"

```
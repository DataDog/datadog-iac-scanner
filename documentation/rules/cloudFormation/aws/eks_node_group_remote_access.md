---
title: "EKS node group remote access"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/eks_node_group_remote_access"
  id: "73d59e76-a12c-4b74-a3d8-d3e1e19c25b3"
  display_name: "EKS node group remote access"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `73d59e76-a12c-4b74-a3d8-d3e1e19c25b3`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html)

### Description

Amazon EKS node groups that configure an EC2 SSH key permit SSH access to worker nodes. If that access is not limited to specific security groups, it can be reachable from untrusted networks, enabling unauthorized access and lateral movement.
 
 For `AWS::EKS::Nodegroup` resources, when `Properties.RemoteAccess.Ec2SshKey` is set, `Properties.RemoteAccess.SourceSecurityGroups` must be defined and not `null` to explicitly restrict SSH ingress to trusted security groups. Resources missing `RemoteAccess.SourceSecurityGroups` or with it set to `null` will be flagged.

Secure configuration example:

```yaml
MyNodeGroup:
  Type: AWS::EKS::Nodegroup
  Properties:
    RemoteAccess:
      Ec2SshKey: my-key
      SourceSecurityGroups:
        - sg-0123456789abcdef0
```

## Compliant Code Examples
```yaml
Resources:
  SSHAccessToNodeSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      VpcId: !Ref VpcId
      GroupName: !Sub "${Project}-${Environment}-${EKSClusterName}-ssh-access-to-workers-source-sg"
      GroupDescription: attach this sg to an instance to let it access via ssh to the eks node
      Tags:
      - Key: Environment
        Value: !Ref Environment
      - Key: Project
        Value: !Ref Project
  EKSNodegroup:
    Type: 'AWS::EKS::Nodegroup'
    Properties:
      ClusterName: prod
      NodeRole: 'arn:aws:iam::012345678910:role/eksInstanceRole'
      ScalingConfig:
        MinSize: 3
        DesiredSize: 5
        MaxSize: 7
      Labels:
        Key1: Value1
        Key2: Value2
      Subnets:
        - subnet-6782e71e
        - subnet-e7e761ac
      RemoteAccess:
        Ec2SshKey: ED25519
        SourceSecurityGroups: 
          - !Ref SSHAccessToNodeSG                            

```

```json
{
  "Resources": {
    "SSHAccessToNodeSG": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "VpcId": "VpcId",
        "GroupName": "${Project}-${Environment}-${EKSClusterName}-ssh-access-to-workers-source-sg",
        "GroupDescription": "attach this sg to an instance to let it access via ssh to the eks node",
        "Tags": [
          {
            "Key": "Environment",
            "Value": "Environment"
          },
          {
            "Key": "Project",
            "Value": "Project"
          }
        ]
      }
    },
    "EKSNodegroup": {
      "Properties": {
        "RemoteAccess": {
          "Ec2SshKey": "ED25519",
          "SourceSecurityGroups": [
            "SSHAccessToNodeSG"
          ]
        },
        "ClusterName": "prod",
        "NodeRole": "arn:aws:iam::012345678910:role/eksInstanceRole",
        "ScalingConfig": {
          "MinSize": 3,
          "DesiredSize": 5,
          "MaxSize": 7
        },
        "Labels": {
          "Key1": "Value1",
          "Key2": "Value2"
        },
        "Subnets": [
          "subnet-6782e71e",
          "subnet-e7e761ac"
        ]
      },
      "Type": "AWS::EKS::Nodegroup"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "EKSNodegroup": {
      "Type": "AWS::EKS::Nodegroup",
      "Properties": {
        "ClusterName": "prod",
        "NodeRole": "arn:aws:iam::012345678910:role/eksInstanceRole",
        "ScalingConfig": {
          "MinSize": 3,
          "DesiredSize": 5,
          "MaxSize": 7
        },
        "Labels": {
          "Key1": "Value1",
          "Key2": "Value2"
        },
        "Subnets": [
          "subnet-6782e71e",
          "subnet-e7e761ac"
        ],
        "RemoteAccess": {
          "Ec2SshKey": "ED25519"
        }
      }
    }
  }
}

```

```yaml
Resources:
  EKSNodegroup:
    Type: 'AWS::EKS::Nodegroup'
    Properties:
      ClusterName: prod
      NodeRole: 'arn:aws:iam::012345678910:role/eksInstanceRole'
      ScalingConfig:
        MinSize: 3
        DesiredSize: 5
        MaxSize: 7
      Labels:
        Key1: Value1
        Key2: Value2
      Subnets:
        - subnet-6782e71e
        - subnet-e7e761ac
      RemoteAccess:
        Ec2SshKey: ED25519

```
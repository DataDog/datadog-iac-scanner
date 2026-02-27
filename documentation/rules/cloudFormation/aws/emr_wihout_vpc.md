---
title: "EMR without VPC"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/emr_wihout_vpc"
  id: "bf89373a-be40-4c04-99f5-746742dfd7f3"
  display_name: "EMR without VPC"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `bf89373a-be40-4c04-99f5-746742dfd7f3`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-ec2subnetid)

### Description

EMR clusters must be launched inside a VPC to ensure network isolation and to allow enforcement of security controls such as security groups, private subnet routing, and network ACLs. Omitting a VPC subnet can make cluster nodes publicly reachable or prevent VPC-level access restrictions.
 
 In CloudFormation, `AWS::EMR::Cluster` resources must define either `Properties.Instances.Ec2SubnetId` (single subnet) or `Properties.Instances.Ec2SubnetIds` (list of subnets) with non-null values. Resources missing both properties or containing `null` or empty values will be flagged.

Secure configuration example:

```yaml
MyEMRCluster:
  Type: AWS::EMR::Cluster
  Properties:
    Name: my-emr-cluster
    ReleaseLabel: emr-6.10.0
    Instances:
      Ec2SubnetId: !Ref MyPrivateSubnet
      MasterInstanceGroup:
        InstanceCount: 1
        InstanceType: m5.xlarge
      CoreInstanceGroup:
        InstanceCount: 2
        InstanceType: m5.xlarge
    ServiceRole: !Ref EMRServiceRole
    JobFlowRole: !Ref EMRInstanceProfile
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  CustomAmiId:
    Type: String
  InstanceType:
    Type: String
  ReleaseLabel:
    Type: String
  SubnetId:
    Type: String
  TerminationProtected:
    Type: String
    Default: 'false'
  ElasticMapReducePrincipal:
    Type: String
  Ec2Principal:
    Type: String
Resources:
  cluster:
    Type: AWS::EMR::Cluster
    Properties:
      CustomAmiId: !Ref CustomAmiId
      Instances:
        MasterInstanceGroup:
          InstanceCount: 1
          InstanceType: !Ref InstanceType
          Market: ON_DEMAND
          Name: cfnMaster
        CoreInstanceGroup:
          InstanceCount: 1
          InstanceType: !Ref InstanceType
          Market: ON_DEMAND
          Name: cfnCore
        TerminationProtected: !Ref TerminationProtected
        Ec2SubnetId: !Ref SubnetId
      Name: CFNtest
      JobFlowRole: !Ref emrEc2InstanceProfile
      ServiceRole: !Ref emrRole
      ReleaseLabel: !Ref ReleaseLabel
      VisibleToAllUsers: true
      Tags:
        - Key: key1
          Value: value1
  emrRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: 2008-10-17
        Statement:
          - Sid: ''
            Effect: Allow
            Principal:
              Service: !Ref ElasticMapReducePrincipal
            Action: 'sts:AssumeRole'
      Path: /
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole'
  emrEc2Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: 2008-10-17
        Statement:
          - Sid: ''
            Effect: Allow
            Principal:
              Service: !Ref Ec2Principal
            Action: 'sts:AssumeRole'
      Path: /
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role'
  emrEc2InstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Path: /
      Roles:
        - !Ref emrEc2Role

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters" : {
    "CustomAmiId" : {
      "Type" : "String"
    },
    "InstanceType" : {
      "Type" : "String"
    },
    "ReleaseLabel" : {
      "Type" : "String"
    },
    "SubnetId" : {
      "Type" : "String"
    },
    "TerminationProtected" : {
      "Type" : "String",
      "Default" : "false"
    },
    "ElasticMapReducePrincipal" : {
      "Type" : "String"
    },
    "Ec2Principal" : {
      "Type" : "String"
    }
  },
  "Resources": {
    "cluster": {
      "Type": "AWS::EMR::Cluster",
      "Properties": {
        "CustomAmiId" : {"Ref" : "CustomAmiId"},
        "Instances": {
          "MasterInstanceGroup": {
            "InstanceCount": 1,
            "InstanceType": {"Ref" : "InstanceType"},
            "Market": "ON_DEMAND",
            "Name": "cfnMaster"
          },
          "CoreInstanceGroup": {
            "InstanceCount": 1,
            "InstanceType": {"Ref" : "InstanceType"},
            "Market": "ON_DEMAND",
            "Name": "cfnCore"
          },
          "TerminationProtected" : {"Ref" : "TerminationProtected"},
          "Ec2SubnetId" : {"Ref" : "SubnetId"}
        },
        "Name": "CFNtest",
        "JobFlowRole" : {"Ref": "emrEc2InstanceProfile"},
        "ServiceRole" : {"Ref": "emrRole"},
        "ReleaseLabel" : {"Ref" : "ReleaseLabel"},
        "VisibleToAllUsers" : true,
        "Tags": [
          {
            "Key": "key1",
            "Value": "value1"
          }
        ]
      }
    },
    "emrRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": {"Ref" : "ElasticMapReducePrincipal"}
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Path": "/",
        "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"]
      }
    },
    "emrEc2Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": {"Ref" : "Ec2Principal"}
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Path": "/",
        "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"]
      }
    },
    "emrEc2InstanceProfile": {
      "Type": "AWS::IAM::InstanceProfile",
      "Properties": {
        "Path": "/",
        "Roles": [ {
          "Ref": "emrEc2Role"
        } ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters" : {
    "CustomAmiId" : {
      "Type" : "String"
    },
    "InstanceType" : {
      "Type" : "String"
    },
    "ReleaseLabel" : {
      "Type" : "String"
    },
    "SubnetId" : {
      "Type" : "String"
    },
    "TerminationProtected" : {
      "Type" : "String",
      "Default" : "false"
    },
    "ElasticMapReducePrincipal" : {
      "Type" : "String"
    },
    "Ec2Principal" : {
      "Type" : "String"
    }
  },
  "Resources": {
    "cluster": {
      "Type": "AWS::EMR::Cluster",
      "Properties": {
        "CustomAmiId" : {"Ref" : "CustomAmiId"},
        "Instances": {
          "MasterInstanceGroup": {
            "InstanceCount": 1,
            "InstanceType": {"Ref" : "InstanceType"},
            "Market": "ON_DEMAND",
            "Name": "cfnMaster"
          },
          "CoreInstanceGroup": {
            "InstanceCount": 1,
            "InstanceType": {"Ref" : "InstanceType"},
            "Market": "ON_DEMAND",
            "Name": "cfnCore"
          },
          "TerminationProtected" : {"Ref" : "TerminationProtected"}
        },
        "Name": "CFNtest",
        "JobFlowRole" : {"Ref": "emrEc2InstanceProfile"},
        "ServiceRole" : {"Ref": "emrRole"},
        "ReleaseLabel" : {"Ref" : "ReleaseLabel"},
        "VisibleToAllUsers" : true,
        "Tags": [
          {
            "Key": "key1",
            "Value": "value1"
          }
        ]
      }
    },
    "emrRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": {"Ref" : "ElasticMapReducePrincipal"}
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Path": "/",
        "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"]
      }
    },
    "emrEc2Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": {"Ref" : "Ec2Principal"}
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Path": "/",
        "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"]
      }
    },
    "emrEc2InstanceProfile": {
      "Type": "AWS::IAM::InstanceProfile",
      "Properties": {
        "Path": "/",
        "Roles": [ {
          "Ref": "emrEc2Role"
        } ]
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  CustomAmiId:
    Type: String
  InstanceType:
    Type: String
  ReleaseLabel:
    Type: String
  SubnetId:
    Type: String
  TerminationProtected:
    Type: String
    Default: 'false'
  ElasticMapReducePrincipal:
    Type: String
  Ec2Principal:
    Type: String
Resources:
  cluster:
    Type: AWS::EMR::Cluster
    Properties:
      CustomAmiId: !Ref CustomAmiId
      Instances:
        MasterInstanceGroup:
          InstanceCount: 1
          InstanceType: !Ref InstanceType
          Market: ON_DEMAND
          Name: cfnMaster
        CoreInstanceGroup:
          InstanceCount: 1
          InstanceType: !Ref InstanceType
          Market: ON_DEMAND
          Name: cfnCore
        TerminationProtected: !Ref TerminationProtected
      Name: CFNtest
      JobFlowRole: !Ref emrEc2InstanceProfile
      ServiceRole: !Ref emrRole
      ReleaseLabel: !Ref ReleaseLabel
      VisibleToAllUsers: true
      Tags:
        - Key: key1
          Value: value1
  emrRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: 2008-10-17
        Statement:
          - Sid: ''
            Effect: Allow
            Principal:
              Service: !Ref ElasticMapReducePrincipal
            Action: 'sts:AssumeRole'
      Path: /
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole'
  emrEc2Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: 2008-10-17
        Statement:
          - Sid: ''
            Effect: Allow
            Principal:
              Service: !Ref Ec2Principal
            Action: 'sts:AssumeRole'
      Path: /
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role'
  emrEc2InstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Path: /
      Roles:
        - !Ref emrEc2Role

```
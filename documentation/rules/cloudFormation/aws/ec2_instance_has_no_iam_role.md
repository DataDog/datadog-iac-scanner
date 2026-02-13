---
title: "EC2 instance has no IAM role"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ec2_instance_has_no_iam_role"
  id: "f914357d-8386-4d56-9ba6-456e5723f9a6"
  display_name: "EC2 instance has no IAM role"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `f914357d-8386-4d56-9ba6-456e5723f9a6`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html)

### Description

 Amazon EC2 instances must be associated with an IAM instance profile so the instance can assume a temporary IAM role. Without a profile, workloads may require embedded long‑lived credentials or run without least‑privilege access, increasing the risk of credential exposure and excessive privileges.
 
 In CloudFormation, every `AWS::EC2::Instance` should define `Resources.<Name>.Properties.IamInstanceProfile`. That value must reference an existing `AWS::IAM::InstanceProfile` resource in the template (either a `Ref` or the resource logical name). The referenced `AWS::IAM::InstanceProfile` resource must include `Properties.Roles` with one or more role names or `Ref`s so the instance actually receives an IAM role.
 
 This rule flags EC2 instances missing `IamInstanceProfile`, instances whose `IamInstanceProfile` does not match any resource in the template, and instance profile resources that do not define `Roles`.

Secure CloudFormation example:

```yaml
MyRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Effect: Allow
          Principal:
            Service: ec2.amazonaws.com
          Action: sts:AssumeRole

MyInstanceProfile:
  Type: AWS::IAM::InstanceProfile
  Properties:
    Roles:
      - Ref: MyRole

MyInstance:
  Type: AWS::EC2::Instance
  Properties:
    IamInstanceProfile: Ref: MyInstanceProfile
    ImageId: ami-0123456789abcdef0
```


## Compliant Code Examples
```yaml

Resources:
  Test:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType:
        Ref: InstanceType
      ImageId:
        Fn::FindInMap:
        - AMIs
        - Ref: AWS::Region
        - Name
      KeyName:
        Ref: KeyName
      IamInstanceProfile:
        Ref: ListS3BucketsInstanceProfile
      SecurityGroupIds:
      - Ref: SSHAccessSG
      Tags:
      - Key: Name
        Value: Test
  ListS3BucketsInstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Path: "/"
      Roles:
      - Ref: ListS3BucketsRole
  ListS3BucketsRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Principal:
            Service:
            - ec2.amazonaws.com
          Action:
          - sts:AssumeRole
      Path: "/"
```

```json
{
  "Resources": {
    "Test": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "InstanceType": {
          "Ref": "InstanceType"
        },
        "ImageId": {
          "Fn::FindInMap": [
            "AMIs",
            {
              "Ref": "AWS::Region"
            },
            "Name"
          ]
        },
        "KeyName": {
          "Ref": "KeyName"
        },
        "IamInstanceProfile": {
          "Ref": "ListS3BucketsInstanceProfile"
        },
        "SecurityGroupIds": [
          {
            "Ref": "SSHAccessSG"
          }
        ],
        "Tags": [
          {
            "Key": "Name",
            "Value": "Test"
          }
        ]
      }
    },
    "ListS3BucketsInstanceProfile": {
      "Properties": {
        "Path": "/",
        "Roles": [
          {
            "Ref": "ListS3BucketsRole"
          }
        ]
      },
      "Type": "AWS::IAM::InstanceProfile"
    },
    "ListS3BucketsRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "ec2.amazonaws.com"
                ]
              },
              "Action": [
                "sts:AssumeRole"
              ]
            }
          ]
        },
        "Path": "/"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "NoIAM": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "InstanceType": {
          "Ref": "InstanceType"
        },
        "ImageId": {
          "Fn::FindInMap": [
            "AMIs",
            {
              "Ref": "AWS::Region"
            },
            "Name"
          ]
        },
        "KeyName": {
          "Ref": "KeyName"
        },
        "Tags": [
          {
            "Key": "Name",
            "Value": "Test"
          }
        ]
      }
    },
    "IAM_Missing": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "InstanceType": {
          "Ref": "InstanceType"
        },
        "ImageId": {
          "Fn::FindInMap": [
            "AMIs",
            {
              "Ref": "AWS::Region"
            },
            "Name"
          ]
        },
        "KeyName": {
          "Ref": "KeyName"
        },
        "IamInstanceProfile": {
          "Ref": "NoProfile"
        },
        "SecurityGroupIds": [
          {
            "Ref": "SSHAccessSG"
          }
        ],
        "Tags": [
          {
            "Key": "Name",
            "Value": "Test"
          }
        ]
      }
    },
    "IAMNoRoles": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "InstanceType": {
          "Ref": "InstanceType"
        },
        "ImageId": {
          "Fn::FindInMap": [
            "AMIs",
            {
              "Ref": "AWS::Region"
            },
            "Name"
          ]
        },
        "KeyName": {
          "Ref": "KeyName"
        },
        "IamInstanceProfile": {
          "Ref": "NoRolesProfile"
        },
        "Tags": [
          {
            "Key": "Name",
            "Value": "Test"
          }
        ]
      }
    },
    "NoRolesProfile": {
      "Type": "AWS::IAM::InstanceProfile",
      "Properties": {
        "Path": "/"
      }
    }
  }
}

```

```yaml
Resources:
  NoIAM:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType:
        Ref: InstanceType
      ImageId:
        Fn::FindInMap:
          - AMIs
          - Ref: AWS::Region
          - Name
      KeyName:
        Ref: KeyName
      Tags:
        - Key: Name
          Value: Test
  IAM_Missing:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType:
        Ref: InstanceType
      ImageId:
        Fn::FindInMap:
          - AMIs
          - Ref: AWS::Region
          - Name
      KeyName:
        Ref: KeyName
      IamInstanceProfile: NonExistantProfile
      SecurityGroupIds:
        - Ref: SSHAccessSG
      Tags:
        - Key: Name
          Value: Test
  IAMNoRoles:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType:
        Ref: InstanceType
      ImageId:
        Fn::FindInMap:
          - AMIs
          - Ref: AWS::Region
          - Name
      KeyName:
        Ref: KeyName
      IamInstanceProfile: NoRolesProfile
      Tags:
        - Key: Name
          Value: Test
  NoRolesProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Path: "/"

```

```yaml
Resources:
  NoIAM:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType:
        Ref: InstanceType
      ImageId:
        Fn::FindInMap:
          - AMIs
          - Ref: AWS::Region
          - Name
      KeyName:
        Ref: KeyName
      Tags:
        - Key: Name
          Value: Test
  IAM_Missing:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType:
        Ref: InstanceType
      ImageId:
        Fn::FindInMap:
          - AMIs
          - Ref: AWS::Region
          - Name
      KeyName:
        Ref: KeyName
      IamInstanceProfile:
        Ref: NonExistantProfile
      SecurityGroupIds:
        - Ref: SSHAccessSG
      Tags:
        - Key: Name
          Value: Test
  IAMNoRoles:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType:
        Ref: InstanceType
      ImageId:
        Fn::FindInMap:
          - AMIs
          - Ref: AWS::Region
          - Name
      KeyName:
        Ref: KeyName
      IamInstanceProfile:
        Ref: NoRolesProfile
      Tags:
        - Key: Name
          Value: Test
  NoRolesProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Path: "/"

```
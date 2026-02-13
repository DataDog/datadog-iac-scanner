---
title: "RDS associated with a public subnet"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/rds_associated_with_public_subnet"
  id: "4e88adee-a8eb-4605-a78d-9fb1096e3091"
  display_name: "RDS associated with a public subnet"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `4e88adee-a8eb-4605-a78d-9fb1096e3091`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-dbsubnetgroupname)

### Description

RDS instances must not be deployed into public subnets because public routability exposes the database to direct internet access, increasing the risk of unauthorized access, brute-force attacks, and data exfiltration. In AWS CloudFormation, verify the `AWS::RDS::DBInstance` `DBSubnetGroupName` reference and ensure the referenced `AWS::RDS::DBSubnetGroup` `SubnetIds` do not include any `AWS::EC2::Subnet` with unrestricted CIDRs. Specifically, flag subnets where `CidrBlock` equals `0.0.0.0/0` or `Ipv6CidrBlock` equals `::/0`. Database subnet groups containing such subnets will be reported as insecure.

Secure example with private subnets:

```yaml
MyPrivateSubnet1:
  Type: AWS::EC2::Subnet
  Properties:
    CidrBlock: 10.0.1.0/24
    VpcId: vpc-12345

MyPrivateSubnet2:
  Type: AWS::EC2::Subnet
  Properties:
    CidrBlock: 10.0.2.0/24
    VpcId: vpc-12345

MyDBSubnetGroup:
  Type: AWS::RDS::DBSubnetGroup
  Properties:
    DBSubnetGroupDescription: "Private subnets for RDS"
    SubnetIds:
      - !Ref MyPrivateSubnet1
      - !Ref MyPrivateSubnet2

MyDBInstance:
  Type: AWS::RDS::DBInstance
  Properties:
    DBSubnetGroupName: !Ref MyDBSubnetGroup
    Engine: mysql
    DBInstanceClass: db.t3.medium
```

## Compliant Code Examples
```yaml
Resources:
 Negative1:
  Type: AWS::RDS::DBInstance
  Properties:
    AllocatedStorage: '5'
    DBInstanceClass: db.t2.small
    Engine: oracle-ee
    LicenseModel: bring-your-own-license
    MasterUsername: master
    MasterUserPassword: SecretPassword01
    BackupRetentionPeriod: 7
    DBSubnetGroupName:
       Ref: myDBSubnetGroup0
  DeletionPolicy: Snapshot
 myDBSubnetGroup0: 
    Properties: 
      DBSubnetGroupDescription: description
      SubnetIds: 
        - Ref: mySubnet10
      Tags: 
        - 
          Key: String
          Value: String
    Type: "AWS::RDS::DBSubnetGroup"
 mySubnet10:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId:
        Ref: myVPC
      CidrBlock: 10.0.0.0/24
      AvailabilityZone: "us-east-1a"
      Tags:
      - Key: stack
        Value: production

```

```json
{
  "Resources": {
    "Negative1": {
      "DeletionPolicy": "Snapshot",
      "Properties": {
        "AllocatedStorage": "5",
        "BackupRetentionPeriod": 7,
        "DBInstanceClass": "db.t2.small",
        "DBSubnetGroupName": {
          "Ref": "myDBSubnetGroup0"
        },
        "Engine": "oracle-ee",
        "LicenseModel": "bring-your-own-license",
        "MasterUserPassword": "SecretPassword01",
        "MasterUsername": "master"
      },
      "Type": "AWS::RDS::DBInstance"
    },
    "myDBSubnetGroup0": {
      "Properties": {
        "DBSubnetGroupDescription": "description",
        "SubnetIds": [
          {
            "Ref": "mySubnet10"
          }
        ],
        "Tags": [
          {
            "Key": "String",
            "Value": "String"
          }
        ]
      },
      "Type": "AWS::RDS::DBSubnetGroup"
    },
    "mySubnet10": {
      "Properties": {
        "AvailabilityZone": "us-east-1a",
        "CidrBlock": "10.0.0.0/24",
        "Tags": [
          {
            "Key": "stack",
            "Value": "production"
          }
        ],
        "VpcId": {
          "Ref": "myVPC"
        }
      },
      "Type": "AWS::EC2::Subnet"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "Positive1": {
      "DeletionPolicy": "Snapshot",
      "Properties": {
        "AllocatedStorage": "5",
        "BackupRetentionPeriod": 7,
        "DBInstanceClass": "db.t2.small",
        "DBSubnetGroupName": {
          "Ref": "myDBSubnetGroup"
        },
        "Engine": "oracle-ee",
        "LicenseModel": "bring-your-own-license",
        "MasterUserPassword": "SecretPassword01",
        "MasterUsername": "master"
      },
      "Type": "AWS::RDS::DBInstance"
    },
    "myDBSubnetGroup": {
      "Properties": {
        "DBSubnetGroupDescription": "description",
        "SubnetIds": [
          {
            "Ref": "mySubnet1"
          },
          {
            "Ref": "mySubnet2"
          }
        ],
        "Tags": [
          {
            "Key": "String",
            "Value": "String"
          }
        ]
      },
      "Type": "AWS::RDS::DBSubnetGroup"
    },
    "mySubnet1": {
      "Properties": {
        "AvailabilityZone": "us-east-1a",
        "CidrBlock": "10.0.0.0/24",
        "Tags": [
          {
            "Key": "stack",
            "Value": "production"
          }
        ],
        "VpcId": {
          "Ref": "myVPC"
        }
      },
      "Type": "AWS::EC2::Subnet"
    },
    "mySubnet2": {
      "Properties": {
        "AvailabilityZone": "us-east-1a",
        "CidrBlock": "0.0.0.0/0",
        "Tags": [
          {
            "Key": "stack",
            "Value": "production"
          }
        ],
        "VpcId": {
          "Ref": "myVPC"
        }
      },
      "Type": "AWS::EC2::Subnet"
    }
  }
}

```

```yaml
Resources:
 Positive1:
  Type: AWS::RDS::DBInstance
  Properties:
    AllocatedStorage: '5'
    DBInstanceClass: db.t2.small
    Engine: oracle-ee
    LicenseModel: bring-your-own-license
    MasterUsername: master
    MasterUserPassword: SecretPassword01
    BackupRetentionPeriod: 7
    DBSubnetGroupName:
       Ref: myDBSubnetGroup
  DeletionPolicy: Snapshot
 myDBSubnetGroup: 
    Properties: 
      DBSubnetGroupDescription: description
      SubnetIds: 
        - Ref: mySubnet1
        - Ref: mySubnet2
      Tags: 
        - 
          Key: String
          Value: String
    Type: "AWS::RDS::DBSubnetGroup"
 mySubnet1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId:
        Ref: myVPC
      CidrBlock: 10.0.0.0/24
      AvailabilityZone: "us-east-1a"
      Tags:
      - Key: stack
        Value: production
 mySubnet2:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId:
        Ref: myVPC
      CidrBlock: 0.0.0.0/0
      AvailabilityZone: "us-east-1a"
      Tags:
      - Key: stack
        Value: production

```
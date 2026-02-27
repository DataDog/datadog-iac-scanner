---
title: "DB security group open to large scope"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/db_security_group_open_to_large_scope"
  id: "0104165b-02d5-426f-abc9-91fb48189899"
  display_name: "DB security group open to large scope"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `0104165b-02d5-426f-abc9-91fb48189899`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html)

### Description

Ingress rules that use large CIDR blocks grant network access to hundreds or thousands of hosts. This increases attack surface and raises the risk of unauthorized access, brute-force attacks, and lateral movement.

 For CloudFormation:
 - For `AWS::EC2::SecurityGroup` resources, `Properties.SecurityGroupIngress` IPv4 entries (`CidrIp`) must use prefix lengths of `/25` through `/32`, and IPv6 entries (`CidrIpv6`) must use `/120` through `/128`.
 - For `AWS::RDS::DBSecurityGroup` resources, `DBSecurityGroupIngress.CIDRIP` IPv4 values must also use `/25` through `/32`.

 Resources missing these properties or that specify less specific prefixes (for example, `/24` or shorter for IPv4, or `/119` or shorter for IPv6) will be flagged. Remediate by replacing broad CIDR blocks with narrower CIDRs, specific host addresses, or security-group references so each ingress entry meets the required prefix length.

Secure examples (CloudFormation YAML):

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Allow limited IPv4 and IPv6 access
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 203.0.113.0/25
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIpv6: 2001:db8::/120
```

```yaml
MyDBSecurityGroup:
  Type: AWS::RDS::DBSecurityGroup
  Properties:
    DBSecurityGroupIngress:
      - CIDRIP: 203.0.113.0/25
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
Resources:
  DBinstance:
    Type: AWS::RDS::DBInstance
    Properties:
      DBSecurityGroups:
        -
          Ref: "DbSecurityByEC2SecurityGroup"
      AllocatedStorage: "5"
      DBInstanceClass: "db.t3.small"
      Engine: "MySQL"
      MasterUsername: "YourName"
      MasterUserPassword: "YourPassword"
    DeletionPolicy: "Snapshot"
  DbSecurityByEC2SecurityGroup:
    Type: AWS::RDS::DBSecurityGroup
    Properties:
      GroupDescription: "Ingress for Amazon EC2 security group"
      DBSecurityGroupIngress:
        CIDRIP: 1.2.3.4/28
```

```json
{
  "Resources": {
    "DBinstance": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "MasterUsername": "YourName",
        "MasterUserPassword": "YourPassword",
        "DBSecurityGroups": [
          {
            "Ref": "DbSecurityByEC2SecurityGroup"
          }
        ],
        "AllocatedStorage": "5",
        "DBInstanceClass": "db.t3.small",
        "Engine": "MySQL"
      },
      "DeletionPolicy": "Snapshot"
    },
    "DbSecurityByEC2SecurityGroup": {
      "Type": "AWS::RDS::DBSecurityGroup",
      "Properties": {
        "GroupDescription": "Ingress for Amazon EC2 security group",
        "DBSecurityGroupIngress": {
          "CIDRIP": "1.2.3.4/28"
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
Resources:
  DBinstance2:
    Type: AWS::RDS::DBInstance
    Properties:
      DBSecurityGroups:
        -
          Ref: "DbSecurityByEC2SecurityGroup1"
      AllocatedStorage: "5"
      DBInstanceClass: "db.t3.small"
      Engine: "MySQL"
      MasterUsername: "YourName"
      MasterUserPassword: "YourPassword"
    DeletionPolicy: "Snapshot"
  DbSecurityByEC2SecurityGroup1:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: "Ingress for Amazon EC2 security group"
      SecurityGroupIngress:
        CidrIp: 1.2.3.4/23

```

```yaml
Resources:
  DBinstance3:
    Type: AWS::RDS::DBInstance
    Properties:
      DBSecurityGroups:
        -
          Ref: "DbSecurityByEC2SecurityGroup2"
      AllocatedStorage: "5"
      DBInstanceClass: "db.t3.small"
      Engine: "MySQL"
      MasterUsername: "YourName"
      MasterUserPassword: "YourPassword"
    DeletionPolicy: "Snapshot"
  DbSecurityByEC2SecurityGroup2:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: "Ingress for Amazon EC2 security group"
      SecurityGroupIngress:
        CidrIpv6: 2001:db8:a::123/64

```

```json
{
  "Resources": {
    "DBinstance2": {
      "DeletionPolicy": "Snapshot",
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "DBSecurityGroups": [
          {
            "Ref": "DbSecurityByEC2SecurityGroup1"
          }
        ],
        "AllocatedStorage": "5",
        "DBInstanceClass": "db.t3.small",
        "Engine": "MySQL",
        "MasterUsername": "YourName",
        "MasterUserPassword": "YourPassword"
      }
    },
    "DbSecurityByEC2SecurityGroup1": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Ingress for Amazon EC2 security group",
        "SecurityGroupIngress": {
          "CidrIp": "1.2.3.4/23"
        }
      }
    }
  }
}

```
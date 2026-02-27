---
title: "Redshift publicly accessible"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/redshift_publicly_accessible"
  id: "bdf8dcb4-75df-4370-92c4-606e4ae6c4d3"
  display_name: "Redshift publicly accessible"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `bdf8dcb4-75df-4370-92c4-606e4ae6c4d3`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html)

### Description

Redshift clusters must not be publicly accessible because exposure to the public internet increases the risk of unauthorized data access and expands the attack surface for brute-force or other network-based attacks. In AWS CloudFormation, `AWS::Redshift::Cluster` resources must include the `PubliclyAccessible` property and set it to `false`. Resources missing this property or with `PubliclyAccessible` set to `true` will be flagged as a security finding.

Secure configuration example:

```yaml
MyRedshiftCluster:
  Type: AWS::Redshift::Cluster
  Properties:
    PubliclyAccessible: false
    # other required properties...
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
Resources:
  myCluster:
    Type: "AWS::Redshift::Cluster"
    Properties:
      PubliclyAccessible: false
      DBName: "mydb"
      MasterUsername: "master"
      MasterUserPassword:
        Ref: "MasterUserPassword"
      NodeType: "ds2.xlarge"
      ClusterType: "single-node"
      Tags:
        - Key: foo
          Value: bar

```

```json
{
  "Resources": {
    "myCluster": {
      "Type": "AWS::Redshift::Cluster",
      "Properties": {
        "MasterUserPassword": {
          "Ref": "MasterUserPassword"
        },
        "NodeType": "ds2.xlarge",
        "ClusterType": "single-node",
        "Tags": [
          {
            "Value": "bar",
            "Key": "foo"
          }
        ],
        "PubliclyAccessible": false,
        "DBName": "mydb",
        "MasterUsername": "master"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "myCluster": {
      "Type": "AWS::Redshift::Cluster",
      "Properties": {
        "NodeType": "ds2.xlarge",
        "ClusterType": "single-node",
        "Tags": [
          {
            "Key": "foo",
            "Value": "bar"
          }
        ],
        "DBName": "mydb",
        "MasterUsername": "master",
        "MasterUserPassword": {
          "Ref": "MasterUserPassword"
        }
      }
    },
    "myCluster2": {
      "Type": "AWS::Redshift::Cluster",
      "Properties": {
        "Tags": [
          {
            "Key": "foo",
            "Value": "bar"
          }
        ],
        "PubliclyAccessible": true,
        "DBName": "mydb",
        "MasterUsername": "master",
        "MasterUserPassword": {
          "Ref": "MasterUserPassword"
        },
        "NodeType": "ds2.xlarge",
        "ClusterType": "single-node"
      }
    }
  }
}

```

```yaml
Resources:
  myCluster:
    Type: "AWS::Redshift::Cluster"
    Properties:
      DBName: "mydb"
      MasterUsername: "master"
      MasterUserPassword:
        Ref: "MasterUserPassword"
      NodeType: "ds2.xlarge"
      ClusterType: "single-node"
      Tags:
        - Key: foo
          Value: bar
  myCluster2:
    Type: "AWS::Redshift::Cluster"
    Properties:
      PubliclyAccessible: true
      DBName: "mydb"
      MasterUsername: "master"
      MasterUserPassword:
        Ref: "MasterUserPassword"
      NodeType: "ds2.xlarge"
      ClusterType: "single-node"
      Tags:
        - Key: foo
          Value: bar

```
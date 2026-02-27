---
title: "Redshift using default port"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/redshift_using_default_port"
  id: "a478af30-8c3a-404d-aa64-0b673cee509a"
  display_name: "Redshift using default port"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `a478af30-8c3a-404d-aa64-0b673cee509a`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html#cfn-redshift-cluster-port)

### Description

Redshift clusters must not use the default TCP port `5439` because predictable ports make it easier for attackers and automated scanners to discover and target database endpoints, increasing the risk of unauthorized access attempts. In AWS CloudFormation, the `AWS::Redshift::Cluster` resource must include the `Port` property and set it to a non-default value (not `5439`). Resources missing `Port` or with `Port` set to `5439` will be flagged. Choose a port within Redshift's valid range (`1024`–`65535`) and update security groups and client configurations to allow only trusted sources. This is a defense-in-depth control and does not replace proper network access restrictions and authentication controls.

Secure configuration example:

```yaml
MyRedshiftCluster:
  Type: AWS::Redshift::Cluster
  Properties:
    Port: 15432
```

## Compliant Code Examples
```yaml
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
      Port: 1150

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
          "MasterUsername": "master",
          "Port": "1150"
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
        "PubliclyAccessible": true,
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
        "ClusterType": "single-node",
        "Port": 5439
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
  myCluster2:
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
      Port: 5439

```
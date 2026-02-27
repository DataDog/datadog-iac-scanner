---
title: "ECS cluster with Container Insights disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ecs_cluster_container_insights_disabled"
  id: "ab759fde-e1e8-4b0e-ad73-ba856e490ed8"
  display_name: "ECS cluster with Container Insights disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `ab759fde-e1e8-4b0e-ad73-ba856e490ed8`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-cluster.html#cfn-ecs-cluster-clustersettings)

### Description

Amazon ECS clusters should have Container Insights enabled to collect container-level metrics and logs for monitoring, performance troubleshooting, and security visibility.
 
 The `ClusterSettings` property in `AWS::ECS::Cluster` resources must include a `ClusterSetting` with `Name` set to `containerInsights` and `Value` set to `enabled`. Resources missing `ClusterSettings` or without an entry setting `containerInsights` to `enabled` will be flagged.

Secure configuration example:

```yaml
MyCluster:
  Type: AWS::ECS::Cluster
  Properties:
    ClusterSettings:
      - Name: containerInsights
        Value: enabled
```

## Compliant Code Examples
```yaml
Resources:
  ECSCluster:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled
      Tags:
        - Key: environment
          Value: production
```

```json
{
  "Resources": {
    "ECSCluster": {
      "Type": "AWS::ECS::Cluster",
      "Properties": {
        "ClusterName": "MyCluster",
        "ClusterSettings": [
          {
              "Name": "containerInsights",
              "Value": "enabled"
          }
        ],
        "Tags": [
          {
              "Key": "environment",
              "Value": "production"
          }
        ]
      }
    }
  }
}
```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "ECSCluster": {
      "Type": "AWS::ECS::Cluster",
      "Properties": {
        "ClusterName": "MyCluster",
        "ClusterSettings": [
          {
              "Name": "containerInsights",
              "Value": "disabled"
          }
        ],
        "Tags": [
          {
              "Key": "environment",
              "Value": "production"
          }
        ]
      }
    }
  }
}
```

```json
{
  "Resources": {
    "ECSCluster": {
      "Type": "AWS::ECS::Cluster",
      "Properties": {
        "ClusterName": "MyCluster",
        "ClusterSettings": [],
        "Tags": [
          {
              "Key": "environment",
              "Value": "production"
          }
        ]
      }
    }
  }
}
```

```yaml
Resources:
  ECSCluster:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
      Tags:
        - Key: environment
          Value: production
```
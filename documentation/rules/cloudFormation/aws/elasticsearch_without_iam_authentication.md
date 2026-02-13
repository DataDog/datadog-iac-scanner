---
title: "Elasticsearch without IAM authentication"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elasticsearch_without_iam_authentication"
  id: "5c666ed9-b586-49ab-9873-c495a833b705"
  display_name: "Elasticsearch without IAM authentication"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `5c666ed9-b586-49ab-9873-c495a833b705`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-accesspolicies)

### Description

 Elasticsearch domains must not grant access to wildcard or anonymous principals because such policies allow unauthenticated access to cluster APIs and data, risking data exposure and unauthorized configuration changes.
 
 In CloudFormation, verify `AWS::Elasticsearch::Domain` resources. The `Properties.AccessPolicies.Statement[].Principal` value must specify explicit IAM principals (for example, AWS account IDs or role/user/service ARNs). It must not be the literal `"*"` and must not include `AWS="*"` (or equivalent wildcard principals). Resources with `Principal="*"` or `Principal.AWS="*"` (or other any-principal patterns) will be flagged. Instead, scope access to specific ARNs, AWS account numbers, or IAM roles/users. You can also combine principals with conditions such as `aws:SourceVpc` or `aws:SourceIp` to limit exposure.

Secure configuration example (CloudFormation YAML):

```yaml
MyEsDomain:
  Type: AWS::Elasticsearch::Domain
  Properties:
    DomainName: my-domain
    AccessPolicies:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:role/EsAccessRole
          Action: es:ESHttp*
          Resource: arn:aws:es:us-west-2:123456789012:domain/my-domain/*
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Creates ES
Resources:
  ElasticsearchDomain:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: "test"
      ElasticsearchVersion: "7.10"
      ElasticsearchClusterConfig:
        DedicatedMasterEnabled: true
        InstanceCount: "2"
        ZoneAwarenessEnabled: true
        InstanceType: "m3.medium.elasticsearch"
        DedicatedMasterType: "m3.medium.elasticsearch"
        DedicatedMasterCount: "3"
      EBSOptions:
        EBSEnabled: true
        Iops: "0"
        VolumeSize: "20"
        VolumeType: "gp2"
      AccessPolicies:
        Version: "2012-10-17"
        Statement:
          - Effect: "Allow"
            Principal:
              AWS: "arn:aws:iam::123456789012:user/es-user"
            Action: "es:*"
            Resource: "arn:aws:es:us-east-1:846973539254:domain/test/*"
      LogPublishingOptions:
        ES_APPLICATION_LOGS:
          CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-application-logs"
          Enabled: true
        SEARCH_SLOW_LOGS:
          CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-slow-logs"
          Enabled: true
        INDEX_SLOW_LOGS:
          CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-index-slow-logs"
          Enabled: true
      AdvancedOptions:
        rest.action.multi.allow_explicit_index: true

```

```json
{
  "Resources": {
    "ElasticsearchDomain": {
      "Type": "AWS::Elasticsearch::Domain",
      "Properties": {
        "DomainName": "test",
        "ElasticsearchVersion": "7.10",
        "ElasticsearchClusterConfig": {
          "DedicatedMasterEnabled": true,
          "InstanceCount": "2",
          "ZoneAwarenessEnabled": true,
          "InstanceType": "m3.medium.elasticsearch",
          "DedicatedMasterType": "m3.medium.elasticsearch",
          "DedicatedMasterCount": "3"
        },
        "EBSOptions": {
          "EBSEnabled": true,
          "Iops": "0",
          "VolumeSize": "20",
          "VolumeType": "gp2"
        },
        "AccessPolicies": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/es-user"
              },
              "Action": "es:*",
              "Resource": "arn:aws:es:us-east-1:123456789012:domain/test/*"
            }
          ]
        },
        "LogPublishingOptions": {
          "ES_APPLICATION_LOGS": {
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-application-logs",
            "Enabled": true
          },
          "SEARCH_SLOW_LOGS": {
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-slow-logs",
            "Enabled": true
          },
          "INDEX_SLOW_LOGS": {
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-index-slow-logs",
            "Enabled": true
          }
        },
        "AdvancedOptions": {
          "rest.action.multi.allow_explicit_index": true
        }
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Creates RDS Cluster"
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "ElasticsearchDomain": {
      "Type": "AWS::Elasticsearch::Domain",
      "Properties": {
        "DomainName": "test",
        "ElasticsearchVersion": "7.10",
        "ElasticsearchClusterConfig": {
          "DedicatedMasterEnabled": true,
          "InstanceCount": "2",
          "ZoneAwarenessEnabled": true,
          "InstanceType": "m3.medium.elasticsearch",
          "DedicatedMasterType": "m3.medium.elasticsearch",
          "DedicatedMasterCount": "3"
        },
        "EBSOptions": {
          "EBSEnabled": true,
          "Iops": "0",
          "VolumeSize": "20",
          "VolumeType": "gp2"
        },
        "AccessPolicies": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": "*"
              },
              "Action": "es:*",
              "Resource": "arn:aws:es:us-east-1:123456789012:domain/test/*"
            }
          ]
        },
        "LogPublishingOptions": {
          "ES_APPLICATION_LOGS": {
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-application-logs",
            "Enabled": true
          },
          "SEARCH_SLOW_LOGS": {
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-slow-logs",
            "Enabled": true
          },
          "INDEX_SLOW_LOGS": {
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-index-slow-logs",
            "Enabled": true
          }
        },
        "AdvancedOptions": {
          "rest.action.multi.allow_explicit_index": true
        }
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Creates RDS Cluster"
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Creates ES
Resources:
  ElasticsearchDomain:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: "test"
      ElasticsearchVersion: "7.10"
      ElasticsearchClusterConfig:
        DedicatedMasterEnabled: true
        InstanceCount: "2"
        ZoneAwarenessEnabled: true
        InstanceType: "m3.medium.elasticsearch"
        DedicatedMasterType: "m3.medium.elasticsearch"
        DedicatedMasterCount: "3"
      EBSOptions:
        EBSEnabled: true
        Iops: "0"
        VolumeSize: "20"
        VolumeType: "gp2"
      AccessPolicies:
        Version: "2012-10-17"
        Statement:
          - Effect: "Allow"
            Principal:
              AWS: "*"
            Action: "es:*"
            Resource: "arn:aws:es:us-east-1:846973539254:domain/test/*"
      LogPublishingOptions:
        ES_APPLICATION_LOGS:
          CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-application-logs"
          Enabled: true
        SEARCH_SLOW_LOGS:
          CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-slow-logs"
          Enabled: true
        INDEX_SLOW_LOGS:
          CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-index-slow-logs"
          Enabled: true
      AdvancedOptions:
        rest.action.multi.allow_explicit_index: true

```
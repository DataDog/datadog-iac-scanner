---
title: "Elasticsearch without slow logs"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elasticsearch_without_slow_logs"
  id: "086ea2eb-14a6-4fd4-914b-38e0bc8703e8"
  display_name: "Elasticsearch without slow logs"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `086ea2eb-14a6-4fd4-914b-38e0bc8703e8`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-logpublishingoptions)

### Description

 Elasticsearch domains must publish slow logs to detect and investigate performance anomalies and suspicious query activity. Without slow logs, you cannot audit slow or resource-intensive queries that may indicate abuse, data exfiltration, or misconfiguration.
 
 In CloudFormation, `AWS::Elasticsearch::Domain` resources must define `Properties.LogPublishingOptions` and include `INDEX_SLOW_LOGS` and/or `SEARCH_SLOW_LOGS` entries with their `Enabled` property set to `true`. Resources missing `LogPublishingOptions`, missing the slow-log keys, or with `Enabled` set to `false` will be flagged. 
 
 Secure configuration example:

```yaml
MyDomain:
  Type: AWS::Elasticsearch::Domain
  Properties:
    DomainName: my-domain
    LogPublishingOptions:
      INDEX_SLOW_LOGS:
        CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:/aws/elasticsearch/index-slow
        Enabled: true
      SEARCH_SLOW_LOGS:
        CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:/aws/elasticsearch/search-slow
        Enabled: true
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: ElasticsearchDomain resource
Resources:
  ElasticsearchDomain:
    Type: "AWS::Elasticsearch::Domain"
    Properties:
      DomainName:
        Ref: DomainName
      ElasticsearchVersion:
        Ref: ElasticsearchVersion
      ElasticsearchClusterConfig:
        InstanceCount: "1"
        InstanceType:
          Ref: InstanceType
      EBSOptions:
        EBSEnabled: "true"
        Iops: 0
        VolumeSize: 10
        VolumeType: standard
      SnapshotOptions:
        AutomatedSnapshotStartHour: "0"
      AccessPolicies:
        Version: "2012-10-17"
        Statement:
          - Effect: Deny
            Principal:
              AWS: "*"
            Action: "es:*"
            Resource: "*"
      LogPublishingOptions:
        SEARCH_SLOW_LOGS:
          CloudWatchLogsLogGroupArn: >-
            arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-slow-logs
          Enabled: "true"
        INDEX_SLOW_LOGS:
          CloudWatchLogsLogGroupArn: >-
            arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-index-slow-logs
          Enabled: "true"
      AdvancedOptions:
        rest.action.multi.allow_explicit_index: "true"

```

```json
{
  "document": [
    {
      "AWSTemplateFormatVersion": "2010-09-09",
      "Description": "ElasticsearchDomain resource",
      "Resources": {
        "ElasticsearchDomain": {
          "Type": "AWS::Elasticsearch::Domain",
          "Properties": {
            "AdvancedOptions": {
              "rest.action.multi.allow_explicit_index": "true"
            },
            "DomainName": {
              "Ref": "DomainName"
            },
            "ElasticsearchVersion": {
              "Ref": "ElasticsearchVersion"
            },
            "ElasticsearchClusterConfig": {
              "InstanceCount": "1",
              "InstanceType": {
                "Ref": "InstanceType"
              }
            },
            "EBSOptions": {
              "Iops": 0,
              "VolumeSize": 10,
              "VolumeType": "standard",
              "EBSEnabled": "true"
            },
            "SnapshotOptions": {
              "AutomatedSnapshotStartHour": "0"
            },
            "AccessPolicies": {
              "Statement": [
                {
                  "Effect": "Deny",
                  "Principal": {
                    "AWS": "*"
                  },
                  "Action": "es:*",
                  "Resource": "*"
                }
              ],
              "Version": "2012-10-17"
            },
            "LogPublishingOptions": {
              "SEARCH_SLOW_LOGS": {
                "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-slow-logs",
                "Enabled": "true"
              },
              "INDEX_SLOW_LOGS": {
                "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-index-slow-logs",
                "Enabled": "true"
              }
            }
          }
        }
      },
      "id": "c886b8d1-8c44-4f23-ba01-6e30a2f5be7b",
      "file": "C:\\Users\\foo\\Desktop\\Data\\yaml\\yaml.yaml"
    }
  ]
}

```

```yaml
Resources:
  ProductionElasticsearch:
    Type: AWS::Elasticsearch::Domain
    Properties:
      EBSOptions:
        EBSEnabled: true
        VolumeSize: 70
        VolumeType: gp2
      ElasticsearchClusterConfig:
        DedicatedMasterCount: 3
        DedicatedMasterEnabled: true
        DedicatedMasterType: omitted
        InstanceCount: 3
        InstanceType: omitted
        ZoneAwarenessConfig:
          AvailabilityZoneCount: 3
        ZoneAwarenessEnabled: true
      ElasticsearchVersion: omitted
      LogPublishingOptions:
        "INDEX_SLOW_LOGS":
          CloudWatchLogsLogGroupArn: !GetAtt ProductionElasticsearchIndexSlowLogs.Arn
          Enabled: true
        "SEARCH_SLOW_LOGS":
          CloudWatchLogsLogGroupArn: !GetAtt ProductionElasticsearchSearchSlowLogs.Arn
          Enabled: true
        "ES_APPLICATION_LOGS":
          CloudWatchLogsLogGroupArn: !GetAtt ProductionElasticsearchApplicationLogs.Arn
          Enabled: true

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: ElasticsearchDomain resource
Resources:
  ElasticsearchDomain:
    Type: "AWS::Elasticsearch::Domain"
    Properties:
      DomainName:
        Ref: DomainName
      ElasticsearchVersion:
        Ref: ElasticsearchVersion
      ElasticsearchClusterConfig:
        InstanceCount: "1"
        InstanceType:
          Ref: InstanceType
      EBSOptions:
        EBSEnabled: "true"
        Iops: 0
        VolumeSize: 10
        VolumeType: standard
      SnapshotOptions:
        AutomatedSnapshotStartHour: "0"
      AccessPolicies:
        Version: "2012-10-17"
        Statement:
          - Effect: Deny
            Principal:
              AWS: "*"
            Action: "es:*"
            Resource: "*"
      LogPublishingOptions:
        ES_APPLICATION_LOGS:
          CloudWatchLogsLogGroupArn: >-
            arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-index-slow-logs
          Enabled: "true"
      AdvancedOptions:
        rest.action.multi.allow_explicit_index: "true"

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: ElasticsearchDomain resource
Resources:
  ElasticsearchDomain:
    Type: "AWS::Elasticsearch::Domain"
    Properties:
      DomainName:
        Ref: DomainName
      ElasticsearchVersion:
        Ref: ElasticsearchVersion
      ElasticsearchClusterConfig:
        InstanceCount: "1"
        InstanceType:
          Ref: InstanceType
      EBSOptions:
        EBSEnabled: "true"
        Iops: 0
        VolumeSize: 10
        VolumeType: standard
      SnapshotOptions:
        AutomatedSnapshotStartHour: "0"
      AccessPolicies:
        Version: "2012-10-17"
        Statement:
          - Effect: Deny
            Principal:
              AWS: "*"
            Action: "es:*"
            Resource: "*"
      AdvancedOptions:
        rest.action.multi.allow_explicit_index: "true"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "ElasticsearchDomain resource",
  "Resources": {
    "ElasticsearchDomain": {
      "Type": "AWS::Elasticsearch::Domain",
      "Properties": {
        "DomainName": {
          "Ref": "DomainName"
        },
        "ElasticsearchVersion": {
          "Ref": "ElasticsearchVersion"
        },
        "ElasticsearchClusterConfig": {
          "InstanceCount": "1",
          "InstanceType": {
            "Ref": "InstanceType"
          }
        },
        "EBSOptions": {
          "Iops": 0,
          "VolumeSize": 10,
          "VolumeType": "standard",
          "EBSEnabled": "true"
        },
        "SnapshotOptions": {
          "AutomatedSnapshotStartHour": "0"
        },
        "AccessPolicies": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": "es:*",
              "Resource": "*",
              "Effect": "Deny",
              "Principal": {
                "AWS": "*"
              }
            }
          ]
        },
        "LogPublishingOptions": {
          "ES_APPLICATION_LOGS": {
            "Enabled": "true",
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-slow-logs"
          }
        },
        "AdvancedOptions": {
          "rest.action.multi.allow_explicit_index": "true"
        }
      }
    }
  }
}

```
---
title: "Elasticsearch logs disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elasticsearch_logs_disabled"
  id: "edbd62d4-8700-41de-b000-b3cfebb5e996"
  display_name: "Elasticsearch logs disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `edbd62d4-8700-41de-b000-b3cfebb5e996`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-logpublishingoptions)

### Description

 Elasticsearch domains must publish slow logs, application logs, and audit logs so you can detect suspicious or malicious activity and perform operational troubleshooting and compliance auditing.
 
 In CloudFormation, `AWS::Elasticsearch::Domain` resources must define `Properties.LogPublishingOptions` entries for each relevant log type (`INDEX_SLOW_LOGS`, `SEARCH_SLOW_LOGS`, `ES_APPLICATION_LOGS`, `AUDIT_LOGS`). For each entry, the `Enabled` property must be set to `true`. Resources that omit `LogPublishingOptions`, omit an `Enabled` key for a log type, or have `Enabled` set to `false` will be flagged. 
 
 Secure configuration example (enable each log type and point to an Amazon CloudWatch Logs log group):

```yaml
MyDomain:
  Type: AWS::Elasticsearch::Domain
  Properties:
    DomainName: my-domain
    LogPublishingOptions:
      INDEX_SLOW_LOGS:
        CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:es-index-slow
        Enabled: true
      SEARCH_SLOW_LOGS:
        CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:es-search-slow
        Enabled: true
      ES_APPLICATION_LOGS:
        CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:es-app-logs
        Enabled: true
      AUDIT_LOGS:
        CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:es-audit-logs
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
        ES_APPLICATION_LOGS:
          CloudWatchLogsLogGroupArn: >-
            arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-application-logs
          Enabled: "true"
        AUDIT_LOGS:
          CloudWatchLogsLogGroupArn: >-
            arn:aws:logs:us-east-1:123456789012:log-group:/aws/aes/domains/es-audit-logs
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
        "AUDIT_LOGS":
          CloudWatchLogsLogGroupArn: !GetAtt ProductionElasticsearchAuditLogs.Arn
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
          "SEARCH_SLOW_LOGS": {
            "Enabled": "false",
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
          "SEARCH_SLOW_LOGS": {
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
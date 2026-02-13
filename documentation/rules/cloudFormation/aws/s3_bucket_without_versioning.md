---
title: "S3 bucket without versioning"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_without_versioning"
  id: "a227ec01-f97a-4084-91a4-47b350c1db54"
  display_name: "S3 bucket without versioning"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `a227ec01-f97a-4084-91a4-47b350c1db54`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html)

### Description

 S3 buckets should have object versioning enabled to protect data from accidental or malicious deletion. Versioning also preserves prior object states for recovery and auditing.

In CloudFormation, `AWS::S3::Bucket` resources must include `Properties.VersioningConfiguration.Status` set to `Enabled`. Resources that omit `VersioningConfiguration`, or have `VersioningConfiguration.Status` set to `Suspended`, will be flagged.

Secure configuration example:

```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: my-bucket
    VersioningConfiguration:
      Status: Enabled
```


## Compliant Code Examples
```yaml
Resources:
  RecordServiceS3Bucket:
    Type: 'AWS::S3::Bucket'
    DeletionPolicy: Retain
    Properties:
      ReplicationConfiguration:
        Role:
          'Fn::GetAtt':
            - WorkItemBucketBackupRole
            - Arn
        Rules:
          - Destination:
              Bucket:
                'Fn::Join':
                  - ''
                  - - 'arn:aws:s3:::'
                    - 'Fn::Join':
                        - '-'
                        - - Ref: 'AWS::Region'
                          - Ref: 'AWS::StackName'
                          - replicationbucket
              StorageClass: STANDARD
            Id: Backup
            Prefix: ''
            Status: Enabled
      VersioningConfiguration:
        Status: Enabled

```

```json
{
  "Resources": {
    "RecordServiceS3Bucket": {
      "Type": "AWS::S3::Bucket",
      "DeletionPolicy": "Retain",
      "Properties": {
        "ReplicationConfiguration": {
          "Rules": [
            {
              "Id": "Backup",
              "Prefix": "",
              "Status": "Enabled",
              "Destination": {
                "Bucket": {
                  "Fn::Join": [
                    "",
                    [
                      "arn:aws:s3:::",
                      {
                        "Fn::Join": [
                          "-",
                          [
                            {
                              "Ref": "AWS::Region"
                            },
                            {
                              "Ref": "AWS::StackName"
                            },
                            "replicationbucket"
                          ]
                        ]
                      }
                    ]
                  ]
                },
                "StorageClass": "STANDARD"
              }
            }
          ],
          "Role": {
            "Fn::GetAtt": [
              "WorkItemBucketBackupRole",
              "Arn"
            ]
          }
        },
        "VersioningConfiguration": {
          "Status": "Enabled"
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
Resources:
  RecordServiceS3Bucket2:
    Type: 'AWS::S3::Bucket'
    DeletionPolicy: Retain
    Properties:
      ReplicationConfiguration:
        Role:
          'Fn::GetAtt':
            - WorkItemBucketBackupRole
            - Arn
        Rules:
          - Destination:
              Bucket:
                'Fn::Join':
                  - ''
                  - - 'arn:aws:s3:::'
                    - 'Fn::Join':
                        - '-'
                        - - Ref: 'AWS::Region'
                          - Ref: 'AWS::StackName'
                          - replicationbucket
              StorageClass: STANDARD
            Id: Backup
            Prefix: ''
            Status: Enabled
      VersioningConfiguration:
        Status: Suspended

```

```json
{
  "Resources": {
    "RecordServiceS3Bucket": {
      "Properties": {
        "ReplicationConfiguration": {
          "Role": {
            "Fn::GetAtt": [
              "WorkItemBucketBackupRole",
              "Arn"
            ]
          },
          "Rules": [
            {
              "Id": "Backup",
              "Prefix": "",
              "Status": "Enabled",
              "Destination": {
                "Bucket": {
                  "Fn::Join": [
                    "",
                    [
                      "arn:aws:s3:::",
                      {
                        "Fn::Join": [
                          "-",
                          [
                            {
                              "Ref": "AWS::Region"
                            },
                            {
                              "Ref": "AWS::StackName"
                            },
                            "replicationbucket"
                          ]
                        ]
                      }
                    ]
                  ]
                },
                "StorageClass": "STANDARD"
              }
            }
          ]
        }
      },
      "Type": "AWS::S3::Bucket",
      "DeletionPolicy": "Retain"
    }
  }
}

```

```json
{
  "Resources": {
    "RecordServiceS3Bucket2": {
      "Type": "AWS::S3::Bucket",
      "DeletionPolicy": "Retain",
      "Properties": {
        "ReplicationConfiguration": {
          "Rules": [
            {
              "Destination": {
                "Bucket": {
                  "Fn::Join": [
                    "",
                    [
                      "arn:aws:s3:::",
                      {
                        "Fn::Join": [
                          "-",
                          [
                            {
                              "Ref": "AWS::Region"
                            },
                            {
                              "Ref": "AWS::StackName"
                            },
                            "replicationbucket"
                          ]
                        ]
                      }
                    ]
                  ]
                },
                "StorageClass": "STANDARD"
              },
              "Id": "Backup",
              "Prefix": "",
              "Status": "Enabled"
            }
          ],
          "Role": {
            "Fn::GetAtt": [
              "WorkItemBucketBackupRole",
              "Arn"
            ]
          }
        },
        "VersioningConfiguration": {
          "Status": "Suspended"
        }
      }
    }
  }
}

```
---
title: "S3 bucket should have bucket policy"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_should_have_bucket_policy"
  id: "37fa8188-738b-42c8-bf82-6334ea567738"
  display_name: "S3 bucket should have bucket policy"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `37fa8188-738b-42c8-bf82-6334ea567738`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html)

### Description

 S3 buckets should have an associated bucket policy so explicit access controls can be enforced. This reduces the risk of unintended public or overly broad access to bucket contents.

This rule checks `AWS::S3::Bucket` resources for a matching `AWS::S3::BucketPolicy` whose `Bucket` property references the same bucket. The policy may reference the bucket using a `Ref` to the bucket's logical ID, or by matching the bucket's `BucketName` property.

Resources missing a matching `AWS::S3::BucketPolicy`, or policies that reference a different identifier, will be flagged. If you omit `BucketName` (letting CloudFormation generate the name), ensure the policy uses `!Ref` to the bucket. If you provide an explicit `BucketName`, the policy may reference that literal name.

Secure configuration example:

```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: my-bucket-name

MyBucketPolicy:
  Type: AWS::S3::BucketPolicy
  Properties:
    Bucket: !Ref MyBucket
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: "arn:aws:iam::123456789012:role/ReadOnlyRole"
          Action: "s3:GetObject"
          Resource: !Sub "arn:aws:s3:::${MyBucket}/*"
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    DeletionPolicy: Retain
    Properties:
      BucketName: docexamplebucket
  SampleBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: docexamplebucket
      PolicyDocument:
        Statement:
          - Action:
              - 's3:GetObject'
            Effect: Allow
            Resource:
              'Fn::Join':
                - ''
                - - 'arn:aws:s3:::'
                  - Ref: docexamplebucket
                  - /*
            Principal: '*'
            Condition:
              StringLike:
                'aws:Referer':
                  - 'http://www.example.com/*'
                  - 'http://example.net/*'
  S3Bucket9:
    Type: 'AWS::S3::Bucket'
    DeletionPolicy: Retain
    Properties:
      BucketName: docexamplebucket
  SampleBucketPolicy10:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref docexamplebucket
      PolicyDocument:
        Statement:
          - Action:
              - 's3:GetObject'
            Effect: Allow
            Resource:
              'Fn::Join':
                - ''
                - - 'arn:aws:s3:::'
                  - Ref: docexamplebucket
                  - /*
            Principal: '*'
            Condition:
              StringLike:
                'aws:Referer':
                  - 'http://www.example.com/*'
                  - 'http://example.net/*'

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "MyS3Bucket22": {
      "Properties": {
        "AccessControl": "PublicRead",
        "MetricsConfigurations": [
          {
            "Id": "EntireBucket"
          }
        ],
        "WebsiteConfiguration": {
          "ErrorDocument": "error.html",
          "IndexDocument": "index.html",
          "RoutingRules": [
            {
              "RedirectRule": {
                "HostName": "ec2-11-22-333-44.compute-1.amazonaws.com",
                "ReplaceKeyPrefixWith": "report-404/"
              },
              "RoutingRuleCondition": {
                "HttpErrorCodeReturnedEquals": "404",
                "KeyPrefixEquals": "out1/"
              }
            }
          ]
        }
      },
      "Type": "AWS::S3::Bucket"
    },
    "SampleBucketPolicy2": {
      "Properties": {
        "Bucket": "MyS3Bucket22",
        "PolicyDocument": {
          "Statement": [
            {
              "Action": [
                "s3:GetObject"
              ],
              "Condition": {
                "StringLike": {
                  "aws:Referer": [
                    "http://www.example.com/*",
                    "http://example.net/*"
                  ]
                }
              },
              "Effect": "Allow",
              "Principal": "*",
              "Resource": {
                "Fn::Join": [
                  "",
                  {
                    "playbooks": [
                      "arn:aws:s3:::",
                      {
                        "Ref": "docexamplebucket"
                      },
                      "/*"
                    ]
                  }
                ]
              }
            }
          ]
        }
      },
      "Type": "AWS::S3::BucketPolicy"
    }
  }
}

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "S3Bucket": {
      "Type": "AWS::S3::Bucket",
      "DeletionPolicy": "Retain",
      "Properties": {
        "BucketName": "docexamplebucket"
      }
    },
    "SampleBucketPolicy": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": "docexamplebucket",
        "PolicyDocument": {
          "Statement": [
            {
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "docexamplebucket"
                    },
                    "/*"
                  ]
                ]
              },
              "Principal": "*",
              "Condition": {
                "StringLike": {
                  "aws:Referer": [
                    "http://www.example.com/*",
                    "http://example.net/*"
                  ]
                }
              },
              "Action": [
                "s3:GetObject"
              ],
              "Effect": "Allow"
            }
          ]
        }
      }
    },
    "S3Bucket9": {
      "Type": "AWS::S3::Bucket",
      "DeletionPolicy": "Retain",
      "Properties": {
        "BucketName": "docexamplebucket"
      }
    },
    "SampleBucketPolicy10": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "PolicyDocument": {
          "Statement": [
            {
              "Principal": "*",
              "Condition": {
                "StringLike": {
                  "aws:Referer": [
                    "http://www.example.com/*",
                    "http://example.net/*"
                  ]
                }
              },
              "Action": [
                "s3:GetObject"
              ],
              "Effect": "Allow",
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "docexamplebucket"
                    },
                    "/*"
                  ]
                ]
              }
            }
          ]
        },
        "Bucket": "docexamplebucket"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "SampleBucketPolicy8": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": "docexamplebucketfail2",
        "PolicyDocument": {
          "Statement": [
            {
              "Action": [
                "s3:GetObject"
              ],
              "Effect": "Allow",
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "docexamplebucket1"
                    },
                    "/*"
                  ]
                ]
              },
              "Principal": "*",
              "Condition": {
                "StringLike": {
                  "aws:Referer": [
                    "http://www.example.com/*",
                    "http://example.net/*"
                  ]
                }
              }
            }
          ]
        }
      }
    },
    "S3Bucket3": {
      "Type": "AWS::S3::Bucket",
      "DeletionPolicy": "Retain",
      "Properties": {
        "BucketName": "docexamplebucket1"
      }
    },
    "SampleBucketPolicy5": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": {
          "Ref": "docexamplebucketfail"
        },
        "PolicyDocument": {
          "Statement": [
            {
              "Condition": {
                "StringLike": {
                  "aws:Referer": [
                    "http://www.example.com/*",
                    "http://example.net/*"
                  ]
                }
              },
              "Action": [
                "s3:GetObject"
              ],
              "Effect": "Allow",
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "docexamplebucket1"
                    },
                    "/*"
                  ]
                ]
              },
              "Principal": "*"
            }
          ]
        }
      }
    },
    "S3Bucket": {
      "Type": "AWS::S3::Bucket",
      "DeletionPolicy": "Retain",
      "Properties": {}
    },
    "SampleBucketPolicy2": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": "docexamplebucket2",
        "PolicyDocument": {
          "Statement": [
            {
              "Action": [
                "s3:GetObject"
              ],
              "Effect": "Allow",
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "docexamplebucket"
                    },
                    "/*"
                  ]
                ]
              },
              "Principal": "*",
              "Condition": {
                "StringLike": {
                  "aws:Referer": [
                    "http://www.example.com/*",
                    "http://example.net/*"
                  ]
                }
              }
            }
          ]
        }
      }
    },
    "S3Bucket7": {
      "DeletionPolicy": "Retain",
      "Properties": {
        "BucketName": "docexamplebucket5"
      },
      "Type": "AWS::S3::Bucket"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
  MyS3Bucket2:
    Type: 'AWS::S3::Bucket'
    Properties:
      AccessControl: PublicRead
      MetricsConfigurations:
        - Id: EntireBucket
      WebsiteConfiguration:
        IndexDocument: index.html
        ErrorDocument: error.html
        RoutingRules:
          - RoutingRuleCondition:
              HttpErrorCodeReturnedEquals: '404'
              KeyPrefixEquals: out1/
            RedirectRule:
              HostName: ec2-11-22-333-44.compute-1.amazonaws.com
              ReplaceKeyPrefixWith: report-404/

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "MyS3Bucket2": {
      "Properties": {
        "AccessControl": "PublicRead",
        "MetricsConfigurations": [
          {
            "Id": "EntireBucket"
          }
        ],
        "WebsiteConfiguration": {
          "ErrorDocument": "error.html",
          "IndexDocument": "index.html",
          "RoutingRules": [
            {
              "RedirectRule": {
                "HostName": "ec2-11-22-333-44.compute-1.amazonaws.com",
                "ReplaceKeyPrefixWith": "report-404/"
              },
              "RoutingRuleCondition": {
                "HttpErrorCodeReturnedEquals": "404",
                "KeyPrefixEquals": "out1/"
              }
            }
          ]
        }
      },
      "Type": "AWS::S3::Bucket"
    }
  }
}

```
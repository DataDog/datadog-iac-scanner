---
title: "CloudFront logging disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cloudfront_logging_disabled"
  id: "de77cd9f-0e8b-46cc-b4a4-b6b436838642"
  display_name: "CloudFront logging disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `de77cd9f-0e8b-46cc-b4a4-b6b436838642`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/logging-and-monitoring.html)

### Description

CloudFront distributions must have access logging enabled so viewer requests are captured for incident investigation and traffic analysis. Without logs, you cannot audit access patterns, investigate abuse, or troubleshoot delivery problems.

 For `AWS::CloudFront::Distribution` resources, `DistributionConfig.Logging` must be defined when the distribution is enabled (that is, `DistributionConfig.Enabled` is not set to `false`).

 The logging configuration must include a `Bucket` value that points to an Amazon S3 bucket using the S3 domain suffix (it must end with `.s3.amazonaws.com`). Resources missing `Logging` or with a `Bucket` that does not end with `.s3.amazonaws.com` will be flagged.

Secure configuration example:

```yaml
MyDistribution:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      Enabled: true
      Logging:
        Bucket: my-log-bucket.s3.amazonaws.com
        IncludeCookies: false
        Prefix: access-logs/
      # ... other distribution settings ...
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myDistribution3:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Origins:
        - DomainName: mybucket.s3.amazonaws.com
          Id: myS3Origin
          S3OriginConfig:
            OriginAccessIdentity: origin-access-identity/cloudfront/E127EXAMPLE51Z
        Enabled: 'true'
        Comment: Some comment
        DefaultRootObject: index.html
        Logging:
          IncludeCookies: 'false'
          Bucket: mylogs.s3.amazonaws.com
          Prefix: myprefix
    DefaultCacheBehavior:
      AllowedMethods:
      - GET
      - HEAD
      - OPTIONS
      TargetOriginId: myS3Origin
      ForwardedValues:
        QueryString: 'false'
        Cookies:
          Forward: none
      TrustedSigners:
      - 1234567890EX
      ViewerProtocolPolicy: allow-all

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myDistribution3": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "Logging": {
            "IncludeCookies": "false",
            "Bucket": "mylogs.s3.amazonaws.com",
            "Prefix": "myprefix"
          },
          "Origins": [
            {
              "DomainName": "mybucket.s3.amazonaws.com",
              "Id": "myS3Origin",
              "S3OriginConfig": {
                "OriginAccessIdentity": "origin-access-identity/cloudfront/E127EXAMPLE51Z"
              }
            }
          ],
          "Enabled": "true",
          "Comment": "Some comment",
          "DefaultRootObject": "index.html"
        }
      },
      "DefaultCacheBehavior": {
        "ForwardedValues": {
          "Cookies": {
            "Forward": "none"
          },
          "QueryString": "false"
        },
        "TrustedSigners": [
          "1234567890EX"
        ],
        "ViewerProtocolPolicy": "allow-all",
        "AllowedMethods": [
          "GET",
          "HEAD",
          "OPTIONS"
        ],
        "TargetOriginId": "myS3Origin"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myDistribution2:
    Type: AWS::CloudFront::Distribution
    Properties:
      DefaultCacheBehavior:
        AllowedMethods:
        - GET
        - HEAD
        - OPTIONS
        TargetOriginId: myS3Origin
        ForwardedValues:
          QueryString: 'false'
          Cookies:
            Forward: none
        TrustedSigners:
        - 1234567890EX
        ViewerProtocolPolicy: allow-all
      DistributionConfig:
        Origins:
        - DomainName: mybucket.s3.amazonaws.com
          Id: myS3Origin
          S3OriginConfig:
            OriginAccessIdentity: origin-access-identity/cloudfront/E127EXAMPLE51Z
        Enabled: 'true'
        Comment: Some comment
        DefaultRootObject: index.html
        Logging:
          IncludeCookies: 'false'
          Bucket: mylogs.amazonaws.com
          Prefix: myprefix

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myDistribution1": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DefaultCacheBehavior": {
          "AllowedMethods": [
            "GET",
            "HEAD",
            "OPTIONS"
          ],
          "TargetOriginId": "myS3Origin",
          "ForwardedValues": {
            "QueryString": "false",
            "Cookies": {
              "Forward": "none"
            }
          },
          "TrustedSigners": [
            "1234567890EX"
          ],
          "ViewerProtocolPolicy": "allow-all"
        },
        "DistributionConfig": {
          "Origins": [
            {
              "DomainName": "mybucket.s3.amazonaws.com",
              "Id": "myS3Origin",
              "S3OriginConfig": {
                "OriginAccessIdentity": "origin-access-identity/cloudfront/E127EXAMPLE51Z"
              }
            }
          ],
          "Enabled": "true",
          "Comment": "Some comment",
          "DefaultRootObject": "index.html"
        }
      }
    }
  }
}

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myDistribution2": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DefaultCacheBehavior": {
          "AllowedMethods": [
            "GET",
            "HEAD",
            "OPTIONS"
          ],
          "TargetOriginId": "myS3Origin",
          "ForwardedValues": {
            "QueryString": "false",
            "Cookies": {
              "Forward": "none"
            }
          },
          "TrustedSigners": [
            "1234567890EX"
          ],
          "ViewerProtocolPolicy": "allow-all"
        },
        "DistributionConfig": {
          "Origins": [
            {
              "S3OriginConfig": {
                "OriginAccessIdentity": "origin-access-identity/cloudfront/E127EXAMPLE51Z"
              },
              "DomainName": "mybucket.s3.amazonaws.com",
              "Id": "myS3Origin"
            }
          ],
          "Enabled": "true",
          "Comment": "Some comment",
          "DefaultRootObject": "index.html",
          "Logging": {
            "IncludeCookies": "false",
            "Bucket": "mylogs.amazonaws.com",
            "Prefix": "myprefix"
          }
        }
      }
    }
  }
}

```
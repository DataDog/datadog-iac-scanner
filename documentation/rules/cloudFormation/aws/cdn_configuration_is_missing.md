---
title: "CDN configuration is missing"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cdn_configuration_is_missing"
  id: "e4f54ff4-d352-40e8-a096-5141073c37a2"
  display_name: "CDN configuration is missing"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `e4f54ff4-d352-40e8-a096-5141073c37a2`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html)

### Description

 CloudFront distributions must be active and include at least one origin so client traffic is routed through CloudFront's caching and security controls (for example, AWS WAF, AWS Shield, and origin access controls). Without an active distribution or defined origins, traffic can bypass these protections and origins can be exposed to direct access and increased attack surface.

 In CloudFormation, ensure resources of type `AWS::CloudFront::Distribution` set `Properties.DistributionConfig.Enabled` to `true` and that `Properties.DistributionConfig` contains an `Origins` entry with at least one origin definition. Resources missing the `Origins` object or with `Enabled` set to `false` (or the string `"false"`) will be flagged.

 For S3 origins, also configure origin access identity (OAI) or origin access control (OAC), and ensure each origin includes required fields such as `Id` and `DomainName` to prevent unintended public access.

Secure configuration example:

```yaml
MyDistribution:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      Enabled: true
      Origins:
        - Id: myS3Origin
          DomainName: my-bucket.s3.amazonaws.com
          S3OriginConfig: {}
      DefaultCacheBehavior:
        TargetOriginId: myS3Origin
        ViewerProtocolPolicy: redirect-to-https
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myDistribution:
    Type: 'AWS::CloudFront::Distribution'
    Properties:
      DistributionConfig:
        Origins:
        - DomainName: www.example.com
          Id: myCustomOrigin
          CustomOriginConfig:
            HTTPPort: '80'
            HTTPSPort: '443'
            OriginProtocolPolicy: http-only
        Enabled: 'true'
        Comment: Somecomment
        DefaultRootObject: index.html
        Logging:
          IncludeCookies: 'true'
          Bucket: mylogs.s3.amazonaws.com
          Prefix: myprefix
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myDistribution": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "Enabled": "true",
          "Comment": "Somecomment",
          "DefaultRootObject": "index.html",
          "Logging": {
            "IncludeCookies": "true",
            "Bucket": "mylogs.s3.amazonaws.com",
            "Prefix": "myprefix"
          },
          "Origins": [
            {
              "DomainName": "www.example.com",
              "Id": "myCustomOrigin",
              "CustomOriginConfig": {
                "OriginProtocolPolicy": "http-only",
                "HTTPPort": "80",
                "HTTPSPort": "443"
              }
            }
          ]
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myDistribution": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "Comment": "Somecomment",
          "DefaultRootObject": "index.html",
          "Logging": {
            "IncludeCookies": "true",
            "Bucket": "mylogs.s3.amazonaws.com",
            "Prefix": "myprefix"
          },
          "Enabled": "false"
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myDistribution:
    Type: 'AWS::CloudFront::Distribution'
    Properties:
      DistributionConfig:
        Enabled: 'false'
        Comment: Somecomment
        DefaultRootObject: index.html
        Logging:
          IncludeCookies: 'true'
          Bucket: mylogs.s3.amazonaws.com
          Prefix: myprefix

```
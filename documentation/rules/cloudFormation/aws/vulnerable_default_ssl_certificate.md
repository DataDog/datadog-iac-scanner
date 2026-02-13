---
title: "Vulnerable default SSL certificate"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/vulnerable_default_ssl_certificate"
  id: "b4d9c12b-bfba-4aeb-9cb8-2358546d8041"
  display_name: "Vulnerable default SSL certificate"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `b4d9c12b-bfba-4aeb-9cb8-2358546d8041`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html)

### Description

 CloudFront distributions should use a custom SSL/TLS certificate for custom domain names so you control certificate trust and can enforce strong TLS protocol and SNI settings.

For `AWS::CloudFront::Distribution` resources, `ViewerCertificate.CloudFrontDefaultCertificate` must be omitted or set to `false`. When a custom certificate is used via `ViewerCertificate.AcmCertificateArn` or `ViewerCertificate.IamCertificateId`, the `ViewerCertificate.SslSupportMethod` and `ViewerCertificate.MinimumProtocolVersion` properties must be defined. Resources with `CloudFrontDefaultCertificate` set to `true` will be flagged. Distributions that specify an ACM or IAM certificate but omit `SslSupportMethod` or `MinimumProtocolVersion` will also be flagged as misconfigured.

Secure configuration example:

```yaml
MyDistribution:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      ViewerCertificate:
        AcmCertificateArn: arn:aws:acm:us-east-1:123456789012:certificate/abcdefg-1234-5678-90ab-cdef12345678
        SslSupportMethod: sni-only
        MinimumProtocolVersion: TLSv1.2_2019
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myDistribution:
    Type: 'AWS::CloudFront::Distribution'
    Properties:
      DistributionConfig:
        ViewerCertificate:
          AcmCertificateArn: arn:aws:autoscaling:us-west-2:123456789012:autoScalingGroup:a1b2c3d4-5678-90ab-cdef-EXAMPLE11111
          MinimumProtocolVersion: TLS1.2_2019
          SslSupportMethod: sni_only

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myDistribution": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "Enabled": "true"
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
    "myDistribution": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "ViewerCertificate": {
            "AcmCertificateArn": "some arn",
            "MinimumProtocolVersion": "TLS1.2_2019",
            "SslSupportMethod": "sni_only"
          }
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  myDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        ViewerCertificate:
          AcmCertificateArn: arn:aws:autoscaling:us-west-2:123456789012:autoScalingGroup:a1b2c3d4-5678-90ab-cdef-EXAMPLE11111

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  myDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        ViewerCertificate:
          CloudfrontDefaultCertificate: true

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myDistribution": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "ViewerCertificate": {
            "AcmCertificateArn": "arn:aws:autoscaling:us-west-2:123456789012:autoScalingGroup:a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
          }
        }
      }
    }
  }
}

```
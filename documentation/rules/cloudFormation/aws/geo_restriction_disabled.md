---
title: "Geo restriction disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/geo_restriction_disabled"
  id: "7f8843f0-9ea5-42b4-a02b-753055113195"
  display_name: "Geo restriction disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `7f8843f0-9ea5-42b4-a02b-753055113195`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html)

### Description

 Geo restriction must be enabled to limit which geographic locations can access your content. Without it, content can be served globally, increasing attack surface and risking data residency or compliance violations.
 
 In CloudFormation, the `AWS::CloudFront::Distribution` resource’s `Properties.DistributionConfig.Restrictions.GeoRestriction.RestrictionType` must be set to either `whitelist` or `blacklist`. Resources that omit this property or set it to `none` (or any value not containing `whitelist` or `blacklist`) will be flagged. When using `whitelist` or `blacklist`, populate the `Locations` array with the appropriate ISO 3166-1 alpha-2 country codes.

Secure configuration example:

```yaml
MyDistribution:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      Enabled: true
      Restrictions:
        GeoRestriction:
          RestrictionType: whitelist
          Locations:
            - US
            - CA
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Logging:
          IncludeCookies: 'false'
          Bucket: mylogs.s3.amazonaws.com
          Prefix: myprefix
        Restrictions:
          GeoRestriction:
            RestrictionType: whitelist
            Locations:
            - AQ
            - CV
        ViewerCertificate:
          CloudFrontDefaultCertificate: 'true'
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myDistribution": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "Logging": {
            "IncludeCookies": "false",
            "Bucket": "mylogs.s3.amazonaws.com",
            "Prefix": "myprefix"
          },
          "Restrictions": {
            "GeoRestriction": {
              "RestrictionType": "whitelist",
              "Locations": [
                "AQ",
                "CV"
              ]
            }
          },
          "ViewerCertificate": {
            "CloudFrontDefaultCertificate": "true"
          }
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
          "Logging": {
            "IncludeCookies": "false",
            "Bucket": "mylogs.s3.amazonaws.com",
            "Prefix": "myprefix"
          },
          "Restrictions": {
            "GeoRestriction": {
              "RestrictionType": "none"
            }
          },
          "ViewerCertificate": {
            "CloudFrontDefaultCertificate": "true"
          }
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
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Logging:
          IncludeCookies: 'false'
          Bucket: mylogs.s3.amazonaws.com
          Prefix: myprefix
        Restrictions:
          GeoRestriction:
            RestrictionType: none
        ViewerCertificate:
          CloudFrontDefaultCertificate: 'true'
```
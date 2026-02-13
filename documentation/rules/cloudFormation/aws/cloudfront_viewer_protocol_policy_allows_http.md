---
title: "CloudFront viewer protocol policy allows HTTP"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cloudfront_viewer_protocol_policy_allows_http"
  id: "31733ee2-fef0-4e87-9778-65da22a8ecf1"
  display_name: "CloudFront viewer protocol policy allows HTTP"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `31733ee2-fef0-4e87-9778-65da22a8ecf1`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html)

### Description

 CloudFront distributions must enforce HTTPS for viewer connections to prevent plaintext interception and downgrade attacks that could expose credentials or sensitive content.

 In CloudFormation, verify `AWS::CloudFront::Distribution` resources: `DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy` and each `DistributionConfig.CacheBehaviors[].ViewerProtocolPolicy` must be set to `https-only` or `redirect-to-https`.

 Resources with `ViewerProtocolPolicy` set to `allow-all` (or missing the property) will be flagged. Ensure both the default cache behavior and all cache behaviors explicitly enforce or redirect to HTTPS.

Secure configuration examples:

```yaml
MyDistribution:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      DefaultCacheBehavior:
        ViewerProtocolPolicy: redirect-to-https
      CacheBehaviors:
        - PathPattern: "/secure/*"
          ViewerProtocolPolicy: https-only
```


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  cloudfrontdistribution_1:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        CacheBehaviors:
          - LambdaFunctionAssociations:
              - EventType: viewer-request
                LambdaFunctionARN: examp
        DefaultCacheBehavior:
          ViewerProtocolPolicy: https-only
          LambdaFunctionAssociations:
            - EventType: viewer-request
              LambdaFunctionARN: examp
        IPV6Enabled: true
        Origins:
          - CustomOriginConfig:
              OriginKeepaliveTimeout: 60
              OriginReadTimeout: 30
      Tags:
        - Key: name
          Value: example
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "cloudfrontdistribution_1": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "CacheBehaviors": [
            {
              "LambdaFunctionAssociations": [
                {
                  "EventType": "viewer-request",
                  "LambdaFunctionARN": "examp"
                }
              ]
            }
          ],
          "DefaultCacheBehavior": {
            "ViewerProtocolPolicy": "https-only",
            "LambdaFunctionAssociations": [
              {
                "EventType": "viewer-request",
                "LambdaFunctionARN": "examp"
              }
            ]
          },
          "IPV6Enabled": true,
          "Origins": [
            {
              "CustomOriginConfig": {
                "OriginKeepaliveTimeout": 60,
                "OriginReadTimeout": 30
              }
            }
          ]
        },
        "Tags": [
          {
            "Key": "name",
            "Value": "example"
          }
        ]
      }
    }
  }
}

```

```yaml
#this code is a correct code for which the query should not find any result
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  cloudfrontdistribution_1:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        CacheBehaviors:
          - LambdaFunctionAssociations:
              - EventType: viewer-request
                LambdaFunctionARN: examp
        DefaultCacheBehavior:
          ViewerProtocolPolicy: redirect-to-https
          LambdaFunctionAssociations:
            - EventType: viewer-request
              LambdaFunctionARN: examp
        IPV6Enabled: true
        Origins:
          - CustomOriginConfig:
              OriginKeepaliveTimeout: 60
              OriginReadTimeout: 30
      Tags:
        - Key: name
          Value: example

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "cloudfrontdistribution_2": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "CacheBehaviors": [
            {
              "ViewerProtocolPolicy": "allow-all",
              "LambdaFunctionAssociations": [
                {
                  "EventType": "viewer-request",
                  "LambdaFunctionARN": "examp"
                }
              ]
            }
          ],
          "DefaultCacheBehavior": {
            "LambdaFunctionAssociations": [
              {
                "LambdaFunctionARN": "examp",
                "EventType": "viewer-request"
              }
            ]
          },
          "IPV6Enabled": true,
          "Origins": [
            {
              "CustomOriginConfig": {
                "OriginKeepaliveTimeout": 60,
                "OriginReadTimeout": 30
              }
            }
          ],
          "Tags": [
            {
              "Value": "example",
              "Key": "name"
            }
          ]
        }
      }
    },
    "cloudfrontdistribution_1": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "DefaultCacheBehavior": {
            "ViewerProtocolPolicy": "allow-all",
            "LambdaFunctionAssociations": [
              {
                "EventType": "viewer-request",
                "LambdaFunctionARN": "examp"
              }
            ]
          },
          "IPV6Enabled": true,
          "Origins": [
            {
              "CustomOriginConfig": {
                "OriginKeepaliveTimeout": 60,
                "OriginReadTimeout": 30
              }
            }
          ],
          "CacheBehaviors": [
            {
              "LambdaFunctionAssociations": [
                {
                  "EventType": "viewer-request",
                  "LambdaFunctionARN": "examp"
                }
              ]
            }
          ]
        },
        "Tags": [
          {
            "Key": "name",
            "Value": "example"
          }
        ]
      }
    }
  }
}

```

```yaml
#this is a problematic code where the query should report a result(s)
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  cloudfrontdistribution_1:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        CacheBehaviors:
          - LambdaFunctionAssociations:
              - EventType: viewer-request
                LambdaFunctionARN: examp
        DefaultCacheBehavior:
          ViewerProtocolPolicy: allow-all
          LambdaFunctionAssociations:
            - EventType: viewer-request
              LambdaFunctionARN: examp
        IPV6Enabled: true
        Origins:
          - CustomOriginConfig:
              OriginKeepaliveTimeout: 60
              OriginReadTimeout: 30
      Tags:
        - Key: name
          Value: example
  cloudfrontdistribution_2:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        CacheBehaviors:
          - ViewerProtocolPolicy: allow-all
            LambdaFunctionAssociations:
              - EventType: viewer-request
                LambdaFunctionARN: examp
        DefaultCacheBehavior:
          LambdaFunctionAssociations:
            - EventType: viewer-request
              LambdaFunctionARN: examp
        IPV6Enabled: true
        Origins:
          - CustomOriginConfig:
              OriginKeepaliveTimeout: 60
              OriginReadTimeout: 30
        Tags:
        - Key: name
          Value: example
```
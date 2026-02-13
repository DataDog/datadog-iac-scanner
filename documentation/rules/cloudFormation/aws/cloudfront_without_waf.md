---
title: "CloudFront without WAF"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cloudfront_without_waf"
  id: "0f139403-303f-467c-96bd-e717e6cfd62d"
  display_name: "CloudFront without WAF"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `0f139403-303f-467c-96bd-e717e6cfd62d`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html#cfn-cloudfront-distribution-distributionconfig-webaclid)

### Description

 CloudFront distributions should be associated with an AWS WAF web ACL to block common web exploits and reduce exposure to application-layer attacks such as SQL injection, cross-site scripting, and automated bot abuse.

 For enabled distributions (resources of type `AWS::CloudFront::Distribution` where `DistributionConfig.Enabled` is not explicitly `false`), the `DistributionConfig.WebACLId` property must be defined and set to a non-empty value. Resources missing `WebACLId` or with `WebACLId` set to an empty string will be flagged.

 `WebACLId` should contain the ARN of an AWS WAF or AWS WAFv2 web ACL (for CloudFront, use the global AWS WAFv2 ARN) or a CloudFormation reference to an existing web ACL.

Secure configuration example:

```yaml
MyDistribution:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      Enabled: true
      WebACLId: arn:aws:wafv2:us-east-1:123456789012:global/webacl/my-webacl/11111111-1111-1111-1111-111111111111
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  cloudfrontdistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Enabled: true
        CacheBehaviors:
          - LambdaFunctionAssociations:
              - EventType: string-value
                LambdaFunctionARN: string-value
        DefaultCacheBehavior:
          LambdaFunctionAssociations:
            - EventType: string-value
              LambdaFunctionARN: string-value
        IPV6Enabled: boolean-value
        Origins:
          - CustomOriginConfig:
              OriginKeepaliveTimeout: integer-value
              OriginReadTimeout: integer-value
        WebACLId: string-value
      Tags:
        - Key: string-value
          Value: string-value

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "cloudfrontdistribution": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "Enabled": true,
          "CacheBehaviors": [
            {
              "LambdaFunctionAssociations": [
                {
                  "EventType": "string-value",
                  "LambdaFunctionARN": "string-value"
                }
              ]
            }
          ],
          "DefaultCacheBehavior": {
            "LambdaFunctionAssociations": [
              {
                "EventType": "string-value",
                "LambdaFunctionARN": "string-value"
              }
            ]
          },
          "IPV6Enabled": "boolean-value",
          "Origins": [
            {
              "CustomOriginConfig": {
                "OriginKeepaliveTimeout": "integer-value",
                "OriginReadTimeout": "integer-value"
              }
            }
          ],
          "WebACLId": "string-value"
        },
        "Tags": [
          {
            "Value": "string-value",
            "Key": "string-value"
          }
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "cloudfrontdistribution": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "Tags": [
          {
            "Key": "string-value",
            "Value": "string-value"
          }
        ],
        "DistributionConfig": {
          "Enabled": true,
          "CacheBehaviors": [
            {
              "LambdaFunctionAssociations": [
                {
                  "EventType": "string-value",
                  "LambdaFunctionARN": "string-value"
                }
              ]
            }
          ],
          "DefaultCacheBehavior": {
            "LambdaFunctionAssociations": [
              {
                "EventType": "string-value",
                "LambdaFunctionARN": "string-value"
              }
            ]
          },
          "IPV6Enabled": "boolean-value",
          "Origins": [
            {
              "CustomOriginConfig": {
                "OriginKeepaliveTimeout": "integer-value",
                "OriginReadTimeout": "integer-value"
              }
            }
          ]
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  cloudfrontdistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Enabled: true
        CacheBehaviors:
          - LambdaFunctionAssociations:
              - EventType: string-value
                LambdaFunctionARN: string-value
        DefaultCacheBehavior:
          LambdaFunctionAssociations:
            - EventType: string-value
              LambdaFunctionARN: string-value
        IPV6Enabled: boolean-value
        Origins:
          - CustomOriginConfig:
              OriginKeepaliveTimeout: integer-value
              OriginReadTimeout: integer-value
        WebACLId: ""
      Tags:
        - Key: string-value
          Value: string-value

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "cloudfrontdistribution": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "Enabled": true,
          "CacheBehaviors": [
            {
              "LambdaFunctionAssociations": [
                {
                  "EventType": "string-value",
                  "LambdaFunctionARN": "string-value"
                }
              ]
            }
          ],
          "DefaultCacheBehavior": {
            "LambdaFunctionAssociations": [
              {
                "EventType": "string-value",
                "LambdaFunctionARN": "string-value"
              }
            ]
          },
          "IPV6Enabled": "boolean-value",
          "Origins": [
            {
              "CustomOriginConfig": {
                "OriginKeepaliveTimeout": "integer-value",
                "OriginReadTimeout": "integer-value"
              }
            }
          ],
          "WebACLId": ""
        },
        "Tags": [
          {
            "Value": "string-value",
            "Key": "string-value"
          }
        ]
      }
    }
  }
}

```
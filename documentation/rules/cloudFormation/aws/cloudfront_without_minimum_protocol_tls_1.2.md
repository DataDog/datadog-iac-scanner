---
title: "CloudFront without minimum protocol TLS 1.2"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cloudfront_without_minimum_protocol_tls_1.2"
  id: "dc17ee4b-ddf2-4e23-96e8-7a36abad1303"
  display_name: "CloudFront without minimum protocol TLS 1.2"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `dc17ee4b-ddf2-4e23-96e8-7a36abad1303`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html)

### Description

 CloudFront distributions must define a `ViewerCertificate` and enforce a minimum TLS version of 1.2 to prevent the use of weak SSL/TLS protocols that can enable downgrade attacks and interception of client connections.

 For `AWS::CloudFront::Distribution` resources, ensure `Properties.DistributionConfig.ViewerCertificate` is present and its `MinimumProtocolVersion` is set to a TLS 1.2 family value (for example, `TLSv1.2_2018` or `TLSv1.2_2019`). Also include an appropriate certificate reference (such as `ACMCertificateArn`) and `SslSupportMethod`.

 This check only applies to distributions that are enabled (`DistributionConfig.Enabled` not set to `false`). Resources missing `ViewerCertificate` or with `MinimumProtocolVersion` lower than TLS 1.2 will be flagged.

Secure CloudFormation example:

```yaml
MyDistribution:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      Enabled: true
      ViewerCertificate:
        ACMCertificateArn: arn:aws:acm:us-east-1:123456789012:certificate/abcdef01-2345-6789-abcd-ef0123456789
        SslSupportMethod: sni-only
        MinimumProtocolVersion: TLSv1.2_2019
      Origins:
        - Id: myOrigin
          DomainName: example.com
          CustomOriginConfig:
            HTTPPort: 80
            HTTPSPort: 443
            OriginProtocolPolicy: https-only
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  cloudfrontdistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
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
        ViewerCertificate:
            AcmCertificateArn: String
            CloudFrontDefaultCertificate: true
            IamCertificateId: String
            MinimumProtocolVersion: "TLSv1.2_2018"
            SslSupportMethod: String
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
          "ViewerCertificate": {
            "IamCertificateId": "String",
            "MinimumProtocolVersion": "TLSv1.2_2018",
            "SslSupportMethod": "String",
            "AcmCertificateArn": "String",
            "CloudFrontDefaultCertificate": true
          }
        },
        "Tags": [
          {
            "Key": "string-value",
            "Value": "string-value"
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
        "DistributionConfig": {
          "Enabled": true,
          "ViewerCertificate": {
            "IamCertificateId": "String",
            "MinimumProtocolVersion": "TLSv1.1_2016",
            "SslSupportMethod": "String",
            "AcmCertificateArn": "String",
            "CloudFrontDefaultCertificate": true
          },
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
        },
        "Tags": [
          {
            "Key": "string-value",
            "Value": "string-value"
          }
        ]
      }
    },
    "cloudfrontdistribution2": {
      "Type": "AWS::CloudFront::Distribution",
      "Properties": {
        "DistributionConfig": {
          "Enabled": true,
          "Origins": [
            {
              "CustomOriginConfig": {
                "OriginKeepaliveTimeout": "integer-value",
                "OriginReadTimeout": "integer-value"
              }
            }
          ],
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
                "LambdaFunctionARN": "string-value",
                "EventType": "string-value"
              }
            ]
          },
          "IPV6Enabled": "boolean-value"
        },
        "Tags": [
          {
            "Key": "string-value",
            "Value": "string-value"
          }
        ]
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
        ViewerCertificate:
            AcmCertificateArn: String
            CloudFrontDefaultCertificate: true
            IamCertificateId: String
            MinimumProtocolVersion: "TLSv1.1_2016"
            SslSupportMethod: String
      Tags:
        - Key: string-value
          Value: string-value
  cloudfrontdistribution2:
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
      Tags:
        - Key: string-value
          Value: string-value

```
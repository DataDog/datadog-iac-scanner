---
title: "S3 bucket with unsecured CORS rule"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_with_unsecured_cors_rule"
  id: "3609d27c-3698-483a-9402-13af6ae80583"
  display_name: "S3 bucket with unsecured CORS rule"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `3609d27c-3698-483a-9402-13af6ae80583`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors.html)

### Description

 CORS rules that allow all methods, all headers, or use overly broad (or multiple) origins can enable unintended cross-origin access. This increases the risk of data exfiltration or unauthorized requests to your S3 objects.

For `AWS::S3::Bucket` resources, examine `Properties.CorsConfiguration.CorsRules` entries. `AllowedMethods` and `AllowedHeaders` must not include the wildcard (`*`). `AllowedOrigins` should be restricted to explicit, trusted origins rather than wildcards or overly broad lists.

This rule flags any `CorsRules` entry where `AllowedMethods` or `AllowedHeaders` contains `*`. It also flags rules where `AllowedOrigins` includes `*` or an unnecessarily broad set of origins.

Secure example with a single trusted origin and explicit methods/headers:

```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    CorsConfiguration:
      CorsRules:
        - AllowedOrigins:
            - "https://example.com"
          AllowedMethods:
            - GET
            - HEAD
          AllowedHeaders:
            - "Content-Type"
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      AccessControl: PublicRead
      CorsConfiguration:
        CorsRules:
          - AllowedMethods:
              - GET
            AllowedOrigins:
              - 'https://s3-website-test.hashicorp.com'
            ExposedHeaders:
              - Date
            Id: myCORSRuleId1
            MaxAge: 3600
          - AllowedMethods:
              - DELETE
            AllowedOrigins:
              - 'http://www.example.com'
              - 'http://www.example.net'
            ExposedHeaders:
              - Connection
              - Server
              - Date
            Id: myCORSRuleId2
            MaxAge: 1800

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "S3Bucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "AccessControl": "PublicRead",
        "CorsConfiguration": {
          "CorsRules": [
            {
              "AllowedMethods": [
                "GET"
              ],
              "AllowedOrigins": [
                "https://s3-website-test.hashicorp.com"
              ],
              "ExposedHeaders": [
                "Date"
              ],
              "Id": "myCORSRuleId1",
              "MaxAge": 3600
            },
            {
              "AllowedMethods": [
                "DELETE"
              ],
              "AllowedOrigins": [
                "http://www.example.com",
                "http://www.example.net"
              ],
              "ExposedHeaders": [
                "Connection",
                "Server",
                "Date"
              ],
              "Id": "myCORSRuleId2",
              "MaxAge": 1800
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
    "S3Bucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "AccessControl": "PublicRead",
        "CorsConfiguration": {
          "CorsRules": [
            {
              "AllowedHeaders": [
                "*"
              ],
              "AllowedMethods": [
                "GET"
              ],
              "AllowedOrigins": [
                "*"
              ],
              "ExposedHeaders": [
                "Date"
              ],
              "Id": "myCORSRuleId1",
              "MaxAge": 3600
            },
            {
              "AllowedMethods": [
                "DELETE"
              ],
              "AllowedOrigins": [
                "http://www.example.com",
                "http://www.example.net"
              ],
              "ExposedHeaders": [
                "Connection",
                "Server",
                "Date"
              ],
              "Id": "myCORSRuleId2",
              "MaxAge": 1800
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
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      AccessControl: PublicRead
      CorsConfiguration:
        CorsRules:
          - AllowedHeaders:
              - '*'
            AllowedMethods:
              - GET
            AllowedOrigins:
              - '*'
            ExposedHeaders:
              - Date
            Id: myCORSRuleId1
            MaxAge: 3600
          - AllowedMethods:
              - DELETE
            AllowedOrigins:
              - 'http://www.example.com'
              - 'http://www.example.net'
            ExposedHeaders:
              - Connection
              - Server
              - Date
            Id: myCORSRuleId2
            MaxAge: 1800

```
---
title: "API Gateway cache encrypted disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/api_gateway_cache_encrypted_disabled"
  id: "37cca703-b74c-48ba-ac81-595b53398e9b"
  display_name: "API Gateway cache encrypted disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `37cca703-b74c-48ba-ac81-595b53398e9b`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-deployment-stagedescription.html)

### Description

API Gateway stage caches can store sensitive response data. If caching is enabled but cache data is not encrypted, cached content at rest may be exposed via compromised storage or unauthorized access.

 For CloudFormation, `AWS::ApiGateway::Deployment` resources must set `StageDescription.CacheDataEncrypted` to `true` whenever `StageDescription.CachingEnabled` is set to `true`. Resources missing the `CacheDataEncrypted` property or with `CacheDataEncrypted` set to `false` while caching is enabled will be flagged. 
 
 Secure configuration example:

```yaml
MyDeployment:
  Type: AWS::ApiGateway::Deployment
  Properties:
    RestApiId: !Ref MyApi
    StageName: prod
    StageDescription:
      CachingEnabled: true
      CacheDataEncrypted: true
```

## Compliant Code Examples
```yaml
Resources:
  Deployment:
    Type: 'AWS::ApiGateway::Deployment'
    Properties:
      RestApiId: !Ref MyApi
      Description: My deployment
      StageName: DummyStage
      StageDescription:
        CacheDataEncrypted: true
        CachingEnabled: true

```

```json
{
  "Resources": {
    "Deployment": {
      "Type": "AWS::ApiGateway::Deployment",
      "Properties": {
        "RestApiId": {
          "Ref": "MyApi"
        },
        "Description": "My deployment",
        "StageName": "DummyStage",
        "StageDescription": {
          "CacheDataEncrypted": true,
          "CachingEnabled": true
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "Deployment": {
      "Type": "AWS::ApiGateway::Deployment",
      "Properties": {
        "RestApiId": {
          "Ref": "MyApi"
        },
        "Description": "My deployment",
        "StageName": "DummyStage",
        "StageDescription": {
          "CachingEnabled": true
        }
      }
    }
  }
}

```

```yaml
Resources:
  Deployment:
    Type: 'AWS::ApiGateway::Deployment'
    Properties:
      RestApiId: !Ref MyApi
      Description: My deployment
      StageName: DummyStage
      StageDescription:
        CacheDataEncrypted: false
        CachingEnabled: true

```

```json
{
  "Resources": {
    "Deployment": {
      "Type": "AWS::ApiGateway::Deployment",
      "Properties": {
        "RestApiId": {
          "Ref": "MyApi"
        },
        "Description": "My deployment",
        "StageName": "DummyStage",
        "StageDescription": {
          "CacheDataEncrypted": false,
          "CachingEnabled": true
        }
      }
    }
  }
}

```
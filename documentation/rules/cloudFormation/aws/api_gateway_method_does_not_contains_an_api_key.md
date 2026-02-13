---
title: "API Gateway method does not contain an API key"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/api_gateway_method_does_not_contains_an_api_key"
  id: "3641d5b4-d339-4bc2-bfb9-208fe8d3477f"
  display_name: "API Gateway method does not contain an API key"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `3641d5b4-d339-4bc2-bfb9-208fe8d3477f`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-method.html)

### Description

 API Gateway methods must require an API key to prevent unauthenticated or uncontrolled usage that can lead to abuse, unexpected costs, or bypassing usage plans. For CloudFormation, `AWS::ApiGateway::Method` resources must define `Properties.ApiKeyRequired` and set it to `true`. Resources missing `ApiKeyRequired` or with `ApiKeyRequired` set to `false` will be flagged. Note that API keys help enforce usage plans and quotas but are not a substitute for strong authentication or authorization.

Secure configuration example:

```yaml
MyMethod:
  Type: AWS::ApiGateway::Method
  Properties:
    RestApiId: !Ref MyApi
    ResourceId: !Ref MyResource
    HttpMethod: GET
    AuthorizationType: NONE
    ApiKeyRequired: true
    Integration:
      Type: MOCK
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: ApiGateway
Resources:
  MockMethod:
    Type: 'AWS::ApiGateway::Method'
    Properties:
      ApiKeyRequired: true
      RestApiId: !Ref MyApi
      ResourceId: !GetAtt
        - MyApi
        - RootResourceId
      HttpMethod: ""
      AuthorizationType: NONE
      Integration:
        Type: MOCK
      MethodResponses:
        - StatusCode : "200"



```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "ApiGateway",
  "Resources": {
    "MockMethod": {
      "Type": "AWS::ApiGateway::Method",
      "Properties": {
        "Integration": {
          "Type": "MOCK"
        },
        "MethodResponses": [
          {
            "StatusCode": "200"
          }
        ],
        "ApiKeyRequired": true,
        "RestApiId": "MyApi",
        "ResourceId": [
          "MyApi",
          "RootResourceId"
        ],
        "HttpMethod": "",
        "AuthorizationType": "NONE"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: ApiGateway
Resources:
  MockMethod1:
    Type: 'AWS::ApiGateway::Method'
    Properties:
      RestApiId: !Ref MyApi
      ResourceId: !GetAtt
        - MyApi
        - RootResourceId
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: MOCK
      MethodResponses:
        - StatusCode : "200"


```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "ApiGateway",
  "Resources": {
    "MockMethod": {
      "Type": "AWS::ApiGateway::Method",
      "Properties": {
        "MethodResponses": [
          {
            "StatusCode": "200"
          }
        ],
        "ApiKeyRequired": false,
        "RestApiId": "MyApi",
        "ResourceId": [
          "MyApi",
          "RootResourceId"
        ],
        "HttpMethod": "GET",
        "AuthorizationType": "NONE",
        "Integration": {
          "Type": "MOCK"
        }
      }
    }
  }
}

```

```json
{
  "Description": "ApiGateway",
  "Resources": {
    "MockMethod1": {
      "Type": "AWS::ApiGateway::Method",
      "Properties": {
        "ResourceId": [
          "MyApi",
          "RootResourceId"
        ],
        "HttpMethod": "GET",
        "AuthorizationType": "NONE",
        "Integration": {
          "Type": "MOCK"
        },
        "MethodResponses": [
          {
            "StatusCode": "200"
          }
        ],
        "RestApiId": "MyApi"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```
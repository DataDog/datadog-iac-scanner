---
title: "API Gateway with open access"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/api_gateway_with_open_access"
  id: "1056dfbb-5802-4762-bf2b-8b9b9684b1b0"
  display_name: "API Gateway with open access"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `1056dfbb-5802-4762-bf2b-8b9b9684b1b0`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-method.html)

### Description

API Gateway methods must not set `AuthorizationType` to `NONE` except for CORS preflight (`OPTIONS`) requests, because leaving a method unauthenticated allows anyone to invoke the endpoint and can lead to unauthorized access, data exposure, or backend abuse.

 For `AWS::ApiGateway::Method` resources, `AuthorizationType` must specify an authentication mechanism (for example, `AWS_IAM`, `CUSTOM`, or `COGNITO_USER_POOLS`) when `HttpMethod` is not `OPTIONS`. This rule flags `Resources.<name>.Properties` where `AuthorizationType` is `NONE` and `HttpMethod` is not `OPTIONS`.

 If you use `CUSTOM`, also set `AuthorizerId` to reference a configured authorizer. If you use `COGNITO_USER_POOLS` or `AWS_IAM`, ensure the corresponding user pool or IAM policies and roles are correctly configured.

Secure configuration example (CloudFormation YAML):

```yaml
MyMethod:
  Type: AWS::ApiGateway::Method
  Properties:
    HttpMethod: POST
    AuthorizationType: AWS_IAM
    RestApiId: !Ref MyApi
    ResourceId: !Ref MyResource
    Integration:
      Type: AWS_PROXY
      IntegrationHttpMethod: POST
      Uri: !Sub arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${MyFunction.Arn}/invocations
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
Resources:
  MockMethod:
    Type: 'AWS::ApiGateway::Method'
    Properties:
      RestApiId: !Ref MyApi
      ResourceId: !GetAtt
        - MyApi
        - RootResourceId
      HttpMethod: OPTIONS
      AuthorizationType: NONE
      Integration:
        Type: MOCK

```

```json
{
  "Description": "Router53",
  "Resources": {
    "MockMethod": {
      "Type": "AWS::ApiGateway::Method",
      "Properties": {
        "RestApiId": "MyApi",
        "ResourceId": [
          "MyApi",
          "RootResourceId"
        ],
        "HttpMethod": "OPTIONS",
        "AuthorizationType": "NONE",
        "Integration": {
          "Type": "MOCK"
        }
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Router53",
  "Resources": {
    "MockMethod": {
      "Type": "AWS::ApiGateway::Method",
      "Properties": {
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

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
Resources:
  MockMethod:
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

```
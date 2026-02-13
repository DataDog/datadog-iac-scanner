---
title: "API Gateway without configured authorizer"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/api_gateway_without_configured_authorizer"
  id: "7fd0d461-5b8c-4815-898c-f2b4b117eb28"
  display_name: "API Gateway without configured authorizer"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `7fd0d461-5b8c-4815-898c-f2b4b117eb28`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-authorizer.html)

### Description

APIs without an associated authorizer can accept unauthenticated or insufficiently authenticated requests, increasing the risk of unauthorized access to backend services and potential data exfiltration or abuse.

 For CloudFormation, each API resource of type `AWS::ApiGateway::RestApi` or `AWS::ApiGatewayV2::Api` must have a corresponding authorizer resource:

 - `AWS::ApiGateway::Authorizer` that sets `RestApiId` to reference the REST API
 - `AWS::ApiGatewayV2::Authorizer` that sets `ApiId` to reference the v2 API

 Resources missing an authorizer reference (or with no matching `RestApiId`/`ApiId`) will be flagged. The identifier may be provided as a `Ref`, `Fn::GetAtt`, a literal ARN, or another expression that resolves to the API identifier.

Secure examples:

```yaml
MyRestApi:
  Type: AWS::ApiGateway::RestApi
  Properties:
    Name: my-rest-api

MyAuthorizer:
  Type: AWS::ApiGateway::Authorizer
  Properties:
    Name: my-authorizer
    RestApiId: !Ref MyRestApi
    Type: TOKEN
    AuthorizerUri: arn:aws:apigateway:region:lambda:path/2015-03-31/functions/arn:aws:lambda:region:acct:function:auth-fn/invocations
```

```yaml
MyHttpApi:
  Type: AWS::ApiGatewayV2::Api
  Properties:
    Name: my-http-api
    ProtocolType: HTTP

MyV2Authorizer:
  Type: AWS::ApiGatewayV2::Authorizer
  Properties:
    Name: my-v2-authorizer
    ApiId: !Ref MyHttpApi
    AuthorizerType: JWT
    IdentitySource:
      - "$request.header.Authorization"
    JwtConfiguration:
      issuer: "https://cognito-idp.region.amazonaws.com/POOL_ID"
      audience:
        - CLIENT_ID
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  DevWebSocket2:
    Type: 'AWS::ApiGatewayV2::Api'
    Properties:
      Name: TL-Dev-WebSocket-API
      ProtocolType: WEBSOCKET
      RouteSelectionExpression: $request.body.action
  DevAuthorizerLambda:
    Type: 'AWS::Serverless::Function'
    Properties:
      CodeUri: WebSockets/Authorizer
      Role: 'arn:aws:iam::************:role/LambdaDynamoDB'
      Environment:
        Variables:
          STAGE: Dev
  DevAuthorizerLambdaPermission:
    Type: 'AWS::Lambda::Permission'
    Properties:
      Action: 'lambda:invokeFunction'
      Principal: apigateway.amazonaws.com
      FunctionName:
        Ref: DevAuthorizerLambda
      SourceArn:
        'Fn::Sub':
          - >-
            arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${__ApiId__}/${__Stage__}/$connect
          - __Stage__: '*'
            __ApiId__:
              Ref: DevWebSocket
  DevWebSocketAuthorizer:
    Type: 'AWS::ApiGatewayV2::Authorizer'
    Properties:
      Name: DevAuthorizer
      ApiId:
        Ref: DevWebSocket2
      AuthorizerType: REQUEST
      AuthorizerUri:
        'Fn::Sub': >-
          arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${DevAuthorizerLambda.Arn}/invocations
      IdentitySource:
        - route.request.querystring.token

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "MyRestApi3": {
      "Properties": {
        "EndpointConfiguration": {
          "Types": [
            "PRIVATE"
          ]
        },
        "Name": "myRestApi"
      },
      "Type": "AWS::ApiGateway::RestApi"
    },
    "Authorizer": {
      "Type": "AWS::ApiGateway::Authorizer",
      "Properties": {
        "RestApiId": "MyRestApi3"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
    MyRestApi2:
        Type: AWS::ApiGateway::RestApi
        Properties:
          EndpointConfiguration:
            Types:
              - PRIVATE
          Name: myRestApi
    Authorizer:
        Type: 'AWS::ApiGateway::Authorizer'
        Properties:
          RestApiId: !Ref MyRestApi2

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  DevWebSocket5:
    Type: 'AWS::ApiGatewayV2::Api'
    Properties:
      Name: TL-Dev-WebSocket-API
      ProtocolType: WEBSOCKET
      RouteSelectionExpression: $request.body.action
  DevAuthorizerLambda5:
    Type: 'AWS::Serverless::Function'
    Properties:
      CodeUri: WebSockets/Authorizer
      Role: 'arn:aws:iam::************:role/LambdaDynamoDB'
      Environment:
        Variables:
          STAGE: Dev
  DevAuthorizerLambdaPermission5:
    Type: 'AWS::Lambda::Permission'
    Properties:
      Action: 'lambda:invokeFunction'
      Principal: apigateway.amazonaws.com
      FunctionName:
        Ref: DevAuthorizerLambda
      SourceArn:
        'Fn::Sub':
          - >-
            arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${__ApiId__}/${__Stage__}/$connect
          - __Stage__: '*'
            __ApiId__:
              Ref: DevWebSocket
  DevWebSocketAuthorizer5:
    Type: 'AWS::ApiGatewayV2::Authorizer'
    Properties:
      Name: DevAuthorizer
      ApiId:
        Ref: DevWebSocket222222
      AuthorizerType: REQUEST
      AuthorizerUri:
        'Fn::Sub': >-
          arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${DevAuthorizerLambda.Arn}/invocations
      IdentitySource:
        - route.request.querystring.token

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
    MyRestApi6:
        Type: AWS::ApiGateway::RestApi
        Properties:
          EndpointConfiguration:
            Types:
              - PRIVATE
          Name: myRestApi

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "DevWebSocket8": {
      "Type": "AWS::ApiGatewayV2::Api",
      "Properties": {
        "Name": "TL-Dev-WebSocket-API",
        "ProtocolType": "WEBSOCKET",
        "RouteSelectionExpression": "$request.body.action"
      }
    }
  }
}

```
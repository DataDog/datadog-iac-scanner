---
title: "API Gateway without SSL certificate"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/api_gateway_without_ssl_certificate"
  id: "ed4c48b8-eccc-4881-95c1-09fdae23db25"
  display_name: "API Gateway without SSL certificate"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `ed4c48b8-eccc-4881-95c1-09fdae23db25`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html)

### Description

 API Gateway stages should present a client SSL/TLS certificate to their backend so the backend can cryptographically verify that requests originate from the API Gateway. Without this, backends cannot reliably distinguish legitimate API Gateway traffic from spoofed or direct requests, increasing the risk of unauthorized access to internal services.

 In CloudFormation, `AWS::ApiGateway::Stage` resources must define the `ClientCertificateId` property and it should reference the ID of an `AWS::ApiGateway::ClientCertificate` (for example, with `!Ref`). Resources missing `ClientCertificateId` will be flagged.

Secure configuration example:

```yaml
MyClientCertificate:
  Type: AWS::ApiGateway::ClientCertificate

MyStage:
  Type: AWS::ApiGateway::Stage
  Properties:
    StageName: prod
    RestApiId: !Ref MyRestApi
    ClientCertificateId: !Ref MyClientCertificate
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  ProdApiGatewayStageNeg:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: Prod
      Description: Prod Stage
      RestApiId: !Ref MyRestApi
      DeploymentId: !Ref TestDeployment
      DocumentationVersion: !Ref MyDocumentationVersion
      ClientCertificateId: !Ref ClientCertificate
      Variables:
        Stack: Prod
      MethodSettings:
        - ResourcePath: /
          HttpMethod: GET
          MetricsEnabled: 'true'
          DataTraceEnabled: 'false'
        - ResourcePath: /stack
          HttpMethod: POST
          MetricsEnabled: 'true'
          DataTraceEnabled: 'false'
          ThrottlingBurstLimit: '999'
        - ResourcePath: /stack
          HttpMethod: GET
          MetricsEnabled: 'true'
          DataTraceEnabled: 'false'
          ThrottlingBurstLimit: '555'


```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "ProdApiGatewayStageNeg2": {
      "Type": "AWS::ApiGateway::Stage",
      "Properties": {
        "StageName": "Prod",
        "RestApiId": {
          "Ref": "MyRestApi"
        },
        "DeploymentId": {
          "Ref": "TestDeployment"
        },
        "DocumentationVersion": {
          "Ref": "MyDocumentationVersion"
        },
        "ClientCertificateId": {
          "Ref": "ClientCertificate"
        },
        "Variables": {
          "Stack": "Prod"
        },
        "MethodSettings": [
          {
            "ResourcePath": "/",
            "HttpMethod": "GET",
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false"
          },
          {
            "ResourcePath": "/stack",
            "HttpMethod": "POST",
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "999"
          },
          {
            "ResourcePath": "/stack",
            "HttpMethod": "GET",
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "555"
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
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "ProdApiGatewayStagePos2": {
      "Type": "AWS::ApiGateway::Stage",
      "Properties": {
        "MethodSettings": [
          {
            "DataTraceEnabled": "false",
            "ResourcePath": "/",
            "HttpMethod": "GET",
            "MetricsEnabled": "true"
          },
          {
            "ResourcePath": "/stack",
            "HttpMethod": "POST",
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "999"
          },
          {
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "555",
            "ResourcePath": "/stack",
            "HttpMethod": "GET"
          }
        ],
        "StageName": "Prod",
        "RestApiId": "MyRestApi",
        "DeploymentId": "TestDeployment",
        "DocumentationVersion": "MyDocumentationVersion",
        "Variables": {
          "Stack": "Prod"
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  ProdApiGatewayStagePos:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: Prod
      Description: Prod Stage
      RestApiId: !Ref MyRestApi
      DeploymentId: !Ref TestDeployment
      DocumentationVersion: !Ref MyDocumentationVersion
      Variables:
        Stack: Prod
      MethodSettings:
        - ResourcePath: /
          HttpMethod: GET
          MetricsEnabled: 'true'
          DataTraceEnabled: 'false'
        - ResourcePath: /stack
          HttpMethod: POST
          MetricsEnabled: 'true'
          DataTraceEnabled: 'false'
          ThrottlingBurstLimit: '999'
        - ResourcePath: /stack
          HttpMethod: GET
          MetricsEnabled: 'true'
          DataTraceEnabled: 'false'
          ThrottlingBurstLimit: '555'


```